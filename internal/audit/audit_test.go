package audit

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTestDB(t *testing.T) *SQLiteAuditor {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test-audit.db")
	a, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open(%q): %v", dbPath, err)
	}
	t.Cleanup(func() {
		if err := a.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return a
}

func sampleChain(eventName, outcome string, ts time.Time, hooks []HookResult) ChainExecution {
	return ChainExecution{
		Timestamp:  ts,
		EventName:  eventName,
		ToolName:   "Bash",
		ToolDetail: "ls -la",
		ChainLen:   len(hooks),
		Outcome:    outcome,
		Reason:     "test reason",
		DurationMs: 42,
		SessionID:  "sess-001",
		Hooks:      hooks,
	}
}

func sampleHooks() []HookResult {
	return []HookResult{
		{
			HookIndex:  0,
			HookName:   "guard",
			ExitCode:   0,
			Outcome:    HookOutcomePass,
			DurationMs: 10,
			Stderr:     "",
		},
		{
			HookIndex:  1,
			HookName:   "logger",
			ExitCode:   0,
			Outcome:    HookOutcomeContext,
			DurationMs: 5,
			Stderr:     "some debug output",
		},
	}
}

func TestOpenCreateDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "subdir", "audit.db")
	a, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open(%q): %v", dbPath, err)
	}
	defer func() {
		if err := a.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	// Verify tables exist by querying them.
	db := a.DB()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM chain_executions").Scan(&count); err != nil {
		t.Fatalf("query chain_executions: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 rows in chain_executions, got %d", count)
	}

	if err := db.QueryRow("SELECT COUNT(*) FROM hook_results").Scan(&count); err != nil {
		t.Fatalf("query hook_results: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 rows in hook_results, got %d", count)
	}
}

func TestSchemaMigration(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "migration-test.db")
	a, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open(%q): %v", dbPath, err)
	}
	defer func() {
		if err := a.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()

	// Verify tool_detail column exists.
	exists, err := columnExists(a.DB(), "chain_executions", "tool_detail")
	if err != nil {
		t.Fatalf("columnExists: %v", err)
	}
	if !exists {
		t.Error("tool_detail column should exist after migration")
	}
}

func TestRecordAndRetrieveChain(t *testing.T) {
	a := openTestDB(t)

	ts := time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)
	hooks := sampleHooks()
	entry := sampleChain("PreToolUse", OutcomeAllow, ts, hooks)

	if err := a.RecordChain(entry); err != nil {
		t.Fatalf("RecordChain: %v", err)
	}

	// Retrieve via GetChain.
	got, err := GetChain(a.DB(), 1)
	if err != nil {
		t.Fatalf("GetChain(1): %v", err)
	}

	if got.EventName != "PreToolUse" {
		t.Errorf("EventName = %q, want PreToolUse", got.EventName)
	}
	if got.ToolName != "Bash" {
		t.Errorf("ToolName = %q, want Bash", got.ToolName)
	}
	if got.Outcome != OutcomeAllow {
		t.Errorf("Outcome = %q, want %q", got.Outcome, OutcomeAllow)
	}
	if got.DurationMs != 42 {
		t.Errorf("DurationMs = %d, want 42", got.DurationMs)
	}
	if got.SessionID != "sess-001" {
		t.Errorf("SessionID = %q, want sess-001", got.SessionID)
	}
	if len(got.Hooks) != 2 {
		t.Fatalf("len(Hooks) = %d, want 2", len(got.Hooks))
	}
	if got.Hooks[0].HookName != "guard" {
		t.Errorf("Hooks[0].HookName = %q, want guard", got.Hooks[0].HookName)
	}
	if got.Hooks[1].HookName != "logger" {
		t.Errorf("Hooks[1].HookName = %q, want logger", got.Hooks[1].HookName)
	}
	if got.Hooks[1].Stderr != "some debug output" {
		t.Errorf("Hooks[1].Stderr = %q, want 'some debug output'", got.Hooks[1].Stderr)
	}
}

func TestListChainsWithFilters(t *testing.T) {
	a := openTestDB(t)

	ts := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)

	entries := []ChainExecution{
		sampleChain("PreToolUse", OutcomeAllow, ts, nil),
		sampleChain("PreToolUse", OutcomeDeny, ts.Add(1*time.Minute), nil),
		sampleChain("PostToolUse", OutcomeAllow, ts.Add(2*time.Minute), nil),
		sampleChain("PreToolUse", OutcomeAllow, ts.Add(3*time.Minute), nil),
	}
	for _, e := range entries {
		if err := a.RecordChain(e); err != nil {
			t.Fatalf("RecordChain: %v", err)
		}
	}

	tests := []struct {
		name          string
		filterEvent   string
		filterOutcome string
		wantCount     int
	}{
		{"no filter", "", "", 4},
		{"filter by event", "PreToolUse", "", 3},
		{"filter by outcome", "", OutcomeDeny, 1},
		{"filter by both", "PreToolUse", OutcomeAllow, 2},
		{"no match", "Unknown", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chains, err := ListChains(a.DB(), 100, 0, tt.filterEvent, tt.filterOutcome)
			if err != nil {
				t.Fatalf("ListChains: %v", err)
			}
			if len(chains) != tt.wantCount {
				t.Errorf("got %d chains, want %d", len(chains), tt.wantCount)
			}
		})
	}
}

func TestTail(t *testing.T) {
	a := openTestDB(t)

	baseTS := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		entry := sampleChain("PreToolUse", OutcomeAllow, baseTS.Add(time.Duration(i)*time.Minute), nil)
		entry.DurationMs = int64(i + 1) // use duration as distinguishing value
		if err := a.RecordChain(entry); err != nil {
			t.Fatalf("RecordChain: %v", err)
		}
	}

	chains, err := Tail(a.DB(), 3)
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}

	if len(chains) != 3 {
		t.Fatalf("got %d chains, want 3", len(chains))
	}

	// Newest first: durations should be 5, 4, 3.
	if chains[0].DurationMs != 5 {
		t.Errorf("chains[0].DurationMs = %d, want 5", chains[0].DurationMs)
	}
	if chains[1].DurationMs != 4 {
		t.Errorf("chains[1].DurationMs = %d, want 4", chains[1].DurationMs)
	}
	if chains[2].DurationMs != 3 {
		t.Errorf("chains[2].DurationMs = %d, want 3", chains[2].DurationMs)
	}
}

func TestPrune(t *testing.T) {
	a := openTestDB(t)

	now := time.Now().UTC()
	oldTS := now.Add(-48 * time.Hour)
	newTS := now.Add(-1 * time.Hour)

	oldEntry := sampleChain("PreToolUse", OutcomeAllow, oldTS, sampleHooks())
	newEntry := sampleChain("PreToolUse", OutcomeDeny, newTS, sampleHooks())

	if err := a.RecordChain(oldEntry); err != nil {
		t.Fatalf("RecordChain (old): %v", err)
	}
	if err := a.RecordChain(newEntry); err != nil {
		t.Fatalf("RecordChain (new): %v", err)
	}

	// Prune entries older than 24 hours.
	count, err := Prune(a.DB(), 24*time.Hour)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if count != 1 {
		t.Errorf("pruned %d chains, want 1", count)
	}

	// Verify only the new entry remains.
	remaining, err := ListChains(a.DB(), 100, 0, "", "")
	if err != nil {
		t.Fatalf("ListChains: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("expected 1 remaining chain, got %d", len(remaining))
	}
	if remaining[0].Outcome != OutcomeDeny {
		t.Errorf("remaining chain outcome = %q, want %q", remaining[0].Outcome, OutcomeDeny)
	}

	// Verify hook results for old chain were also pruned.
	var hookCount int
	if err := a.DB().QueryRow("SELECT COUNT(*) FROM hook_results").Scan(&hookCount); err != nil {
		t.Fatalf("count hook_results: %v", err)
	}
	if hookCount != 2 {
		t.Errorf("expected 2 hook_results (for new chain), got %d", hookCount)
	}
}

func TestStats(t *testing.T) {
	a := openTestDB(t)

	ts := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)

	entries := []ChainExecution{
		{Timestamp: ts, EventName: "PreToolUse", ToolName: "Bash", Outcome: OutcomeAllow, DurationMs: 10},
		{Timestamp: ts.Add(1 * time.Minute), EventName: "PreToolUse", ToolName: "Bash", Outcome: OutcomeAllow, DurationMs: 20},
		{Timestamp: ts.Add(2 * time.Minute), EventName: "PreToolUse", ToolName: "Bash", Outcome: OutcomeDeny, DurationMs: 30},
	}
	for _, e := range entries {
		if err := a.RecordChain(e); err != nil {
			t.Fatalf("RecordChain: %v", err)
		}
	}

	stats, err := Stats(a.DB())
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}

	if stats.TotalChains != 3 {
		t.Errorf("TotalChains = %d, want 3", stats.TotalChains)
	}

	if stats.CountByOutcome[OutcomeAllow] != 2 {
		t.Errorf("CountByOutcome[allow] = %d, want 2", stats.CountByOutcome[OutcomeAllow])
	}
	if stats.CountByOutcome[OutcomeDeny] != 1 {
		t.Errorf("CountByOutcome[deny] = %d, want 1", stats.CountByOutcome[OutcomeDeny])
	}

	// Average: (10+20+30)/3 = 20.
	if stats.AvgDurationMs != 20 {
		t.Errorf("AvgDurationMs = %f, want 20", stats.AvgDurationMs)
	}

	if !stats.OldestEntry.Equal(ts) {
		t.Errorf("OldestEntry = %v, want %v", stats.OldestEntry, ts)
	}
	if !stats.NewestEntry.Equal(ts.Add(2 * time.Minute)) {
		t.Errorf("NewestEntry = %v, want %v", stats.NewestEntry, ts.Add(2*time.Minute))
	}
}

func TestStatsEmpty(t *testing.T) {
	a := openTestDB(t)

	stats, err := Stats(a.DB())
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.TotalChains != 0 {
		t.Errorf("TotalChains = %d, want 0", stats.TotalChains)
	}
	if stats.AvgDurationMs != 0 {
		t.Errorf("AvgDurationMs = %f, want 0", stats.AvgDurationMs)
	}
}

func TestNilAuditorNoOp(t *testing.T) {
	var a *SQLiteAuditor

	if err := a.RecordChain(ChainExecution{}); err != nil {
		t.Errorf("nil RecordChain returned error: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Errorf("nil Close returned error: %v", err)
	}
	if db := a.DB(); db != nil {
		t.Errorf("nil DB() returned non-nil: %v", db)
	}
}

func TestRecordChainTransaction(t *testing.T) {
	a := openTestDB(t)

	entry := sampleChain("PreToolUse", OutcomeAllow, time.Now().UTC(), sampleHooks())

	if err := a.RecordChain(entry); err != nil {
		t.Fatalf("RecordChain: %v", err)
	}

	// Verify both chain and hooks were written atomically.
	var chainCount int
	if err := a.DB().QueryRow("SELECT COUNT(*) FROM chain_executions").Scan(&chainCount); err != nil {
		t.Fatalf("count chain_executions: %v", err)
	}
	if chainCount != 1 {
		t.Errorf("chain_executions count = %d, want 1", chainCount)
	}

	var hookCount int
	if err := a.DB().QueryRow("SELECT COUNT(*) FROM hook_results").Scan(&hookCount); err != nil {
		t.Fatalf("count hook_results: %v", err)
	}
	if hookCount != 2 {
		t.Errorf("hook_results count = %d, want 2", hookCount)
	}

	// Verify hook results reference the correct chain.
	var chainID int64
	if err := a.DB().QueryRow("SELECT id FROM chain_executions LIMIT 1").Scan(&chainID); err != nil {
		t.Fatalf("get chain id: %v", err)
	}

	var refCount int
	if err := a.DB().QueryRow("SELECT COUNT(*) FROM hook_results WHERE chain_id = ?", chainID).Scan(&refCount); err != nil {
		t.Fatalf("count hook_results by chain_id: %v", err)
	}
	if refCount != 2 {
		t.Errorf("hook_results referencing chain %d = %d, want 2", chainID, refCount)
	}
}

func TestTruncateStderr(t *testing.T) {
	tests := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"empty", "", 10, ""},
		{"short", "hello", 10, "hello"},
		{"exact", "hello", 5, "hello"},
		{"truncated", "hello world", 8, "hello..."},
		{"zero max", "hello", 0, ""},
		{"max 3", "hello", 3, "hel"},
		{"max 2", "hello", 2, "he"},
		{"max 1", "hello", 1, "h"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TruncateStderr(tt.in, tt.max)
			if got != tt.want {
				t.Errorf("TruncateStderr(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
			}
		})
	}
}

func TestListChainsLimitOffset(t *testing.T) {
	a := openTestDB(t)

	baseTS := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		entry := sampleChain("PreToolUse", OutcomeAllow, baseTS.Add(time.Duration(i)*time.Minute), nil)
		entry.DurationMs = int64(i + 1)
		if err := a.RecordChain(entry); err != nil {
			t.Fatalf("RecordChain: %v", err)
		}
	}

	// Limit to 3, offset 2 (skip the 2 newest).
	chains, err := ListChains(a.DB(), 3, 2, "", "")
	if err != nil {
		t.Fatalf("ListChains: %v", err)
	}
	if len(chains) != 3 {
		t.Fatalf("got %d chains, want 3", len(chains))
	}
	// Newest first: durations 10,9,8,7,6... offset 2 skips 10,9 => first is 8.
	if chains[0].DurationMs != 8 {
		t.Errorf("chains[0].DurationMs = %d, want 8", chains[0].DurationMs)
	}
}

func TestStderrTruncationOnRecord(t *testing.T) {
	a := openTestDB(t)

	longStderr := strings.Repeat("x", 1000)
	entry := ChainExecution{
		Timestamp:  time.Now().UTC(),
		EventName:  "PreToolUse",
		ToolName:   "Bash",
		Outcome:    OutcomeAllow,
		DurationMs: 10,
		Hooks: []HookResult{
			{
				HookIndex:  0,
				HookName:   "verbose",
				ExitCode:   0,
				Outcome:    HookOutcomePass,
				DurationMs: 5,
				Stderr:     longStderr,
			},
		},
	}

	if err := a.RecordChain(entry); err != nil {
		t.Fatalf("RecordChain: %v", err)
	}

	got, err := GetChain(a.DB(), 1)
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if len(got.Hooks) != 1 {
		t.Fatalf("expected 1 hook, got %d", len(got.Hooks))
	}
	if len(got.Hooks[0].Stderr) > maxStderrLen {
		t.Errorf("stderr length = %d, want <= %d", len(got.Hooks[0].Stderr), maxStderrLen)
	}
}

func TestToolDetailRoundTrip(t *testing.T) {
	a := openTestDB(t)
	ts := time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)
	entry := sampleChain("PreToolUse", OutcomeAllow, ts, nil)
	entry.ToolDetail = "echo hello world"

	if err := a.RecordChain(entry); err != nil {
		t.Fatalf("RecordChain: %v", err)
	}

	got, err := GetChain(a.DB(), 1)
	if err != nil {
		t.Fatalf("GetChain: %v", err)
	}
	if got.ToolDetail != "echo hello world" {
		t.Errorf("ToolDetail = %q, want %q", got.ToolDetail, "echo hello world")
	}

	// Also verify via ListChains
	chains, err := ListChains(a.DB(), 10, 0, "", "")
	if err != nil {
		t.Fatalf("ListChains: %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("len(chains) = %d, want 1", len(chains))
	}
	if chains[0].ToolDetail != "echo hello world" {
		t.Errorf("ListChains ToolDetail = %q, want %q", chains[0].ToolDetail, "echo hello world")
	}
}

func TestMigrationIdempotent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "migrate-test.db")
	// Open twice -- second Open should not fail
	a1, err := Open(dbPath)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := a1.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	a2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer func() {
		if err := a2.Close(); err != nil {
			t.Errorf("second Close: %v", err)
		}
	}()

	// Verify column exists
	exists, err := columnExists(a2.DB(), "chain_executions", "tool_detail")
	if err != nil {
		t.Fatalf("columnExists: %v", err)
	}
	if !exists {
		t.Error("tool_detail column should exist after migration")
	}
}

func TestPruneBefore(t *testing.T) {
	a := openTestDB(t)

	now := time.Now().UTC()
	oldTS := now.Add(-48 * time.Hour)
	newTS := now.Add(-1 * time.Hour)

	oldEntry := sampleChain("PreToolUse", OutcomeAllow, oldTS, sampleHooks())
	newEntry := sampleChain("PreToolUse", OutcomeDeny, newTS, sampleHooks())

	if err := a.RecordChain(oldEntry); err != nil {
		t.Fatalf("RecordChain (old): %v", err)
	}
	if err := a.RecordChain(newEntry); err != nil {
		t.Fatalf("RecordChain (new): %v", err)
	}

	// Use explicit cutoff at 24h ago.
	cutoff := now.Add(-24 * time.Hour)
	count, err := PruneBefore(a.DB(), cutoff)
	if err != nil {
		t.Fatalf("PruneBefore: %v", err)
	}
	if count != 1 {
		t.Errorf("pruned %d chains, want 1", count)
	}

	remaining, err := ListChains(a.DB(), 100, 0, "", "")
	if err != nil {
		t.Fatalf("ListChains: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("expected 1 remaining chain, got %d", len(remaining))
	}
	if remaining[0].Outcome != OutcomeDeny {
		t.Errorf("remaining outcome = %q, want deny", remaining[0].Outcome)
	}
}

func TestListChainsOffsetWithoutLimit(t *testing.T) {
	a := openTestDB(t)

	baseTS := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)
	for i := range 5 {
		entry := sampleChain("PreToolUse", OutcomeAllow, baseTS.Add(time.Duration(i)*time.Minute), nil)
		entry.DurationMs = int64(i + 1)
		if err := a.RecordChain(entry); err != nil {
			t.Fatalf("RecordChain: %v", err)
		}
	}

	// limit=0 with offset=2 should return ALL rows (limit=0 means no limit,
	// and offset is only valid with a limit).
	chains, err := ListChains(a.DB(), 0, 2, "", "")
	if err != nil {
		t.Fatalf("ListChains: %v", err)
	}
	// With limit=0, offset is ignored, so all 5 entries are returned.
	if len(chains) != 5 {
		t.Errorf("got %d chains, want 5 (limit=0 means all)", len(chains))
	}
}
