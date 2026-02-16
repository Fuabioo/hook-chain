package audit

import "time"

// Outcome constants for ChainExecution.
const (
	OutcomeAllow = "allow"
	OutcomeDeny  = "deny"
	OutcomeAsk   = "ask"
	OutcomeError = "error"
)

// HookOutcome constants for HookResult.
const (
	HookOutcomePass    = "pass"
	HookOutcomeDeny    = "deny"
	HookOutcomeSkip    = "skip"
	HookOutcomeError   = "error"
	HookOutcomeAsk     = "ask"
	HookOutcomeMerge   = "merge"
	HookOutcomeContext = "context"
)

// Auditor records chain execution audit trails.
type Auditor interface {
	RecordChain(entry ChainExecution) error
	Close() error
}

// ChainExecution represents one pipeline.Run invocation.
type ChainExecution struct {
	ID         int64
	Timestamp  time.Time
	EventName  string
	ToolName   string
	ChainLen   int
	Outcome    string // allow|deny|ask|error
	Reason     string
	DurationMs int64
	SessionID  string
	Hooks      []HookResult
}

// HookResult represents one hook execution within a chain.
type HookResult struct {
	ID         int64
	ChainID    int64
	HookIndex  int
	HookName   string
	ExitCode   int
	Outcome    string // pass|deny|skip|error|ask|merge|context
	DurationMs int64
	Stderr     string // truncated to maxStderrLen bytes
}

// AuditStats holds aggregate statistics from the audit database.
type AuditStats struct {
	TotalChains    int64
	CountByOutcome map[string]int64
	AvgDurationMs  float64
	OldestEntry    time.Time
	NewestEntry    time.Time
}

// TruncateStderr truncates s to max bytes, appending "..." if truncated.
func TruncateStderr(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
