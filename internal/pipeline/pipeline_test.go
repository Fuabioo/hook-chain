package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/Fuabioo/hook-chain/internal/audit"
	"github.com/Fuabioo/hook-chain/internal/config"
	"github.com/Fuabioo/hook-chain/internal/hook"
	"github.com/Fuabioo/hook-chain/internal/runner"
)

// mockRunner implements runner.Runner for testing.
type mockRunner struct {
	results []mockResult
	calls   []mockCall
	callIdx int
}

type mockResult struct {
	result runner.Result
	err    error
}

type mockCall struct {
	hookName string
	input    []byte
}

func (m *mockRunner) Run(_ context.Context, h config.HookEntry, input []byte) (runner.Result, error) {
	m.calls = append(m.calls, mockCall{hookName: h.Name, input: input})
	if m.callIdx >= len(m.results) {
		return runner.Result{}, nil
	}
	r := m.results[m.callIdx]
	m.callIdx++
	return r.result, r.err
}

// mockAuditor implements audit.Auditor for testing.
type mockAuditor struct {
	entries []audit.ChainExecution
	err     error // if set, RecordChain returns this error
}

func (m *mockAuditor) RecordChain(entry audit.ChainExecution) error {
	m.entries = append(m.entries, entry)
	return m.err
}

func (m *mockAuditor) Close() error { return nil }

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func makeInput(toolInput string) *hook.Input {
	raw := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":` + toolInput + `}`)
	var inp hook.Input
	if err := json.Unmarshal(raw, &inp); err != nil {
		panic(err)
	}
	return &inp
}

func TestEmptyChainPassthrough(t *testing.T) {
	inp := makeInput(`{"command":"ls"}`)
	m := &mockRunner{}

	result := Run(context.Background(), inp, nil, m, nil, testLogger())
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", result.ExitCode)
	}
	if result.Output != nil {
		t.Errorf("Output = %s, want nil", result.Output)
	}
	if len(m.calls) != 0 {
		t.Errorf("expected no calls, got %d", len(m.calls))
	}
}

func TestSingleHookPassthrough(t *testing.T) {
	inp := makeInput(`{"command":"ls"}`)
	hooks := []config.HookEntry{{Name: "pass", Command: "pass"}}
	m := &mockRunner{
		results: []mockResult{
			{result: runner.Result{ExitCode: 0, Stdout: nil}},
		},
	}

	result := Run(context.Background(), inp, hooks, m, nil, testLogger())
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", result.ExitCode)
	}
	if result.Output != nil {
		t.Errorf("Output = %s, want nil", result.Output)
	}
}

func TestSingleHookDenyJSON(t *testing.T) {
	inp := makeInput(`{"command":"rm -rf /"}`)
	hooks := []config.HookEntry{{Name: "guard", Command: "guard"}}

	denyOutput := `{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"dangerous command"}}`
	m := &mockRunner{
		results: []mockResult{
			{result: runner.Result{ExitCode: 0, Stdout: []byte(denyOutput)}},
		},
	}

	result := Run(context.Background(), inp, hooks, m, nil, testLogger())
	if result.ExitCode != 2 {
		t.Errorf("ExitCode = %d, want 2", result.ExitCode)
	}

	var out hook.Output
	if err := json.Unmarshal(result.Output, &out); err != nil {
		t.Fatalf("Unmarshal output: %v", err)
	}
	if out.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("decision = %q, want deny", out.HookSpecificOutput.PermissionDecision)
	}
}

func TestSingleHookExit2Deny(t *testing.T) {
	inp := makeInput(`{"command":"ls"}`)
	hooks := []config.HookEntry{{Name: "exit2", Command: "exit2"}}
	m := &mockRunner{
		results: []mockResult{
			{result: runner.Result{ExitCode: 2, Stderr: "forbidden"}},
		},
	}

	result := Run(context.Background(), inp, hooks, m, nil, testLogger())
	if result.ExitCode != 2 {
		t.Errorf("ExitCode = %d, want 2", result.ExitCode)
	}
}

func TestChainedUpdatedInputMerging(t *testing.T) {
	inp := makeInput(`{"command":"original"}`)
	hooks := []config.HookEntry{
		{Name: "hook1", Command: "hook1"},
		{Name: "hook2", Command: "hook2"},
	}

	hook1Out := `{"hookSpecificOutput":{"updatedInput":{"command":"modified","extra_a":"from_hook1"}}}`
	hook2Out := `{"hookSpecificOutput":{"updatedInput":{"extra_b":"from_hook2"}}}`

	m := &mockRunner{
		results: []mockResult{
			{result: runner.Result{ExitCode: 0, Stdout: []byte(hook1Out)}},
			{result: runner.Result{ExitCode: 0, Stdout: []byte(hook2Out)}},
		},
	}

	result := Run(context.Background(), inp, hooks, m, nil, testLogger())
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", result.ExitCode)
	}
	if result.Output == nil {
		t.Fatal("Output is nil, expected updatedInput")
	}

	var out hook.Output
	if err := json.Unmarshal(result.Output, &out); err != nil {
		t.Fatalf("Unmarshal output: %v", err)
	}

	var updated map[string]any
	if err := json.Unmarshal(out.HookSpecificOutput.UpdatedInput, &updated); err != nil {
		t.Fatalf("Unmarshal updatedInput: %v", err)
	}

	if updated["command"] != "modified" {
		t.Errorf("command = %v, want modified", updated["command"])
	}
	if updated["extra_a"] != "from_hook1" {
		t.Errorf("extra_a = %v, want from_hook1", updated["extra_a"])
	}
	if updated["extra_b"] != "from_hook2" {
		t.Errorf("extra_b = %v, want from_hook2", updated["extra_b"])
	}

	// Verify hook2's stdin received the merged toolInput from hook1.
	if len(m.calls) < 2 {
		t.Fatalf("expected at least 2 calls, got %d", len(m.calls))
	}

	var hook2Input hook.Input
	if err := json.Unmarshal(m.calls[1].input, &hook2Input); err != nil {
		t.Fatalf("Unmarshal hook2 input: %v", err)
	}

	var hook2ToolInput map[string]any
	if err := json.Unmarshal(hook2Input.ToolInput, &hook2ToolInput); err != nil {
		t.Fatalf("Unmarshal hook2 toolInput: %v", err)
	}

	if hook2ToolInput["command"] != "modified" {
		t.Errorf("hook2 stdin toolInput.command = %v, want modified", hook2ToolInput["command"])
	}
	if hook2ToolInput["extra_a"] != "from_hook1" {
		t.Errorf("hook2 stdin toolInput.extra_a = %v, want from_hook1", hook2ToolInput["extra_a"])
	}
}

func TestMidChainDenyShortCircuits(t *testing.T) {
	inp := makeInput(`{"command":"ls"}`)
	hooks := []config.HookEntry{
		{Name: "hook1", Command: "hook1"},
		{Name: "hook2", Command: "hook2"},
		{Name: "hook3", Command: "hook3"},
	}

	denyOutput := `{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"blocked"}}`
	m := &mockRunner{
		results: []mockResult{
			{result: runner.Result{ExitCode: 0}},
			{result: runner.Result{ExitCode: 0, Stdout: []byte(denyOutput)}},
			{result: runner.Result{ExitCode: 0}}, // should never be called
		},
	}

	result := Run(context.Background(), inp, hooks, m, nil, testLogger())
	if result.ExitCode != 2 {
		t.Errorf("ExitCode = %d, want 2", result.ExitCode)
	}
	if len(m.calls) != 2 {
		t.Errorf("expected 2 calls (hook3 should not run), got %d", len(m.calls))
	}
}

func TestAskEscalationShortCircuits(t *testing.T) {
	inp := makeInput(`{"command":"ls"}`)
	hooks := []config.HookEntry{
		{Name: "hook1", Command: "hook1"},
		{Name: "hook2", Command: "hook2"},
	}

	askOutput := `{"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"needs approval"}}`
	m := &mockRunner{
		results: []mockResult{
			{result: runner.Result{ExitCode: 0, Stdout: []byte(askOutput)}},
			{result: runner.Result{ExitCode: 0}}, // should never be called
		},
	}

	result := Run(context.Background(), inp, hooks, m, nil, testLogger())
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", result.ExitCode)
	}
	if len(m.calls) != 1 {
		t.Errorf("expected 1 call, got %d", len(m.calls))
	}

	var out hook.Output
	if err := json.Unmarshal(result.Output, &out); err != nil {
		t.Fatalf("Unmarshal output: %v", err)
	}
	if out.HookSpecificOutput.PermissionDecision != "ask" {
		t.Errorf("decision = %q, want ask", out.HookSpecificOutput.PermissionDecision)
	}
}

func TestOnErrorDenyForRunnerError(t *testing.T) {
	inp := makeInput(`{"command":"ls"}`)
	hooks := []config.HookEntry{
		{Name: "broken", Command: "broken", OnError: "deny"},
	}

	m := &mockRunner{
		results: []mockResult{
			{err: errors.New("binary not found")},
		},
	}

	result := Run(context.Background(), inp, hooks, m, nil, testLogger())
	if result.ExitCode != 2 {
		t.Errorf("ExitCode = %d, want 2", result.ExitCode)
	}
}

func TestOnErrorSkipForRunnerError(t *testing.T) {
	inp := makeInput(`{"command":"ls"}`)
	hooks := []config.HookEntry{
		{Name: "broken", Command: "broken", OnError: "skip"},
		{Name: "pass", Command: "pass"},
	}

	m := &mockRunner{
		results: []mockResult{
			{err: errors.New("binary not found")},
			{result: runner.Result{ExitCode: 0}},
		},
	}

	result := Run(context.Background(), inp, hooks, m, nil, testLogger())
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", result.ExitCode)
	}
	if len(m.calls) != 2 {
		t.Errorf("expected 2 calls (skip + continue), got %d", len(m.calls))
	}
}

func TestOnErrorSkipForNonZeroExit(t *testing.T) {
	inp := makeInput(`{"command":"ls"}`)
	hooks := []config.HookEntry{
		{Name: "flaky", Command: "flaky", OnError: "skip"},
		{Name: "pass", Command: "pass"},
	}

	m := &mockRunner{
		results: []mockResult{
			{result: runner.Result{ExitCode: 1}},
			{result: runner.Result{ExitCode: 0}},
		},
	}

	result := Run(context.Background(), inp, hooks, m, nil, testLogger())
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", result.ExitCode)
	}
	if len(m.calls) != 2 {
		t.Errorf("expected 2 calls, got %d", len(m.calls))
	}
}

func TestExit2IgnoresOnErrorSkip(t *testing.T) {
	inp := makeInput(`{"command":"ls"}`)
	hooks := []config.HookEntry{
		{Name: "hard-deny", Command: "hard-deny", OnError: "skip"},
	}

	m := &mockRunner{
		results: []mockResult{
			{result: runner.Result{ExitCode: 2, Stderr: "absolutely not"}},
		},
	}

	result := Run(context.Background(), inp, hooks, m, nil, testLogger())
	if result.ExitCode != 2 {
		t.Errorf("ExitCode = %d, want 2 (exit 2 should ignore on_error=skip)", result.ExitCode)
	}
}

func TestExplicitDenyIgnoresOnErrorSkip(t *testing.T) {
	inp := makeInput(`{"command":"ls"}`)
	hooks := []config.HookEntry{
		{Name: "denier", Command: "denier", OnError: "skip"},
	}

	denyOutput := `{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"nope"}}`
	m := &mockRunner{
		results: []mockResult{
			{result: runner.Result{ExitCode: 0, Stdout: []byte(denyOutput)}},
		},
	}

	result := Run(context.Background(), inp, hooks, m, nil, testLogger())
	if result.ExitCode != 2 {
		t.Errorf("ExitCode = %d, want 2 (explicit deny should ignore on_error=skip)", result.ExitCode)
	}
}

func TestAdditionalContextAccumulation(t *testing.T) {
	inp := makeInput(`{"command":"ls"}`)
	hooks := []config.HookEntry{
		{Name: "ctx1", Command: "ctx1"},
		{Name: "ctx2", Command: "ctx2"},
	}

	ctx1Out := `{"hookSpecificOutput":{"additionalContext":"context from hook1"}}`
	ctx2Out := `{"hookSpecificOutput":{"additionalContext":"context from hook2"}}`

	m := &mockRunner{
		results: []mockResult{
			{result: runner.Result{ExitCode: 0, Stdout: []byte(ctx1Out)}},
			{result: runner.Result{ExitCode: 0, Stdout: []byte(ctx2Out)}},
		},
	}

	result := Run(context.Background(), inp, hooks, m, nil, testLogger())
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", result.ExitCode)
	}
	if result.Output == nil {
		t.Fatal("Output is nil, expected additionalContext")
	}

	var out hook.Output
	if err := json.Unmarshal(result.Output, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	got := out.HookSpecificOutput.AdditionalContext
	if got != "context from hook1\ncontext from hook2" {
		t.Errorf("additionalContext = %q, want combined", got)
	}
}

func TestInvalidJSONOutputDenyByDefault(t *testing.T) {
	inp := makeInput(`{"command":"ls"}`)
	hooks := []config.HookEntry{
		{Name: "bad-json", Command: "bad-json"},
		// on_error defaults to "" which means EffectiveOnError() returns "deny"
	}

	m := &mockRunner{
		results: []mockResult{
			{result: runner.Result{ExitCode: 0, Stdout: []byte("this is not json")}},
		},
	}

	result := Run(context.Background(), inp, hooks, m, nil, testLogger())
	if result.ExitCode != 2 {
		t.Errorf("ExitCode = %d, want 2 (invalid JSON with default on_error should deny)", result.ExitCode)
	}

	var out hook.Output
	if err := json.Unmarshal(result.Output, &out); err != nil {
		t.Fatalf("Unmarshal output: %v", err)
	}
	if out.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("decision = %q, want deny", out.HookSpecificOutput.PermissionDecision)
	}
}

func TestInvalidJSONOutputSkipOnError(t *testing.T) {
	inp := makeInput(`{"command":"ls"}`)
	hooks := []config.HookEntry{
		{Name: "bad-json", Command: "bad-json", OnError: "skip"},
		{Name: "pass", Command: "pass"},
	}

	m := &mockRunner{
		results: []mockResult{
			{result: runner.Result{ExitCode: 0, Stdout: []byte("not valid json")}},
			{result: runner.Result{ExitCode: 0}}, // passthrough
		},
	}

	result := Run(context.Background(), inp, hooks, m, nil, testLogger())
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0 (invalid JSON with on_error=skip should continue)", result.ExitCode)
	}
	if len(m.calls) != 2 {
		t.Errorf("expected 2 calls (skip invalid JSON + run second hook), got %d", len(m.calls))
	}
}

func TestShallowMerge_TopLevelKeyOverride(t *testing.T) {
	inp := makeInput(`{"command":"original","flag":"old"}`)
	hooks := []config.HookEntry{
		{Name: "hook1", Command: "hook1"},
		{Name: "hook2", Command: "hook2"},
	}

	hook1Out := `{"hookSpecificOutput":{"updatedInput":{"command":"from_hook1","flag":"hook1_flag"}}}`
	hook2Out := `{"hookSpecificOutput":{"updatedInput":{"flag":"hook2_flag"}}}`

	m := &mockRunner{
		results: []mockResult{
			{result: runner.Result{ExitCode: 0, Stdout: []byte(hook1Out)}},
			{result: runner.Result{ExitCode: 0, Stdout: []byte(hook2Out)}},
		},
	}

	result := Run(context.Background(), inp, hooks, m, nil, testLogger())
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", result.ExitCode)
	}
	if result.Output == nil {
		t.Fatal("Output is nil, expected updatedInput")
	}

	var out hook.Output
	if err := json.Unmarshal(result.Output, &out); err != nil {
		t.Fatalf("Unmarshal output: %v", err)
	}

	var updated map[string]any
	if err := json.Unmarshal(out.HookSpecificOutput.UpdatedInput, &updated); err != nil {
		t.Fatalf("Unmarshal updatedInput: %v", err)
	}

	// hook1 set command, hook2 did not override it, so it persists.
	if updated["command"] != "from_hook1" {
		t.Errorf("command = %v, want from_hook1", updated["command"])
	}
	// hook2 overrides flag from hook1.
	if updated["flag"] != "hook2_flag" {
		t.Errorf("flag = %v, want hook2_flag (second hook should win)", updated["flag"])
	}
}

func TestShallowMerge_NestedObjectReplacedWholesale(t *testing.T) {
	inp := makeInput(`{"command":"ls","opts":{"a":1,"b":2}}`)
	hooks := []config.HookEntry{
		{Name: "hook1", Command: "hook1"},
		{Name: "hook2", Command: "hook2"},
	}

	// hook1 passes through (no updatedInput).
	// hook2 sets opts to {"c":3} — should replace wholesale, NOT deep-merge.
	hook2Out := `{"hookSpecificOutput":{"updatedInput":{"opts":{"c":3}}}}`

	m := &mockRunner{
		results: []mockResult{
			{result: runner.Result{ExitCode: 0}},
			{result: runner.Result{ExitCode: 0, Stdout: []byte(hook2Out)}},
		},
	}

	result := Run(context.Background(), inp, hooks, m, nil, testLogger())
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", result.ExitCode)
	}
	if result.Output == nil {
		t.Fatal("Output is nil, expected updatedInput")
	}

	var out hook.Output
	if err := json.Unmarshal(result.Output, &out); err != nil {
		t.Fatalf("Unmarshal output: %v", err)
	}

	var updated map[string]json.RawMessage
	if err := json.Unmarshal(out.HookSpecificOutput.UpdatedInput, &updated); err != nil {
		t.Fatalf("Unmarshal updatedInput: %v", err)
	}

	// opts should be {"c":3} — replaced wholesale, not deep-merged.
	var opts map[string]any
	if err := json.Unmarshal(updated["opts"], &opts); err != nil {
		t.Fatalf("Unmarshal opts: %v", err)
	}

	if _, exists := opts["a"]; exists {
		t.Errorf("opts contains key 'a', but shallow merge should have replaced the whole object")
	}
	if _, exists := opts["b"]; exists {
		t.Errorf("opts contains key 'b', but shallow merge should have replaced the whole object")
	}
	// c should be float64(3) from JSON unmarshaling.
	if opts["c"] != float64(3) {
		t.Errorf("opts.c = %v, want 3", opts["c"])
	}

	// command should still be present from original input (not overridden by hook2).
	if _, exists := updated["command"]; !exists {
		t.Error("expected 'command' key to persist from original input")
	}
}

func TestAuditRecording(t *testing.T) {
	// Run a 2-hook chain where hook1 passes through and hook2 denies.
	inp := makeInput(`{"command":"ls"}`)
	hooks := []config.HookEntry{
		{Name: "hook1", Command: "hook1"},
		{Name: "hook2", Command: "hook2"},
	}

	denyOutput := `{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"blocked by hook2"}}`
	m := &mockRunner{
		results: []mockResult{
			{result: runner.Result{ExitCode: 0}}, // passthrough
			{result: runner.Result{ExitCode: 0, Stdout: []byte(denyOutput)}},
		},
	}

	a := &mockAuditor{}
	result := Run(context.Background(), inp, hooks, m, a, testLogger())

	// Verify pipeline result is deny.
	if result.ExitCode != 2 {
		t.Fatalf("ExitCode = %d, want 2", result.ExitCode)
	}

	// Verify RecordChain was called exactly once.
	if len(a.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(a.entries))
	}

	entry := a.entries[0]

	// Verify chain-level fields.
	if entry.EventName != "PreToolUse" {
		t.Errorf("EventName = %q, want PreToolUse", entry.EventName)
	}
	if entry.ToolName != "Bash" {
		t.Errorf("ToolName = %q, want Bash", entry.ToolName)
	}
	if entry.ToolDetail != "ls" {
		t.Errorf("ToolDetail = %q, want %q", entry.ToolDetail, "ls")
	}
	if entry.ChainLen != 2 {
		t.Errorf("ChainLen = %d, want 2", entry.ChainLen)
	}
	if entry.Outcome != "deny" {
		t.Errorf("Outcome = %q, want deny", entry.Outcome)
	}
	if entry.Reason != "blocked by hook2" {
		t.Errorf("Reason = %q, want %q", entry.Reason, "blocked by hook2")
	}
	if entry.DurationMs < 0 {
		t.Errorf("DurationMs = %d, want >= 0", entry.DurationMs)
	}

	// Verify hook-level results: 2 hooks recorded (hook1 pass, hook2 deny).
	if len(entry.Hooks) != 2 {
		t.Fatalf("hook results = %d, want 2", len(entry.Hooks))
	}

	h1 := entry.Hooks[0]
	if h1.HookName != "hook1" {
		t.Errorf("hook[0].HookName = %q, want hook1", h1.HookName)
	}
	if h1.HookIndex != 0 {
		t.Errorf("hook[0].HookIndex = %d, want 0", h1.HookIndex)
	}
	if h1.Outcome != "pass" {
		t.Errorf("hook[0].Outcome = %q, want pass", h1.Outcome)
	}
	if h1.ExitCode != 0 {
		t.Errorf("hook[0].ExitCode = %d, want 0", h1.ExitCode)
	}

	h2 := entry.Hooks[1]
	if h2.HookName != "hook2" {
		t.Errorf("hook[1].HookName = %q, want hook2", h2.HookName)
	}
	if h2.HookIndex != 1 {
		t.Errorf("hook[1].HookIndex = %d, want 1", h2.HookIndex)
	}
	if h2.Outcome != "deny" {
		t.Errorf("hook[1].Outcome = %q, want deny", h2.Outcome)
	}
	if h2.ExitCode != 0 {
		t.Errorf("hook[1].ExitCode = %d, want 0", h2.ExitCode)
	}
}

func TestAuditErrorDoesNotBlockPipeline(t *testing.T) {
	// Mock auditor returns error from RecordChain.
	// Verify pipeline still returns correct result (fail-open).
	inp := makeInput(`{"command":"ls"}`)
	hooks := []config.HookEntry{
		{Name: "pass", Command: "pass"},
	}

	m := &mockRunner{
		results: []mockResult{
			{result: runner.Result{ExitCode: 0}},
		},
	}

	a := &mockAuditor{err: fmt.Errorf("disk full")}
	result := Run(context.Background(), inp, hooks, m, a, testLogger())

	// Pipeline should still succeed despite audit error.
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0 (audit error should not block pipeline)", result.ExitCode)
	}
	if result.Output != nil {
		t.Errorf("Output = %s, want nil (passthrough)", result.Output)
	}

	// Verify RecordChain was still called (the error was returned but not fatal).
	if len(a.entries) != 1 {
		t.Errorf("audit entries = %d, want 1 (RecordChain should still be called)", len(a.entries))
	}
}

func TestExtractToolDetail_BashCommand(t *testing.T) {
	inp := makeInput(`{"command":"ls -la /tmp"}`)
	got := extractToolDetail(inp)
	if got != "ls -la /tmp" {
		t.Errorf("extractToolDetail = %q, want %q", got, "ls -la /tmp")
	}
}

func TestExtractToolDetail_NonBashTool(t *testing.T) {
	raw := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/etc/hosts"}}`)
	var inp hook.Input
	if err := json.Unmarshal(raw, &inp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	got := extractToolDetail(&inp)
	if got != "" {
		t.Errorf("extractToolDetail = %q, want empty for non-Bash tool", got)
	}
}

func TestExtractToolDetail_Truncation(t *testing.T) {
	longCmd := strings.Repeat("x", 300)
	inp := makeInput(`{"command":"` + longCmd + `"}`)
	got := extractToolDetail(inp)
	if len(got) != 256 {
		t.Errorf("len(extractToolDetail) = %d, want 256", len(got))
	}
}

func TestExtractToolDetail_EmptyToolInput(t *testing.T) {
	raw := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`)
	var inp hook.Input
	if err := json.Unmarshal(raw, &inp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	got := extractToolDetail(&inp)
	if got != "" {
		t.Errorf("extractToolDetail = %q, want empty for nil tool_input", got)
	}
}

func TestExtractToolDetail_InvalidJSON(t *testing.T) {
	raw := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":"not-json-object"}`)
	var inp hook.Input
	if err := json.Unmarshal(raw, &inp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	got := extractToolDetail(&inp)
	if got != "" {
		t.Errorf("extractToolDetail = %q, want empty for invalid JSON", got)
	}
}
