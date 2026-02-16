package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/Fuabioo/hook-chain/internal/audit"
	"github.com/Fuabioo/hook-chain/internal/config"
	"github.com/Fuabioo/hook-chain/internal/hook"
	"github.com/Fuabioo/hook-chain/internal/runner"
)

// Result holds the final outcome of executing a hook chain.
type Result struct {
	ExitCode int
	Output   []byte // JSON to write to stdout (nil = nothing to write)
}

// Run executes hooks sequentially, threading accumulated toolInput state
// through the chain. It implements the fold/reduce algorithm described in
// the hook-chain spec.
func Run(ctx context.Context, input *hook.Input, hooks []config.HookEntry, r runner.Runner, auditor audit.Auditor, logger *slog.Logger) Result {
	chainStart := time.Now()
	hookResults := make([]audit.HookResult, 0, len(hooks))

	if len(hooks) == 0 {
		recordAudit(auditor, input, 0, "allow", "", chainStart, hookResults, logger)
		return Result{ExitCode: 0}
	}

	originalToolInput := input.ToolInput
	accumulated := input.ToolInput
	var contextParts []string

	for i, h := range hooks {
		logger.Debug("running hook", "index", i, "name", h.Name)

		// Build sub-hook input with accumulated toolInput.
		subInput := input.WithToolInput(accumulated)
		inputBytes, err := json.Marshal(subInput)
		if err != nil {
			logger.Error("marshal sub-hook input", "hook", h.Name, "err", err)
			res := denyResult(input.HookEventName, fmt.Sprintf("hook-chain: failed to marshal input for hook %q: %v", h.Name, err))
			recordAudit(auditor, input, len(hooks), "error", fmt.Sprintf("marshal input for hook %q: %v", h.Name, err), chainStart, hookResults, logger)
			return res
		}

		// Execute the hook.
		hookStart := time.Now()
		runRes, err := r.Run(ctx, h, inputBytes)
		if err != nil {
			// Runner-level error (binary not found, timeout, etc.).
			logger.Warn("runner error", "hook", h.Name, "err", err)
			if h.EffectiveOnError() == "skip" {
				logger.Warn("skipping hook due to on_error=skip", "hook", h.Name)
				hookResults = append(hookResults, audit.HookResult{
					HookIndex:  i,
					HookName:   h.Name,
					ExitCode:   -1,
					Outcome:    "skip",
					DurationMs: time.Since(hookStart).Milliseconds(),
					Stderr:     audit.TruncateStderr(err.Error(), 512),
				})
				continue
			}
			hookResults = append(hookResults, audit.HookResult{
				HookIndex:  i,
				HookName:   h.Name,
				ExitCode:   -1,
				Outcome:    "error",
				DurationMs: time.Since(hookStart).Milliseconds(),
				Stderr:     audit.TruncateStderr(err.Error(), 512),
			})
			res := denyResult(input.HookEventName, fmt.Sprintf("hook-chain: hook %q failed: %v", h.Name, err))
			recordAudit(auditor, input, len(hooks), "error", fmt.Sprintf("hook %q runner error: %v", h.Name, err), chainStart, hookResults, logger)
			return res
		}

		// Exit code 2 always denies, regardless of on_error.
		if runRes.ExitCode == 2 {
			logger.Info("hook denied (exit 2)", "hook", h.Name, "stderr", runRes.Stderr)
			reason := fmt.Sprintf("hook %q denied (exit 2)", h.Name)
			if runRes.Stderr != "" {
				reason = runRes.Stderr
			}
			hookResults = append(hookResults, audit.HookResult{
				HookIndex:  i,
				HookName:   h.Name,
				ExitCode:   2,
				Outcome:    "deny",
				DurationMs: time.Since(hookStart).Milliseconds(),
				Stderr:     audit.TruncateStderr(runRes.Stderr, 512),
			})
			res := denyResult(input.HookEventName, reason)
			recordAudit(auditor, input, len(hooks), "deny", reason, chainStart, hookResults, logger)
			return res
		}

		// Non-zero exit (not 2).
		if runRes.ExitCode != 0 {
			logger.Warn("hook non-zero exit", "hook", h.Name, "exitCode", runRes.ExitCode, "stderr", runRes.Stderr)
			if h.EffectiveOnError() == "skip" {
				logger.Warn("skipping hook due to on_error=skip", "hook", h.Name)
				hookResults = append(hookResults, audit.HookResult{
					HookIndex:  i,
					HookName:   h.Name,
					ExitCode:   runRes.ExitCode,
					Outcome:    "skip",
					DurationMs: time.Since(hookStart).Milliseconds(),
					Stderr:     audit.TruncateStderr(runRes.Stderr, 512),
				})
				continue
			}
			reason := fmt.Sprintf("hook %q failed (exit %d)", h.Name, runRes.ExitCode)
			if runRes.Stderr != "" {
				reason = runRes.Stderr
			}
			hookResults = append(hookResults, audit.HookResult{
				HookIndex:  i,
				HookName:   h.Name,
				ExitCode:   runRes.ExitCode,
				Outcome:    "deny",
				DurationMs: time.Since(hookStart).Milliseconds(),
				Stderr:     audit.TruncateStderr(runRes.Stderr, 512),
			})
			res := denyResult(input.HookEventName, reason)
			recordAudit(auditor, input, len(hooks), "deny", reason, chainStart, hookResults, logger)
			return res
		}

		// Exit 0, check stdout.
		stdout := bytes.TrimSpace(runRes.Stdout)
		if len(stdout) == 0 {
			logger.Debug("hook passthrough (empty stdout)", "hook", h.Name)
			hookResults = append(hookResults, audit.HookResult{
				HookIndex:  i,
				HookName:   h.Name,
				ExitCode:   0,
				Outcome:    "pass",
				DurationMs: time.Since(hookStart).Milliseconds(),
			})
			continue
		}

		// Parse hook output JSON.
		var output hook.Output
		if err := json.Unmarshal(stdout, &output); err != nil {
			logger.Warn("failed to parse hook stdout as JSON", "hook", h.Name, "err", err)
			if h.EffectiveOnError() == "skip" {
				hookResults = append(hookResults, audit.HookResult{
					HookIndex:  i,
					HookName:   h.Name,
					ExitCode:   0,
					Outcome:    "skip",
					DurationMs: time.Since(hookStart).Milliseconds(),
					Stderr:     audit.TruncateStderr(err.Error(), 512),
				})
				continue
			}
			hookResults = append(hookResults, audit.HookResult{
				HookIndex:  i,
				HookName:   h.Name,
				ExitCode:   0,
				Outcome:    "error",
				DurationMs: time.Since(hookStart).Milliseconds(),
				Stderr:     audit.TruncateStderr(err.Error(), 512),
			})
			res := denyResult(input.HookEventName, fmt.Sprintf("hook-chain: hook %q returned invalid JSON: %v", h.Name, err))
			recordAudit(auditor, input, len(hooks), "error", fmt.Sprintf("hook %q invalid JSON: %v", h.Name, err), chainStart, hookResults, logger)
			return res
		}

		hso := output.HookSpecificOutput

		// Explicit deny always short-circuits.
		if hso.PermissionDecision == "deny" {
			logger.Info("hook denied (explicit)", "hook", h.Name, "reason", hso.PermissionDecisionReason)
			hookResults = append(hookResults, audit.HookResult{
				HookIndex:  i,
				HookName:   h.Name,
				ExitCode:   0,
				Outcome:    "deny",
				DurationMs: time.Since(hookStart).Milliseconds(),
			})
			res := buildDecisionResult(input.HookEventName, "deny", hso.PermissionDecisionReason)
			recordAudit(auditor, input, len(hooks), "deny", hso.PermissionDecisionReason, chainStart, hookResults, logger)
			return res
		}

		// Ask escalation always short-circuits.
		if hso.PermissionDecision == "ask" {
			logger.Info("hook ask escalation", "hook", h.Name, "reason", hso.PermissionDecisionReason)
			hookResults = append(hookResults, audit.HookResult{
				HookIndex:  i,
				HookName:   h.Name,
				ExitCode:   0,
				Outcome:    "ask",
				DurationMs: time.Since(hookStart).Milliseconds(),
			})
			res := buildDecisionResult(input.HookEventName, "ask", hso.PermissionDecisionReason)
			recordAudit(auditor, input, len(hooks), "ask", hso.PermissionDecisionReason, chainStart, hookResults, logger)
			return res
		}

		// Determine hook-level outcome for audit.
		hookOutcome := "pass"

		// Merge updatedInput if present.
		if len(hso.UpdatedInput) > 0 {
			merged, err := shallowMergeJSON(accumulated, hso.UpdatedInput)
			if err != nil {
				logger.Error("merge updatedInput", "hook", h.Name, "err", err)
				hookResults = append(hookResults, audit.HookResult{
					HookIndex:  i,
					HookName:   h.Name,
					ExitCode:   0,
					Outcome:    "error",
					DurationMs: time.Since(hookStart).Milliseconds(),
					Stderr:     audit.TruncateStderr(err.Error(), 512),
				})
				res := denyResult(input.HookEventName, fmt.Sprintf("hook-chain: failed to merge updatedInput from hook %q: %v", h.Name, err))
				recordAudit(auditor, input, len(hooks), "error", fmt.Sprintf("merge updatedInput from hook %q: %v", h.Name, err), chainStart, hookResults, logger)
				return res
			}
			accumulated = merged
			logger.Debug("merged updatedInput", "hook", h.Name)
			hookOutcome = "merge"
		}

		// Collect additionalContext.
		if hso.AdditionalContext != "" {
			contextParts = append(contextParts, hso.AdditionalContext)
			if hookOutcome == "pass" {
				hookOutcome = "context"
			}
		}

		hookResults = append(hookResults, audit.HookResult{
			HookIndex:  i,
			HookName:   h.Name,
			ExitCode:   0,
			Outcome:    hookOutcome,
			DurationMs: time.Since(hookStart).Milliseconds(),
		})
	}

	// After all hooks: determine if anything changed.
	changed := !bytes.Equal(normalizeJSON(accumulated), normalizeJSON(originalToolInput))
	hasContext := len(contextParts) > 0

	if !changed && !hasContext {
		logger.Debug("all hooks passed through, no changes")
		recordAudit(auditor, input, len(hooks), "allow", "", chainStart, hookResults, logger)
		return Result{ExitCode: 0}
	}

	// Build allow output with accumulated state.
	out := hook.Output{
		HookSpecificOutput: hook.HookSpecificOutput{
			HookEventName: input.HookEventName,
		},
	}

	if changed {
		out.HookSpecificOutput.UpdatedInput = accumulated
	}

	if hasContext {
		out.HookSpecificOutput.AdditionalContext = strings.Join(contextParts, "\n")
	}

	data, err := json.Marshal(out)
	if err != nil {
		logger.Error("marshal final output", "err", err)
		res := denyResult(input.HookEventName, fmt.Sprintf("hook-chain: failed to marshal final output: %v", err))
		recordAudit(auditor, input, len(hooks), "error", fmt.Sprintf("marshal final output: %v", err), chainStart, hookResults, logger)
		return res
	}

	recordAudit(auditor, input, len(hooks), "allow", "", chainStart, hookResults, logger)
	return Result{ExitCode: 0, Output: data}
}

// extractToolDetail extracts a human-readable summary from tool_input for audit display.
// Supports Bash (command), Read (file path), Write (file path + line count),
// and Edit (file path + lines removed/added). Returns empty string for
// unsupported tools or on any error (fail-silent).
func extractToolDetail(input *hook.Input) string {
	if len(input.ToolInput) == 0 {
		return ""
	}

	var detail string

	switch input.ToolName {
	case "Bash":
		var ti struct {
			Command string `json:"command"`
		}
		if err := json.Unmarshal(input.ToolInput, &ti); err != nil {
			return ""
		}
		detail = ti.Command

	case "Read":
		var ti struct {
			FilePath string `json:"file_path"`
		}
		if err := json.Unmarshal(input.ToolInput, &ti); err != nil {
			return ""
		}
		detail = ti.FilePath

	case "Write":
		var ti struct {
			FilePath string `json:"file_path"`
			Content  string `json:"content"`
		}
		if err := json.Unmarshal(input.ToolInput, &ti); err != nil {
			return ""
		}
		lines := countLines(ti.Content)
		detail = fmt.Sprintf("%s (+%d lines)", ti.FilePath, lines)

	case "Edit":
		var ti struct {
			FilePath  string `json:"file_path"`
			OldString string `json:"old_string"`
			NewString string `json:"new_string"`
		}
		if err := json.Unmarshal(input.ToolInput, &ti); err != nil {
			return ""
		}
		oldLines := countLines(ti.OldString)
		newLines := countLines(ti.NewString)
		detail = fmt.Sprintf("%s (-%d/+%d lines)", ti.FilePath, oldLines, newLines)

	default:
		return ""
	}

	if len(detail) > 256 {
		detail = detail[:256]
	}
	return detail
}

// countLines returns the number of lines in s. An empty string has 0 lines.
// A string without newlines has 1 line. Each newline adds a line.
func countLines(s string) int {
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}

// recordAudit sends a chain execution record to the auditor. Errors are logged
// but never affect the pipeline return value.
func recordAudit(auditor audit.Auditor, input *hook.Input, chainLen int, outcome string, reason string, chainStart time.Time, hookResults []audit.HookResult, logger *slog.Logger) {
	if auditor == nil {
		return
	}
	entry := audit.ChainExecution{
		EventName:  input.HookEventName,
		ToolName:   input.ToolName,
		ToolDetail: extractToolDetail(input),
		ChainLen:   chainLen,
		Outcome:    outcome,
		Reason:     reason,
		DurationMs: time.Since(chainStart).Milliseconds(),
		SessionID:  input.SessionID,
		Hooks:      hookResults,
	}
	if err := auditor.RecordChain(entry); err != nil {
		logger.Warn("audit record failed", "err", err)
	}
}

// denyResult builds a deny Result with exit code 2.
func denyResult(eventName, reason string) Result {
	out := hook.Output{
		HookSpecificOutput: hook.HookSpecificOutput{
			HookEventName:            eventName,
			PermissionDecision:       "deny",
			PermissionDecisionReason: reason,
		},
	}
	data, err := json.Marshal(out)
	if err != nil {
		// Last resort: write raw JSON.
		return Result{
			ExitCode: 2,
			Output:   []byte(`{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"hook-chain: internal error"}}`),
		}
	}
	return Result{ExitCode: 2, Output: data}
}

// buildDecisionResult builds a Result for a specific permission decision.
func buildDecisionResult(eventName, decision, reason string) Result {
	out := hook.Output{
		HookSpecificOutput: hook.HookSpecificOutput{
			HookEventName:            eventName,
			PermissionDecision:       decision,
			PermissionDecisionReason: reason,
		},
	}
	data, err := json.Marshal(out)
	if err != nil {
		return Result{ExitCode: 2}
	}
	exitCode := 0
	if decision == "deny" {
		exitCode = 2
	}
	return Result{ExitCode: exitCode, Output: data}
}

// normalizeJSON re-marshals JSON to normalize key ordering for comparison.
func normalizeJSON(data json.RawMessage) []byte {
	if len(data) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return data
	}
	normalized, err := json.Marshal(v)
	if err != nil {
		return data
	}
	return normalized
}
