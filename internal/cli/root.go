package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Fuabioo/hook-chain/internal/audit"
	"github.com/Fuabioo/hook-chain/internal/config"
	"github.com/Fuabioo/hook-chain/internal/hook"
	"github.com/Fuabioo/hook-chain/internal/pipeline"
	"github.com/Fuabioo/hook-chain/internal/runner"
)

var (
	Version = "dev"
	Commit  = "unknown"
)

type exitError struct {
	code int
}

func (e *exitError) Error() string {
	return fmt.Sprintf("exit code %d", e.code)
}

func newLogger() *slog.Logger {
	level := slog.LevelWarn
	if os.Getenv("HOOK_CHAIN_DEBUG") == "1" {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "hook-chain",
		Short:         "Sequential hook executor for Claude Code",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          runRoot,
	}

	root.AddCommand(newValidateCmd())
	root.AddCommand(newVersionCmd())
	root.AddCommand(newAuditCmd())

	return root
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	cmd := newRootCmd()
	if err := cmd.Execute(); err != nil {
		var ee *exitError
		if errors.As(err, &ee) {
			return ee.code
		}
		fmt.Fprintf(os.Stderr, "hook-chain: %v\n", err)
		return 1
	}
	return 0
}

// runRoot is the default command: read stdin, resolve chain, run pipeline.
func runRoot(cmd *cobra.Command, _ []string) error {
	logger := newLogger()

	// Read all of stdin.
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		logger.Warn("failed to read stdin", "err", err)
		return nil // passthrough on stdin failure
	}

	if len(data) == 0 {
		logger.Debug("empty stdin, passthrough")
		return nil
	}

	// Parse as hook.Input.
	var input hook.Input
	if err := json.Unmarshal(data, &input); err != nil {
		logger.Warn("failed to parse stdin as JSON", "err", err)
		return nil // passthrough on parse failure
	}

	// Load config.
	cfg, err := config.Load()
	if err != nil {
		// Config parse error → fail closed (exit 2).
		fmt.Fprintf(os.Stderr, "hook-chain: config error: %v\n", err)
		return &exitError{code: 2}
	}

	// Setup auditor (fail-open: errors logged, never block pipeline).
	var auditor audit.Auditor
	auditEnabled := os.Getenv("HOOK_CHAIN_AUDIT") == "1" || (cfg.Audit != nil && cfg.Audit.Enabled)
	if auditEnabled {
		dbPath := ""
		if cfg.Audit != nil && cfg.Audit.DBPath != "" {
			dbPath = cfg.Audit.DBPath
		} else {
			dbPath = audit.DefaultDBPath()
		}
		a, err := audit.Open(dbPath)
		if err != nil {
			logger.Warn("failed to open audit db, continuing without audit", "err", err)
		} else {
			auditor = a
			defer a.Close()
		}
	}

	// Resolve chain.
	hooks := cfg.Resolve(input.HookEventName, input.ToolName)
	if len(hooks) == 0 {
		logger.Debug("no matching chain, passthrough",
			"event", input.HookEventName, "tool", input.ToolName)
		return nil
	}

	logger.Debug("resolved chain",
		"event", input.HookEventName,
		"tool", input.ToolName,
		"hooks", len(hooks))

	// Run pipeline.
	ctx := context.Background()
	result := pipeline.Run(ctx, &input, hooks, runner.ProcessRunner{}, auditor, logger)

	// Write output if present.
	if len(result.Output) > 0 {
		if _, err := os.Stdout.Write(result.Output); err != nil {
			logger.Error("failed to write output", "err", err)
		}
	}

	if result.ExitCode != 0 {
		return &exitError{code: result.ExitCode}
	}
	return nil
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("hook-chain %s (%s)\n", Version, Commit)
		},
	}
}

func newValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate config and check hook commands",
		RunE:  runValidate,
	}
}

func runValidate(cmd *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "hook-chain: config error: %v\n", err)
		return &exitError{code: 1}
	}

	if len(cfg.Chains) == 0 {
		fmt.Println("No chains configured.")
		return nil
	}

	hasIssues := false

	for i, chain := range cfg.Chains {
		fmt.Printf("Chain %d: event=%s tools=%v\n", i+1, chain.Event, chain.Tools)
		for j, h := range chain.Hooks {
			cmdStr := expandTilde(h.Command)
			parts := strings.Fields(cmdStr)
			status := "OK"
			if len(parts) == 0 {
				status = "EMPTY COMMAND"
				hasIssues = true
			} else if _, err := exec.LookPath(parts[0]); err != nil {
				status = fmt.Sprintf("NOT FOUND: %s", parts[0])
				hasIssues = true
			}

			timeout := h.Timeout.String()
			if h.Timeout == 0 {
				timeout = "30s (default)"
			}
			onError := h.EffectiveOnError()

			fmt.Printf("  Hook %d: name=%s command=%q timeout=%s on_error=%s [%s]\n",
				j+1, h.Name, h.Command, timeout, onError, status)
		}
	}

	if hasIssues {
		return &exitError{code: 1}
	}
	return nil
}

// expandTilde replaces a leading ~ with $HOME.
func expandTilde(path string) string {
	if !strings.HasPrefix(path, "~") {
		return path
	}
	home := os.Getenv("HOME")
	if home == "" {
		return path
	}
	return home + path[1:]
}
