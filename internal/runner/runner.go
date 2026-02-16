package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Fuabioo/hook-chain/internal/config"
)

// Result holds the output from executing a hook process.
type Result struct {
	ExitCode int
	Stdout   []byte
	Stderr   string
}

// Runner executes a hook command with the given input on stdin.
type Runner interface {
	Run(ctx context.Context, hook config.HookEntry, input []byte) (Result, error)
}

// ProcessRunner executes hooks as OS processes.
type ProcessRunner struct{}

const defaultTimeout = 30 * time.Second

// Run executes the hook command, feeding input via stdin.
// It captures stdout and stderr separately.
//
// Limitation: the command string is split with strings.Fields,
// so commands containing paths with spaces must use Args instead.
func (pr ProcessRunner) Run(ctx context.Context, hook config.HookEntry, input []byte) (Result, error) {
	cmdStr := expandTilde(hook.Command)
	parts := strings.Fields(cmdStr)
	if len(parts) == 0 {
		return Result{}, fmt.Errorf("runner: empty command for hook %q", hook.Name)
	}

	args := parts[1:]
	if len(hook.Args) > 0 {
		args = append(args, hook.Args...)
	}

	timeout := hook.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, parts[0], args...)
	cmd.Stdin = bytes.NewReader(input)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if len(hook.Env) > 0 {
		cmd.Env = append(os.Environ(), hook.Env...)
	}

	err := cmd.Run()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return Result{
				ExitCode: exitErr.ExitCode(),
				Stdout:   stdout.Bytes(),
				Stderr:   stderr.String(),
			}, nil
		}
		return Result{}, fmt.Errorf("runner: execute hook %q: %w", hook.Name, err)
	}

	return Result{
		ExitCode: 0,
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.String(),
	}, nil
}

// expandTilde replaces a leading ~ with the user's home directory.
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
