package runner

import (
	"context"
	"testing"

	"github.com/Fuabioo/hook-chain/internal/config"
)

func TestProcessRunnerEcho(t *testing.T) {
	pr := ProcessRunner{}
	hook := config.HookEntry{
		Name:    "echo-test",
		Command: "cat",
	}

	input := []byte(`{"hello": "world"}`)
	result, err := pr.Run(context.Background(), hook, input)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", result.ExitCode)
	}
	if string(result.Stdout) != string(input) {
		t.Errorf("Stdout = %q, want %q", string(result.Stdout), string(input))
	}
}

func TestProcessRunnerNonZeroExit(t *testing.T) {
	pr := ProcessRunner{}
	hook := config.HookEntry{
		Name:    "false-test",
		Command: "false",
	}

	result, err := pr.Run(context.Background(), hook, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode == 0 {
		t.Error("ExitCode = 0, want non-zero")
	}
}

func TestProcessRunnerMissingCommand(t *testing.T) {
	pr := ProcessRunner{}
	hook := config.HookEntry{
		Name:    "missing",
		Command: "/nonexistent/binary/xyz",
	}

	_, err := pr.Run(context.Background(), hook, nil)
	if err == nil {
		t.Fatal("expected error for missing command, got nil")
	}
}

func TestProcessRunnerWithArgs(t *testing.T) {
	pr := ProcessRunner{}
	hook := config.HookEntry{
		Name:    "echo-args",
		Command: "echo",
		Args:    []string{"hello", "world"},
	}

	result, err := pr.Run(context.Background(), hook, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", result.ExitCode)
	}
	got := string(result.Stdout)
	if got != "hello world\n" {
		t.Errorf("Stdout = %q, want %q", got, "hello world\n")
	}
}

func TestProcessRunnerWithEnv(t *testing.T) {
	pr := ProcessRunner{}
	hook := config.HookEntry{
		Name:    "env-test",
		Command: "sh",
		Args:    []string{"-c", "echo $HOOK_TEST_VAR"},
		Env:     []string{"HOOK_TEST_VAR=test_value"},
	}

	result, err := pr.Run(context.Background(), hook, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := string(result.Stdout)
	if got != "test_value\n" {
		t.Errorf("Stdout = %q, want %q", got, "test_value\n")
	}
}

func TestExpandTilde(t *testing.T) {
	tests := []struct {
		input string
		want  string // prefix check only for ~ expansion
		tilde bool
	}{
		{"/usr/bin/foo", "/usr/bin/foo", false},
		{"~/bin/foo", "", true},
		{"foo", "foo", false},
	}

	for _, tt := range tests {
		got := expandTilde(tt.input)
		if tt.tilde {
			if got == tt.input {
				t.Errorf("expandTilde(%q) = %q, expected tilde to be expanded", tt.input, got)
			}
		} else {
			if got != tt.want {
				t.Errorf("expandTilde(%q) = %q, want %q", tt.input, got, tt.want)
			}
		}
	}
}
