package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadFromYAML(t *testing.T) {
	yaml := `
chains:
  - event: PreToolUse
    tools: [Bash, Write]
    hooks:
      - name: guard
        command: /usr/local/bin/guard
        args: ["--strict"]
        timeout: 5s
        on_error: skip
      - name: logger
        command: /usr/local/bin/logger
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}

	if len(cfg.Chains) != 1 {
		t.Fatalf("len(Chains) = %d, want 1", len(cfg.Chains))
	}

	chain := cfg.Chains[0]
	if chain.Event != "PreToolUse" {
		t.Errorf("Event = %q, want %q", chain.Event, "PreToolUse")
	}
	if len(chain.Tools) != 2 {
		t.Fatalf("len(Tools) = %d, want 2", len(chain.Tools))
	}
	if chain.Tools[0] != "Bash" || chain.Tools[1] != "Write" {
		t.Errorf("Tools = %v, want [Bash Write]", chain.Tools)
	}

	if len(chain.Hooks) != 2 {
		t.Fatalf("len(Hooks) = %d, want 2", len(chain.Hooks))
	}

	h0 := chain.Hooks[0]
	if h0.Name != "guard" {
		t.Errorf("Hooks[0].Name = %q, want %q", h0.Name, "guard")
	}
	if h0.Timeout != 5*time.Second {
		t.Errorf("Hooks[0].Timeout = %v, want 5s", h0.Timeout)
	}
	if h0.OnError != "skip" {
		t.Errorf("Hooks[0].OnError = %q, want %q", h0.OnError, "skip")
	}
	if len(h0.Args) != 1 || h0.Args[0] != "--strict" {
		t.Errorf("Hooks[0].Args = %v, want [--strict]", h0.Args)
	}
}

func TestResolveMatch(t *testing.T) {
	cfg := Config{
		Chains: []ChainEntry{
			{
				Event: "PreToolUse",
				Tools: []string{"Bash", "Write"},
				Hooks: []HookEntry{
					{Name: "hook-a", Command: "a"},
				},
			},
			{
				Event: "PostToolUse",
				Tools: []string{"Read"},
				Hooks: []HookEntry{
					{Name: "hook-b", Command: "b"},
				},
			},
		},
	}

	hooks := cfg.Resolve("PreToolUse", "Bash")
	if len(hooks) != 1 || hooks[0].Name != "hook-a" {
		t.Errorf("Resolve(PreToolUse, Bash) = %v, want [hook-a]", hooks)
	}

	hooks = cfg.Resolve("PreToolUse", "Write")
	if len(hooks) != 1 || hooks[0].Name != "hook-a" {
		t.Errorf("Resolve(PreToolUse, Write) = %v, want [hook-a]", hooks)
	}

	hooks = cfg.Resolve("PostToolUse", "Read")
	if len(hooks) != 1 || hooks[0].Name != "hook-b" {
		t.Errorf("Resolve(PostToolUse, Read) = %v, want [hook-b]", hooks)
	}
}

func TestResolveMiss(t *testing.T) {
	cfg := Config{
		Chains: []ChainEntry{
			{
				Event: "PreToolUse",
				Tools: []string{"Bash"},
				Hooks: []HookEntry{{Name: "hook-a", Command: "a"}},
			},
		},
	}

	if hooks := cfg.Resolve("PreToolUse", "Read"); hooks != nil {
		t.Errorf("Resolve(PreToolUse, Read) = %v, want nil", hooks)
	}
	if hooks := cfg.Resolve("PostToolUse", "Bash"); hooks != nil {
		t.Errorf("Resolve(PostToolUse, Bash) = %v, want nil", hooks)
	}
}

func TestResolveFirstMatch(t *testing.T) {
	cfg := Config{
		Chains: []ChainEntry{
			{
				Event: "PreToolUse",
				Tools: []string{"Bash"},
				Hooks: []HookEntry{{Name: "first", Command: "a"}},
			},
			{
				Event: "PreToolUse",
				Tools: []string{"Bash"},
				Hooks: []HookEntry{{Name: "second", Command: "b"}},
			},
		},
	}

	hooks := cfg.Resolve("PreToolUse", "Bash")
	if len(hooks) != 1 || hooks[0].Name != "first" {
		t.Errorf("Resolve should return first match, got %v", hooks)
	}
}

func TestEffectiveOnError(t *testing.T) {
	tests := []struct {
		onError string
		want    string
	}{
		{"", "deny"},
		{"deny", "deny"},
		{"skip", "skip"},
	}

	for _, tt := range tests {
		h := HookEntry{OnError: tt.onError}
		if got := h.EffectiveOnError(); got != tt.want {
			t.Errorf("EffectiveOnError(%q) = %q, want %q", tt.onError, got, tt.want)
		}
	}
}

func TestLoadMissingFileReturnsEmpty(t *testing.T) {
	// Point to a nonexistent directory so no config is found.
	t.Setenv("HOOK_CHAIN_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Chains) != 0 {
		t.Errorf("expected empty chains, got %d", len(cfg.Chains))
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("{{invalid yaml"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := LoadFrom(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoadFromEnvVar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.yaml")
	yaml := `
chains:
  - event: PreToolUse
    tools: [Bash]
    hooks:
      - name: custom-hook
        command: /bin/true
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Setenv("HOOK_CHAIN_CONFIG", path)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(cfg.Chains))
	}
	if cfg.Chains[0].Hooks[0].Name != "custom-hook" {
		t.Errorf("hook name = %q, want %q", cfg.Chains[0].Hooks[0].Name, "custom-hook")
	}
}
