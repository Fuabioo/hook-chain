package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level hook-chain configuration.
type Config struct {
	Chains []ChainEntry `yaml:"chains"`
	Audit  *AuditConfig `yaml:"audit,omitempty"`
}

// AuditConfig controls the audit logging subsystem.
type AuditConfig struct {
	Disabled  bool   `yaml:"disabled"` // default: false (audit enabled)
	DBPath    string `yaml:"db_path,omitempty"`
	Retention string `yaml:"retention,omitempty"` // e.g. "7d", "30d"
}

// ChainEntry maps an event+tool pattern to a sequence of hooks.
type ChainEntry struct {
	Event string      `yaml:"event"`
	Tools []string    `yaml:"tools"`
	Hooks []HookEntry `yaml:"hooks"`
}

// HookEntry describes a single hook command to execute.
type HookEntry struct {
	Name    string        `yaml:"name"`
	Command string        `yaml:"command"`
	Args    []string      `yaml:"args,omitempty"`
	Timeout time.Duration `yaml:"timeout,omitempty"`
	Env     []string      `yaml:"env,omitempty"`
	OnError string        `yaml:"on_error,omitempty"` // "deny" (default) | "skip"
}

// EffectiveOnError returns the on_error policy, defaulting to "deny".
func (h HookEntry) EffectiveOnError() string {
	if h.OnError == "" {
		return "deny"
	}
	return h.OnError
}

// Load searches for the config file in standard locations and parses it.
// Search order: $HOOK_CHAIN_CONFIG → $XDG_CONFIG_HOME/hook-chain/config.yaml
// → ~/.config/hook-chain/config.yaml.
// Returns zero-value Config if no file is found. Returns error if file exists
// but contains invalid YAML.
func Load() (Config, error) {
	path, err := findConfigPath()
	if err != nil {
		return Config{}, err
	}
	if path == "" {
		return Config{}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
	}

	return cfg, nil
}

// LoadFrom parses a config from the given file path.
// Returns error if the file cannot be read or contains invalid YAML.
func LoadFrom(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
	}

	return cfg, nil
}

// Resolve returns the hooks from the first matching chain entry where
// eventName matches AND toolName is in the Tools list.
// Uses exact string matching. Returns nil if no chain matches.
func (c Config) Resolve(eventName, toolName string) []HookEntry {
	for _, chain := range c.Chains {
		if chain.Event != eventName {
			continue
		}
		for _, t := range chain.Tools {
			if t == toolName {
				return chain.Hooks
			}
		}
	}
	return nil
}

// findConfigPath returns the path to the first config file found,
// or empty string if none exists.
func findConfigPath() (string, error) {
	// 1. Explicit env var.
	if p := os.Getenv("HOOK_CHAIN_CONFIG"); p != "" {
		if _, err := os.Stat(p); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return "", fmt.Errorf("config: $HOOK_CHAIN_CONFIG points to %s which does not exist", p)
			}
			return "", fmt.Errorf("config: stat %s: %w", p, err)
		}
		return p, nil
	}

	// 2. XDG_CONFIG_HOME.
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		p := filepath.Join(xdg, "hook-chain", "config.yaml")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	// 3. Default ~/.config.
	home, err := os.UserHomeDir()
	if err != nil {
		return "", nil // Can't determine home, treat as no config.
	}
	p := filepath.Join(home, ".config", "hook-chain", "config.yaml")
	if _, err := os.Stat(p); err == nil {
		return p, nil
	}

	return "", nil
}
