# hook-chain

**Sequential Hook Executor for [Claude Code](https://docs.anthropic.com/en/docs/claude-code).**

Claude Code hooks let you run a command before or after tool calls — but only *one* command per event. hook-chain removes that limitation: define an ordered list of hooks in YAML, and hook-chain runs them as a single pipeline, threading state through the chain with fold/reduce semantics.

```
Claude Code  ──stdin──▶  hook-chain  ──▶  hook-1  ──▶  hook-2  ──▶  hook-N  ──stdout──▶  Claude Code
                           │                                            │
                           └──── accumulated toolInput state ───────────┘
```

## Install

**Homebrew:**

```bash
brew tap Fuabioo/tap
brew install hook-chain
```

**Go:**

```bash
go install github.com/Fuabioo/hook-chain@latest
```

**Binary:** download from [Releases](https://github.com/Fuabioo/hook-chain/releases) (linux/darwin, amd64/arm64).

## Quick start

**1. Create a config file:**

```bash
mkdir -p ~/.config/hook-chain
cat > ~/.config/hook-chain/config.yaml << 'EOF'
chains:
  - event: PreToolUse
    tools: [Bash]
    hooks:
      - name: log-command
        command: ~/hooks/log-bash.sh
      - name: block-rm-rf
        command: ~/hooks/block-rm-rf.sh
EOF
```

**2. Point Claude Code at hook-chain:**

In your `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": { "tool_name": "Bash" },
        "hooks": [
          { "type": "command", "command": "hook-chain" }
        ]
      }
    ]
  }
}
```

**3. Verify your setup:**

```bash
hook-chain validate
```

## How the pipeline works

hook-chain reads the [hook protocol](https://docs.anthropic.com/en/docs/claude-code/hooks) JSON from stdin, resolves the matching chain from config, and executes hooks sequentially. Each hook receives the full input on stdin and can:

- **Pass through** — exit 0 with empty stdout. No effect; next hook runs.
- **Modify `toolInput`** — return JSON with `hookSpecificOutput.updatedInput`. The updates are shallow-merged into the accumulated state and forwarded to the next hook.
- **Add context** — return `hookSpecificOutput.additionalContext`. All context strings are collected and joined in the final output.
- **Deny** — exit 2, or return `permissionDecision: "deny"`. Immediately stops the chain and blocks the tool call.
- **Escalate** — return `permissionDecision: "ask"`. Immediately stops the chain and prompts the user.

When all hooks pass, hook-chain emits the accumulated output (merged `updatedInput` + combined `additionalContext`) back to Claude Code. If nothing changed, it exits silently — a clean passthrough.

### Exit code semantics

| Exit code | Meaning |
|-----------|---------|
| 0 | Success. Parse stdout for hook output (if any). |
| 2 | **Deny.** Always blocks the tool call, regardless of `on_error`. |
| Any other | Error. Behavior depends on the hook's `on_error` policy. |

### Error policies

Each hook can set `on_error` to control what happens on non-zero exits (other than 2) or invalid output:

- **`deny`** (default) — fail closed. The chain stops and the tool call is blocked.
- **`skip`** — fail open. The broken hook is skipped and the chain continues.

## Configuration

Config file search order:

1. `$HOOK_CHAIN_CONFIG` (explicit path)
2. `$XDG_CONFIG_HOME/hook-chain/config.yaml`
3. `~/.config/hook-chain/config.yaml`

### Schema

```yaml
chains:
  - event: PreToolUse          # hook event name (PreToolUse, PostToolUse, etc.)
    tools: [Bash, Write, Edit] # tool names to match
    hooks:
      - name: my-hook          # human-readable name (shown in logs and audit)
        command: /path/to/hook  # executable (supports ~/ expansion)
        args: [--flag, value]   # additional arguments (optional)
        timeout: 10s            # per-hook timeout (default: 30s)
        env: [KEY=value]        # extra environment variables (optional)
        on_error: deny          # "deny" (default) or "skip"

audit:
  disabled: false              # set true to disable audit logging
  db_path: /custom/audit.db    # override default DB location
  retention: 30d               # auto-rotation retention (default: 7d)
```

Chain resolution uses **first match**: the first chain entry where `event` matches AND the tool name appears in `tools` is selected. Hook execution order within a chain is preserved exactly as written.

## Audit log

Every chain execution is recorded to a local SQLite database. Audit is **enabled by default** and runs fail-open — if the database can't be opened, the pipeline runs normally without auditing.

Old entries are automatically archived to compressed zip files and pruned based on the configured retention period (default: 7 days). Rotation runs at most once per hour.

### Querying the audit log

```bash
# Recent executions
hook-chain audit tail

# List with filters
hook-chain audit list --event PreToolUse --outcome deny --limit 50

# Full details of a specific chain execution (including per-hook results)
hook-chain audit show 42

# Aggregate statistics
hook-chain audit stats

# All commands support --json for machine-readable output
hook-chain audit list --json

# Manual pruning
hook-chain audit prune --older-than 30d

# View archived entries
hook-chain audit archives

# Print the database path
hook-chain audit db-path
```

### Storage locations

| Path | Purpose |
|------|---------|
| `$HOOK_CHAIN_AUDIT_DB` | Explicit DB path override |
| `$XDG_DATA_HOME/hook-chain/audit.db` | XDG-compliant default |
| `~/.local/share/hook-chain/audit.db` | Fallback default |
| `.../hook-chain/archives/` | Rotated zip archives |

## Environment variables

| Variable | Purpose |
|----------|---------|
| `HOOK_CHAIN_CONFIG` | Explicit config file path |
| `HOOK_CHAIN_DEBUG=1` | Enable debug logging to stderr |
| `HOOK_CHAIN_AUDIT=0` | Disable audit logging entirely |
| `HOOK_CHAIN_AUDIT_DB` | Override audit database path |

## CLI reference

```
hook-chain                Run the pipeline (reads hook protocol JSON from stdin)
hook-chain validate       Validate config and check that hook commands exist on PATH
hook-chain version        Print version and commit info
hook-chain audit list     List chain executions (--limit, --offset, --event, --outcome, --json)
hook-chain audit show     Show full details of a chain execution (--json)
hook-chain audit tail     Show last N executions (--n, --json)
hook-chain audit stats    Aggregate statistics (--json)
hook-chain audit prune    Delete entries older than a duration (--older-than)
hook-chain audit archives List rotated archive files (--json)
hook-chain audit db-path  Print the audit database path
```

## Architecture

```
main.go                     Entry point
internal/
├── cli/                    Cobra CLI (root pipe handler, validate, version, audit subcommands)
├── hook/                   Hook protocol types (Input/Output JSON with round-trip preservation)
├── config/                 YAML config loading with ordered chain resolution
├── pipeline/               Core fold/reduce algorithm + shallow JSON merge
├── runner/                 Process execution (Runner interface + ProcessRunner)
├── audit/                  SQLite audit logging, rotation, archival, and query helpers
└── pathutil/               Tilde expansion utility
```

### Design decisions

- **Ordered lists, not maps.** Chains and hooks are YAML arrays to preserve execution order deterministically.
- **Round-trip JSON preservation.** Unknown fields in the hook protocol input survive marshaling/unmarshaling via `json.RawMessage`, ensuring forward compatibility as Claude Code evolves.
- **Shallow merge for `updatedInput`.** Matches Claude Code's own semantics — top-level keys are replaced, not deep-merged.
- **Fail closed by default.** Config errors, stdin parse failures, and hook errors all result in deny (exit 2) unless explicitly configured otherwise with `on_error: skip`.
- **Audit as a side effect.** Recording is fire-and-forget. A broken audit database never blocks the security pipeline.

## Development

Requires: Go 1.26+, Docker, [just](https://github.com/casey/just).

```bash
just build          # Build binary to bin/hook-chain
just test           # Run tests in Docker (mandatory — never on host)
just test-verbose   # Verbose test output
just test-coverage  # Coverage report
just lint           # golangci-lint
just vulncheck      # govulncheck
just snapshot       # GoReleaser snapshot build
```

## License

MIT
