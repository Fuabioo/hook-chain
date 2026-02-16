## hook-chain

Sequential Hook Executor for Claude Code.

### Build & Test

- `just build` — build binary to `bin/hook-chain`
- `just test` — run tests in Docker (MANDATORY, never on host)
- `just test-verbose` — verbose test output in Docker
- `just lint` — run golangci-lint
- `just snapshot` — goreleaser snapshot build

### Architecture

- `internal/hook/` — Claude Code hook protocol types (Input/Output JSON)
- `internal/config/` — YAML config loading with ordered chain resolution
- `internal/runner/` — Process execution (Runner interface + ProcessRunner)
- `internal/pipeline/` — Core fold/reduce algorithm that chains hooks sequentially
- `internal/cli/` — Cobra CLI (root pipe handler + validate + version subcommands)

### Conventions

- Go error handling: never ignore errors
- Named structs preferred over anonymous
- `json.RawMessage` for transparent JSON forwarding
- Tests are table-driven with mock runner
- Config uses ordered lists (not maps) to preserve hook execution order
