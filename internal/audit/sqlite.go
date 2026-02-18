package audit

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const maxStderrLen = 512

// SQLiteAuditor implements Auditor using a local SQLite database.
type SQLiteAuditor struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS chain_executions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f','now')),
    event_name  TEXT    NOT NULL,
    tool_name   TEXT    NOT NULL,
    chain_len   INTEGER NOT NULL,
    outcome     TEXT    NOT NULL,
    reason      TEXT    NOT NULL DEFAULT '',
    duration_ms INTEGER NOT NULL,
    session_id  TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS hook_results (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id     INTEGER NOT NULL REFERENCES chain_executions(id),
    hook_index   INTEGER NOT NULL,
    hook_name    TEXT    NOT NULL,
    exit_code    INTEGER NOT NULL,
    outcome      TEXT    NOT NULL,
    duration_ms  INTEGER NOT NULL,
    stderr       TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_chain_ts ON chain_executions(timestamp);
CREATE INDEX IF NOT EXISTS idx_hook_chain ON hook_results(chain_id);
`

// DefaultDBPath returns the default audit database path.
// It checks $HOOK_CHAIN_AUDIT_DB, then $XDG_DATA_HOME/hook-chain/audit.db,
// then falls back to ~/.local/share/hook-chain/audit.db.
func DefaultDBPath() string {
	if p := os.Getenv("HOOK_CHAIN_AUDIT_DB"); p != "" {
		return p
	}
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dataHome, "hook-chain", "audit.db")
}

// Open opens (or creates) a SQLite audit database at the given path.
// It runs the schema migration and configures WAL mode with a 5-second busy timeout.
func Open(dbPath string) (*SQLiteAuditor, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("audit: create directory %q: %w", dir, err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("audit: open database %q: %w", dbPath, err)
	}

	// Set WAL mode for better concurrency.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		closeErr := db.Close()
		if closeErr != nil {
			return nil, fmt.Errorf("audit: set WAL mode: %w (also failed to close: %v)", err, closeErr)
		}
		return nil, fmt.Errorf("audit: set WAL mode: %w", err)
	}

	// Set busy timeout to 5 seconds.
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		closeErr := db.Close()
		if closeErr != nil {
			return nil, fmt.Errorf("audit: set busy_timeout: %w (also failed to close: %v)", err, closeErr)
		}
		return nil, fmt.Errorf("audit: set busy_timeout: %w", err)
	}

	// Run base schema (CREATE IF NOT EXISTS).
	if _, err := db.Exec(schema); err != nil {
		closeErr := db.Close()
		if closeErr != nil {
			return nil, fmt.Errorf("audit: create schema: %w (also failed to close: %v)", err, closeErr)
		}
		return nil, fmt.Errorf("audit: create schema: %w", err)
	}

	// Run migrations.
	if err := migrate(db); err != nil {
		closeErr := db.Close()
		if closeErr != nil {
			return nil, fmt.Errorf("audit: migrate: %w (also failed to close: %v)", err, closeErr)
		}
		return nil, fmt.Errorf("audit: migrate: %w", err)
	}

	return &SQLiteAuditor{db: db}, nil
}

// migrate applies incremental schema migrations using PRAGMA user_version.
func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}

	if version == 0 {
		exists, err := columnExists(db, "chain_executions", "tool_detail")
		if err != nil {
			return fmt.Errorf("check tool_detail column: %w", err)
		}
		if !exists {
			if _, err := db.Exec("ALTER TABLE chain_executions ADD COLUMN tool_detail TEXT NOT NULL DEFAULT ''"); err != nil {
				return fmt.Errorf("add tool_detail column: %w", err)
			}
		}
		if _, err := db.Exec("PRAGMA user_version = 1"); err != nil {
			return fmt.Errorf("set user_version to 1: %w", err)
		}
	}

	// version >= 1: schema is current, nothing to do.
	return nil
}

// columnExists checks whether a column exists in the given table.
func columnExists(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue *string
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// DB returns the underlying *sql.DB for use with query helpers.
// Returns nil if the receiver is nil.
func (a *SQLiteAuditor) DB() *sql.DB {
	if a == nil {
		return nil
	}
	return a.db
}

// RecordChain inserts a chain execution and its hook results in a single transaction.
// Nil receiver is a no-op.
func (a *SQLiteAuditor) RecordChain(entry ChainExecution) error {
	if a == nil {
		return nil
	}

	tx, err := a.db.Begin()
	if err != nil {
		return fmt.Errorf("audit: begin transaction: %w", err)
	}
	defer func() {
		// Rollback is a no-op if the transaction was already committed.
		_ = tx.Rollback()
	}()

	ts := entry.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	result, err := tx.Exec(
		`INSERT INTO chain_executions (timestamp, event_name, tool_name, tool_detail, chain_len, outcome, reason, duration_ms, session_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts.Format("2006-01-02T15:04:05.000"),
		entry.EventName,
		entry.ToolName,
		entry.ToolDetail,
		entry.ChainLen,
		entry.Outcome,
		entry.Reason,
		entry.DurationMs,
		entry.SessionID,
	)
	if err != nil {
		return fmt.Errorf("audit: insert chain_execution: %w", err)
	}

	chainID, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("audit: get last insert id: %w", err)
	}

	for _, h := range entry.Hooks {
		stderr := TruncateStderr(h.Stderr, maxStderrLen)
		_, err := tx.Exec(
			`INSERT INTO hook_results (chain_id, hook_index, hook_name, exit_code, outcome, duration_ms, stderr)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			chainID,
			h.HookIndex,
			h.HookName,
			h.ExitCode,
			h.Outcome,
			h.DurationMs,
			stderr,
		)
		if err != nil {
			return fmt.Errorf("audit: insert hook_result for hook %q: %w", h.HookName, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit: commit transaction: %w", err)
	}

	return nil
}

// Close closes the underlying database connection.
// Nil receiver is a no-op.
func (a *SQLiteAuditor) Close() error {
	if a == nil {
		return nil
	}
	if err := a.db.Close(); err != nil {
		return fmt.Errorf("audit: close database: %w", err)
	}
	return nil
}
