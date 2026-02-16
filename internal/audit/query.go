package audit

import (
	"database/sql"
	"fmt"
	"time"
)

// ListChains returns chain executions with optional filtering by event name and outcome.
// Results are ordered by timestamp descending (newest first).
func ListChains(db *sql.DB, limit, offset int, filterEvent, filterOutcome string) ([]ChainExecution, error) {
	if db == nil {
		return nil, fmt.Errorf("audit: ListChains called with nil db")
	}

	query := "SELECT id, timestamp, event_name, tool_name, chain_len, outcome, reason, duration_ms, session_id FROM chain_executions WHERE 1=1"
	var args []any

	if filterEvent != "" {
		query += " AND event_name = ?"
		args = append(args, filterEvent)
	}
	if filterOutcome != "" {
		query += " AND outcome = ?"
		args = append(args, filterOutcome)
	}

	query += " ORDER BY timestamp DESC"

	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}
	if offset > 0 {
		query += " OFFSET ?"
		args = append(args, offset)
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: list chains: %w", err)
	}
	defer rows.Close()

	var chains []ChainExecution
	for rows.Next() {
		var c ChainExecution
		var tsStr string
		if err := rows.Scan(&c.ID, &tsStr, &c.EventName, &c.ToolName, &c.ChainLen, &c.Outcome, &c.Reason, &c.DurationMs, &c.SessionID); err != nil {
			return nil, fmt.Errorf("audit: scan chain row: %w", err)
		}
		ts, err := time.Parse("2006-01-02T15:04:05.000", tsStr)
		if err != nil {
			return nil, fmt.Errorf("audit: parse timestamp %q: %w", tsStr, err)
		}
		c.Timestamp = ts
		chains = append(chains, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate chain rows: %w", err)
	}

	return chains, nil
}

// GetChain returns a single chain execution by ID, including its hook results.
func GetChain(db *sql.DB, id int64) (*ChainExecution, error) {
	if db == nil {
		return nil, fmt.Errorf("audit: GetChain called with nil db")
	}

	var c ChainExecution
	var tsStr string
	err := db.QueryRow(
		"SELECT id, timestamp, event_name, tool_name, chain_len, outcome, reason, duration_ms, session_id FROM chain_executions WHERE id = ?",
		id,
	).Scan(&c.ID, &tsStr, &c.EventName, &c.ToolName, &c.ChainLen, &c.Outcome, &c.Reason, &c.DurationMs, &c.SessionID)
	if err != nil {
		return nil, fmt.Errorf("audit: get chain %d: %w", id, err)
	}

	ts, err := time.Parse("2006-01-02T15:04:05.000", tsStr)
	if err != nil {
		return nil, fmt.Errorf("audit: parse timestamp %q: %w", tsStr, err)
	}
	c.Timestamp = ts

	rows, err := db.Query(
		"SELECT id, chain_id, hook_index, hook_name, exit_code, outcome, duration_ms, stderr FROM hook_results WHERE chain_id = ? ORDER BY hook_index",
		id,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: get hook results for chain %d: %w", id, err)
	}
	defer rows.Close()

	for rows.Next() {
		var h HookResult
		if err := rows.Scan(&h.ID, &h.ChainID, &h.HookIndex, &h.HookName, &h.ExitCode, &h.Outcome, &h.DurationMs, &h.Stderr); err != nil {
			return nil, fmt.Errorf("audit: scan hook result: %w", err)
		}
		c.Hooks = append(c.Hooks, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate hook results: %w", err)
	}

	return &c, nil
}

// Tail returns the last n chain executions ordered by timestamp descending (newest first).
func Tail(db *sql.DB, n int) ([]ChainExecution, error) {
	return ListChains(db, n, 0, "", "")
}

// Prune deletes chain executions (and their hook results) older than the given duration.
// Returns the number of chain executions deleted.
func Prune(db *sql.DB, olderThan time.Duration) (int64, error) {
	if db == nil {
		return 0, fmt.Errorf("audit: Prune called with nil db")
	}

	cutoff := time.Now().UTC().Add(-olderThan).Format("2006-01-02T15:04:05.000")

	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("audit: begin prune transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Delete hook results for old chains first (foreign key reference).
	_, err = tx.Exec(
		"DELETE FROM hook_results WHERE chain_id IN (SELECT id FROM chain_executions WHERE timestamp < ?)",
		cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("audit: prune hook results: %w", err)
	}

	result, err := tx.Exec("DELETE FROM chain_executions WHERE timestamp < ?", cutoff)
	if err != nil {
		return 0, fmt.Errorf("audit: prune chain executions: %w", err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("audit: prune rows affected: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("audit: commit prune: %w", err)
	}

	return count, nil
}

// Stats returns aggregate statistics from the audit database.
func Stats(db *sql.DB) (*AuditStats, error) {
	if db == nil {
		return nil, fmt.Errorf("audit: Stats called with nil db")
	}

	stats := &AuditStats{
		CountByOutcome: make(map[string]int64),
	}

	// Total count and average duration.
	err := db.QueryRow("SELECT COALESCE(COUNT(*), 0), COALESCE(AVG(duration_ms), 0) FROM chain_executions").
		Scan(&stats.TotalChains, &stats.AvgDurationMs)
	if err != nil {
		return nil, fmt.Errorf("audit: stats totals: %w", err)
	}

	if stats.TotalChains == 0 {
		return stats, nil
	}

	// Oldest and newest entries.
	var oldestStr, newestStr string
	err = db.QueryRow("SELECT MIN(timestamp), MAX(timestamp) FROM chain_executions").
		Scan(&oldestStr, &newestStr)
	if err != nil {
		return nil, fmt.Errorf("audit: stats min/max timestamp: %w", err)
	}

	oldest, err := time.Parse("2006-01-02T15:04:05.000", oldestStr)
	if err != nil {
		return nil, fmt.Errorf("audit: parse oldest timestamp %q: %w", oldestStr, err)
	}
	stats.OldestEntry = oldest

	newest, err := time.Parse("2006-01-02T15:04:05.000", newestStr)
	if err != nil {
		return nil, fmt.Errorf("audit: parse newest timestamp %q: %w", newestStr, err)
	}
	stats.NewestEntry = newest

	// Counts by outcome.
	rows, err := db.Query("SELECT outcome, COUNT(*) FROM chain_executions GROUP BY outcome")
	if err != nil {
		return nil, fmt.Errorf("audit: stats by outcome: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var outcome string
		var count int64
		if err := rows.Scan(&outcome, &count); err != nil {
			return nil, fmt.Errorf("audit: scan outcome count: %w", err)
		}
		stats.CountByOutcome[outcome] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate outcome rows: %w", err)
	}

	return stats, nil
}
