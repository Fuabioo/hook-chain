package audit

import (
	"archive/zip"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// RotationConfig controls auto-rotation of audit entries.
type RotationConfig struct {
	Retention   time.Duration // entries older than this are archived
	ArchiveDir  string        // directory for zip archives
	ThrottleDir string        // directory for .last-rotation marker
}

// ArchiveInfo describes a single audit archive file.
type ArchiveInfo struct {
	Path    string
	Name    string
	Size    int64
	ModTime time.Time
}

// MaybeRotate exports old entries to a zip archive and prunes them from the DB.
// It is throttled to run at most once per hour. All errors are logged but never
// returned — rotation is best-effort and must not affect the pipeline.
func MaybeRotate(db *sql.DB, cfg RotationConfig, logger *slog.Logger) {
	if db == nil {
		return
	}

	markerPath := filepath.Join(cfg.ThrottleDir, ".last-rotation")
	if !shouldRotate(markerPath) {
		logger.Debug("rotation throttled")
		return
	}

	// Touch marker FIRST — prevents thundering herd if rotation fails.
	touchMarker(markerPath, logger)

	cutoff := time.Now().UTC().Add(-cfg.Retention)

	entries, err := exportEntries(db, cutoff)
	if err != nil {
		logger.Warn("rotation: export entries failed", "err", err)
		return
	}
	if len(entries) == 0 {
		logger.Debug("rotation: no entries to archive")
		return
	}

	// Ensure archive dir exists.
	if err := os.MkdirAll(cfg.ArchiveDir, 0o755); err != nil {
		logger.Warn("rotation: create archive dir", "err", err)
		return
	}

	archiveName := fmt.Sprintf("audit-%s.zip", time.Now().UTC().Format("20060102T150405Z"))
	archivePath := filepath.Join(cfg.ArchiveDir, archiveName)

	if err := writeArchive(archivePath, entries); err != nil {
		logger.Warn("rotation: write archive failed", "err", err)
		return
	}

	// Prune exported entries.
	pruned, err := PruneBefore(db, cutoff)
	if err != nil {
		logger.Warn("rotation: prune failed (archive already written)", "err", err)
		return
	}

	logger.Info("rotation complete",
		"archived", len(entries),
		"pruned", pruned,
		"archive", archivePath,
	)
}

// shouldRotate returns true if the marker file does not exist or is older than 1 hour.
func shouldRotate(markerPath string) bool {
	info, err := os.Stat(markerPath)
	if err != nil {
		// File doesn't exist or can't be read — allow rotation.
		return true
	}
	return time.Since(info.ModTime()) >= time.Hour
}

// touchMarker creates or updates the marker file's modification time.
func touchMarker(path string, logger *slog.Logger) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		logger.Warn("rotation: create throttle dir", "err", err)
		return
	}
	f, err := os.Create(path)
	if err != nil {
		logger.Warn("rotation: touch marker", "err", err)
		return
	}
	if err := f.Close(); err != nil {
		logger.Warn("rotation: close marker", "err", err)
	}
}

// exportEntries queries chain executions older than cutoff, including their hook results.
func exportEntries(db *sql.DB, cutoff time.Time) ([]ChainExecution, error) {
	cutoffStr := cutoff.Format("2006-01-02T15:04:05.000")

	rows, err := db.Query(
		"SELECT id FROM chain_executions WHERE timestamp < ? ORDER BY timestamp ASC",
		cutoffStr,
	)
	if err != nil {
		return nil, fmt.Errorf("query old chain IDs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan chain ID: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate chain IDs: %w", err)
	}

	if len(ids) == 0 {
		return nil, nil
	}

	entries := make([]ChainExecution, 0, len(ids))
	for _, id := range ids {
		chain, err := GetChain(db, id)
		if err != nil {
			return nil, fmt.Errorf("get chain %d: %w", id, err)
		}
		entries = append(entries, *chain)
	}

	return entries, nil
}

// writeArchive writes entries as a JSON file inside a zip archive.
// Uses atomic write: writes to a temp file, then renames.
func writeArchive(path string, entries []ChainExecution) error {
	tmpPath := path + ".tmp"

	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create temp archive: %w", err)
	}

	zw := zip.NewWriter(f)

	w, err := zw.Create("audit.json")
	if err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("create zip entry: %w", err)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(entries); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("encode entries: %w", err)
	}

	if err := zw.Close(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close zip writer: %w", err)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename temp archive: %w", err)
	}

	return nil
}

// ListArchives returns archive files in the given directory, sorted by modification time (newest first).
func ListArchives(archiveDir string) ([]ArchiveInfo, error) {
	dirEntries, err := os.ReadDir(archiveDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read archive dir: %w", err)
	}

	var archives []ArchiveInfo
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		if !strings.HasSuffix(de.Name(), ".zip") {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue // skip files we can't stat
		}
		archives = append(archives, ArchiveInfo{
			Path:    filepath.Join(archiveDir, de.Name()),
			Name:    de.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}

	sort.Slice(archives, func(i, j int) bool {
		return archives[i].ModTime.After(archives[j].ModTime)
	})

	return archives, nil
}
