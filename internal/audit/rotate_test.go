package audit

import (
	"archive/zip"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestMaybeRotate_NoEntries(t *testing.T) {
	a := openTestDB(t)
	dir := t.TempDir()

	cfg := RotationConfig{
		Retention:   24 * time.Hour,
		ArchiveDir:  filepath.Join(dir, "archives"),
		ThrottleDir: filepath.Join(dir, "archives"),
	}

	MaybeRotate(a.DB(), cfg, testLogger())

	// No archive should be created.
	archives, err := ListArchives(cfg.ArchiveDir)
	if err != nil {
		t.Fatalf("ListArchives: %v", err)
	}
	if len(archives) != 0 {
		t.Errorf("expected 0 archives, got %d", len(archives))
	}
}

func TestMaybeRotate_ExportAndPrune(t *testing.T) {
	a := openTestDB(t)
	dir := t.TempDir()

	// Insert an old entry and a new entry.
	now := time.Now().UTC()
	oldTS := now.Add(-48 * time.Hour)
	newTS := now.Add(-1 * time.Hour)

	oldEntry := sampleChain("PreToolUse", OutcomeAllow, oldTS, sampleHooks())
	newEntry := sampleChain("PreToolUse", OutcomeDeny, newTS, nil)

	if err := a.RecordChain(oldEntry); err != nil {
		t.Fatalf("RecordChain (old): %v", err)
	}
	if err := a.RecordChain(newEntry); err != nil {
		t.Fatalf("RecordChain (new): %v", err)
	}

	cfg := RotationConfig{
		Retention:   24 * time.Hour,
		ArchiveDir:  filepath.Join(dir, "archives"),
		ThrottleDir: filepath.Join(dir, "archives"),
	}

	MaybeRotate(a.DB(), cfg, testLogger())

	// Verify archive was created.
	archives, err := ListArchives(cfg.ArchiveDir)
	if err != nil {
		t.Fatalf("ListArchives: %v", err)
	}
	if len(archives) != 1 {
		t.Fatalf("expected 1 archive, got %d", len(archives))
	}

	// Verify only the new entry remains in DB.
	remaining, err := ListChains(a.DB(), 100, 0, "", "")
	if err != nil {
		t.Fatalf("ListChains: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("expected 1 remaining chain, got %d", len(remaining))
	}
	if remaining[0].Outcome != OutcomeDeny {
		t.Errorf("remaining outcome = %q, want deny", remaining[0].Outcome)
	}
}

func TestMaybeRotate_Throttled(t *testing.T) {
	a := openTestDB(t)
	dir := t.TempDir()

	// Insert an old entry.
	oldTS := time.Now().UTC().Add(-48 * time.Hour)
	if err := a.RecordChain(sampleChain("PreToolUse", OutcomeAllow, oldTS, nil)); err != nil {
		t.Fatalf("RecordChain: %v", err)
	}

	archiveDir := filepath.Join(dir, "archives")
	cfg := RotationConfig{
		Retention:   24 * time.Hour,
		ArchiveDir:  archiveDir,
		ThrottleDir: archiveDir,
	}

	// First rotation should work.
	MaybeRotate(a.DB(), cfg, testLogger())

	// Insert another old entry.
	if err := a.RecordChain(sampleChain("PreToolUse", OutcomeAllow, oldTS, nil)); err != nil {
		t.Fatalf("RecordChain: %v", err)
	}

	// Second rotation should be throttled (marker was just touched).
	MaybeRotate(a.DB(), cfg, testLogger())

	// Only 1 archive should exist (second rotation was throttled).
	archives, err := ListArchives(archiveDir)
	if err != nil {
		t.Fatalf("ListArchives: %v", err)
	}
	if len(archives) != 1 {
		t.Errorf("expected 1 archive (throttled), got %d", len(archives))
	}
}

func TestMaybeRotate_ThrottleExpired(t *testing.T) {
	a := openTestDB(t)
	dir := t.TempDir()

	archiveDir := filepath.Join(dir, "archives")
	if err := os.MkdirAll(archiveDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	// Create a marker file with an old modification time.
	markerPath := filepath.Join(archiveDir, ".last-rotation")
	f, err := os.Create(markerPath)
	if err != nil {
		t.Fatalf("create marker: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close marker: %v", err)
	}
	oldTime := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(markerPath, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// Insert an old entry.
	oldTS := time.Now().UTC().Add(-48 * time.Hour)
	if err := a.RecordChain(sampleChain("PreToolUse", OutcomeAllow, oldTS, nil)); err != nil {
		t.Fatalf("RecordChain: %v", err)
	}

	cfg := RotationConfig{
		Retention:   24 * time.Hour,
		ArchiveDir:  archiveDir,
		ThrottleDir: archiveDir,
	}

	MaybeRotate(a.DB(), cfg, testLogger())

	// Rotation should have run since marker is >1h old.
	archives, err := ListArchives(archiveDir)
	if err != nil {
		t.Fatalf("ListArchives: %v", err)
	}
	if len(archives) != 1 {
		t.Errorf("expected 1 archive (throttle expired), got %d", len(archives))
	}
}

func TestArchiveContents(t *testing.T) {
	a := openTestDB(t)
	dir := t.TempDir()

	oldTS := time.Now().UTC().Add(-48 * time.Hour)
	entry := sampleChain("PreToolUse", OutcomeAllow, oldTS, sampleHooks())
	if err := a.RecordChain(entry); err != nil {
		t.Fatalf("RecordChain: %v", err)
	}

	archiveDir := filepath.Join(dir, "archives")
	cfg := RotationConfig{
		Retention:   24 * time.Hour,
		ArchiveDir:  archiveDir,
		ThrottleDir: archiveDir,
	}

	MaybeRotate(a.DB(), cfg, testLogger())

	archives, err := ListArchives(archiveDir)
	if err != nil {
		t.Fatalf("ListArchives: %v", err)
	}
	if len(archives) != 1 {
		t.Fatalf("expected 1 archive, got %d", len(archives))
	}

	// Read the zip and verify contents.
	r, err := zip.OpenReader(archives[0].Path)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer r.Close()

	if len(r.File) != 1 {
		t.Fatalf("expected 1 file in zip, got %d", len(r.File))
	}
	if r.File[0].Name != "audit.json" {
		t.Errorf("zip file name = %q, want audit.json", r.File[0].Name)
	}

	rc, err := r.File[0].Open()
	if err != nil {
		t.Fatalf("open audit.json: %v", err)
	}
	defer rc.Close()

	var entries []ChainExecution
	if err := json.NewDecoder(rc).Decode(&entries); err != nil {
		t.Fatalf("decode audit.json: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry in archive, got %d", len(entries))
	}
	if entries[0].EventName != "PreToolUse" {
		t.Errorf("archived entry EventName = %q, want PreToolUse", entries[0].EventName)
	}
	if len(entries[0].Hooks) != 2 {
		t.Errorf("archived entry hooks = %d, want 2", len(entries[0].Hooks))
	}
}

func TestListArchives_Empty(t *testing.T) {
	dir := t.TempDir()
	archives, err := ListArchives(dir)
	if err != nil {
		t.Fatalf("ListArchives: %v", err)
	}
	if len(archives) != 0 {
		t.Errorf("expected 0 archives, got %d", len(archives))
	}
}

func TestListArchives_NonExistentDir(t *testing.T) {
	archives, err := ListArchives("/nonexistent/path/to/archives")
	if err != nil {
		t.Fatalf("ListArchives should not error for non-existent dir: %v", err)
	}
	if len(archives) != 0 {
		t.Errorf("expected 0 archives, got %d", len(archives))
	}
}

func TestMaybeRotate_NilDB(t *testing.T) {
	cfg := RotationConfig{
		Retention:   24 * time.Hour,
		ArchiveDir:  t.TempDir(),
		ThrottleDir: t.TempDir(),
	}
	// Should not panic.
	MaybeRotate(nil, cfg, testLogger())
}
