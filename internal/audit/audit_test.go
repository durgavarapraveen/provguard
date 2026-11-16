package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGC(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "audit")
	os.MkdirAll(dir, 0o700)
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	for _, name := range []string{"2026-09-01.jsonl", "2026-10-16.jsonl", "2026-10-17.jsonl", "2026-11-16.jsonl", "notes.jsonl"} {
		os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o600)
	}
	if n := GC(home, 30, now); n != 2 {
		t.Fatalf("removed %d, want 2 (09-01 and 10-16)", n)
	}
	for _, keep := range []string{"2026-10-17.jsonl", "2026-11-16.jsonl", "notes.jsonl"} {
		if _, err := os.Stat(filepath.Join(dir, keep)); err != nil {
			t.Errorf("%s removed", keep)
		}
	}
	if n := GC(home, -1, now.AddDate(1, 0, 0)); n != 0 {
		t.Fatal("negative retention must keep everything")
	}
}
