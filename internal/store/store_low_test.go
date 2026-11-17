package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GC must not remove the lock of a long-idle session while a hook still
// holds it mid-update.
func TestGCKeepsLiveLocks(t *testing.T) {
	home := t.TempDir()
	_ = Update(home, "old", func(*Session) error { return nil })
	d := dir(home)
	old := time.Now().Add(-MaxAge - time.Hour)
	os.Chtimes(filepath.Join(d, "old.json"), old, old)

	// A lock a hook is holding right now, for that same old session.
	live := filepath.Join(d, "old.json.lock")
	if err := os.WriteFile(live, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// Leftovers from a hook that crashed long ago.
	dead := filepath.Join(d, "gone.json.lock")
	os.WriteFile(dead, nil, 0o600)
	deadTmp := filepath.Join(d, "gone.json.tmp")
	os.WriteFile(deadTmp, nil, 0o600)
	ancient := time.Now().Add(-2 * abandoned)
	os.Chtimes(dead, ancient, ancient)
	os.Chtimes(deadTmp, ancient, ancient)
	// Something that is not ours.
	keep := filepath.Join(d, "notes.txt")
	os.WriteFile(keep, nil, 0o600)
	os.Chtimes(keep, ancient, ancient)

	if n := GC(home); n != 1 {
		t.Fatalf("removed %d session files, want 1", n)
	}
	if _, err := os.Stat(live); err != nil {
		t.Error("GC removed a lock a hook is holding")
	}
	for _, p := range []string{dead, deadTmp} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("GC kept the abandoned %s", filepath.Base(p))
		}
	}
	if _, err := os.Stat(keep); err != nil {
		t.Error("GC removed a file that is not provguard's")
	}
}
