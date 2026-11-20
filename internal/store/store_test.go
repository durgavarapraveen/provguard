package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestConcurrentUpdatesKeepEveryWrite(t *testing.T) {
	home := t.TempDir()
	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- Update(home, "s1", func(s *Session) error {
				s.AddValues(fmt.Sprintf("v%d", i))
				return nil
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	s, err := Get(home, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.UntrustedValues) != n {
		t.Fatalf("lost updates: have %d values, want %d", len(s.UntrustedValues), n)
	}
	if _, err := os.Stat(path(home, "s1") + ".lock"); !os.IsNotExist(err) {
		t.Fatal("lock file left behind")
	}
}

// On Windows, a reader holding the session file open must not make the
// writer's rename fail with "Access is denied" and lose the update.
func TestUpdateWhileReaderHoldsFile(t *testing.T) {
	home := t.TempDir()
	if err := Update(home, "s", func(s *Session) error { return nil }); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path(home, "s"))
	if err != nil {
		t.Fatal(err)
	}
	go func() { time.Sleep(15 * time.Millisecond); f.Close() }()
	if err := Update(home, "s", func(s *Session) error {
		s.MarkTainted(Source{Tool: "WebFetch", Reason: "x"})
		return nil
	}); err != nil {
		t.Fatalf("update lost while a reader held the file: %v", err)
	}
	if s, _ := Get(home, "s"); !s.Tainted {
		t.Fatal("taint not saved")
	}
}

func TestTaintIsSticky(t *testing.T) {
	home := t.TempDir()
	_ = Update(home, "s", func(s *Session) error {
		s.MarkTainted(Source{Tool: "WebFetch", Reason: "web_fetch"})
		return nil
	})
	_ = Update(home, "s", func(s *Session) error { return nil })
	s, _ := Get(home, "s")
	if !s.Tainted || len(s.TaintSources) != 1 {
		t.Fatalf("taint lost: %+v", s)
	}
}

func TestCapsAndDedupe(t *testing.T) {
	var s Session
	for i := 0; i < MaxValues+10; i++ {
		s.AddValues(fmt.Sprint(i), fmt.Sprint(i))
	}
	if len(s.UntrustedValues) != MaxValues || s.UntrustedValues[0] != "10" {
		t.Fatalf("cap/dedupe wrong: len=%d first=%s", len(s.UntrustedValues), s.UntrustedValues[0])
	}
}

func TestRejectsUnsafeSessionID(t *testing.T) {
	for _, id := range []string{"", "../x", `a\b`, "a/b", "a:b"} {
		if err := Update(t.TempDir(), id, func(*Session) error { return nil }); err == nil {
			t.Errorf("id %q accepted", id)
		}
	}
}

func TestStaleLockIsBroken(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(dir(home), 0o700)
	lk := path(home, "s") + ".lock"
	os.WriteFile(lk, nil, 0o600)
	old := time.Now().Add(-time.Minute)
	os.Chtimes(lk, old, old)
	if err := Update(home, "s", func(*Session) error { return nil }); err != nil {
		t.Fatalf("stale lock not broken: %v", err)
	}
}

// Breaking a stale lock must not delete a fresh one.
func TestBreakStaleKeepsFreshLock(t *testing.T) {
	dir := t.TempDir()
	lk := filepath.Join(dir, "s.json.lock")
	os.WriteFile(lk, nil, 0o600) // fresh lock, just taken by another hook
	breakStale(lk)
	if _, err := os.Stat(lk); err != nil {
		t.Fatal("fresh lock was removed")
	}
	old := time.Now().Add(-time.Minute)
	os.Chtimes(lk, old, old)
	breakStale(lk)
	if _, err := os.Stat(lk); !os.IsNotExist(err) {
		t.Fatal("stale lock not removed")
	}
	if m, _ := filepath.Glob(lk + ".stale-*"); len(m) != 0 {
		t.Fatalf("leftover files: %v", m)
	}
}

func TestGC(t *testing.T) {
	home := t.TempDir()
	_ = Update(home, "old", func(*Session) error { return nil })
	_ = Update(home, "new", func(*Session) error { return nil })
	old := time.Now().Add(-MaxAge - time.Hour)
	os.Chtimes(filepath.Join(dir(home), "old.json"), old, old)
	if n := GC(home); n != 1 {
		t.Fatalf("removed %d", n)
	}
	if _, err := os.Stat(filepath.Join(dir(home), "new.json")); err != nil {
		t.Fatal("fresh session removed")
	}
}

// Clearing one checked source keeps the label while others remain; the last
// one clears it, unless the list was full and may have dropped older ones.
func TestClearTaintSource(t *testing.T) {
	at := time.Now().UTC()
	s := &Session{}
	s.MarkTainted(Source{At: at, Tool: "WebFetch", Reason: "web"})
	s.MarkHidden(Source{At: at, Tool: "Read", Reason: "unicode_tags"})
	s.AddValues("evil.test")
	if s.ClearTaintSource(1) || !s.Tainted || len(s.HiddenSources) != 0 || len(s.TaintSources) != 1 {
		t.Fatalf("after clearing 1 of 2: %+v", s)
	}
	if !s.ClearTaintSource(0) || s.Tainted || len(s.UntrustedValues) != 0 {
		t.Fatalf("last source did not clear the label: %+v", s)
	}
	if s.ClearTaintSource(0) {
		t.Error("cleared a source that does not exist")
	}

	full := &Session{}
	for i := 0; i < MaxSources+5; i++ {
		full.MarkTainted(Source{At: at, Tool: "WebFetch", Reason: "web"})
	}
	for len(full.TaintSources) > 0 {
		if full.ClearTaintSource(0) {
			t.Fatal("a capped list cleared the label: older sources may be missing")
		}
	}
	if !full.Tainted {
		t.Error("label lost")
	}
}
