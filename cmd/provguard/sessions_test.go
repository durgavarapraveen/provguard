package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/durgavarapraveen/provguard/internal/event"
	"github.com/durgavarapraveen/provguard/internal/store"
)

// saveSession writes a session record and sets its file time.
func saveSession(t *testing.T, home, id, cwd, title string, tainted bool, mod time.Time) {
	t.Helper()
	if err := store.Update(home, id, func(s *store.Session) error {
		s.Cwd, s.Title, s.Tainted = cwd, title, tainted
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(home, "sessions", id+".json"), mod, mod); err != nil {
		t.Fatal(err)
	}
}

func TestResolveSession(t *testing.T) {
	home := t.TempDir()
	proj := t.TempDir()
	other := t.TempDir()
	now := time.Now()
	saveSession(t, home, "78d5c84e-aaaa", proj, "New project features", true, now.Add(-time.Hour))
	saveSession(t, home, "ce9b49bb-bbbb", other, "Proxy work", false, now)
	saveSession(t, home, "ce9c0000-cccc", other, "", false, now.Add(-2*time.Hour))

	sub := filepath.Join(proj, "cmd")
	os.MkdirAll(sub, 0o700)
	for _, c := range []struct{ dir, want string }{
		{proj, "78d5c84e-aaaa"},        // this folder's session, though another is newer
		{sub, "78d5c84e-aaaa"},         // a folder inside the project
		{t.TempDir(), "ce9b49bb-bbbb"}, // no session here: the newest of all
	} {
		wd, _ := os.Getwd()
		os.Chdir(c.dir)
		got, err := resolveSession(home, "latest")
		os.Chdir(wd)
		if err != nil || got != c.want {
			t.Errorf("latest in %s = %q, %v; want %q", c.dir, got, err, c.want)
		}
	}

	if got, err := resolveSession(home, "78d5"); err != nil || got != "78d5c84e-aaaa" {
		t.Errorf("prefix: %q, %v", got, err)
	}
	if _, err := resolveSession(home, "ce9"); err == nil || !strings.Contains(err.Error(), "matches 2 sessions") {
		t.Errorf("ambiguous prefix: %v", err)
	}
	if got, err := resolveSession(home, "ce9b49bb-bbbb"); err != nil || got != "ce9b49bb-bbbb" {
		t.Errorf("full id: %q, %v", got, err)
	}
	if got, err := resolveSession(home, "nothing"); err != nil || got != "nothing" {
		t.Errorf("unknown id is passed on: %q, %v", got, err)
	}
	if _, err := resolveSession(t.TempDir(), "latest"); err == nil {
		t.Error("no sessions: want error")
	}
}

func TestNoteSession(t *testing.T) {
	home := t.TempDir()
	e := event.Event{SessionID: "s1", Cwd: `C:\work\proj`, Title: "🔴 🟡 Fix the login bug"}
	noteSession(home, e)
	s, err := store.Get(home, "s1")
	if err != nil || s.Cwd != `C:\work\proj` || s.Title != "Fix the login bug" {
		t.Fatalf("saved %+v, %v", s, err)
	}
	// Unchanged: no write.
	p := filepath.Join(home, "sessions", "s1.json")
	old := time.Now().Add(-time.Hour)
	os.Chtimes(p, old, old)
	noteSession(home, e)
	if fi, _ := os.Stat(p); !fi.ModTime().Equal(old) {
		t.Error("unchanged session was written again")
	}
	// An event without a title keeps the saved one.
	noteSession(home, event.Event{SessionID: "s1", Cwd: `C:\work\other`})
	if s, _ := store.Get(home, "s1"); s.Title != "Fix the login bug" || s.Cwd != `C:\work\other` {
		t.Errorf("after a move: %+v", s)
	}
}

func TestSessionsAndStatusNameTheSession(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PROVGUARD_HOME", home)
	proj := t.TempDir()
	saveSession(t, home, "78d5c84e-aaaa", proj, "New project features", true, time.Now())
	saveSession(t, home, "0000aaaa-bbbb", "", "", false, time.Now().Add(-time.Hour))

	var out bytes.Buffer
	if code := runSessions(nil, &out); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"🟡 78d5c84e", "“New project features” in " + proj, "🟢 0000aaaa", "(no title or folder recorded yet)", "provguard explain 78d5c84e"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("sessions output misses %q:\n%s", want, out.String())
		}
	}

	out.Reset()
	runStatus([]string{"--session", "78d5", "--plain"}, strings.NewReader(""), &out)
	if s := out.String(); !strings.Contains(s, "UNTRUSTED") || !strings.Contains(s, "session 78d5c84e “New project features” in "+proj) {
		t.Errorf("status output:\n%s", s)
	}
}
