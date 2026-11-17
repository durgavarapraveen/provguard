package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/durgavarapraveen/provguard/internal/install"
)

// installed makes a provguard home with hooks in a temp settings file, the
// way `provguard init --yes` leaves them.
func installed(t *testing.T) (home, settings string) {
	t.Helper()
	home = filepath.Join(t.TempDir(), ".provguard")
	settings = filepath.Join(t.TempDir(), "settings.json")
	t.Setenv("PROVGUARD_HOME", home)
	os.MkdirAll(filepath.Join(home, "bin"), 0o700)
	s := map[string]any{"theme": "dark"}
	if err := install.Add(s, filepath.Join(home, "bin", "provguard.exe"), []string{"PreToolUse", "PostToolUse", "SessionStart", "UserPromptSubmit"}); err != nil {
		t.Fatal(err)
	}
	if _, err := install.Save(settings, s); err != nil {
		t.Fatal(err)
	}
	return home, settings
}

func hookCommands(t *testing.T, settings string) string {
	t.Helper()
	s, err := install.Load(settings)
	if err != nil {
		t.Fatal(err)
	}
	return install.HooksJSON(s)
}

func uninstallRun(home, settings string, now, keep bool) (int, string) {
	var out bytes.Buffer
	r := installRun{settings: settings, home: home, write: true, now: now, keepData: keep, out: &out, errOut: &out}
	return r.uninstall(), out.String()
}

// prompt sends a UserPromptSubmit to the cleanup hook and returns the new
// title it answered with ("" for none).
func cleanupPrompt(t *testing.T, home, session, title string, at time.Time) string {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"session_id": session, "hook_event_name": "UserPromptSubmit", "session_title": title, "prompt": "hi"})
	var out bytes.Buffer
	runCleanupHook(bytes.NewReader(b), &out, home, at)
	if out.Len() == 0 {
		return ""
	}
	var v struct {
		H struct {
			T string `json:"sessionTitle"`
		} `json:"hookSpecificOutput"`
	}
	json.Unmarshal(out.Bytes(), &v)
	return v.H.T
}

func TestHookRecordsMarkedTitles(t *testing.T) {
	s := newSession(t, `{"profile":"balanced"}`)
	s.run(readEnv)
	s.run(issueView)
	p := map[string]any{"session_id": "ovr", "hook_event_name": "UserPromptSubmit", "session_title": "Fix login", "prompt": "go on"}
	b, _ := json.Marshal(p)
	var out bytes.Buffer
	runHook(bytes.NewReader(b), &out, "")
	if !strings.Contains(out.String(), "🔴 Fix login") {
		t.Fatalf("no icon set: %s", out.String())
	}
	if !isTitled(s.home, "ovr") {
		t.Error("marked session not recorded")
	}
}

func TestUninstallRestoresTitlesThenRemovesItself(t *testing.T) {
	home, settings := installed(t)
	markTitled(home, "s1", true)
	markTitled(home, "s2", true)

	code, out := uninstallRun(home, settings, false, false)
	if code != 0 || !strings.Contains(out, "2 sessions still show a trust icon") {
		t.Fatalf("code %d: %s", code, out)
	}
	h := hookCommands(t, settings)
	if strings.Contains(h, "hook PreToolUse") || !strings.Contains(h, "hook cleanup") {
		t.Fatalf("after uninstall, hooks are:\n%s", h)
	}

	now := time.Now()
	if got := cleanupPrompt(t, home, "s1", "🔴 Fix login", now); got != "Fix login" {
		t.Errorf("s1 title: got %q", got)
	}
	if got := cleanupPrompt(t, home, "other", "🟡 Not ours", now); got != "" {
		t.Errorf("unmarked session retitled to %q", got)
	}
	if _, err := os.Stat(home); err != nil {
		t.Fatal("home removed while a marked session is left")
	}
	if got := cleanupPrompt(t, home, "s2", "🟠 Deploy", now); got != "Deploy" {
		t.Errorf("s2 title: got %q", got)
	}
	if h := hookCommands(t, settings); strings.Contains(h, "provguard") {
		t.Errorf("cleanup hook left behind:\n%s", h)
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Error("provguard folder not removed at the end")
	}
	if s, _ := install.Load(settings); s["theme"] != "dark" {
		t.Error("other settings lost")
	}
}

func TestCleanupEndsAfterWindow(t *testing.T) {
	home, settings := installed(t)
	markTitled(home, "s1", true)
	uninstallRun(home, settings, false, false)
	later := time.Now().Add(cleanupWindow + time.Hour)
	cleanupPrompt(t, home, "unrelated", "", later)
	if h := hookCommands(t, settings); strings.Contains(h, "provguard") {
		t.Errorf("cleanup hook kept after 30 days:\n%s", h)
	}
}

func TestUninstallNowAndKeepData(t *testing.T) {
	home, settings := installed(t)
	markTitled(home, "s1", true)
	if code, out := uninstallRun(home, settings, true, false); code != 0 || !strings.Contains(out, "Removed") {
		t.Fatalf("code %d: %s", code, out)
	}
	if h := hookCommands(t, settings); strings.Contains(h, "provguard") {
		t.Errorf("--now left hooks:\n%s", h)
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Error("--now kept the folder")
	}

	home, settings = installed(t)
	os.WriteFile(filepath.Join(home, "config.json"), []byte(`{}`), 0o600)
	if code, _ := uninstallRun(home, settings, false, true); code != 0 {
		t.Fatal(code)
	}
	if _, err := os.Stat(filepath.Join(home, "config.json")); err != nil {
		t.Error("--keep-data deleted the config")
	}
}

func TestCleanupHookIdleWithoutUninstall(t *testing.T) {
	home := t.TempDir()
	markTitled(home, "s1", true)
	if got := cleanupPrompt(t, home, "s1", "🔴 X", time.Now()); got != "" {
		t.Errorf("cleanup ran without a pending uninstall: %q", got)
	}
	if !isTitled(home, "s1") {
		t.Error("record dropped without a pending uninstall")
	}
}
