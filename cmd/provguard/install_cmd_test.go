package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/install"
)

// guided runs the interactive init with the given answers, one per line.
func guided(t *testing.T, home, settings, answers string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	r := installRun{
		settings: settings, home: home, exe: filepath.Join(home, "provguard.exe"),
		interactive: true, in: strings.NewReader(answers), out: &out, errOut: &out,
		detectUser: func() string { return "octo-user" },
	}
	return r.init(), out.String()
}

func hooksInstalled(t *testing.T, settings string) bool {
	t.Helper()
	s, err := install.Load(settings)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(install.HooksJSON(s), "provguard")
}

func TestGuidedInitDefaults(t *testing.T) {
	home := t.TempDir()
	settings := filepath.Join(t.TempDir(), "settings.json")
	// Enter on every question: detected owner, Protect, Ask, install.
	code, out := guided(t, home, settings, "\n\n\n\n")
	if code != 0 {
		t.Fatalf("code %d: %s", code, out)
	}
	c, err := config.Load(home)
	if err != nil {
		t.Fatal(err)
	}
	if c.ProfileName() != config.Balanced || !c.BlockAsks() || !c.RepoOwnerTrusted("octo-user") {
		t.Errorf("config %+v", c)
	}
	if !hooksInstalled(t, settings) {
		t.Error("hooks not installed")
	}
	for _, want := range []string{"provguard is on", "provguard status", "provguard uninstall --yes",
		"🟡 untrusted", "🟠 sensitive", "🔴 both", "session titles get the icon", "provguard explain latest"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary misses %q:\n%s", want, out)
		}
	}
}

func TestGuidedInitChoicesAndRetry(t *testing.T) {
	home := t.TempDir()
	settings := filepath.Join(t.TempDir(), "settings.json")
	// Bad owner, then two owners; a wrong number, then Lockdown; package
	// check on; install.
	code, out := guided(t, home, settings, "not/valid\nme, @my-org\n9\n3\ny\ny\n")
	if code != 0 {
		t.Fatalf("code %d: %s", code, out)
	}
	c, _ := config.Load(home)
	if c.ProfileName() != config.Strict || !c.RepoOwnerTrusted("me") || !c.RepoOwnerTrusted("my-org") || c.BlockAsks() || !c.PackageCheck {
		t.Errorf("config %+v", c)
	}
	if !strings.Contains(out, "not a GitHub name") || !strings.Contains(out, "number from 1 to 3") {
		t.Errorf("no retry message:\n%s", out)
	}
	s, _ := install.Load(settings)
	if !strings.Contains(install.HooksJSON(s), `"onFailure": "block"`) {
		t.Error("strict mode did not fail closed")
	}
}

// init --yes (no terminal) also explains the trust states: most agents and
// the Claude desktop app show no notice when a session's state changes.
func TestInitYesExplainsTrustStates(t *testing.T) {
	home := t.TempDir()
	settings := filepath.Join(t.TempDir(), "settings.json")
	var out bytes.Buffer
	r := installRun{settings: settings, home: home, exe: filepath.Join(home, "pg.exe"), write: true, out: &out, errOut: &out}
	if code := r.init(); code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	for _, want := range []string{"🟡 untrusted", "🟠 sensitive", "🔴 both", "provguard explain latest"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output misses %q:\n%s", want, out.String())
		}
	}
}

func TestGuidedInitDeclineChangesNothing(t *testing.T) {
	home := t.TempDir()
	settings := filepath.Join(t.TempDir(), "settings.json")
	// Owner, Watch only, Enter on the agent question (all), then decline.
	code, out := guided(t, home, settings, "none\n2\n\n\nn\n")
	if code != 0 || !strings.Contains(out, "Nothing changed") {
		t.Fatalf("code %d: %s", code, out)
	}
	if _, err := os.Stat(config.Path(home)); !os.IsNotExist(err) {
		t.Error("config written after decline")
	}
	if _, err := os.Stat(settings); !os.IsNotExist(err) {
		t.Error("settings written after decline")
	}
}

// Choosing only other agents leaves Claude Code's settings alone.
func TestGuidedInitWithoutClaudeCode(t *testing.T) {
	home := t.TempDir()
	settings := filepath.Join(t.TempDir(), "settings.json")
	agentHome := t.TempDir()
	t.Setenv("PROVGUARD_OPENCODE_HOME", agentHome)
	n := 0
	for i, a := range otherAgents {
		if a.name == "OpenCode" {
			n = i + 2 // Claude Code is 1
		}
	}
	// Owner, Watch only, a wrong answer, then OpenCode only; install.
	code, out := guided(t, home, settings, "none\n2\n\n0\n"+strconv.Itoa(n)+"\ny\n")
	if code != 0 || !strings.Contains(out, "Please type all") || !strings.Contains(out, "OpenCode is protected") {
		t.Fatalf("code %d: %s", code, out)
	}
	if _, err := os.Stat(settings); !os.IsNotExist(err) {
		t.Error("Claude Code settings written although not chosen")
	}
	if _, err := os.Stat(filepath.Join(agentHome, "plugins", "provguard.js")); err != nil {
		t.Error("OpenCode plugin not written:", err)
	}
}

func TestGuidedInitKeepsExistingSettings(t *testing.T) {
	home := t.TempDir()
	settings := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(config.Path(home), []byte(`{"profile":"audit","trusted_repo_owners":["me"],"extra":1}`), 0o600)
	// No owner question; Enter keeps Watch only; install.
	code, out := guided(t, home, settings, "\n\n")
	if code != 0 {
		t.Fatalf("code %d: %s", code, out)
	}
	if strings.Contains(out, "Which GitHub users") {
		t.Error("asked for owners although they are set")
	}
	c, _ := config.Load(home)
	if c.ProfileName() != config.Audit || len(c.TrustedRepoOwners) != 1 {
		t.Errorf("config changed: %+v", c)
	}
	if b, _ := os.ReadFile(config.Path(home)); !strings.Contains(string(b), `"extra"`) {
		t.Error("unknown key dropped")
	}
}

func TestGuidedInitClosedInputTakesDefaults(t *testing.T) {
	home := t.TempDir()
	settings := filepath.Join(t.TempDir(), "settings.json")
	if code, out := guided(t, home, settings, ""); code != 0 || !hooksInstalled(t, settings) {
		t.Fatalf("code %d: %s", code, out)
	}
}

func TestInitWithoutTerminalOnlyPreviews(t *testing.T) {
	home := t.TempDir()
	settings := filepath.Join(t.TempDir(), "settings.json")
	var out bytes.Buffer
	r := installRun{settings: settings, home: home, exe: "pg", in: strings.NewReader(""), out: &out, errOut: &out}
	if code := r.init(); code != 0 {
		t.Fatalf("code %d", code)
	}
	if _, err := os.Stat(settings); !os.IsNotExist(err) {
		t.Error("preview wrote settings")
	}
	if !strings.Contains(out.String(), "No change written") {
		t.Error(out.String())
	}
}
