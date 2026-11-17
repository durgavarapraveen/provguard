package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/durgavarapraveen/provguard/internal/adapter/claudecode"
	"github.com/durgavarapraveen/provguard/internal/install"
)

// liveSetup installs provguard's hooks for every agent into temporary
// folders and runs hook commands in-process. It returns the Claude Code
// settings path and the provguard home.
func liveSetup(t *testing.T) (settings, home string) {
	t.Helper()
	root := t.TempDir()
	dir := func(name string) string {
		d := filepath.Join(root, name)
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		return d
	}
	t.Setenv("COPILOT_HOME", dir("copilot"))
	t.Setenv("CODEX_HOME", dir("codex"))
	t.Setenv("GEMINI_CLI_HOME", filepath.Dir(dir("gemini-home/.gemini")))
	os.WriteFile(filepath.Join(root, "gemini-home", ".gemini", "installation_id"), []byte("x"), 0o600)
	t.Setenv("PROVGUARD_KIRO_HOME", dir("kiro"))
	t.Setenv("PROVGUARD_FACTORY_HOME", dir("factory"))
	t.Setenv("PROVGUARD_OPENCODE_HOME", dir("opencode"))
	t.Setenv("PROVGUARD_ANTIGRAVITY_HOME", filepath.Dir(dir("agy/antigravity")))

	home = dir("provguard")
	bin := filepath.Join(dir("provguard/bin"), "provguard"+exeSuffix())
	if err := os.WriteFile(bin, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	settings = filepath.Join(dir("claude"), "settings.json")
	s := map[string]any{}
	if err := install.Add(s, bin, claudecode.Events); err != nil {
		t.Fatal(err)
	}
	if _, err := install.Save(settings, s); err != nil {
		t.Fatal(err)
	}
	for _, a := range otherAgents {
		if !a.present() {
			t.Fatalf("%s: not present in the test setup", a.name)
		}
		if _, err := a.install(bin); err != nil {
			t.Fatalf("%s: %v", a.name, err)
		}
	}

	old := runHookCommand
	t.Cleanup(func() { runHookCommand = old })
	runHookCommand = func(_ string, args []string, tmpHome string, stdin []byte) ([]byte, int, error) {
		agent, ev := "", args[len(args)-1]
		if len(args) == 4 { // hook --agent NAME EVENT
			agent = args[2]
		}
		was, had := os.LookupEnv("PROVGUARD_HOME")
		os.Setenv("PROVGUARD_HOME", tmpHome)
		defer func() {
			if had {
				os.Setenv("PROVGUARD_HOME", was)
			} else {
				os.Unsetenv("PROVGUARD_HOME")
			}
		}()
		var out bytes.Buffer
		code := runHookIO(bytes.NewReader(stdin), &out, io.Discard, ev, agent)
		return out.Bytes(), code, nil
	}
	return settings, home
}

func TestDoctorLiveBlocksInEveryAgent(t *testing.T) {
	settings, home := liveSetup(t)
	var out bytes.Buffer
	if code := runDoctorLive(&out, settings, home); code != 0 || strings.Contains(out.String(), "✘") {
		t.Fatalf("exit %d:\n%s", code, out.String())
	}
	for _, name := range []string{"Claude Code", "Cursor", "Devin"} {
		if !strings.Contains(out.String(), "✔ "+name) {
			t.Errorf("no line for %s:\n%s", name, out.String())
		}
	}
	for _, a := range otherAgents {
		if !strings.Contains(out.String(), "✔ "+a.name) {
			t.Errorf("no line for %s:\n%s", a.name, out.String())
		}
	}
	if !strings.Contains(out.String(), "/hooks") {
		t.Error("Codex's trust step is not shown")
	}
}

func TestDoctorLiveReportsProblems(t *testing.T) {
	settings, home := liveSetup(t)
	// A hook that lets everything through.
	runHookCommand = func(string, []string, string, []byte) ([]byte, int, error) { return []byte("{}"), 0, nil }
	var out bytes.Buffer
	if code := runDoctorLive(&out, settings, home); code != 1 || !strings.Contains(out.String(), "without a block") {
		t.Errorf("exit %d:\n%s", code, out.String())
	}

	// A missing hook file.
	settings, home = liveSetup(t)
	p, _ := otherAgents[0].hookFile()
	os.Remove(p)
	out.Reset()
	if code := runDoctorLive(&out, settings, home); code != 1 || !strings.Contains(out.String(), "not installed") {
		t.Errorf("exit %d:\n%s", code, out.String())
	}
}
