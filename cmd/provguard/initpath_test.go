package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A downloaded binary is on nobody's PATH, and `init --yes` is how the
// install script and the README install provguard, so --yes puts it there.
func TestInitYesAddsToPath(t *testing.T) {
	dirs := withFakePath(t)
	home := t.TempDir()
	var out bytes.Buffer
	r := installRun{
		settings: filepath.Join(t.TempDir(), "settings.json"),
		home:     home, exe: fakeExe(t), write: true, copyBinary: true,
		out: &out, errOut: &out, in: strings.NewReader(""),
		detectUser: func() string { return "" },
	}
	if code := r.init(); code != 0 {
		t.Fatalf("install: exit %d\n%s", code, out.String())
	}
	bin := filepath.Join(home, "bin")
	if !dirs[filepath.Clean(bin)] {
		t.Errorf("%s was not added to PATH; output:\n%s", bin, out.String())
	}
	if !strings.Contains(out.String(), "new terminal") {
		t.Errorf("no hint to open a new terminal:\n%s", out.String())
	}
}

func TestInitNoPathLeavesPathAlone(t *testing.T) {
	dirs := withFakePath(t)
	home := t.TempDir()
	var out bytes.Buffer
	r := installRun{
		settings: filepath.Join(t.TempDir(), "settings.json"),
		home:     home, exe: fakeExe(t), write: true, copyBinary: true, noPath: true,
		out: &out, errOut: &out, in: strings.NewReader(""),
		detectUser: func() string { return "" },
	}
	if code := r.init(); code != 0 {
		t.Fatalf("install: exit %d\n%s", code, out.String())
	}
	if dirs[filepath.Clean(filepath.Join(home, "bin"))] {
		t.Error("--no-path still changed PATH")
	}
	if !strings.Contains(out.String(), "add "+filepath.Join(home, "bin")) {
		t.Errorf("no note saying how to do it by hand:\n%s", out.String())
	}
}

// Found live: the folder was already on the saved PATH from an earlier
// init, so init said nothing, and `provguard` kept failing in the terminal
// the user already had open.
func TestPathNoteWhenShellIsStale(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "bin")
	dirs := withFakePath(t)
	dirs[filepath.Clean(bin)] = true // saved PATH has it
	r := installRun{home: home, copyBinary: true}

	// This process does not: a terminal opened before the change.
	t.Setenv("PATH", filepath.Join(t.TempDir(), "elsewhere"))
	note := r.pathNote(false)
	if !strings.Contains(note, "new terminal") {
		t.Errorf("stale shell: note = %q", note)
	}

	// This process does: nothing to say.
	t.Setenv("PATH", bin+string(os.PathListSeparator)+filepath.Join(t.TempDir(), "elsewhere"))
	if note := r.pathNote(false); note != "" {
		t.Errorf("current shell already has it: note = %q", note)
	}

	// Hooks run from where the binary is: PATH is not provguard's business.
	r.copyBinary = false
	if note := r.pathNote(true); note != "" {
		t.Errorf("--no-copy: note = %q", note)
	}
}

// fakeExe is a file standing in for the provguard binary, so init can copy
// it into <home>/bin.
func fakeExe(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "provguard.exe")
	if err := os.WriteFile(p, []byte("not a real binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}
