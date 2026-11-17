package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeUserPath is an in-memory PATH for tests (installed in TestMain).
func fakeUserPath(dirs map[string]bool) pathOps {
	return pathOps{
		has:    func(d string) bool { return dirs[filepath.Clean(d)] },
		add:    func(d string) (string, error) { dirs[filepath.Clean(d)] = true; return "your user PATH", nil },
		remove: func(d string) error { delete(dirs, filepath.Clean(d)); return nil },
	}
}

func withFakePath(t *testing.T) map[string]bool {
	t.Helper()
	dirs := map[string]bool{}
	old := userPath
	userPath = fakeUserPath(dirs)
	t.Cleanup(func() { userPath = old })
	return dirs
}

func TestPathList(t *testing.T) {
	if pathListHas("/usr/bin:/Opt/pg", "/opt/pg", ":", false) {
		t.Error("unix PATH is case-sensitive")
	}
	if runtime.GOOS != "windows" {
		return // the cases below use Windows paths
	}
	list := `C:\Windows;%USERPROFILE%\bin;;C:\Tools\`
	if !pathListHas(list, `c:\tools`, ";", true) || pathListHas(list, `C:\Tool`, ";", true) {
		t.Error("has")
	}
	if got := pathListAdd(list, `C:\pg\bin`, ";", true); got != `C:\Windows;%USERPROFILE%\bin;;C:\Tools\;C:\pg\bin` {
		t.Errorf("add: %q", got)
	}
	if got := pathListAdd("", `C:\pg\bin`, ";", true); got != `C:\pg\bin` {
		t.Errorf("add to empty: %q", got)
	}
	if got := pathListAdd(list, `c:\tools`, ";", true); got != list {
		t.Errorf("added twice: %q", got)
	}
	if got := pathListRemove(`C:\a;C:\pg\bin;C:\b;C:\PG\bin\`, `C:\pg\bin`, ";", true); got != `C:\a;C:\b` {
		t.Errorf("remove: %q", got)
	}
}

func TestGuidedInitAddsToPath(t *testing.T) {
	dirs := withFakePath(t)
	home := t.TempDir()
	settings := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(filepath.Join(home, "provguard.exe"), []byte("x"), 0o700)
	var out bytes.Buffer
	r := installRun{settings: settings, home: home, exe: filepath.Join(home, "provguard.exe"), copyBinary: true,
		interactive: true, in: strings.NewReader("\n\n\n\n\n"), out: &out, errOut: &out, detectUser: func() string { return "" }}
	if code := r.init(); code != 0 {
		t.Fatalf("code %d: %s", code, out.String())
	}
	bin := filepath.Join(home, "bin")
	if !dirs[filepath.Clean(bin)] || !strings.Contains(out.String(), "Added "+bin) {
		t.Fatalf("not added to PATH:\n%s", out.String())
	}

	// Uninstall --now takes it off again.
	var u bytes.Buffer
	ur := installRun{settings: settings, home: home, write: true, now: true, out: &u, errOut: &u}
	if code := ur.uninstall(); code != 0 {
		t.Fatalf("uninstall %d: %s", code, u.String())
	}
	if dirs[filepath.Clean(bin)] {
		t.Errorf("still on PATH after uninstall:\n%s", u.String())
	}
}

func TestGuidedInitPathDeclined(t *testing.T) {
	dirs := withFakePath(t)
	home := t.TempDir()
	os.WriteFile(filepath.Join(home, "provguard.exe"), []byte("x"), 0o700)
	var out bytes.Buffer
	r := installRun{settings: filepath.Join(t.TempDir(), "s.json"), home: home, exe: filepath.Join(home, "provguard.exe"), copyBinary: true,
		interactive: true, in: strings.NewReader("\n\n\nn\ny\n"), out: &out, errOut: &out, detectUser: func() string { return "" }}
	if code := r.init(); code != 0 {
		t.Fatalf("code %d: %s", code, out.String())
	}
	if len(dirs) != 0 || !strings.Contains(out.String(), "add "+filepath.Join(home, "bin")+" to your PATH") {
		t.Errorf("declined, but: %v\n%s", dirs, out.String())
	}
}
