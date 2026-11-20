package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Paths with characters that a shell would expand or split.
var oddPaths = []string{
	"/home/u/.provguard/bin/provguard",
	"/home/a b/.provguard/bin/provguard",
	"/home/u$HOME/bin/provguard",
	"/home/u`id`/bin/provguard",
	`/home/u"x/bin/provguard`,
	"/home/o'neil/bin/provguard",
	"/home/a'b'c/bin/provguard'",
	"C:/Users/Jürgen (x86)/bin/provguard.exe",
	"C:/Users/a&b;c/bin/provguard.exe",
}

func TestQuoteRoundTrip(t *testing.T) {
	for _, p := range oddPaths {
		for _, cmd := range []string{QuotePOSIX(p) + " hook X", QuotePowerShell(p) + " hook X"} {
			if got := filepath.ToSlash(CommandProgram(cmd)); got != p {
				t.Errorf("%s: program %q, want %q", cmd, got, p)
			}
		}
	}
	// Commands written by older versions.
	if got := filepath.ToSlash(CommandProgram(`"/a b/provguard" hook X`)); got != "/a b/provguard" {
		t.Errorf("old form: %q", got)
	}
	if got := QuotePowerShell("C:/Users/u/.provguard/bin/provguard.exe"); got != "C:/Users/u/.provguard/bin/provguard.exe" {
		t.Errorf("plain path quoted: %q", got)
	}
}

// The quoted command runs the right program in a real shell, with nothing
// in the path expanded.
func TestQuotedCommandRuns(t *testing.T) {
	name := "pg $HOME `x` \"q\" o'neil !"
	if runtime.GOOS == "windows" {
		name = "pg $HOME `x` o'neil & (1)" // " is not allowed in Windows names
	}
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skip("file system refuses the name:", err)
	}
	if runtime.GOOS == "windows" {
		exe := filepath.Join(dir, "pg.cmd")
		os.WriteFile(exe, []byte("@echo ran %*\r\n"), 0o755)
		out, err := exec.Command("powershell", "-NoProfile", "-Command", QuotePowerShell(filepath.ToSlash(exe))+" hook X").CombinedOutput()
		if err != nil || !strings.Contains(string(out), "ran hook X") {
			t.Fatalf("PowerShell: %v: %s", err, out)
		}
		return
	}
	exe := filepath.Join(dir, "pg")
	os.WriteFile(exe, []byte("#!/bin/sh\necho ran \"$@\"\n"), 0o755)
	out, err := exec.Command("sh", "-c", Command(exe, "X")).CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "ran hook X" {
		t.Fatalf("sh: %v: %s", err, out)
	}
}
