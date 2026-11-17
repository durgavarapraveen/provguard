//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShellStartLines(t *testing.T) {
	home := t.TempDir()
	rc := filepath.Join(home, ".zshrc")
	os.WriteFile(rc, []byte("alias ll='ls -l'"), 0o644) // no final newline
	dir := "/home/u/.provguard/bin"

	for i := 0; i < 2; i++ { // twice: the line is added once
		if f, err := addStartLine(home, "/bin/zsh", dir); err != nil || f != rc {
			t.Fatalf("add: %s %v", f, err)
		}
	}
	b, _ := os.ReadFile(rc)
	if strings.Count(string(b), pathTag) != 1 || !strings.HasPrefix(string(b), "alias ll='ls -l'\nexport PATH='/home/u/.provguard/bin':\"$PATH\"") {
		t.Fatalf("zshrc:\n%s", b)
	}

	fish, _ := addStartLine(home, "/usr/bin/fish", dir)
	if err := removeStartLines(home, "/bin/zsh", dir); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(rc); string(b) != "alias ll='ls -l'\n" {
		t.Errorf("zshrc after remove: %q", b)
	}
	if _, err := os.Stat(fish); !os.IsNotExist(err) {
		t.Error("fish file left behind")
	}
}
