package protect

import (
	"os"
	"path/filepath"
	"testing"
)

// `bash -n` only checks a script's syntax, so a script that mentions
// provguard's files may be checked; running it is still denied.
func TestSyntaxCheckOfProtectedScript(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home", ".provguard")
	os.WriteFile(filepath.Join(dir, "install.sh"), []byte("#!/bin/sh\ncp provguard ~/.provguard/bin/\n"), 0o700)

	for cmd, deny := range map[string]bool{
		"sh -n install.sh":                false,
		"bash -n install.sh && echo ok":   false,
		"sh install.sh":                   true,
		"sh -n install.sh; sh install.sh": true,
		"bash -n +n install.sh":           true,
		"bash -e install.sh":              true, // was a bypass: -e read as inline code
		"bash +x install.sh":              true,
		"sh -n -c 'rm -rf ~/.provguard'":  true, // inline code is not a syntax check of a file
	} {
		v := Check(preIn("Bash", dir, map[string]any{"command": cmd}), home, nil)
		if v.Deny != deny {
			t.Errorf("%s: deny=%v, want %v (%s)", cmd, v.Deny, deny, v.Reason)
		}
	}
}
