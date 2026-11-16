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

// A program named through folder variables is now a known program, so the
// self-protection checks by name must catch it.
func TestKnownProgramPathStillProtected(t *testing.T) {
	for cmd, tool := range map[string]string{
		`& "$env:USERPROFILE\.provguard\bin\provguard.exe" uninstall --yes`: "PowerShell",
		`& "$env:TEMP\provguard.exe" config mode audit`:                     "PowerShell",
		`"$HOME/.provguard/bin/provguard" allow 0123456789`:                 "Bash",
	} {
		mustDeny(t, cmd, Check(preIn(tool, t.TempDir(), map[string]any{"command": cmd}), "/home/u/.provguard", nil))
	}
}

// Review findings 8 and 9: settings changed through an argument feeder, or
// from a script that quotes the setting.
func TestConfigChangeBypasses(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home", ".provguard")
	os.WriteFile(filepath.Join(dir, "a.sh"), []byte("provguard config 'mode' audit\n"), 0o700)
	os.WriteFile(filepath.Join(dir, "b.sh"), []byte(`provguard "allow" 0123456789`+"\n"), 0o700)
	for _, cmd := range []string{
		"echo mode audit | xargs provguard config",
		`find . -name x -exec provguard config {} \;`,
		"parallel provguard config ::: mode",
		"sh a.sh",
		"sh b.sh",
	} {
		mustDeny(t, cmd, Check(preIn("Bash", dir, map[string]any{"command": cmd}), home, nil))
	}
	if v := Check(preIn("Bash", dir, map[string]any{"command": "provguard config"}), home, nil); v.Deny {
		t.Errorf("reading the settings denied: %s", v.Reason)
	}
}
