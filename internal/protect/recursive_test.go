package protect

import (
	"os"
	"path/filepath"
	"testing"
)

// A recursive read of a folder that holds provguard's folder reads the key,
// so it is blocked unless it leaves .provguard out. Reads of other folders,
// and listings of names, stay allowed.
func TestRecursiveReadOfHome(t *testing.T) {
	u := filepath.ToSlash(filepath.Join(t.TempDir(), "u"))
	home := u + "/.provguard"
	proj := u + "/proj"
	os.MkdirAll(home, 0o700)
	os.MkdirAll(proj, 0o700)

	for _, tc := range []struct {
		tool, cwd, cmd string
		deny           bool
	}{
		{"Bash", proj, "grep -r AKIA " + u, true},
		{"Bash", proj, "grep -rn AKIA " + u + "/", true},
		{"Bash", u, "grep -r AKIA .", true},
		{"Bash", proj, "cd " + u + " && grep -R x .", true},
		{"Bash", proj, "tar czf out.tgz " + u, true},
		{"Bash", proj, "cp -a " + u + " /backup", true},
		{"Bash", proj, "rsync -avz " + u + "/ /backup", true},
		{"Bash", proj, "zip -r out.zip " + u, true},
		{"Bash", proj, "find " + u + " -type f | xargs cat", true},
		{"Bash", proj, "find " + u + " -type f -exec grep -l AKIA {} +", true},
		{"Bash", proj, "rg --hidden AKIA " + u, true},
		{"PowerShell", proj, "Get-ChildItem " + u + " -Recurse | Select-String AKIA", true},
		{"PowerShell", proj, "Copy-Item " + u + " D:/bk -Recurse", true},
		{"PowerShell", proj, "Compress-Archive " + u + " out.zip", true},

		{"Bash", proj, "grep -r --exclude-dir=.provguard AKIA " + u, false},
		{"Bash", proj, "tar czf out.tgz --exclude=.provguard " + u, false},
		{"Bash", proj, "rsync -a --exclude .provguard " + u + "/ /backup", false},
		{"Bash", proj, "rg AKIA " + u, false}, // ripgrep skips hidden folders
		{"Bash", proj, "grep -r AKIA .", false},
		{"Bash", proj, "grep -r AKIA " + proj, false},
		{"Bash", proj, "grep AKIA " + u + "/notes.txt", false},
		{"Bash", proj, "find " + u + " -name '*.env'", false},
		{"Bash", proj, "cp -r src /tmp/x", false},
		{"PowerShell", proj, "Get-ChildItem " + u + " -Recurse -Filter *.env", false},
	} {
		v := Check(preIn(tc.tool, tc.cwd, map[string]any{"command": tc.cmd}), home, nil)
		if v.Deny != tc.deny {
			t.Errorf("%s (cwd %s): deny=%v, want %v (%s)", tc.cmd, tc.cwd, v.Deny, tc.deny, v.Reason)
		}
	}
}

// The word after an rsync option such as --exclude is that option's value,
// not a file to copy; real destinations are still checked.
func TestRsyncOptionValues(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "u", ".provguard")
	claude := filepath.ToSlash(filepath.Join(dir, "u", ".claude"))
	for cmd, deny := range map[string]bool{
		"rsync -a --exclude .provguard src/ /backup":                       false,
		"rsync -a --exclude-from list.txt --filter '- *.tmp' src/ /backup": false,
		"rsync -a --exclude .git src/ " + claude + "/":                     true,
		"rsync -a --exclude x " + filepath.ToSlash(home) + "/ /tmp/k":      true,
	} {
		v := Check(preIn("Bash", dir, map[string]any{"command": cmd}), home, nil)
		if v.Deny != deny {
			t.Errorf("%s: deny=%v, want %v (%s)", cmd, v.Deny, deny, v.Reason)
		}
	}
}
