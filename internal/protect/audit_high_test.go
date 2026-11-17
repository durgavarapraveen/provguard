package protect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Code provguard cannot read must not grant itself a blocked call.
func TestAuditAllowOnceVerb(t *testing.T) {
	for name, cmd := range map[string]string{
		"python -c": `python3 -c "import os; os.system('provguard allow 0123456789')"`,
		"eval":      `eval "provguard allow 0123456789"`,
		"direct":    `provguard allow 0123456789`,
	} {
		mustDeny(t, name, Check(preIn("Bash", "/work/proj", map[string]any{"command": cmd}), "/home/u/.provguard", nil))
	}
}

// A script file that refers to protected things is blocked, however it is
// spelled and however much filler comes first.
func TestAuditScriptScan(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home", ".provguard")
	pad := strings.Repeat("# filler\n", 200000) // ~1.8 MiB, past one window

	scripts := map[string]string{
		"glob.sh":     "#!/bin/sh\nrm -rf ~/.prov*\n",
		"padded.sh":   pad + "rm -rf ~/.provguard\n",
		"allow.sh":    "provguard allow 0123456789\n",
		"settings.sh": "echo '{}' > ~/.claude/sett*\n",
	}
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
		mustDeny(t, name, Check(preIn("Bash", dir, map[string]any{"command": "bash " + name}), home, nil))
	}

	// A script split so the reference crosses a window boundary.
	split := strings.Repeat("x", scriptWindow-5) + "rm -rf ~/.provguard\n"
	os.WriteFile(filepath.Join(dir, "split.sh"), []byte(split), 0o700)
	mustDeny(t, "split.sh", Check(preIn("Bash", dir, map[string]any{"command": "bash split.sh"}), home, nil))

	// An ordinary script still runs.
	os.WriteFile(filepath.Join(dir, "ok.sh"), []byte("#!/bin/sh\ngo test ./...\n"), 0o700)
	if Check(preIn("Bash", dir, map[string]any{"command": "bash ok.sh"}), home, nil).Deny {
		t.Error("ordinary script denied")
	}
}

// Copying the binary out of any folder, to run it under another name, is
// blocked.
func TestAuditCopyBinary(t *testing.T) {
	for name, cmd := range map[string]string{
		"which":     "cp $(which provguard) /tmp/pg",
		"go bin":    "cp ~/go/bin/provguard /tmp/pg",
		"protected": "cp ~/.provguard/bin/provguard /tmp/pg",
		"move":      "mv /usr/local/bin/provguard /tmp/pg",
		"backticks": "cp `which provguard` /tmp/pg",
	} {
		mustDeny(t, name, Check(preIn("Bash", "/work/proj", map[string]any{"command": cmd}), "/home/u/.provguard", nil))
	}
	// Windows paths only parse in the PowerShell dialect.
	mustDeny(t, "windows", Check(preIn("PowerShell", `C:\work\proj`,
		map[string]any{"command": `copy C:\Users\u\go\bin\provguard.exe C:\tmp\pg.exe`}), `C:\Users\u\.provguard`, nil))
	// Working on provguard's own source stays allowed.
	for _, cmd := range []string{
		"cp cmd/provguard/main.go /tmp/x.go",
		"cp internal/policy/policy.go /tmp/p.go",
	} {
		if v := Check(preIn("Bash", "/work/proj", map[string]any{"command": cmd}), "/home/u/.provguard", nil); v.Deny {
			t.Errorf("%q denied (%s)", cmd, v.Rule)
		}
	}
}
