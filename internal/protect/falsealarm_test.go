package protect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// B5: a grep pattern is text. "a\|b\*\*c" was read as the path a/|b/*/*c,
// whose * segments matched .provguard/key as a glob.
func TestSearchPatternIsNotAPath(t *testing.T) {
	home := "/home/u/.provguard"
	for _, cmd := range []string{
		`grep -n "20 attack cases\|| audit | 4 | 0 | 16\|| strict | \*\*20\*\*\|3b | With" README.md`,
		`grep -E '\*\*/\*\*' docs/x.md`,
		`rg -n 'a\|b\*\*c' src`,
		`grep -A 3 -- '\*\*/key' notes.md`,
	} {
		if v := Check(preIn("Bash", "/work/proj", map[string]any{"command": cmd}), home, nil); v.Deny {
			t.Errorf("%s: denied (%s)", cmd, v.Reason)
		}
	}
	// Files are still checked, wherever they stand.
	for name, cmd := range map[string]string{
		"file after pattern":   `grep x ~/.provguard/key`,
		"after -E":             `grep -E x ~/.provguard/key`,
		"after -A value":       `grep -A 3 x ~/.provguard/sessions/s.json`,
		"-e then file":         `grep -e x ~/.provguard/key`,
		"pattern file":         `grep -f ~/.provguard/key notes.md`,
		"pattern file, joined": `grep -rf ~/.provguard/key .`,
		"rg file":              `rg -n x ~/.provguard/key`,
		"glob file":            `grep x ~/.prov*/k*`,
	} {
		mustDeny(t, name, Check(preIn("Bash", "/work/proj", map[string]any{"command": cmd}), home, nil))
	}
}

// B6: a shell script that only writes text naming provguard commands to
// files (a Homebrew formula's caveats) runs.
func TestScriptHeredocDataRuns(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home", ".provguard")
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write("packaging.sh", "#!/usr/bin/env sh\nset -eu\nmkdir -p out\n"+
		"cat > out/provguard.rb <<RB\n  def caveats\n    \"Run: provguard init\"\n  end\nRB\n"+
		"cat > \"out/$id.yaml\" <<YAML\nDescription: Run provguard init after you install it.\nYAML\n"+
		"echo \"wrote out/provguard.rb\"\n")
	if v := Check(preIn("Bash", dir, map[string]any{"command": "sh packaging.sh 0.5.2"}), home, nil); v.Deny {
		t.Errorf("packaging script denied: %s", v.Reason)
	}

	for name, body := range map[string]string{
		"runs it":            "#!/bin/sh\nprovguard uninstall --yes\n",
		"writes then runs":   "#!/bin/sh\ncat > b.sh <<EOF\nprovguard uninstall --yes\nEOF\nsh ./b.sh\n",
		"heredoc to a shell": "#!/bin/sh\nsh <<EOF\nprovguard uninstall --yes\nEOF\n",
		"substitution":       "#!/bin/sh\ncat > out.txt <<EOF\n$(provguard uninstall --yes)\nEOF\n",
		"heredoc to key":     "#!/bin/sh\ncat > ~/.provguard/key <<EOF\nx\nEOF\n",
		"no extension":       "#!/bin/bash\nrm -rf ~/.provguard\n",
	} {
		file := "s-" + strings.ReplaceAll(name, " ", "-")
		if name == "no extension" {
			file = "tool"
		} else {
			file += ".sh"
		}
		write(file, body)
		mustDeny(t, name, Check(preIn("Bash", dir, map[string]any{"command": "bash " + file}), home, nil))
	}
}
