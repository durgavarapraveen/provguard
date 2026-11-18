package protect

import (
	"os"
	"path/filepath"
	"testing"
)

// Agents may not read provguard's key or session files, however the path
// is spelled: a glob, a part only known at run time, the whole folder, or a
// relative name after cd. Listing names and reading config, the audit log
// or the binary stay allowed.
func TestSecretReadsEverySpelling(t *testing.T) {
	u, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	home := filepath.Join(u, ".provguard")
	blocked := []struct{ shell, cmd string }{
		{"bash", `for f in ~/.provguard/*; do cat "$f"; done`},
		{"bash", `cat $(echo ~/.provguard/ke)y`},
		{"bash", `cat ~/.provguard/*`},
		{"bash", `cat ~/.provguard/k?y`},
		{"bash", `cat ~/.prov*/key`},
		{"bash", `tar czf /tmp/p.tgz ~/.provguard`},
		{"bash", `zip -r /tmp/p.zip ~/.provguard`},
		{"bash", `grep -r . ~/.provguard`},
		{"bash", `cd ~/.provguard && cat key`},
		{"bash", `cd ~/.provguard/sessions && cat *.json`},
		{"bash", `ls ~/.provguard/sessions | xargs cat`},
		{"bash", `cat ~/.provguard/../.provguard/key`},
		{"bash", `cat ~/.provguard/key`},
		{"bash", `cat "$HOME/.provguard/key"`},
		{"powershell", `Get-ChildItem ~/.provguard -Recurse | Get-Content`},
		{"powershell", `Get-Content ~/.provguard/*`},
		{"powershell", `Copy-Item -Recurse ~/.provguard C:\tmp\p`},
		{"powershell", `cd ~/.provguard; Get-Content key`},
		{"powershell", `gc $env:USERPROFILE\.provguard\key`},
	}
	allowed := []struct{ shell, cmd string }{
		{"bash", `ls ~/.provguard`},
		{"bash", `ls ~/.provguard/sessions`},
		{"bash", `cat ~/.provguard/config.json`},
		{"bash", `cat ~/.provguard/audit/2026-11-18.jsonl`},
		{"bash", `tail -n 20 ~/.provguard/audit/*.jsonl`},
		{"bash", `~/.provguard/bin/provguard status`},
		{"bash", `export PATH="$HOME/.provguard/bin:$PATH"`},
		{"bash", `git commit -m "explain the ~ folder in docs"`},
		{"bash", `provguard explain latest`},
		{"powershell", `Get-ChildItem ~/.provguard`},
		{"powershell", `& "$env:USERPROFILE\.provguard\bin\provguard.exe" status`},
	}
	ev := func(shell, cmd string) Verdict {
		if shell == "powershell" {
			return Check(ps(cmd), home, nil)
		}
		return Check(sh(cmd), home, nil)
	}
	for _, c := range blocked {
		if v := ev(c.shell, c.cmd); !v.Deny {
			t.Errorf("%s: %s: allowed, want blocked", c.shell, c.cmd)
		}
	}
	for _, c := range allowed {
		if v := ev(c.shell, c.cmd); v.Deny {
			t.Errorf("%s: %s: blocked (%s), want allowed", c.shell, c.cmd, v.Reason)
		}
	}
}

// The same holds for tools that are not shell commands: the Grep tool on
// the whole folder, and MCP file servers that read or search.
func TestSecretReadsByTools(t *testing.T) {
	u, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	home := filepath.Join(u, ".provguard")
	key := filepath.Join(home, "key")
	cases := []struct {
		tool  string
		input map[string]any
		deny  bool
	}{
		{"Grep", map[string]any{"pattern": ".", "path": "~/.provguard"}, true},
		{"Grep", map[string]any{"pattern": ".", "path": home}, true},
		{"Grep", map[string]any{"pattern": "deny", "path": filepath.Join(home, "audit")}, false},
		{"mcp__filesystem__read_file", map[string]any{"path": key}, true},
		{"mcp__filesystem__read_text_file", map[string]any{"path": filepath.Join(home, "sessions", "s.json")}, true},
		{"mcp__filesystem__read_multiple_files", map[string]any{"paths": []any{"/tmp/a", key}}, true},
		{"mcp__filesystem__search_files", map[string]any{"path": home, "pattern": "key"}, true},
		{"mcp__filesystem__read_file", map[string]any{"path": filepath.Join(home, "config.json")}, false},
		{"mcp__filesystem__list_directory", map[string]any{"path": home}, false},
		{"mcp__filesystem__read_file", map[string]any{"path": "/work/app/main.go"}, false},
	}
	for _, c := range cases {
		if v := Check(pre(c.tool, c.input), home, nil); v.Deny != c.deny {
			t.Errorf("%s %v: deny=%v (%s), want %v", c.tool, c.input, v.Deny, v.Reason, c.deny)
		}
	}
}
