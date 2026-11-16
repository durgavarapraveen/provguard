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

func ps(cmd string) event.Event { return pre("PowerShell", map[string]any{"command": cmd}) }

func TestShell(t *testing.T) {
	cases := []struct {
		cmd  string
		deny bool
	}{
		// attacks: direct writes
		{`echo '{"disableAllHooks": true}' > .claude/settings.json`, true},
		{`echo '{}' >> ~/.claude/settings.local.json`, true},
		{`printf '{"disableAllHooks":true}' | tee .claude/settings.local.json`, true},
		{`cd .claude && echo {} > settings.json`, true},
		{`sed -i 's/provguard//' ~/.claude/settings.json`, true},
		{`cp /tmp/x ~/.claude/settings.json`, true},
		{`mv ~/.claude/settings.json /tmp/bak`, true},
		{`rm ~/.claude/settings.json`, true},
		{`rm -rf ~/.claude`, true},
		{`rm -rf ~/.provguard`, true},
		{`cat x > ~/.provguard/key`, true},
		{`find ~/.provguard -delete`, true},
		{`touch "$HOME/.claude/settings.json"`, true},
		// attacks: indirection the old regex missed
		{`F=~/.claude/settings.json; echo '{}' > "$F"`, true},
		{`D=.claude; echo '{}' > "$D/settings.json"`, true},
		{`echo '{}' > "$(echo .claude)/settings.json"`, true},
		{`bash -c 'echo {} > ~/.claude/settings.json'`, true},
		{`sudo -u me tee ~/.claude/settings.json < x`, true},
		{`env A=1 timeout 5 cp x ~/.claude/settings.json`, true},
		{"bash <<'EOF'\necho {} > ~/.claude/settings.json\nEOF", true},
		{`python -c "import json;json.dump({'disableAllHooks':True},open('x','w'))"`, true},
		{`eval "echo {} > ~/.claude/settings.json"`, true},
		{`"C:/tools/provguard.exe" uninstall --yes`, true},
		{`provguard init --yes`, true},
		{`x=$(cat p.txt); echo hi > "$x" # .claude/settings.json`, true},
		// allowed: reads and mentions
		{`cat ~/.claude/settings.json`, false},
		{`cat ~/.claude/settings.json | jq .hooks`, false},
		{`bash -c "cat ~/.claude/settings.json"`, false},
		{`tail -n 5 ~/.provguard/audit/2026-11-16.jsonl 2>&1`, false},
		{`ls ~/.provguard/sessions > /dev/null`, false},
		{`grep -c disableAllHooks docs/FINDINGS.md`, false},
		{`go test ./...`, false},
		{`echo hello > out.txt`, false},
		{`echo "run provguard init to install"`, false},
		// regression: false positive seen live on 2026-11-16
		{`git commit -q -m "protect: deny changes to hooks/disableAllHooks in .claude/settings*.json"`, false},
		{`git log --grep disableAllHooks`, false},
	}
	for _, c := range cases {
		v := Check(sh(c.cmd), "", nil)
		if v.Deny != c.deny {
			t.Errorf("deny=%v want %v: %s (rule %s: %s)", v.Deny, c.deny, c.cmd, v.Rule, v.Reason)
		}
	}
}

func TestPowerShell(t *testing.T) {
	cases := []struct {
		cmd  string
		deny bool
	}{
		{`Set-Content -Path $HOME\.claude\settings.json -Value '{}'`, true},
		{`'{}' | Out-File "$env:USERPROFILE\.claude\settings.local.json"`, true},
		{`sc .claude\settings.json '{"disableAllHooks":true}'`, true},
		{`Remove-Item -Recurse $env:USERPROFILE\.provguard`, true},
		{`Copy-Item x.json -Destination C:\Users\u\.claude\settings.json`, true},
		{`Move-Item C:\Users\u\.claude\settings.json C:\tmp\x.json`, true},
		{`Set-Location .claude; '{}' > settings.json`, true},
		{`[IO.File]::WriteAllText("$HOME\.claude\settings.json", "{}")`, true},
		{`iex "Set-Content .claude/settings.json '{}'"`, true},
		{`powershell -EncodedCommand ZQBjAGgAbwA= # .provguard`, true},
		{`Get-Content $HOME\.claude\settings.json | ConvertFrom-Json`, false},
		{`Get-ChildItem $HOME\.provguard\audit | Select-Object -Last 1`, false},
		{`git commit -m "disableAllHooks in .claude/settings.json"`, false},
		{`Write-Output "provguard uninstall"`, false},
	}
	for _, c := range cases {
		v := Check(ps(c.cmd), "", nil)
		if v.Deny != c.deny {
			t.Errorf("deny=%v want %v: %s (rule %s: %s)", v.Deny, c.deny, c.cmd, v.Rule, v.Reason)
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
		if v := Check(c.e, "", nil); v.Deny != c.deny {
			t.Errorf("%s: deny=%v want %v", c.name, v.Deny, c.deny)
		}
	}
}

func TestProvguardHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), "pghome")
	if !Check(pre("Write", map[string]any{"file_path": filepath.Join(home, "config.json"), "content": "{}"}), home, nil).Deny {
		t.Fatal("write to config.json allowed")
	}
	if Check(pre("Write", map[string]any{"file_path": filepath.Join(home+"x", "a"), "content": ""}), home, nil).Deny {
		t.Fatal("sibling dir with same prefix blocked")
	}
	if Check(pre("Read", map[string]any{"file_path": filepath.Join(home, "key")}), home, nil).Deny {
		t.Fatal("read must not be blocked by self-protection")
	}
	if !Check(sh("rm -rf "+filepath.ToSlash(home)), home, nil).Deny {
		t.Fatal("shell delete of custom PROVGUARD_HOME allowed")
	}
}
