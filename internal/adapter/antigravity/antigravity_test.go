package antigravity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/durgavarapraveen/provguard/internal/adapter/core"
	"github.com/durgavarapraveen/provguard/internal/event"
	"github.com/durgavarapraveen/provguard/internal/install"
)

// Payloads follow https://antigravity.google/docs/hooks.
func TestParse(t *testing.T) {
	cases := []struct {
		raw, tool, key, want string
	}{
		{`{"conversationId":"a1","workspacePaths":["/w"],"toolCall":{"name":"run_command","args":{"CommandLine":"ls","Cwd":"/w/sub"}}}`, event.ShellTool, "command", "ls"},
		{`{"conversationId":"a1","workspacePaths":["/w"],"toolCall":{"name":"view_file","args":{"AbsolutePath":"/w/.env"}}}`, "Read", "file_path", "/w/.env"},
		{`{"conversationId":"a1","workspacePaths":["/w"],"toolCall":{"name":"write_to_file","args":{"TargetFile":"/w/a.go","CodeContent":"x"}}}`, "Write", "content", "x"},
		{`{"conversationId":"a1","workspacePaths":["/w"],"toolCall":{"name":"replace_file_content","args":{"TargetFile":"/w/a.go","TargetContent":"a","ReplacementContent":"b"}}}`, "Edit", "new_string", "b"},
		{`{"conversationId":"a1","workspacePaths":["/w"],"toolCall":{"name":"read_url_content","args":{"Url":"https://x.test"}}}`, "WebFetch", "url", "https://x.test"},
	}
	for _, c := range cases {
		e, err := Adapter{}.Parse([]byte(c.raw), "PreToolUse")
		if err != nil || e.Agent != Agent || e.Kind != event.PreTool || e.SessionID != "a1" || e.ToolName != c.tool || e.ToolInput[c.key] != c.want {
			t.Errorf("%s: %+v %v", c.raw, e, err)
		}
	}
	e, _ := Adapter{}.Parse([]byte(`{"conversationId":"a1","workspacePaths":["/w"],"toolCall":{"name":"run_command","args":{"CommandLine":"ls","Cwd":"/w/sub"}}}`), "PreToolUse")
	if e.Cwd != "/w/sub" {
		t.Errorf("cwd %q", e.Cwd)
	}
	e, _ = Adapter{}.Parse([]byte(`{"conversationId":"a1","toolCall":{"name":"multi_replace_file_content","args":{"TargetFile":"/w/a.go","ReplacementChunks":[{"TargetContent":"a","ReplacementContent":"b"}]}}}`), "PreToolUse")
	if e.ToolName != "MultiEdit" || len(e.ToolInput["edits"].([]any)) != 1 {
		t.Errorf("multi edit %+v", e)
	}
	e, _ = Adapter{}.Parse([]byte(`{"conversationId":"a1","toolCall":null}`), "PostToolUse")
	if e.Kind != event.Other {
		t.Errorf("non-tool step: %+v", e)
	}
	e, _ = Adapter{}.Parse([]byte(`{"conversationId":"a1","lastUserInput":"hi"}`), "PreInvocation")
	if e.Kind != event.UserPrompt || e.Prompt != "hi" {
		t.Errorf("prompt: %+v", e)
	}
}

func TestReply(t *testing.T) {
	for d, want := range map[core.Decision]string{core.Deny: `"decision":"deny"`, core.Ask: `"decision":"force_ask"`} {
		r, err := Adapter{}.Reply(d, "why")
		if err != nil || r.ExitCode != 0 || !strings.Contains(string(r.Stdout), want) || !strings.Contains(string(r.Stdout), `"reason":"why"`) {
			t.Errorf("%s: %+v %v", d, r, err)
		}
	}
}

func TestInstallKeepsOtherHooks(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PROVGUARD_ANTIGRAVITY_HOME", dir)
	p := filepath.Join(dir, "config", "hooks.json")
	os.MkdirAll(filepath.Dir(p), 0o700)
	os.WriteFile(p, []byte(`{"my-linter":{"PostToolUse":[{"matcher":"run_command","hooks":[{"command":"lint.sh"}]}]}}`), 0o600)
	if _, err := Install("/home/u/.provguard/bin/provguard"); err != nil {
		t.Fatal(err)
	}
	s, _ := install.Load(p)
	if _, ok := s["my-linter"]; !ok {
		t.Error("other hook removed")
	}
	def, _ := s[HookName].(map[string]any)
	pre, _ := def["PreToolUse"].([]any)
	if def["enabled"] != true || len(pre) != 1 || pre[0].(map[string]any)["matcher"] != "*" {
		t.Errorf("provguard entry %v", def)
	}
	start, _ := def["SessionStart"].([]any)
	if len(start) != 1 || !strings.HasSuffix(start[0].(map[string]any)["command"].(string), "hook --agent antigravity SessionStart") {
		t.Errorf("SessionStart %v", start)
	}
	if removed, err := Uninstall(); !removed || err != nil {
		t.Errorf("uninstall %v %v", removed, err)
	}
	s, _ = install.Load(p)
	if _, ok := s[HookName]; ok || s["my-linter"] == nil {
		t.Errorf("after uninstall %v", s)
	}
}
