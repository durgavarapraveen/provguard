package droid

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/durgavarapraveen/provguard/internal/adapter/core"
	"github.com/durgavarapraveen/provguard/internal/event"
)

// Payloads follow https://docs.factory.com/harness/hooks.
func TestParse(t *testing.T) {
	cases := []struct {
		raw, tool string
	}{
		{`{"hook_event_name":"PreToolUse","cwd":"/w","session_id":"d1","tool_name":"Execute","tool_input":{"command":"ls"}}`, event.ShellTool},
		{`{"hook_event_name":"PreToolUse","cwd":"/w","session_id":"d1","tool_name":"Create","tool_input":{"file_path":"/w/a.go","content":"x"}}`, "Write"},
		{`{"hook_event_name":"PreToolUse","cwd":"/w","session_id":"d1","tool_name":"FetchUrl","tool_input":{"url":"https://x.test"}}`, "WebFetch"},
		{`{"hook_event_name":"PreToolUse","cwd":"/w","session_id":"d1","tool_name":"Read","tool_input":{"file_path":"/w/.env"}}`, "Read"},
	}
	for _, c := range cases {
		e, err := Adapter{}.Parse([]byte(c.raw), "")
		if err != nil || e.Agent != Agent || e.Kind != event.PreTool || e.SessionID != "d1" || e.ToolName != c.tool {
			t.Errorf("%s: %+v %v", c.raw, e, err)
		}
	}
	patch := "*** Begin Patch\n*** Update File: /w/a.go\n@@\n-x\n+y\n*** End Patch"
	raw, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "d1", "tool_name": "ApplyPatch", "tool_input": map[string]any{"input": patch}})
	e, _ := Adapter{}.Parse(raw, "")
	if e.ToolName != core.PatchTool || !strings.Contains(core.PatchFiles(patch)[0], "a.go") {
		t.Errorf("patch: %+v", e)
	}
}

func TestReplyDeny(t *testing.T) {
	r, err := Adapter{}.Reply(core.Deny, "no")
	if err != nil || !strings.Contains(string(r.Stdout), `"permissionDecision":"deny"`) {
		t.Errorf("reply %+v %v", r, err)
	}
	if (Adapter{}).CanAsk() {
		t.Error("Droid's ask does not prompt; CanAsk must be false")
	}
}

func TestInstallKeepsOtherHooks(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PROVGUARD_FACTORY_HOME", dir)
	p := filepath.Join(dir, "hooks.json")
	other := `{"PreToolUse":[{"matcher":"Execute","hooks":[{"type":"command","command":"lint.sh"}]}]}`
	if err := os.WriteFile(p, []byte(other), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install("/home/u/.provguard/bin/provguard"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	s := string(b)
	if !strings.Contains(s, "lint.sh") || !strings.Contains(s, "hook --agent factory-droid PreToolUse") || strings.Contains(s, `"hooks":{`) {
		t.Errorf("hooks.json %s", s)
	}
	if removed, err := Uninstall(); !removed || err != nil {
		t.Errorf("uninstall %v %v", removed, err)
	}
	b, _ = os.ReadFile(p)
	if strings.Contains(string(b), "provguard") || !strings.Contains(string(b), "lint.sh") {
		t.Errorf("after uninstall %s", b)
	}
}
