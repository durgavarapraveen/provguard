package copilot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/durgavarapraveen/provguard/internal/adapter/core"
	"github.com/durgavarapraveen/provguard/internal/event"
)

// Payloads follow the "VS Code compatible" examples in
// https://docs.github.com/en/copilot/reference/hooks-reference.
func TestParsePreToolUse(t *testing.T) {
	raw := `{"hook_event_name":"PreToolUse","session_id":"s1","timestamp":"2026-11-17T10:00:00Z","cwd":"/work/app","tool_name":"Bash","tool_input":{"command":"npm test"}}`
	e, err := Adapter{}.Parse([]byte(raw), "PreToolUse")
	if err != nil {
		t.Fatal(err)
	}
	if e.Agent != Agent || e.Kind != event.PreTool || e.SessionID != "s1" || e.Cwd != "/work/app" ||
		e.ToolName != event.ShellTool || e.ToolInput["command"] != "npm test" {
		t.Errorf("event %+v", e)
	}
}

func TestParsePostToolUseResult(t *testing.T) {
	raw := `{"hook_event_name":"PostToolUse","session_id":"s1","timestamp":"t","cwd":"/w","tool_name":"WebFetch","tool_input":{"url":"https://x.test"},"tool_result":{"result_type":"success","text_result_for_llm":"page text"}}`
	e, err := Adapter{}.Parse([]byte(raw), "")
	if err != nil {
		t.Fatal(err)
	}
	var s string
	if e.Kind != event.PostTool || e.ToolName != "WebFetch" || json.Unmarshal(e.ToolOutput, &s) != nil || s != "page text" {
		t.Errorf("event %+v output %s", e, e.ToolOutput)
	}
}

func TestReply(t *testing.T) {
	r, _ := Adapter{}.Reply(core.Deny, "no")
	b := r.Stdout
	if string(b) != `{"permissionDecision":"deny","permissionDecisionReason":"no"}` {
		t.Errorf("reply %s", b)
	}
}

func TestInstallAndUninstall(t *testing.T) {
	t.Setenv("COPILOT_HOME", t.TempDir())
	p, err := Install(`C:\Users\me\.provguard\bin\provguard.exe`, 10)
	if err != nil {
		t.Fatal(err)
	}
	var f hookFile
	b, _ := os.ReadFile(p)
	if err := json.Unmarshal(b, &f); err != nil || f.Version != 1 || len(f.Hooks) != len(Events) {
		t.Fatalf("hook file %s", b)
	}
	h := f.Hooks["PreToolUse"][0]
	if h.Bash != `"C:/Users/me/.provguard/bin/provguard.exe" hook --agent copilot PreToolUse` ||
		h.PowerShell != `C:/Users/me/.provguard/bin/provguard.exe hook --agent copilot PreToolUse` || h.TimeoutSec != 10 {
		t.Errorf("entry %+v", h)
	}
	if filepath.Base(p) != FileName {
		t.Errorf("path %s", p)
	}
	if removed, err := Uninstall(); !removed || err != nil {
		t.Errorf("uninstall: %v %v", removed, err)
	}
	if removed, _ := Uninstall(); removed {
		t.Error("removed twice")
	}
}
