package devin

import (
	"testing"

	"github.com/durgavarapraveen/provguard/internal/adapter/core"
	"github.com/durgavarapraveen/provguard/internal/event"
)

// Payloads follow https://docs.devin.ai/cli/extensibility/hooks.
func TestDetect(t *testing.T) {
	for raw, want := range map[string]bool{
		`{"hook_event_name":"PreToolUse","tool_name":"exec","tool_input":{"command":"ls"},"session_id":"s","prompt_id":"p"}`: true,
		`{"hook_event_name":"PostToolUse","tool_name":"mcp__gh__x","session_id":"s","prompt_id":"p"}`:                        true,
		`{"hook_event_name":"PreToolUse","tool_name":"webfetch","session_id":"s"}`:                                           true,
		`{"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"s","transcript_path":"/t"}`:                        false,
	} {
		if got := (Adapter{}).Detect([]byte(raw)); got != want {
			t.Errorf("%s: got %v", raw, got)
		}
	}
}

func TestParse(t *testing.T) {
	e, err := Adapter{}.Parse([]byte(`{"hook_event_name":"PreToolUse","tool_name":"exec","tool_input":{"command":"rm -rf /","shell_id":"main"},"session_id":"s1","prompt_id":"p1"}`), "")
	if err != nil || e.Agent != Agent || e.Kind != event.PreTool || e.ToolName != event.ShellTool || e.SessionID != "s1" {
		t.Fatalf("exec: %+v %v", e, err)
	}
	e, _ = Adapter{}.Parse([]byte(`{"hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"patch":"*** Begin Patch\n*** Add File: .claude/settings.json\n+{}\n*** End Patch"},"session_id":"s1","prompt_id":"p1"}`), "")
	if paths, _ := e.ToolInput["path"].([]any); e.ToolName != core.PatchTool || len(paths) != 1 || paths[0] != ".claude/settings.json" {
		t.Errorf("apply_patch: %+v", e)
	}
	b, _ := Adapter{}.Reply(core.Deny, "no")
	if string(b) != `{"decision":"block","reason":"no"}` {
		t.Errorf("reply %s", b)
	}
}
