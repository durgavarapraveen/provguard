package cursor

import (
	"encoding/json"
	"testing"

	"github.com/durgavarapraveen/provguard/internal/event"
)

// Payloads follow the examples in https://cursor.com/docs/agent/hooks.
const common = `"conversation_id":"conv-1","generation_id":"gen-1","model":"m","cursor_version":"2.4.0","workspace_roots":["/work/app"],"user_email":null,"transcript_path":null`

func TestDetect(t *testing.T) {
	if !isCursor([]byte(`{` + common + `}`)) {
		t.Error("cursor payload not recognized")
	}
	if isCursor([]byte(`{"session_id":"s","hook_event_name":"PreToolUse"}`)) {
		t.Error("claude code payload taken for cursor")
	}
}

func TestParsePreToolUseShell(t *testing.T) {
	raw := `{` + common + `,"hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":"npm install","working_directory":"/project"},"tool_use_id":"abc123","cwd":"/project"}`
	e, err := parse([]byte(raw), "PreToolUse")
	if err != nil {
		t.Fatal(err)
	}
	if e.Agent != Agent || e.Kind != event.PreTool || e.RawEvent != "PreToolUse" ||
		e.SessionID != "conv-1" || e.ToolName != event.ShellTool || e.Cwd != "/project" || e.ToolInput["command"] != "npm install" {
		t.Errorf("event %+v", e)
	}
}

func TestParsePostToolUseOutput(t *testing.T) {
	raw := `{` + common + `,"hook_event_name":"postToolUse","tool_name":"Shell","tool_input":{"command":"npm test"},"tool_output":"{\"exitCode\":0,\"stdout\":\"All tests passed\"}","tool_use_id":"abc123","duration":5432}`
	e, err := parse([]byte(raw), "")
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ Stdout string }
	if e.Kind != event.PostTool || e.Cwd != "/work/app" || json.Unmarshal(e.ToolOutput, &out) != nil || out.Stdout != "All tests passed" {
		t.Errorf("event %+v output %s", e, e.ToolOutput)
	}
}

func TestParseOtherEvents(t *testing.T) {
	cases := []struct {
		raw  string
		kind event.Kind
	}{
		{`{` + common + `,"hook_event_name":"beforeSubmitPrompt","prompt":"hi"}`, event.UserPrompt},
		{`{` + common + `,"hook_event_name":"sessionStart","session_id":"sess-9"}`, event.SessionBeg},
		{`{` + common + `,"hook_event_name":"afterAgentThought","text":"x"}`, event.Other},
	}
	for _, c := range cases {
		e, err := parse([]byte(c.raw), "")
		if err != nil || e.Kind != c.kind {
			t.Errorf("%s: kind %v err %v", c.raw, e.Kind, err)
		}
	}
	if e, _ := parse([]byte(cases[1].raw), ""); e.SessionID != "sess-9" {
		t.Errorf("sessionStart id: %q", e.SessionID)
	}
}

func TestParseToolNamesAndInputs(t *testing.T) {
	raw := `{` + common + `,"hook_event_name":"preToolUse","tool_name":"MCP:create_issue","tool_input":{"title":"x"}}`
	e, _ := parse([]byte(raw), "")
	if e.ToolName != "mcp__cursor__create_issue" || e.MCPServer != "cursor-mcp" {
		t.Errorf("mcp: %+v", e)
	}
	raw = `{` + common + `,"hook_event_name":"preToolUse","tool_name":"Write","tool_input":{"target_file":"/work/app/a.go","contents":"package a"}}`
	e, _ = parse([]byte(raw), "")
	if e.ToolInput["file_path"] != "/work/app/a.go" || e.ToolInput["content"] != "package a" || e.ToolInput["target_file"] == nil {
		t.Errorf("aliases: %v", e.ToolInput)
	}
}
