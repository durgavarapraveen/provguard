package claudecode

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"provguard/internal/event"
)

func load(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "claudecode", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseFixtures(t *testing.T) {
	cases := []struct {
		file string
		kind event.Kind
		tool string
		key  string // a tool_input key that must be present
	}{
		{"pre_bash.json", event.PreTool, "Bash", "command"},
		{"post_read.json", event.PostTool, "Read", "file_path"},
		{"pre_webfetch.json", event.PreTool, "WebFetch", "url"},
		{"pre_mcp.json", event.PreTool, "mcp__github__get_issue", "issue_number"},
		{"session_start.json", event.SessionBeg, "", ""},
		{"user_prompt.json", event.UserPrompt, "", ""},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			e, err := Parse(load(t, c.file), "")
			if err != nil {
				t.Fatal(err)
			}
			if e.Kind != c.kind || e.ToolName != c.tool || e.SessionID == "" {
				t.Fatalf("got kind=%s tool=%q session=%q", e.Kind, e.ToolName, e.SessionID)
			}
			if c.key != "" {
				if _, ok := e.ToolInput[c.key]; !ok {
					t.Fatalf("tool_input missing %q", c.key)
				}
			}
		})
	}
}

// Real payloads recorded from Claude Code 2.1.238 on Windows, then sanitized.
func TestParseRealFixtures(t *testing.T) {
	cases := []struct {
		file, tool, key       string
		kind                  event.Kind
		subagent, mcp, output bool
	}{
		{"real/pre_bash.json", "Bash", "command", event.PreTool, false, false, false},
		{"real/post_powershell.json", "PowerShell", "command", event.PostTool, false, false, true},
		{"real/post_edit.json", "Edit", "old_string", event.PostTool, false, false, true},
		{"real/post_webfetch_subagent.json", "WebFetch", "url", event.PostTool, true, false, true},
		{"real/post_mcp.json", "mcp__ccd_turn__update_plan", "", event.PostTool, false, true, true},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			e, err := Parse(load(t, c.file), "")
			if err != nil {
				t.Fatal(err)
			}
			if e.Kind != c.kind || e.ToolName != c.tool || e.SessionID == "" || e.ToolUseID == "" {
				t.Fatalf("got %+v", e)
			}
			if c.key != "" {
				if _, ok := e.ToolInput[c.key]; !ok {
					t.Fatalf("tool_input missing %q", c.key)
				}
			}
			if (e.AgentID != "") != c.subagent || (e.MCPServer != "") != c.mcp || (len(e.ToolOutput) > 0) != c.output {
				t.Fatalf("agent=%q mcp=%q output=%d", e.AgentID, e.MCPServer, len(e.ToolOutput))
			}
		})
	}
}

func TestParsePostHasOutput(t *testing.T) {
	e, err := Parse(load(t, "post_read.json"), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(e.ToolOutput) == 0 || e.ToolUseID == "" {
		t.Fatal("post event lost tool_response or tool_use_id")
	}
}

func TestParseEventFallback(t *testing.T) {
	e, err := Parse([]byte(`{"session_id":"s"}`), "PreToolUse")
	if err != nil {
		t.Fatal(err)
	}
	if e.Kind != event.PreTool {
		t.Fatalf("fallback event not used: %s", e.Kind)
	}
}

func TestParseStripsBOM(t *testing.T) {
	raw := append([]byte("\xef\xbb\xbf"), load(t, "pre_bash.json")...)
	e, err := Parse(raw, "")
	if err != nil || e.ToolName != "Bash" {
		t.Fatalf("BOM input failed: %v", err)
	}
}

func TestParseBadJSON(t *testing.T) {
	if _, err := Parse([]byte("not json"), "PreToolUse"); err == nil {
		t.Fatal("expected error")
	}
}

func TestPreToolResponseShape(t *testing.T) {
	b, err := PreToolResponse(Deny, "test")
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		H struct {
			Name     string `json:"hookEventName"`
			Decision string `json:"permissionDecision"`
			Reason   string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.H.Name != "PreToolUse" || out.H.Decision != "deny" || out.H.Reason != "test" {
		t.Fatalf("bad response: %s", b)
	}
}
