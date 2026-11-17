package gemini

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/durgavarapraveen/provguard/internal/adapter/core"
	"github.com/durgavarapraveen/provguard/internal/event"
)

// Payloads follow https://geminicli.com/docs/hooks/reference.
func parse(t *testing.T, raw string) event.Event {
	t.Helper()
	e, err := Adapter{}.Parse([]byte(raw), "")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestParse(t *testing.T) {
	base := `"session_id":"g1","transcript_path":"/t.json","cwd":"/w","timestamp":"2026-11-17T10:00:00Z"`
	e := parse(t, `{`+base+`,"hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"ls","dir_path":"/w"}}`)
	if e.Agent != Agent || e.Kind != event.PreTool || e.ToolName != event.ShellTool || e.SessionID != "g1" {
		t.Errorf("shell: %+v", e)
	}
	e = parse(t, `{`+base+`,"hook_event_name":"AfterTool","tool_name":"read_file","tool_input":{"file_path":"/w/.env"},"tool_response":{"llmContent":"A=1","returnDisplay":"read"}}`)
	if e.Kind != event.PostTool || e.ToolName != "Read" || !strings.Contains(string(e.ToolOutput), "A=1") {
		t.Errorf("read: %+v %s", e, e.ToolOutput)
	}
	e = parse(t, `{`+base+`,"hook_event_name":"BeforeTool","tool_name":"web_fetch","tool_input":{"prompt":"Summarize https://evil.test/a?x=1 please"}}`)
	if e.ToolName != "WebFetch" || e.ToolInput["url"] != "https://evil.test/a?x=1" {
		t.Errorf("web_fetch: %+v", e)
	}
	e = parse(t, `{`+base+`,"hook_event_name":"BeforeTool","tool_name":"mcp_github_create_issue","tool_input":{}}`)
	if e.ToolName != "mcp__github_create_issue" || e.MCPServer != "github_create_issue" {
		t.Errorf("mcp: %+v", e)
	}
	if e := parse(t, `{`+base+`,"hook_event_name":"BeforeAgent","prompt":"hi"}`); e.Kind != event.UserPrompt {
		t.Errorf("BeforeAgent: %+v", e)
	}
}

func TestReplyAndFeedback(t *testing.T) {
	r, _ := Adapter{}.Reply(core.Deny, "no")
	b := r.Stdout
	if string(b) != `{"decision":"deny","reason":"no"}` {
		t.Errorf("reply %s", b)
	}
	if f := (Adapter{}).Feedback(event.Event{Kind: event.PostTool}, "untrusted", "t"); string(f) != `{"systemMessage":"untrusted"}` {
		t.Errorf("feedback %s", f)
	}
}

func TestInstallKeepsSettings(t *testing.T) {
	t.Setenv("GEMINI_CLI_HOME", t.TempDir())
	p, _ := SettingsFile()
	os.MkdirAll(strings.TrimSuffix(p, "settings.json"), 0o700)
	os.WriteFile(p, []byte(`{"theme":"Dracula","hooks":{"AfterAgent":[{"hooks":[{"type":"command","command":"notify"}]}]}}`), 0o600)
	if _, err := Install("/home/u/.provguard/bin/provguard"); err != nil {
		t.Fatal(err)
	}
	var s struct {
		Theme string
		Hooks map[string][]struct {
			Matcher string
			Hooks   []struct {
				Command string
				Timeout int
			}
		}
	}
	b, _ := os.ReadFile(p)
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	bt := s.Hooks["BeforeTool"]
	if s.Theme != "Dracula" || len(s.Hooks["AfterAgent"]) != 1 || len(bt) != 1 || bt[0].Matcher != ".*" ||
		bt[0].Hooks[0].Command != "/home/u/.provguard/bin/provguard hook --agent gemini-cli BeforeTool" || bt[0].Hooks[0].Timeout != 10000 {
		t.Errorf("settings:\n%s", b)
	}
	if removed, err := Uninstall(); !removed || err != nil {
		t.Fatalf("uninstall %v %v", removed, err)
	}
	if b, _ := os.ReadFile(p); strings.Contains(string(b), "provguard") || !strings.Contains(string(b), "notify") {
		t.Errorf("after uninstall:\n%s", b)
	}
}
