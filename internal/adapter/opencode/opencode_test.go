package opencode

import (
	"os"
	"strings"
	"testing"

	"github.com/durgavarapraveen/provguard/internal/adapter/core"
	"github.com/durgavarapraveen/provguard/internal/event"
)

// Payloads are what the plugin sends (see pluginSource).
func TestParse(t *testing.T) {
	cases := []struct {
		raw, tool, path string
	}{
		{`{"hook_event_name":"PreToolUse","cwd":"/w","session_id":"o1","tool_name":"bash","tool_input":{"command":"ls"}}`, event.ShellTool, ""},
		{`{"hook_event_name":"PreToolUse","cwd":"/w","session_id":"o1","tool_name":"read","tool_input":{"filePath":"/w/.env"}}`, "Read", "/w/.env"},
		{`{"hook_event_name":"PreToolUse","cwd":"/w","session_id":"o1","tool_name":"edit","tool_input":{"filePath":"/w/a.go","oldString":"a","newString":"b"}}`, "Edit", "/w/a.go"},
		{`{"hook_event_name":"PreToolUse","cwd":"/w","session_id":"o1","tool_name":"webfetch","tool_input":{"url":"https://x.test"}}`, "WebFetch", ""},
	}
	for _, c := range cases {
		e, err := Adapter{}.Parse([]byte(c.raw), "")
		if err != nil || e.Agent != Agent || e.Kind != event.PreTool || e.SessionID != "o1" || e.ToolName != c.tool {
			t.Errorf("%s: %+v %v", c.raw, e, err)
		}
		if c.path != "" && e.ToolInput["file_path"] != c.path {
			t.Errorf("%s: file_path %v", c.raw, e.ToolInput)
		}
	}
	e, _ := Adapter{}.Parse([]byte(`{"hook_event_name":"PreToolUse","session_id":"o1","tool_name":"edit","tool_input":{"filePath":"/w/a.go","oldString":"a","newString":"b"}}`), "")
	if e.ToolInput["old_string"] != "a" || e.ToolInput["new_string"] != "b" {
		t.Errorf("edit keys: %v", e.ToolInput)
	}
}

// The plugin throws when provguard exits non-zero, with stderr as the reason.
func TestReplyBlocksByExitCode(t *testing.T) {
	r, err := Adapter{}.Reply(core.Deny, "no")
	if err != nil || r.ExitCode == 0 || r.Stderr != "no\n" || len(r.Stdout) != 0 {
		t.Errorf("reply %+v %v", r, err)
	}
}

func TestInstallAndUninstall(t *testing.T) {
	t.Setenv("PROVGUARD_OPENCODE_HOME", t.TempDir())
	exe := `C:\Users\a b\.provguard\bin\provguard.exe`
	p, err := Install(exe)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	s := string(b)
	for _, want := range []string{
		`const PROVGUARD = "C:\\Users\\a b\\.provguard\\bin\\provguard.exe"`,
		`"--agent", "opencode"`, `id: "provguard"`, `"tool.execute.before"`, `ctx.tool.hook("execute.before"`, "throw new Error",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("plugin lacks %q", want)
		}
	}
	if strings.Contains(s, "\t") || strings.Contains(s, "%!") {
		t.Errorf("plugin formatting: %s", s)
	}
	if removed, err := Uninstall(); !removed || err != nil {
		t.Errorf("uninstall %v %v", removed, err)
	}
	if removed, _ := Uninstall(); removed {
		t.Error("second uninstall reported a removal")
	}
}
