package kiro

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/durgavarapraveen/provguard/internal/adapter/core"
	"github.com/durgavarapraveen/provguard/internal/event"
)

// Payloads follow https://kiro.dev/docs/hooks/types.
func TestParse(t *testing.T) {
	cases := []struct {
		raw, tool string
	}{
		{`{"hook_event_name":"PreToolUse","cwd":"/w","session_id":"k1","tool_name":"shell","tool_input":{"command":"ls"}}`, event.ShellTool},
		{`{"hook_event_name":"PreToolUse","cwd":"/w","session_id":"k1","tool_name":"read_file","tool_input":{"path":"/w/.env"}}`, "Read"},
		{`{"hook_event_name":"PreToolUse","cwd":"/w","session_id":"k1","tool_name":"mcp_postgres_query","tool_input":{"sql":"x"}}`, "mcp__postgres_query"},
	}
	for _, c := range cases {
		e, err := Adapter{}.Parse([]byte(c.raw), "")
		if err != nil || e.Agent != Agent || e.Kind != event.PreTool || e.SessionID != "k1" || e.ToolName != c.tool {
			t.Errorf("%s: %+v %v", c.raw, e, err)
		}
	}
	e, _ := Adapter{}.Parse([]byte(`{"hook_event_name":"PreToolUse","session_id":"k1","tool_name":"write","tool_input":{"path":"/w/a.go","file_text":"x"}}`), "")
	if e.ToolInput["file_path"] != "/w/a.go" || e.ToolInput["content"] != "x" {
		t.Errorf("write aliases: %v", e.ToolInput)
	}
}

// Kiro blocks only on a non-zero exit, reading the reason from stderr.
func TestReplyBlocksByExitCode(t *testing.T) {
	r, err := Adapter{}.Reply(core.Deny, "no")
	if err != nil || r.ExitCode == 0 || r.Stderr != "no\n" || len(r.Stdout) != 0 {
		t.Errorf("reply %+v %v", r, err)
	}
}

func TestInstallAndUninstall(t *testing.T) {
	t.Setenv("PROVGUARD_KIRO_HOME", t.TempDir())
	p, err := Install("/home/u/.provguard/bin/provguard")
	if err != nil {
		t.Fatal(err)
	}
	var f hookFile
	b, _ := os.ReadFile(p)
	if err := json.Unmarshal(b, &f); err != nil || f.Version != "v1" || len(f.Hooks) != len(Events) {
		t.Fatalf("hook file %s", b)
	}
	if h := f.Hooks[0]; h.Trigger != "PreToolUse" || !h.Enabled || h.Action.Type != "command" ||
		!strings.HasSuffix(h.Action.Command, "hook --agent kiro PreToolUse") {
		t.Errorf("hook %+v", h)
	}
	if removed, err := Uninstall(); !removed || err != nil {
		t.Errorf("uninstall %v %v", removed, err)
	}
}
