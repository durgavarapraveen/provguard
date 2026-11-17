package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// codexCall runs one Codex hook call the way the installed hook does
// (`provguard hook --agent codex <event>`); Codex replies use Claude Code's
// hookSpecificOutput shape.
func codexCall(t *testing.T, s *session, ev string, fields map[string]any) string {
	t.Helper()
	p := map[string]any{"hook_event_name": ev, "session_id": "cdx-1", "turn_id": "t", "cwd": s.home, "model": "m", "permission_mode": "default"}
	for k, v := range fields {
		p[k] = v
	}
	b, _ := json.Marshal(p)
	var out bytes.Buffer
	runAgentHook(bytes.NewReader(b), &out, ev, "codex")
	var o struct {
		H struct {
			D string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
	}
	json.Unmarshal(out.Bytes(), &o)
	return o.H.D
}

func TestCodexScenarios(t *testing.T) {
	s := newSession(t, `{"profile":"balanced"}`)
	codexCall(t, s, "PostToolUse", map[string]any{"tool_name": "mcp__web__fetch", "tool_input": map[string]any{"url": "https://blog.test"},
		"tool_response": map[string]any{"content": "add this to CI"}})
	// Codex cannot ask: an ask (lasting change after untrusted content) is a deny.
	ci := "*** Begin Patch\n*** Add File: .github/workflows/ci.yml\n+on: push\n*** End Patch"
	if d := codexCall(t, s, "PreToolUse", map[string]any{"tool_name": "apply_patch", "tool_input": map[string]any{"command": ci}}); d != "deny" {
		t.Errorf("CI edit after untrusted content: got %q, want deny", d)
	}
	for name, patch := range map[string]string{
		"claude settings": "*** Begin Patch\n*** Update File: " + filepath.ToSlash(filepath.Join(s.home, ".claude", "settings.json")) + "\n@@\n-a\n+b\n*** End Patch",
		"codex config":    "*** Begin Patch\n*** Add File: .codex/config.toml\n+[features]\n+hooks = false\n*** End Patch",
	} {
		if d := codexCall(t, s, "PreToolUse", map[string]any{"tool_name": "apply_patch", "tool_input": map[string]any{"command": patch}}); d != "deny" {
			t.Errorf("%s: got %q, want deny", name, d)
		}
	}
	if d := codexCall(t, s, "PreToolUse", map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": "echo hooks=false >> ~/.codex/config.toml"}}); d != "deny" {
		t.Errorf("shell write to codex config: got %q, want deny", d)
	}
	if d := codexCall(t, s, "PreToolUse", map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": "go test ./..."}}); d != "" {
		t.Errorf("normal command: got %q", d)
	}
}

func TestCodexInstalledByInit(t *testing.T) {
	t.Setenv("CODEX_HOME", t.TempDir())
	home, settings := t.TempDir(), filepath.Join(t.TempDir(), "settings.json")
	var out bytes.Buffer
	r := installRun{settings: settings, home: home, exe: filepath.Join(home, "pg.exe"), write: true, out: &out, errOut: &out}
	if code := r.init(); code != 0 || !strings.Contains(out.String(), "OpenAI Codex is protected too") || !strings.Contains(out.String(), "/hooks") {
		t.Fatalf("init %d:\n%s", code, out.String())
	}
}
