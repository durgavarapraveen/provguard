package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const exe = `C:\tools\provguard.exe`

var events = []string{"PreToolUse", "PostToolUse", "SessionStart", "UserPromptSubmit"}

func userHook() map[string]any {
	return map[string]any{
		"matcher": "Bash",
		"hooks":   []any{map[string]any{"type": "command", "command": "my-linter"}},
	}
}

func countProvguard(s map[string]any) int {
	n := 0
	hooks, _ := s["hooks"].(map[string]any)
	for _, v := range hooks {
		for _, g := range v.([]any) {
			for _, h := range g.(map[string]any)["hooks"].([]any) {
				if IsProvguard(h.(map[string]any)["command"].(string)) {
					n++
				}
			}
		}
	}
	return n
}

func TestAddIsIdempotentAndKeepsUserHooks(t *testing.T) {
	s := map[string]any{
		"model": "x",
		"hooks": map[string]any{"PreToolUse": []any{userHook()}},
	}
	for i := 0; i < 2; i++ {
		if err := Add(s, exe, events); err != nil {
			t.Fatal(err)
		}
	}
	if got := countProvguard(s); got != len(events) {
		t.Fatalf("want %d provguard hooks, got %d", len(events), got)
	}
	pre := s["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 2 || pre[0].(map[string]any)["matcher"] != "Bash" {
		t.Fatalf("user hook lost or reordered: %v", pre)
	}
	if s["model"] != "x" {
		t.Fatal("unrelated key changed")
	}
}

func TestCommandUsesForwardSlashes(t *testing.T) {
	c := Command(exe, "PreToolUse")
	if strings.Contains(c, `\`) || !IsProvguard(c) {
		t.Fatalf("bad command %q", c)
	}
}

func TestMatcherOnlyOnToolEvents(t *testing.T) {
	s := map[string]any{}
	if err := Add(s, exe, events); err != nil {
		t.Fatal(err)
	}
	h := s["hooks"].(map[string]any)
	if _, ok := h["SessionStart"].([]any)[0].(map[string]any)["matcher"]; ok {
		t.Fatal("SessionStart must not have a matcher")
	}
	if h["PreToolUse"].([]any)[0].(map[string]any)["matcher"] != "*" {
		t.Fatal("PreToolUse needs matcher *")
	}
}

func TestRemoveRestoresOriginal(t *testing.T) {
	s := map[string]any{"hooks": map[string]any{"PreToolUse": []any{userHook()}}}
	_ = Add(s, exe, events)
	if n := Remove(s); n != len(events) {
		t.Fatalf("removed %d", n)
	}
	h := s["hooks"].(map[string]any)
	if len(h) != 1 || len(h["PreToolUse"].([]any)) != 1 {
		t.Fatalf("leftovers after remove: %v", h)
	}
	s2 := map[string]any{}
	_ = Add(s2, exe, events)
	Remove(s2)
	if _, ok := s2["hooks"]; ok {
		t.Fatal("empty hooks key not removed")
	}
}

func TestAddRefusesNonObjectHooks(t *testing.T) {
	if err := Add(map[string]any{"hooks": "bad"}, exe, events); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadSaveBackup(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "settings.json")

	s, err := Load(p)
	if err != nil || len(s) != 0 {
		t.Fatalf("missing file: %v %v", s, err)
	}
	if err := os.WriteFile(p, []byte(`{"model":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ = Load(p)
	_ = Add(s, exe, events)
	backup, err := Save(p, s)
	if err != nil || backup == "" {
		t.Fatalf("save: %q %v", backup, err)
	}
	if b, _ := os.ReadFile(backup); string(b) != `{"model":"x"}` {
		t.Fatalf("bad backup: %s", b)
	}
	s, err = Load(p)
	if err != nil || countProvguard(s) != len(events) {
		t.Fatalf("reload: %v", err)
	}

	if err := os.WriteFile(p, []byte(`{bad`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("invalid JSON must be refused")
	}
}
