package codex

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/durgavarapraveen/provguard/internal/event"
	"github.com/durgavarapraveen/provguard/internal/install"
)

const patch = `*** Begin Patch
*** Update File: src/app.go
@@
-a
+b
*** Add File: .github/workflows/ci.yml
+on: push
*** Delete File: old.txt
*** Update File: a.go
*** Move to: b.go
*** End Patch`

func TestPatchFiles(t *testing.T) {
	want := []string{"src/app.go", ".github/workflows/ci.yml", "old.txt", "a.go", "b.go"}
	if got := PatchFiles(patch); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
}

// Payloads follow https://developers.openai.com/codex/hooks.
func TestParse(t *testing.T) {
	raw := `{"session_id":"s1","turn_id":"t1","transcript_path":null,"cwd":"/w","hook_event_name":"PreToolUse","model":"m","permission_mode":"default","tool_name":"apply_patch","tool_use_id":"u1","tool_input":{"command":` + quote(patch) + `}}`
	e, err := Adapter{}.Parse([]byte(raw), "PreToolUse")
	if err != nil {
		t.Fatal(err)
	}
	paths, _ := e.ToolInput["path"].([]any)
	if e.Agent != Agent || e.Kind != event.PreTool || e.SessionID != "s1" || len(paths) != 5 {
		t.Errorf("event %+v", e)
	}
	raw = `{"session_id":"s1","cwd":"/w","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`
	if e, _ := (Adapter{}).Parse([]byte(raw), ""); e.ToolName != event.ShellTool {
		t.Errorf("Bash → %q", e.ToolName)
	}
}

func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s) + `"`
}

func TestInstallKeepsOtherHooks(t *testing.T) {
	t.Setenv("CODEX_HOME", t.TempDir())
	p, _ := HooksFile()
	os.WriteFile(p, []byte(`{"description":"mine","hooks":{"Stop":[{"hooks":[{"type":"command","command":"say done"}]}]}}`), 0o600)

	if _, err := Install(`C:/Program Files/pg/provguard.exe`); err != nil {
		t.Fatal(err)
	}
	s, _ := install.Load(p)
	h := install.HooksJSON(s)
	for _, want := range []string{"say done", `hook --agent codex PreToolUse`, `& \"C:/Program Files/pg/provguard.exe\"`, `"description"`} {
		if !strings.Contains(h+string(mustRead(t, p)), want) {
			t.Errorf("hooks.json lacks %s:\n%s", want, mustRead(t, p))
		}
	}
	if removed, err := Uninstall(); !removed || err != nil {
		t.Fatalf("uninstall %v %v", removed, err)
	}
	if b := mustRead(t, p); strings.Contains(string(b), "provguard") || !strings.Contains(string(b), "say done") {
		t.Errorf("after uninstall:\n%s", b)
	}
	if filepath.Base(p) != "hooks.json" {
		t.Error(p)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
