package doctor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// LOW: `provguard init` writes "onFailure": "block" only for strict, so a
// profile changed afterwards left the hook's behaviour behind, and nothing
// said that a timed-out hook does not block.
func TestFailClosedFindings(t *testing.T) {
	hooksWith := func(onFailure bool) map[string]any {
		h := map[string]any{"type": "command", "command": `"C:/u/.provguard/bin/provguard.exe" hook PreToolUse`}
		if onFailure {
			h["onFailure"] = "block"
		}
		return map[string]any{"PreToolUse": []any{map[string]any{"hooks": []any{h}}}}
	}
	cases := []struct {
		name      string
		profile   string
		onFailure bool
		want      string // "" = no finding
	}{
		{"strict without onFailure", "strict", false, Medium},
		{"strict with onFailure", "strict", true, ""},
		{"balanced without onFailure", "balanced", false, Info},
		{"balanced with onFailure", "balanced", true, ""},
		{"audit says nothing", "audit", false, ""},
		{"a misspelled profile is balanced", "balancd", false, Info},
	}
	for _, c := range cases {
		home := t.TempDir()
		b, _ := json.Marshal(map[string]any{"profile": c.profile})
		if err := os.WriteFile(filepath.Join(home, "config.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		f := failClosedFindings(Options{Home: home}, hooksWith(c.onFailure))
		switch {
		case c.want == "":
			if len(f) != 0 {
				t.Errorf("%s: unexpected %v", c.name, f)
			}
		case len(f) != 1:
			t.Errorf("%s: %d findings, want 1", c.name, len(f))
		case f[0].Severity != c.want:
			t.Errorf("%s: severity %s, want %s", c.name, f[0].Severity, c.want)
		case !strings.Contains(f[0].Message, "PreToolUse"):
			t.Errorf("%s: message does not name the hook: %q", c.name, f[0].Message)
		}
	}
	// Without a home there is no config to compare against.
	if f := failClosedFindings(Options{}, hooksWith(false)); len(f) != 0 {
		t.Errorf("no home: unexpected %v", f)
	}
}
