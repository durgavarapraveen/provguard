package adapter

import (
	"testing"

	"github.com/durgavarapraveen/provguard/internal/adapter/claudecode"
	"github.com/durgavarapraveen/provguard/internal/adapter/cursor"
)

func TestForPayload(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{`{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Bash"}`, claudecode.Agent},
		{`{"conversation_id":"c","cursor_version":"2.4.0","hook_event_name":"preToolUse"}`, cursor.Agent},
		{"\xef\xbb\xbf" + `{"conversation_id":"c","cursor_version":"2.4.0"}`, cursor.Agent},
		{`not json`, claudecode.Agent}, // the default answers, and its parser reports the error
	}
	for _, c := range cases {
		ad, body := ForPayload([]byte(c.raw))
		if ad.Name() != c.want {
			t.Errorf("%q: got %s, want %s", c.raw, ad.Name(), c.want)
		}
		if len(body) > 0 && body[0] == 0xef {
			t.Errorf("%q: BOM kept", c.raw)
		}
	}
}

// Every adapter must have a unique name: audit logs and events use it.
func TestAdapterNamesUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range adapters {
		if seen[a.Name()] {
			t.Errorf("duplicate adapter name %q", a.Name())
		}
		seen[a.Name()] = true
	}
}
