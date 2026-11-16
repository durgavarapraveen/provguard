package main

import (
	"strings"
	"testing"
	"time"

	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/store"
)

// LOW: balanced failed open on every internal error, so a crash in the
// check was itself a way through. It now denies once the session holds both
// untrusted content and secrets.
func TestFailClosedReason(t *testing.T) {
	home := t.TempDir()
	mark := func(id string, tainted, sensitive bool) {
		t.Helper()
		err := store.Update(home, id, func(s *store.Session) error {
			now := time.Now().UTC()
			if tainted {
				s.MarkTainted(store.Source{At: now, Tool: "WebFetch", Reason: "web_fetch"})
			}
			if sensitive {
				s.MarkSensitive(store.Source{At: now, Tool: "Read", Reason: "file:.env"})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	mark("red", true, true)
	mark("tainted", true, false)
	mark("sensitive", false, true)
	mark("clean", false, false)

	cfg := func(profile string) config.Config { return config.Config{Profile: profile} }
	cases := []struct {
		name    string
		cfg     config.Config
		session string
		want    bool
	}{
		{"strict denies anything", cfg("strict"), "clean", true},
		{"strict with no session", cfg("strict"), "", true},
		{"audit never denies", cfg("audit"), "red", false},
		{"default profile is audit", config.Config{}, "red", false},
		{"balanced denies a red session", cfg("balanced"), "red", true},
		{"balanced allows tainted only", cfg("balanced"), "tainted", false},
		{"balanced allows sensitive only", cfg("balanced"), "sensitive", false},
		{"balanced allows a clean session", cfg("balanced"), "clean", false},
		{"balanced with no session", cfg("balanced"), "", false},
		{"balanced with an unknown session", cfg("balanced"), "never-seen", false},
		{"balanced with an unsafe id", cfg("balanced"), "../../etc/passwd", false},
		{"a misspelled profile is balanced", cfg("balancd"), "red", true},
	}
	for _, c := range cases {
		why := failClosedReason(c.cfg, home, c.session)
		if (why != "") != c.want {
			t.Errorf("%s: reason %q, want deny=%v", c.name, why, c.want)
		}
		if why != "" && strings.HasSuffix(why, ".") {
			t.Errorf("%s: reason must not end in a period, the caller adds one: %q", c.name, why)
		}
	}
}
