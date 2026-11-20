package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/durgavarapraveen/provguard/internal/audit"
	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/store"
)

// trustState is what `provguard status` reports for one session.
type trustState struct {
	Session   string `json:"session"`
	Tainted   bool   `json:"tainted"`
	Sensitive bool   `json:"sensitive"`
	Taint     string `json:"taint_reason,omitempty"`
	Secret    string `json:"sensitive_reason,omitempty"`
	Profile   string `json:"profile"`
	Level     string `json:"level"` // clean | untrusted | sensitive | both | not_tracked | unreadable
}

// runStatus prints a session's trust state. Used as a Claude Code status
// line: the CLI passes JSON with session_id on stdin. It never fails loudly,
// because a status line must not show errors.
func runStatus(args []string, stdin io.Reader, w io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	sid := fs.String("session", "", "session id (default: session_id from stdin JSON, else the latest)")
	asJSON := fs.Bool("json", false, "print JSON")
	plain := fs.Bool("plain", false, "no colors")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	home, err := audit.Home()
	if err != nil {
		return 0
	}
	id := *sid
	if id == "" && stdinIsPiped() {
		var in struct {
			SessionID string `json:"session_id"`
		}
		b, _ := io.ReadAll(io.LimitReader(stdin, 1<<20))
		_ = json.Unmarshal(b, &in)
		id = in.SessionID
	}
	if id == "" {
		if id, err = resolveSession(home, "latest"); err != nil {
			fmt.Fprintln(w, "provguard: no session yet")
			return 0
		}
	}
	st := trustState{Session: id, Level: "clean"}
	s, err := store.Get(home, id)
	switch {
	case !store.Exists(home, id):
		st.Level = "not_tracked"
	case err != nil:
		st.Level = "unreadable"
	default:
		st.Tainted, st.Sensitive = s.Tainted, s.Sensitive
		if len(s.TaintSources) > 0 {
			st.Taint = s.TaintSources[0].Tool + ": " + s.TaintSources[0].Reason
		}
		if len(s.SensitiveSources) > 0 {
			st.Secret = s.SensitiveSources[0].Tool + ": " + s.SensitiveSources[0].Reason
		}
	}
	cfg, err := config.Load(home)
	st.Profile = cfg.ProfileName()
	if err != nil {
		st.Profile = "balanced (config error)"
	}
	switch {
	case st.Tainted && st.Sensitive:
		st.Level = "both"
	case st.Tainted:
		st.Level = "untrusted"
	case st.Sensitive:
		st.Level = "sensitive"
	}
	if *asJSON {
		b, _ := json.Marshal(st)
		fmt.Fprintln(w, string(b))
		return 0
	}
	fmt.Fprintln(w, statusLine(st, !*plain))
	return 0
}

// statusLine renders the one-line indicator, with ANSI colors when color is true.
func statusLine(st trustState, color bool) string {
	type look struct{ icon, text, ansi string }
	l := map[string]look{
		"clean":     {"🟢", "clean", "\x1b[32m"},
		"untrusted": {"🟡", "UNTRUSTED", "\x1b[33m"},
		"sensitive": {"🟠", "SENSITIVE", "\x1b[38;5;208m"},
		"both":      {"🔴", "UNTRUSTED + SENSITIVE", "\x1b[31;1m"},
		// No provguard hook has seen the session: it may run without provguard.
		"not_tracked": {"⚪", "not tracked", "\x1b[2m"},
		"unreadable":  {"⚪", "record unreadable (run provguard doctor)", "\x1b[33m"},
	}[st.Level]
	if !color {
		return fmt.Sprintf("%s provguard: %s · %s", l.icon, l.text, st.Profile)
	}
	return fmt.Sprintf("%s%s provguard: %s\x1b[0m \x1b[2m· %s\x1b[0m", l.ansi, l.icon, l.text, st.Profile)
}

func stdinIsPiped() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice == 0
}
