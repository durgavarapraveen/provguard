package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Session titles marked with a trust icon.
//
// provguard puts 🔴 🟡 🟠 in front of a session title through Claude Code's
// hook answer. The title keeps the icon after provguard is gone, and only a
// hook answer inside that session can change it again. So provguard records
// each session it marked, and `provguard uninstall` leaves a small cleanup
// hook that restores those titles (see cleanup.go).

var titleIcons = []string{"🔴 ", "🟡 ", "🟠 ", "🟢 "}

// stripIcons removes every leading trust icon from a title.
func stripIcons(title string) string {
	for again := true; again; {
		again = false
		for _, ic := range titleIcons {
			if rest, ok := strings.CutPrefix(title, ic); ok {
				title, again = rest, true
			}
		}
	}
	return title
}

// titleWithIcon returns the title with the icon for the session's state,
// or "" when the title is already right (or there is no title to change).
func titleWithIcon(current string, tainted, sensitive bool) string {
	if strings.TrimSpace(current) == "" {
		return ""
	}
	base := stripIcons(current)
	want := base
	switch {
	case tainted && sensitive:
		want = "🔴 " + base
	case tainted:
		want = "🟡 " + base
	case sensitive:
		want = "🟠 " + base
	}
	if want == current {
		return ""
	}
	return want
}

var sessionIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func titledDir(home string) string { return filepath.Join(home, "titled") }

// markTitled records the title with its icon, so uninstall can name the
// session, or forgets the session when title has no icon (""). Errors are
// ignored: a missed record only means one title is not restored on
// uninstall.
func markTitled(home, session, title string) {
	if !sessionIDRe.MatchString(session) {
		return
	}
	p := filepath.Join(titledDir(home), session)
	if stripIcons(title) == title {
		_ = os.Remove(p)
		return
	}
	if old, err := os.ReadFile(p); err == nil && string(old) == title {
		return // already recorded; most prompts change nothing
	}
	if os.MkdirAll(titledDir(home), 0o700) == nil {
		_ = os.WriteFile(p, []byte(title), 0o600)
	}
}

// titledTitles lists the recorded titles that still carry an icon, sorted.
// A record from an older version holds no title; it shows as the session id.
func titledTitles(home string) []string {
	var out []string
	for _, id := range titledSessions(home) {
		t, _ := os.ReadFile(filepath.Join(titledDir(home), id))
		name := strings.TrimSpace(string(t))
		if name == "" {
			name = "(session " + id + ")"
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func isTitled(home, session string) bool {
	if !sessionIDRe.MatchString(session) {
		return false
	}
	_, err := os.Stat(filepath.Join(titledDir(home), session))
	return err == nil
}

// titledSessions lists the sessions whose title still carries an icon.
func titledSessions(home string) []string {
	es, _ := os.ReadDir(titledDir(home))
	var out []string
	for _, e := range es {
		if sessionIDRe.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out
}
