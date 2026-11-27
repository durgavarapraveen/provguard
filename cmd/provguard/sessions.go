package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/durgavarapraveen/provguard/internal/audit"
	"github.com/durgavarapraveen/provguard/internal/event"
	"github.com/durgavarapraveen/provguard/internal/store"
)

// noteSession saves the working folder and the title (without the trust
// icon) in the session record, so the commands can name the session. It
// writes only when something changed. Errors are ignored: the names are
// only for the user.
func noteSession(home string, e event.Event) {
	if e.SessionID == "" {
		return
	}
	title := strings.TrimSpace(stripIcons(strings.TrimSpace(e.Title)))
	if store.Exists(home, e.SessionID) {
		if s, err := store.Get(home, e.SessionID); err == nil && (e.Cwd == "" || s.Cwd == e.Cwd) && (title == "" || s.Title == title) {
			return
		}
	}
	_ = store.Update(home, e.SessionID, func(s *store.Session) error {
		if e.Cwd != "" {
			s.Cwd = e.Cwd
		}
		if title != "" {
			s.Title = title
		}
		return nil
	})
}

// sessionFile is one saved session, newest first after sortSessions.
type sessionFile struct {
	id  string
	mod time.Time
}

func listSessions(home string) []sessionFile {
	files, _ := filepath.Glob(filepath.Join(home, "sessions", "*.json"))
	var out []sessionFile
	for _, f := range files {
		if fi, err := os.Stat(f); err == nil {
			out = append(out, sessionFile{strings.TrimSuffix(filepath.Base(f), ".json"), fi.ModTime()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].mod.After(out[j].mod) })
	return out
}

// latestScan caps how many recent sessions "latest" reads to find one in
// the current folder.
const latestScan = 50

// resolveSession turns a session argument into a session id:
//   - "" or "latest": the most recently updated session in the current
//     folder (or a folder above or below it), else the most recent of all;
//   - a full id: that id;
//   - the start of an id (78d5): the one session whose id starts with it.
func resolveSession(home, id string) (string, error) {
	all := listSessions(home)
	if id != "" && id != "latest" {
		if store.Exists(home, id) {
			return id, nil
		}
		var hits []string
		for _, f := range all {
			if strings.HasPrefix(f.id, id) {
				hits = append(hits, f.id)
			}
		}
		switch len(hits) {
		case 0:
			return id, nil // reported by the caller as not found / not tracked
		case 1:
			return hits[0], nil
		}
		return "", fmt.Errorf("%q matches %d sessions (%s); type more of the id", id, len(hits), strings.Join(hits[:min(3, len(hits))], ", "))
	}
	if len(all) == 0 {
		return "", errors.New("no sessions recorded yet")
	}
	if cwd, err := os.Getwd(); err == nil {
		for _, f := range all[:min(latestScan, len(all))] {
			if s, err := store.Get(home, f.id); err == nil && sameProject(s.Cwd, cwd) {
				return f.id, nil
			}
		}
	}
	return all[0].id, nil
}

// sameProject: one folder is the other or holds it.
func sameProject(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	a, b = filepath.Clean(a), filepath.Clean(b)
	if strings.EqualFold(a, b) {
		return true
	}
	in := func(dir, p string) bool {
		rel, err := filepath.Rel(dir, p)
		return err == nil && rel != "." && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel)
	}
	return in(a, b) || in(b, a)
}

// sessionName is one line that names a session: its title and folder.
func sessionName(s *store.Session) string {
	var parts []string
	if s.Title != "" {
		parts = append(parts, "“"+s.Title+"”")
	}
	if s.Cwd != "" {
		parts = append(parts, "in "+s.Cwd)
	}
	return strings.Join(parts, " ")
}

func stateIcon(s *store.Session) string {
	switch {
	case s.Tainted && s.Sensitive:
		return "🔴"
	case s.Tainted:
		return "🟡"
	case s.Sensitive:
		return "🟠"
	}
	return "🟢"
}

// runSessions lists recent sessions: icon, short id, time, title, folder.
func runSessions(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("sessions", flag.ContinueOnError)
	n := fs.Int("n", 15, "how many sessions to list")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	home, err := audit.Home()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	all := listSessions(home)
	if len(all) == 0 {
		fmt.Fprintln(w, "No sessions recorded yet.")
		return 0
	}
	for _, f := range all[:min(*n, len(all))] {
		s, err := store.Get(home, f.id)
		if err != nil {
			fmt.Fprintf(w, "⚪ %-8s  %s  (record unreadable)\n", short(f.id), f.mod.Local().Format("2006-01-02 15:04"))
			continue
		}
		name := sessionName(s)
		if name == "" {
			name = "(no title or folder recorded yet)"
		}
		fmt.Fprintf(w, "%s %-8s  %s  %s\n", stateIcon(s), short(f.id), f.mod.Local().Format("2006-01-02 15:04"), name)
	}
	fmt.Fprintln(w, "\nUse the short id with explain, status --session or reset, e.g. provguard explain "+short(all[0].id))
	return 0
}

func short(id string) string { return id[:min(8, len(id))] }
