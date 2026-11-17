// Package store keeps per-session security state on disk.
//
// Claude Code runs matching hooks in parallel, so every update takes a
// cross-process lock (a lock file created with O_EXCL; works on all OSes).
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	MaxValues       = 2000 // untrusted values kept per session
	MaxFingerprints = 500
	MaxSources      = 50
	MaxHistory      = 50
	MaxAge          = 7 * 24 * time.Hour

	lockWait  = 3 * time.Second
	lockStale = 10 * time.Second
	// abandoned is when a lock or temp file is certainly leftover: far past
	// lockStale, so GC never deletes one a live hook is holding.
	abandoned = time.Hour
)

// Source records why a session got a label.
type Source struct {
	At     time.Time `json:"at"`
	Tool   string    `json:"tool"`
	Reason string    `json:"reason"`
}

// Step is one short history entry.
type Step struct {
	At     time.Time `json:"at"`
	Event  string    `json:"event"`
	Tool   string    `json:"tool,omitempty"`
	Labels []string  `json:"labels,omitempty"`
}

// Session is the saved state. It never holds raw secrets.
type Session struct {
	ID        string    `json:"id"`
	Created   time.Time `json:"created"`
	Updated   time.Time `json:"updated"`
	Tainted   bool      `json:"tainted"`
	Sensitive bool      `json:"sensitive"`

	TaintSources     []Source `json:"taint_sources,omitempty"`
	SensitiveSources []Source `json:"sensitive_sources,omitempty"`

	// UntrustedValues: URLs, hosts and IPs seen in untrusted content.
	UntrustedValues []string `json:"untrusted_values,omitempty"`
	// Fingerprints: HMACs of secret values seen in this session.
	Fingerprints []string `json:"fingerprints,omitempty"`
	// HiddenSources: content that hid text from the user (label.HiddenText).
	HiddenSources []Source `json:"hidden_sources,omitempty"`
	// TaintedAgents: subagent ids that read untrusted content.
	TaintedAgents []string `json:"tainted_agents,omitempty"`
	// RepoOwners caches git repo root -> origin owner ("" = no remote).
	RepoOwners map[string]string `json:"repo_owners,omitempty"`

	History []Step `json:"history,omitempty"`
}

// MarkTainted sets the taint flag. Taint never goes away by itself.
func (s *Session) MarkTainted(src Source) {
	s.Tainted = true
	s.TaintSources = appendCapped(s.TaintSources, src, MaxSources)
}

func (s *Session) MarkSensitive(src Source) {
	s.Sensitive = true
	s.SensitiveSources = appendCapped(s.SensitiveSources, src, MaxSources)
}

// MarkHidden records content that hid text from the user. It also taints.
func (s *Session) MarkHidden(src Source) {
	s.MarkTainted(src)
	s.HiddenSources = appendCapped(s.HiddenSources, src, MaxSources)
}

func (s *Session) AddValues(vs ...string) {
	s.UntrustedValues = addUnique(s.UntrustedValues, vs, MaxValues)
}

func (s *Session) AddFingerprints(fps ...string) {
	s.Fingerprints = addUnique(s.Fingerprints, fps, MaxFingerprints)
}

func (s *Session) AddTaintedAgent(id string) {
	s.TaintedAgents = addUnique(s.TaintedAgents, []string{id}, 200)
}

func (s *Session) AgentTainted(id string) bool {
	for _, a := range s.TaintedAgents {
		if a == id {
			return true
		}
	}
	return false
}

func (s *Session) AddStep(st Step) { s.History = appendCapped(s.History, st, MaxHistory) }

func appendCapped[T any](list []T, v T, max int) []T {
	list = append(list, v)
	if len(list) > max {
		list = list[len(list)-max:]
	}
	return list
}

// addUnique appends new non-empty values and drops the oldest past max.
func addUnique(list, vs []string, max int) []string {
	seen := make(map[string]bool, len(list))
	for _, v := range list {
		seen[v] = true
	}
	for _, v := range vs {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		list = append(list, v)
	}
	if len(list) > max {
		list = list[len(list)-max:]
	}
	return list
}

// Session ids come from the agent. Allow only safe file-name characters.
var safeID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func dir(home string) string { return filepath.Join(home, "sessions") }

func path(home, id string) string { return filepath.Join(dir(home), id+".json") }

// Update loads the session, runs fn, and saves the result, all under the lock.
func Update(home, id string, fn func(*Session) error) error {
	if !safeID.MatchString(id) {
		return fmt.Errorf("unsafe session id %q", id)
	}
	if err := os.MkdirAll(dir(home), 0o700); err != nil {
		return err
	}
	unlock, err := lock(path(home, id) + ".lock")
	if err != nil {
		return err
	}
	defer unlock()

	s, err := load(home, id)
	if err != nil {
		return err
	}
	if err := fn(s); err != nil {
		return err
	}
	s.Updated = time.Now().UTC()
	return save(home, s)
}

// Get loads a session without the lock (read-only use).
func Get(home, id string) (*Session, error) {
	if !safeID.MatchString(id) {
		return nil, fmt.Errorf("unsafe session id %q", id)
	}
	return load(home, id)
}

func load(home, id string) (*Session, error) {
	b, err := os.ReadFile(path(home, id))
	if errors.Is(err, os.ErrNotExist) {
		now := time.Now().UTC()
		return &Session{ID: id, Created: now, Updated: now}, nil
	}
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("corrupt session %s: %w", id, err)
	}
	return &s, nil
}

func save(home string, s *Session) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	p := path(home, s.ID)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	// Windows refuses to rename over a file that another hook process is
	// reading (unlocked Get) with "Access is denied". Retry briefly instead
	// of losing the update.
	for i := 0; i < 50; i++ {
		if err = os.Rename(tmp, p); err == nil || !errors.Is(err, os.ErrPermission) {
			break
		}
		time.Sleep(time.Duration(i+1) * time.Millisecond)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// lock creates name exclusively. It waits up to lockWait and breaks locks
// older than lockStale (a hook that crashed while holding it).
func lock(name string) (func(), error) {
	deadline := time.Now().Add(lockWait)
	delay := time.Millisecond
	for {
		f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			return func() { os.Remove(name) }, nil
		}
		// Windows returns "Access is denied" while another process's delete
		// of the lock file is still pending. Treat it like "exists" and retry.
		if !errors.Is(err, os.ErrExist) && !errors.Is(err, os.ErrPermission) {
			return nil, err
		}
		if fi, err := os.Stat(name); err == nil && time.Since(fi.ModTime()) > lockStale {
			breakStale(name)
			continue
		}
		if time.Now().After(deadline) {
			return nil, errors.New("session lock timeout: " + name)
		}
		time.Sleep(delay)
		if delay < 20*time.Millisecond {
			delay *= 2
		}
	}
}

// breakStale removes a lock left by a crashed hook. Two waiters can both see
// it stale, and a plain os.Remove by the second would delete the first one's
// fresh lock. Renaming is atomic, so only one waiter moves the file; if what
// it moved turns out to be fresh, it puts it back.
func breakStale(name string) {
	tmp := fmt.Sprintf("%s.stale-%d-%d", name, os.Getpid(), time.Now().UnixNano())
	if os.Rename(name, tmp) != nil {
		return // another waiter broke it first
	}
	if fi, err := os.Stat(tmp); err == nil && time.Since(fi.ModTime()) <= lockStale {
		if _, err := os.Stat(name); errors.Is(err, os.ErrNotExist) {
			os.Rename(tmp, name) // we took a live lock: restore it
			return
		}
	}
	os.Remove(tmp)
}

// GC deletes session files not updated for MaxAge. It returns the count removed.
func GC(home string) int {
	entries, err := os.ReadDir(dir(home))
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			continue
		}
		age := time.Since(fi.ModTime())
		name := e.Name()
		switch {
		case strings.HasSuffix(name, ".json"):
			if age < MaxAge {
				continue
			}
		case strings.HasSuffix(name, ".lock"), strings.HasSuffix(name, ".tmp"),
			strings.Contains(name, ".lock.stale-"):
			// A session untouched for MaxAge can still have a hook holding
			// its lock, so lock files get a longer age: a lock is only
			// leftover once it is far past the age at which lock() breaks it.
			if age < abandoned {
				continue
			}
		default:
			continue // not ours: leave it alone
		}
		if os.Remove(filepath.Join(dir(home), name)) == nil && strings.HasSuffix(name, ".json") {
			n++
		}
	}
	return n
}
