// Package install adds and removes provguard hooks in a Claude Code settings file.
package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// HookTimeoutSeconds is far below Claude Code's 600 s default, so a stuck
// hook cannot freeze the agent. A timeout does not block the tool call.
const HookTimeoutSeconds = 10

// toolEvents take a matcher. Other events fire without one.
var toolEvents = map[string]bool{"PreToolUse": true, "PostToolUse": true}

// DefaultSettingsPath returns ~/.claude/settings.json.
func DefaultSettingsPath() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".claude", "settings.json"), nil
}

// Command returns the hook command line for one event.
// Forward slashes work in both Git Bash and cmd on Windows.
func Command(exe, eventName string) string {
	return fmt.Sprintf("\"%s\" hook %s", filepath.ToSlash(exe), eventName)
}

// CleanupEvent is the hook name of the title cleanup that uninstall leaves
// behind (`provguard hook cleanup`).
const CleanupEvent = "cleanup"

// CleanupEvents are the Claude Code events whose hook answer can set a
// session title.
var CleanupEvents = []string{"SessionStart", "UserPromptSubmit"}

// AddCleanup adds the title-cleanup hook, running exe, for CleanupEvents.
func AddCleanup(s map[string]any, exe string) error {
	hooks, ok := s["hooks"].(map[string]any)
	if !ok {
		if _, exists := s["hooks"]; exists {
			return errors.New(`"hooks" in settings is not an object, refusing to change it`)
		}
		hooks = map[string]any{}
		s["hooks"] = hooks
	}
	for _, ev := range CleanupEvents {
		existing, _ := hooks[ev].([]any)
		hooks[ev] = append(existing, map[string]any{"hooks": []any{map[string]any{
			"type": "command", "command": Command(exe, CleanupEvent), "timeout": HookTimeoutSeconds,
		}}})
	}
	return nil
}

// HookBinary returns the program the installed provguard hooks run, or "".
func HookBinary(s map[string]any) string {
	hooks, _ := s["hooks"].(map[string]any)
	for _, groups := range hooks {
		gs, _ := groups.([]any)
		for _, g := range gs {
			gm, _ := g.(map[string]any)
			hs, _ := gm["hooks"].([]any)
			for _, h := range hs {
				hm, _ := h.(map[string]any)
				if cmd, _ := hm["command"].(string); IsProvguard(cmd) {
					return commandProgram(cmd)
				}
			}
		}
	}
	return ""
}

// commandProgram returns the program of a hook command line ("exe" args…).
func commandProgram(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if rest, ok := strings.CutPrefix(cmd, `"`); ok {
		if i := strings.IndexByte(rest, '"'); i >= 0 {
			return filepath.FromSlash(rest[:i])
		}
	}
	if f := strings.Fields(cmd); len(f) > 0 {
		return filepath.FromSlash(f[0])
	}
	return ""
}

// IsProvguard reports whether a hook command belongs to provguard.
func IsProvguard(cmd string) bool {
	c := strings.ToLower(cmd)
	return strings.Contains(c, "provguard") && strings.Contains(c, " hook ")
}

// Load reads a settings file. A missing file returns an empty object.
func Load(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return map[string]any{}, nil
	}
	var s map[string]any
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON, refusing to change it: %w", path, err)
	}
	return s, nil
}

// Remove deletes every provguard hook. It drops groups and events that become empty.
// It returns the number of hooks removed.
func Remove(s map[string]any) int {
	hooks, ok := s["hooks"].(map[string]any)
	if !ok {
		return 0
	}
	removed := 0
	for ev, v := range hooks {
		groups, ok := v.([]any)
		if !ok {
			continue
		}
		var keptGroups []any
		for _, g := range groups {
			gm, ok := g.(map[string]any)
			if !ok {
				keptGroups = append(keptGroups, g)
				continue
			}
			inner, ok := gm["hooks"].([]any)
			if !ok {
				keptGroups = append(keptGroups, g)
				continue
			}
			var kept []any
			for _, h := range inner {
				hm, ok := h.(map[string]any)
				if ok {
					if cmd, _ := hm["command"].(string); IsProvguard(cmd) {
						removed++
						continue
					}
				}
				kept = append(kept, h)
			}
			if len(kept) == 0 {
				continue
			}
			gm["hooks"] = kept
			keptGroups = append(keptGroups, gm)
		}
		if len(keptGroups) == 0 {
			delete(hooks, ev)
		} else {
			hooks[ev] = keptGroups
		}
	}
	if len(hooks) == 0 {
		delete(s, "hooks")
	}
	return removed
}

// Options change how hooks are written.
type Options struct {
	// FailClosed adds "onFailure": "block" to PreToolUse, so a crashed or
	// timed-out hook blocks the call (strict profile; finding F2).
	FailClosed bool
}

// Add replaces any old provguard hooks with fresh entries for exe.
func Add(s map[string]any, exe string, events []string) error {
	return AddWith(s, exe, events, Options{})
}

// AddWith is Add with options.
func AddWith(s map[string]any, exe string, events []string, o Options) error {
	if err := add(s, exe, events); err != nil {
		return err
	}
	if o.FailClosed {
		hooks := s["hooks"].(map[string]any)
		for _, g := range hooks["PreToolUse"].([]any) {
			for _, h := range g.(map[string]any)["hooks"].([]any) {
				hm := h.(map[string]any)
				if cmd, _ := hm["command"].(string); IsProvguard(cmd) {
					hm["onFailure"] = "block"
				}
			}
		}
	}
	return nil
}

// CopyBinary installs the running binary as <home>/bin/provguard[.exe] and
// returns that path. Self-protection guards <home>, so an agent cannot
// replace the program its hooks run. A running copy on Windows cannot be
// overwritten but can be renamed, so the old file is moved aside first.
func CopyBinary(src, home string) (string, error) {
	b, err := os.ReadFile(src)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, "bin")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, "provguard"+filepath.Ext(src))
	if same, _ := filepath.Abs(src); strings.EqualFold(same, dst) {
		return dst, nil
	}
	tmp := dst + ".new"
	if err := os.WriteFile(tmp, b, 0o700); err != nil {
		return "", err
	}
	if _, err := os.Stat(dst); err == nil {
		old := dst + ".old"
		os.Remove(old) // may fail if a hook still runs it; then rename fails below
		if err := os.Rename(dst, old); err != nil {
			os.Remove(tmp)
			return "", fmt.Errorf("move old binary aside: %w", err)
		}
	}
	if err := os.Rename(tmp, dst); err != nil {
		return "", err
	}
	return dst, nil
}

func add(s map[string]any, exe string, events []string) error {
	Remove(s)
	hooks, ok := s["hooks"].(map[string]any)
	if !ok {
		if _, exists := s["hooks"]; exists {
			return errors.New(`"hooks" in settings is not an object, refusing to change it`)
		}
		hooks = map[string]any{}
		s["hooks"] = hooks
	}
	for _, ev := range events {
		group := map[string]any{
			"hooks": []any{map[string]any{
				"type":    "command",
				"command": Command(exe, ev),
				"timeout": HookTimeoutSeconds,
			}},
		}
		if toolEvents[ev] {
			group["matcher"] = "*"
		}
		existing, _ := hooks[ev].([]any)
		hooks[ev] = append(existing, group)
	}
	return nil
}

// Save backs up the old file (if any) and writes s atomically.
// It returns the backup path, or "" when there was no old file.
func Save(path string, s map[string]any) (string, error) {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", err
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	backup := ""
	if old, err := os.ReadFile(path); err == nil {
		backup = path + ".provguard-bak-" + time.Now().Format("20060102-150405")
		if err := os.WriteFile(backup, old, 0o600); err != nil {
			return "", fmt.Errorf("backup failed, settings not changed: %w", err)
		}
		pruneBackups(path, KeepBackups)
	}
	tmp := path + ".provguard-tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return backup, nil
}

// KeepBackups is how many settings backups init keeps.
const KeepBackups = 3

// pruneBackups deletes all but the newest keep backups of path. Review
// finding (LOW): one backup per init piled up, and backups can hold env
// secrets. The timestamp in the name sorts in time order.
func pruneBackups(path string, keep int) {
	files, _ := filepath.Glob(path + ".provguard-bak-*")
	sort.Strings(files)
	for len(files) > keep {
		os.Remove(files[0])
		files = files[1:]
	}
}

// HooksJSON returns the "hooks" section as indented JSON, for showing a diff.
func HooksJSON(s map[string]any) string {
	h, ok := s["hooks"]
	if !ok {
		return "(none)"
	}
	b, _ := json.MarshalIndent(h, "", "  ")
	return string(b)
}
