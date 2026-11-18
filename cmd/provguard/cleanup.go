package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/durgavarapraveen/provguard/internal/adapter"
	"github.com/durgavarapraveen/provguard/internal/install"
)

// Uninstall in two steps.
//
// `provguard uninstall` turns protection off at once. If some session titles
// still carry a trust icon, it leaves one hook (`provguard hook cleanup`) on
// SessionStart and UserPromptSubmit. That hook protects nothing and logs
// nothing; in each marked session it answers once with the clean title. When
// no marked session is left, or after cleanupWindow, it removes itself and
// the provguard folder.

const cleanupWindow = 30 * 24 * time.Hour

// pending is <home>/uninstall-pending.json, written by uninstall.
type pending struct {
	Since    time.Time `json:"since"`
	Settings string    `json:"settings"`            // the settings file the hook is in
	KeepData bool      `json:"keep_data,omitempty"` // keep <home> at the end
}

func pendingPath(home string) string { return filepath.Join(home, "uninstall-pending.json") }

func readPending(home string) (pending, bool) {
	var p pending
	b, err := os.ReadFile(pendingPath(home))
	if err != nil || json.Unmarshal(b, &p) != nil || p.Settings == "" {
		return p, false
	}
	return p, true
}

func writePending(home string, p pending) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return os.WriteFile(pendingPath(home), b, 0o600)
}

// runCleanupHook is `provguard hook cleanup`. It always exits 0 and never
// blocks anything: a cleanup error must not get in the user's way.
func runCleanupHook(stdin io.Reader, stdout io.Writer, home string, now time.Time) int {
	defer func() { _ = recover() }()
	p, ok := readPending(home)
	if !ok {
		return 0 // not uninstalling (or already done): nothing to do
	}
	raw, _ := io.ReadAll(io.LimitReader(stdin, maxPayload))
	ad, body := adapter.ForPayload(raw)
	if e, err := ad.Parse(body, ""); err == nil && isTitled(home, e.SessionID) && e.Title != "" {
		if clean := stripIcons(e.Title); clean != e.Title {
			if b := ad.Feedback(e, "", clean); b != nil {
				stdout.Write(b)
			}
		}
		markTitled(home, e.SessionID, "")
	}
	if len(titledSessions(home)) == 0 || now.Sub(p.Since) > cleanupWindow {
		_ = finishUninstall(home, p)
	}
	return 0
}

// finishUninstall removes the cleanup hook and, unless asked to keep it, the
// provguard folder.
func finishUninstall(home string, p pending) error {
	s, err := install.Load(p.Settings)
	if err != nil {
		return err
	}
	if install.Remove(s) > 0 {
		if _, err := install.Save(p.Settings, s); err != nil {
			return err
		}
	}
	if p.KeepData {
		return os.Remove(pendingPath(home))
	}
	if bin := filepath.Join(home, "bin"); userPath.has(bin) {
		_ = userPath.remove(bin)
	}
	return removeHome(home)
}

// removeHome deletes the provguard folder. On Windows a program that is
// running cannot be deleted but can be renamed, and the cleanup hook or the
// uninstall command itself may be running from <home>/bin; such files are
// moved to the temp folder first. It reports a folder it could not delete.
func removeHome(home string) error {
	bins, _ := filepath.Glob(filepath.Join(home, "bin", "*"))
	for i, b := range bins {
		_ = os.Rename(b, filepath.Join(os.TempDir(), fmt.Sprintf("provguard-removed-%d-%d%s", time.Now().UnixNano(), i, filepath.Ext(b))))
	}
	if err := os.RemoveAll(home); err != nil {
		return errors.Join(fmt.Errorf("could not delete %s", home), err)
	}
	return nil
}
