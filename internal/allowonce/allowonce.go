// Package allowonce lets the user approve one blocked tool call, once.
//
// When policy blocks a call, the hook records a pending entry under
// <home>/allow/<token>.pending and tells the user the token. The user runs
// `provguard allow <token>` in their own terminal; that turns the entry into
// a grant. The next identical call (same session, tool and text) within TTL
// uses the grant up and gets no provguard decision.
//
// Agents cannot grant: writes to <home> and `provguard allow` are blocked by
// self-protection, and the token is an HMAC with the install key, which
// agents cannot read, so an agent cannot compute a token for a call that was
// never blocked.
package allowonce

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/durgavarapraveen/provguard/internal/redact"
)

// TTL is how long a pending block can be granted, and how long a grant lasts.
const TTL = 10 * time.Minute

// Pending is what the user sees before granting. Command is redacted.
type Pending struct {
	Session string    `json:"session"`
	Tool    string    `json:"tool"`
	Command string    `json:"command"`
	Rule    string    `json:"rule"`
	Time    time.Time `json:"ts"`
}

var tokenRe = regexp.MustCompile(`^[0-9a-f]{10}$`)

// Token identifies one exact call in one session.
func Token(key []byte, session, tool, text string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(session + "\x00" + tool + "\x00" + text))
	return hex.EncodeToString(m.Sum(nil))[:10]
}

func dir(home string) string { return filepath.Join(home, "allow") }

// Valid reports whether s has the token format.
func Valid(s string) bool { return tokenRe.MatchString(s) }

// Consume uses up a fresh grant for token. It reports true at most once.
func Consume(home, token string, now time.Time) bool {
	if !Valid(token) {
		return false
	}
	p := filepath.Join(dir(home), token+".granted")
	fi, err := os.Stat(p)
	if err != nil {
		return false
	}
	// Remove first: only the process that removes the file may use it.
	if os.Remove(p) != nil {
		return false
	}
	return now.Sub(fi.ModTime()) <= TTL
}

// Record writes the pending entry for a blocked call.
func Record(home, token string, p Pending) error {
	if !Valid(token) {
		return errors.New("bad token")
	}
	p.Command = redact.String(p.Command)
	if len(p.Command) > 300 {
		p.Command = p.Command[:300] + "…"
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir(home), 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir(home), token+".pending"), b, 0o600)
}

// Grant turns a fresh pending entry into a grant and returns it.
func Grant(home, token string, now time.Time) (Pending, error) {
	var p Pending
	token = strings.ToLower(strings.TrimSpace(token))
	if !Valid(token) {
		return p, fmt.Errorf("%q is not a provguard token (10 hex characters)", token)
	}
	src := filepath.Join(dir(home), token+".pending")
	b, err := os.ReadFile(src)
	if errors.Is(err, os.ErrNotExist) {
		return p, fmt.Errorf("no blocked call with token %s (already used, or wrong token)", token)
	}
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, err
	}
	if now.Sub(p.Time) > TTL {
		_ = os.Remove(src)
		return p, fmt.Errorf("token %s is older than %v; let the agent try again for a new one", token, TTL)
	}
	if err := os.WriteFile(filepath.Join(dir(home), token+".granted"), nil, 0o600); err != nil {
		return p, err
	}
	_ = os.Remove(src)
	return p, nil
}

// GC removes entries older than TTL.
func GC(home string, now time.Time) {
	es, err := os.ReadDir(dir(home))
	if err != nil {
		return
	}
	for _, e := range es {
		if fi, err := e.Info(); err == nil && now.Sub(fi.ModTime()) > TTL {
			_ = os.Remove(filepath.Join(dir(home), e.Name()))
		}
	}
}

// Hint is appended to a block reason.
func Hint(token string) string {
	return " If you trust this exact call, run in your own terminal: provguard allow " + token + " (one time, within 10 minutes)."
}
