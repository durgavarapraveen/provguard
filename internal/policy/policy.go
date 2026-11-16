// Package policy decides allow / ask / deny for a tool call, from the
// session's labels (week 2) and the call's sinks (week 3).
//
// Rules, first match wins (DESIGN.md 5.4):
//  1. a secret seen in this session appears in the call      → deny
//  2. EGRESS while the session is both tainted and sensitive  → deny  (lethal trifecta)
//  3. EGRESS to a host/URL taken from untrusted content       → ask
//  4. PERSIST / EXEC_REMOTE / OPAQUE while tainted            → ask
//  5. DESTROY                                                 → ask
//  6. anything else                                           → allow (no decision)
package policy

import (
	"fmt"
	"strings"

	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/fingerprint"
	"github.com/durgavarapraveen/provguard/internal/shell"
	"github.com/durgavarapraveen/provguard/internal/store"
)

// Decision values.
const (
	None = ""     // no decision: Claude Code's normal permission flow
	Ask  = "ask"  // force the user's approval prompt
	Deny = "deny" // block
)

// Input is one tool call to judge.
type Input struct {
	Tool    string
	Sinks   []shell.Sink
	Text    string         // raw call text (command, URL, file content) for secret matching
	Session *store.Session // may be nil (new session)
	Key     fingerprint.Key
	Config  config.Config
}

// Result is the judgment.
type Result struct {
	Decision string // what provguard returns to the agent (None in audit mode)
	Would    string // what balanced/strict would return; set in every profile
	Rule     string
	Reason   string
}

// Evaluate applies the rules and the active profile.
func Evaluate(in Input) Result {
	r := evaluate(in)
	switch in.Config.ProfileName() {
	case config.Audit:
		r.Decision = None
	case config.Strict:
		if r.Would == Ask {
			r.Would = Deny
		}
		r.Decision = r.Would
	default:
		r.Decision = r.Would
	}
	return r
}

func evaluate(in Input) Result {
	if len(in.Sinks) == 0 {
		return Result{}
	}
	s := in.Session
	if s == nil {
		s = &store.Session{}
	}

	// 1. Secret in the call. Only for sinks that can carry data somewhere.
	if len(s.Fingerprints) > 0 && in.Key != nil && carriesData(in.Sinks) {
		if kind := SecretIn(in.Text, s.Fingerprints, in.Key); kind != "" {
			return result(Deny, "secret_in_sink", fmt.Sprintf(
				"this %s call contains a secret this session read earlier (%s; matched as %s)",
				in.Tool, firstSource(s.SensitiveSources), kind), in.Sinks)
		}
	}

	// Plain link-following fetches are only checked by rule 1.
	var egress []shell.Sink
	for _, s := range filter(in.Sinks, shell.Egress) {
		if s.Detail != PlainFetch {
			egress = append(egress, s)
		}
	}

	// 2. Lethal trifecta.
	if len(egress) > 0 && s.Tainted && s.Sensitive {
		return result(Deny, "lethal_trifecta", fmt.Sprintf(
			"this session read untrusted content (%s) and secrets (%s), and this call can send data out",
			firstSource(s.TaintSources), firstSource(s.SensitiveSources)), egress)
	}

	// 3. Egress to a destination that came from untrusted content.
	if len(egress) > 0 && len(s.UntrustedValues) > 0 {
		if v := untrustedDestination(in, egress, s.UntrustedValues); v != "" {
			return result(Ask, "untrusted_destination", fmt.Sprintf(
				"this call sends data to %q, which came from untrusted content (%s)", v, firstSource(s.TaintSources)), egress)
		}
	}

	// 4. Lasting change, remote code or unreadable code after untrusted input.
	if s.Tainted {
		if risky := filter(in.Sinks, shell.Persist, shell.ExecRemote, shell.Opaque); len(risky) > 0 {
			return result(Ask, "tainted_"+strings.ToLower(risky[0].Class), fmt.Sprintf(
				"this session read untrusted content (%s), and this call makes a lasting change, runs remote code, or runs code provguard cannot read",
				firstSource(s.TaintSources)), risky)
		}
	}

	// 5. Destruction.
	if d := filter(in.Sinks, shell.Destroy); len(d) > 0 {
		return result(Ask, "destroy", "this call can delete data or history", d)
	}
	return Result{}
}

func result(would, rule, why string, sinks []shell.Sink) Result {
	var ss []string
	for i, s := range sinks {
		if i == 3 {
			ss = append(ss, "…")
			break
		}
		ss = append(ss, s.String())
	}
	return Result{Would: would, Rule: rule,
		Reason: "provguard (" + rule + "): " + why + ". Action: " + strings.Join(ss, ", ") + "."}
}

func carriesData(sinks []shell.Sink) bool {
	for _, s := range sinks {
		if s.Class != shell.Destroy {
			return true
		}
	}
	return false
}

func filter(sinks []shell.Sink, classes ...string) []shell.Sink {
	var out []shell.Sink
	for _, s := range sinks {
		for _, c := range classes {
			if s.Class == c {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

func firstSource(src []store.Source) string {
	if len(src) == 0 {
		return "unknown"
	}
	s := src[0]
	return s.Tool + ": " + s.Reason
}

// untrustedDestination returns the first untrusted URL or host that the
// egress call targets. Allowed hosts never match.
func untrustedDestination(in Input, egress []shell.Sink, values []string) string {
	hay := strings.ToLower(in.Text)
	for _, e := range egress {
		hay += " " + strings.ToLower(e.Target)
	}
	for _, v := range values {
		lv := strings.ToLower(v)
		if strings.Contains(lv, "://") {
			if strings.Contains(hay, lv) {
				return v
			}
			continue
		}
		if in.Config.HostAllowed(lv) || len(lv) < 4 {
			continue
		}
		if containsHost(hay, lv) {
			return v
		}
	}
	return ""
}

// containsHost matches host as a whole label sequence, so "evil.test" does
// not match "notevil.test" and "a.test" does not match "a.testing".
func containsHost(hay, host string) bool {
	for i := 0; ; {
		j := strings.Index(hay[i:], host)
		if j < 0 {
			return false
		}
		j += i
		before := j == 0 || !isHostChar(hay[j-1])
		end := j + len(host)
		after := end == len(hay) || !isHostChar(hay[end])
		if before && after {
			return true
		}
		i = j + 1
	}
}

func isHostChar(c byte) bool {
	return c == '-' || c == '.' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}
