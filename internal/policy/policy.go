// Package policy decides allow / ask / deny for a tool call, from the
// session's labels (week 2) and the call's sinks (week 3).
//
// Rules, first match wins (DESIGN.md 5.4, tuned in week 6):
//  1. a secret seen in this session appears in the call      → deny
//  2. EGRESS while the session is both tainted and sensitive  → deny  (lethal trifecta)
//  3. EGRESS to a host/URL taken from untrusted content       → ask
//  4. PERSIST / EXEC_REMOTE / OPAQUE while tainted            → ask
//  5. reverse shell, or risky DESTROY                         → ask
//  6. anything else                                           → allow (no decision)
//
// Not counted as EGRESS for rules 2–3 (week 6, false-positive tuning):
// pushes to a git remote owned by a trusted owner, and requests to localhost.
package policy

import (
	"fmt"
	"net/url"
	"path"
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
	Cwd     string // working directory of the call
	// RemoteTrusted reports whether a git remote (name or URL) belongs to a
	// trusted owner. nil means "never trusted".
	RemoteTrusted func(remote string) bool
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

	egress := externalEgress(in)

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
		var risky []shell.Sink
		for _, x := range filter(in.Sinks, shell.Persist, shell.ExecRemote, shell.Opaque) {
			// An install from the project's manifest (npm install, pip install
			// -r requirements.txt) names no package the untrusted content
			// could have chosen.
			if strings.HasPrefix(x.Detail, "package_install:") && x.Target == "" {
				continue
			}
			risky = append(risky, x)
		}
		if len(risky) > 0 {
			return result(Ask, "tainted_"+strings.ToLower(risky[0].Class), fmt.Sprintf(
				"this session read untrusted content (%s), and this call makes a lasting change, runs remote code, or runs code provguard cannot read",
				firstSource(s.TaintSources)), risky)
		}
	}

	// 5. Reverse shell (always) and risky destruction.
	for _, x := range in.Sinks {
		if x.Detail == "reverse_shell" {
			return result(Ask, "remote_shell", "this call connects a shell to a network socket (a reverse shell)", []shell.Sink{x})
		}
	}
	var destroy []shell.Sink
	for _, d := range filter(in.Sinks, shell.Destroy) {
		if s.Tainted || riskyDestroy(d, in.Cwd) {
			destroy = append(destroy, d)
		}
	}
	if len(destroy) > 0 {
		return result(Ask, "destroy", "this call can delete data or history", destroy)
	}
	return Result{}
}

// externalEgress returns the EGRESS sinks that can carry data to a third party.
func externalEgress(in Input) []shell.Sink {
	var out []shell.Sink
	for _, s := range filter(in.Sinks, shell.Egress) {
		switch {
		case s.Detail == PlainFetch:
			continue // following links: only rule 1 applies
		case s.Detail == "git_push" && in.RemoteTrusted != nil && in.RemoteTrusted(gitRemote(s.Target)):
			continue // pushing to your own repository
		case isLocal(s.Target) && !in.Config.LocalhostIsExternal:
			continue // localhost: dev servers, local APIs
		}
		out = append(out, s)
	}
	return out
}

// gitRemote returns the remote of a "git push" target ("origin main" → "origin").
func gitRemote(target string) string {
	f := strings.Fields(target)
	if len(f) == 0 {
		return "origin"
	}
	return f[0]
}

// isLocal reports whether a sink target points to this machine.
func isLocal(target string) bool {
	t := strings.ToLower(strings.TrimSpace(target))
	if t == "" {
		return false
	}
	host := t
	if u, err := url.Parse(t); err == nil && u.Host != "" {
		host = u.Hostname()
	} else {
		host = strings.Split(strings.Split(t, "/")[0], ":")[0]
	}
	return host == "localhost" || strings.HasPrefix(host, "127.") || host == "::1" || host == "[::1]" || host == "0.0.0.0" ||
		strings.HasSuffix(host, ".localhost")
}

// protectedBranches: force-pushing these always asks.
var protectedBranches = map[string]bool{"main": true, "master": true, "develop": true, "production": true, "prod": true, "trunk": true}

// riskyDestroy decides whether a DESTROY sink needs approval in an untainted
// session. Deleting inside the project and force-pushing a feature branch are
// normal work; deleting outside it, history rewrites on shared branches, and
// remote deletions are not.
func riskyDestroy(d shell.Sink, cwd string) bool {
	switch d.Detail {
	case "rm_recursive", "find_delete", "remove_item_recurse":
		targets := strings.Fields(d.Target)
		if len(targets) == 0 {
			return true
		}
		for _, t := range targets {
			if !insideWorkspace(t, cwd) {
				return true
			}
		}
		return false
	case "git_force_push":
		f := strings.Fields(d.Target)
		if len(f) < 2 {
			return true // branch unknown
		}
		for _, ref := range f[1:] {
			b := strings.TrimPrefix(ref, "+")
			if i := strings.LastIndex(b, ":"); i >= 0 {
				b = b[i+1:]
			}
			b = strings.TrimPrefix(b, "refs/heads/")
			if b == "" || protectedBranches[b] || strings.HasPrefix(b, "release") {
				return true
			}
		}
		return false
	}
	return true
}

// insideWorkspace: a relative path without ".." or variables, or an absolute
// path under cwd.
func insideWorkspace(p, cwd string) bool {
	n := strings.ReplaceAll(strings.ToLower(p), `\`, "/")
	if n == "" || n == "." || n == "./" || n == "*" || strings.ContainsAny(n, "$~") {
		return false
	}
	isAbs := strings.HasPrefix(n, "/") || len(n) > 1 && n[1] == ':'
	if !isAbs {
		return !strings.HasPrefix(path.Clean(n), "..")
	}
	c := strings.TrimSuffix(strings.ReplaceAll(strings.ToLower(cwd), `\`, "/"), "/")
	return c != "" && strings.HasPrefix(path.Clean(n), c+"/")
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
