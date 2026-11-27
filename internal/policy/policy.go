// Package policy decides allow / ask / deny for a tool call, from the
// session's labels and the call's sinks.
//
// Rules, first match wins:
//  1. a secret seen in this session appears in the call      → deny
//  2. EGRESS while the session is both tainted and sensitive  → deny  (lethal trifecta)
//  3. EGRESS to a host/URL taken from untrusted content       → ask
//  4. PERSIST / EXEC_REMOTE / OPAQUE while tainted            → ask
//  5. reverse shell, or risky DESTROY                         → ask
//  6. anything else                                           → allow (no decision)
//
// Also: between rules 3 and 4, the dependency gate (packages.go) denies a
// package the registry does not know and asks about a new one; egress to a
// blocked host is denied (after rule 1); the user's,
// a repository's and the packs' rules apply after rule 2; and in a session
// whose content hid text from the user, rules 3 and 4 deny instead of ask.
//
// Not counted as EGRESS for rules 2–3, to avoid false positives:
// pushes to a git remote owned by a trusted owner, and requests to localhost.
package policy

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/fingerprint"
	"github.com/durgavarapraveen/provguard/internal/registry"
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
	Cmds    []shell.Cmd    // the commands of a shell call, for command rules
	Text    string         // raw call text (command, URL, file content) for secret matching
	Session *store.Session // may be nil (new session)
	Key     fingerprint.Key
	Config  config.Config
	Cwd     string // working directory of the call
	// RemoteTrusted reports whether a git remote (name or URL) belongs to a
	// trusted owner. nil means "never trusted".
	RemoteTrusted func(remote string) bool

	// GHRepoTrusted reports whether a gh command's target repository
	// ("OWNER/REPO", or "." for the current folder's) belongs to a trusted
	// owner. It may ask GitHub, so it is called only when a rule needs it.
	// nil means "no repository is trusted".
	GHRepoTrusted func(repo string) bool
	// OutgoingDiff returns the commits a git push would send (patch text).
	// Used only when the session holds secrets. nil means "unknown".
	OutgoingDiff func() string
	// PackageInfo looks up a package that a call installs or runs (remote:
	// npx-style runners). ok is false when the lookup failed or was skipped
	// (private registry, a local binary). nil turns the dependency gate off.
	PackageInfo func(p registry.Pkg, remote bool) (info registry.Info, ok bool)
}

// Result is the judgment.
type Result struct {
	Decision string // what provguard returns to the agent (None in audit mode)
	Would    string // what balanced/strict would return; set in every profile
	Rule     string
	Reason   string   // technical: rule, labels and sinks (audit log, explain)
	Summary  string   // one plain sentence for the user; see Message
	Hosts    []string // egress hosts the user could add to allowed_hosts

	sinks []shell.Sink
	dest  string // untrusted_destination: the address from untrusted content
	say   string // the summary, when the rule writes its own
}

// Evaluate applies the rules and the active profile.
func Evaluate(in Input) Result {
	r := evaluate(in)
	if r.Rule != "" {
		s := in.Session
		if s == nil {
			s = &store.Session{}
		}
		r.Summary = summary(r.Rule, s, r.sinks, r.dest)
		if r.say != "" {
			r.Summary = r.say
		}
		if r.Rule == "secret_in_sink" || r.Rule == "lethal_trifecta" {
			r.Hosts = safeHosts(r.sinks, s.UntrustedValues)
		}
		// Content that hid text from the user is a deliberate attack, not
		// only an unknown source: what untrusted content would make provguard
		// ask about is blocked instead.
		if n := len(s.HiddenSources); n > 0 && r.Would == Ask && (r.Rule == "untrusted_destination" || strings.HasPrefix(r.Rule, "tainted_")) {
			kind := strings.TrimPrefix(s.HiddenSources[n-1].Reason, "hidden_text:")
			r.Would = Deny
			r.Rule += "+hidden_text"
			r.Summary += ", and that content hid text from you (" + strings.ReplaceAll(kind, "_", " ") + ")"
		}
	}
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
		if r.Would == Deny && in.Config.BlockAsks() {
			// block_mode "ask": the user decides in Claude Code's prompt.
			r.Decision = Ask
		}
	}
	return r
}

func evaluate(in Input) Result {
	rule, ruleName, ruleHit := matchRules(in)
	userRule := func() Result {
		r := result(rule.Action, ruleName, "this call matches "+ruleName, in.Sinks)
		r.say = rule.Reason
		if r.say == "" {
			r.say = "this call matches " + ruleName
		}
		return r
	}
	if len(in.Sinks) == 0 {
		if ruleHit {
			return userRule()
		}
		return Result{}
	}
	s := in.Session
	if s == nil {
		s = &store.Session{}
	}

	// 1. Secret in the call. Only for sinks that can carry data somewhere.
	if len(s.Fingerprints) > 0 && in.Key != nil && carriesData(withoutAllowed(in)) {
		if kind := secretOrPiece(in.Text, s, in.Key); kind != "" {
			return result(Deny, "secret_in_sink", fmt.Sprintf(
				"this %s call contains a secret this session read earlier (%s; matched as %s)",
				in.Tool, firstSource(s.SensitiveSources), kind), in.Sinks)
		}
	}

	// 1b. A secret inside the commits being pushed. Pushes to a trusted
	// remote skip rule 2, so without this check an agent could commit .env
	// and push it to a public repository.
	if len(s.Fingerprints) > 0 && in.Key != nil && in.OutgoingDiff != nil && hasGitPush(in.Sinks) {
		if kind := secretOrPiece(in.OutgoingDiff(), s, in.Key); kind != "" {
			return result(Deny, "secret_in_push", fmt.Sprintf(
				"the commits this push would send contain a secret this session read earlier (%s; matched as %s)",
				firstSource(s.SensitiveSources), kind), filter(in.Sinks, shell.Egress))
		}
	}

	// 1c. Hosts the user or a repository policy blocked.
	for _, x := range filter(in.Sinks, shell.Egress) {
		if h := targetHost(x.Target); h != "" && in.Config.HostBlocked(h) {
			r := result(Deny, "blocked_host", "this call sends data to "+h+", a blocked host", []shell.Sink{x})
			r.say = "this call sends data to " + h + ", which is on the blocked list"
			return r
		}
	}

	// Rules 2 and 3 need the external egress; work it out only for them,
	// because the gh repository check can ask GitHub.
	var egress []shell.Sink
	if s.Tainted && s.Sensitive || len(s.UntrustedValues) > 0 {
		egress = externalEgress(in)
	}

	// 2. Lethal trifecta.
	if len(egress) > 0 && s.Tainted && s.Sensitive {
		return result(Deny, "lethal_trifecta", fmt.Sprintf(
			"this session read untrusted content (%s) and secrets (%s), and this call can send data out",
			firstSource(s.TaintSources), firstSource(s.SensitiveSources)), egress)
	}

	// The user's, the repository's and the packs' rules come after the
	// built-in denies, so they can add checks but never hide a leak.
	if ruleHit {
		return userRule()
	}

	// 3. Egress to a destination that came from untrusted content.
	if len(egress) > 0 && len(s.UntrustedValues) > 0 {
		if v := untrustedDestination(in, egress, s.UntrustedValues); v != "" {
			r := result(Ask, "untrusted_destination", fmt.Sprintf(
				"this call sends data to %q, which came from untrusted content (%s)", v, firstSource(s.TaintSources)), egress)
			r.dest = v
			return r
		}
	}

	// 3b. Dependency gate: a package the registry does not know, or a new one.
	if r, ok := unverifiedPackage(in); ok {
		return r
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
		// The temp-folder exemption holds only in a clean session: a link
		// inside %TEMP% can point anywhere, and untrusted content can make
		// the agent create one first.
		if s.Tainted || riskyDestroy(d, in.Cwd) && !tempOnly(d, in.Text) {
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
		case strings.HasPrefix(s.Target, shell.GHRepoPrefix) && ghAllTrusted(in, strings.TrimPrefix(s.Target, shell.GHRepoPrefix)):
			continue // a pull request, issue or release in your own repository
		case isLocal(s.Target) && !in.Config.LocalhostIsExternal:
			continue // localhost: dev servers, local APIs
		case allowedTarget(in.Config, s.Target):
			continue // a destination the user listed in allowed_hosts
		}
		out = append(out, s)
	}
	return out
}

// withoutAllowed drops EGRESS sinks whose destination the user allows, so a
// secret sent to your own API (allowed_hosts) is not "a secret leaving".
func withoutAllowed(in Input) []shell.Sink {
	var out []shell.Sink
	for _, s := range in.Sinks {
		if s.Class == shell.Egress && allowedTarget(in.Config, s.Target) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// allowedTarget: the sink's destination host is in allowed_hosts (or a
// subdomain of one).
func allowedTarget(cfg config.Config, target string) bool {
	h := targetHost(target)
	return h != "" && cfg.HostAllowed(h)
}

// targetHost extracts the host from a URL, user@host:path, or host:port.
func targetHost(target string) string {
	f := strings.Fields(target)
	if len(f) == 0 {
		return ""
	}
	t := f[0]
	if u, err := url.Parse(t); err == nil && u.Host != "" {
		return strings.ToLower(u.Hostname())
	}
	// The authority comes first: in "evil.com/u@allowed.test" the host is
	// evil.com, and only the part before the first "/" can hold userinfo.
	// Taking the text after the last "@" would read the path as the host,
	// so a path ending in an allowed host would turn every egress rule off.
	t = strings.SplitN(t, "/", 2)[0]
	if i := strings.LastIndex(t, "@"); i >= 0 {
		t = t[i+1:] // user@host:path (scp, ssh)
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		t = h
	} else {
		t = strings.SplitN(t, ":", 2)[0]
	}
	if !strings.Contains(t, ".") {
		return "" // not a host name (a file, a remote name like "origin")
	}
	return strings.ToLower(t)
}

// ghEnvRe: gh reads GH_REPO, GH_HOST and other GH_* settings from the
// environment, and PATH decides which gh runs. Any GH_ text, however it is
// assembled, or setting an environment variable from PowerShell code, means
// the call may write elsewhere. (In sh, a quoted or built name is a separate
// command or an assignment, which shell.scopeGHTargets already refuses.)
var ghEnvRe = regexp.MustCompile(`(?i)gh_|setenvironmentvariable|env:\s*[a-z_]*\s*=|\$\{env:`)

// ghAllTrusted: every repository a gh call may write to is the user's.
func ghAllTrusted(in Input, list string) bool {
	repos := strings.Fields(list)
	if in.GHRepoTrusted == nil || len(repos) == 0 || ghEnvRe.MatchString(in.Text) {
		return false
	}
	for _, r := range repos {
		if !in.GHRepoTrusted(r) {
			return false
		}
	}
	return true
}

// hasGitPush: the call pushes commits. gh pr create pushes the branch
// first when it is not on the remote yet.
func hasGitPush(sinks []shell.Sink) bool {
	for _, s := range sinks {
		if strings.HasPrefix(s.Detail, "git_push") || s.Detail == "gh_pr_create" {
			return true
		}
	}
	return false
}

// gitRemote returns the remote of a "git push" target ("origin main" → "origin").
func gitRemote(target string) string {
	f := strings.Fields(target)
	if len(f) == 0 {
		return "origin"
	}
	return f[0]
}

// isLocal reports whether a sink target points to this machine. The host
// must parse as a loopback IP: a prefix test on "127." would accept
// attacker hosts such as "127.attacker.example".
func isLocal(target string) bool {
	t := strings.ToLower(strings.TrimSpace(target))
	if t == "" {
		return false
	}
	host := t
	if u, err := url.Parse(t); err == nil && u.Host != "" {
		host = u.Hostname()
	} else if h, _, err := net.SplitHostPort(strings.Split(t, "/")[0]); err == nil {
		host = h
	} else {
		host = strings.Split(t, "/")[0]
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
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
// path under cwd. When cwd is the home folder or a filesystem root there is
// no project, so nothing counts as inside it ("rm -rf Documents" from ~
// must ask).
func insideWorkspace(p, cwd string) bool {
	if !isProjectDir(cwd) {
		return false
	}
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

// isProjectDir: cwd is known and is neither the home folder (or a parent of
// it) nor a filesystem root.
// tempOnly: a recursive delete whose every target is inside the system
// temp folder, which holds throwaway files. Found live: cleaning up a test
// folder under %TEMP% asked every time.
func tempOnly(d shell.Sink, text string) bool {
	switch d.Detail {
	case "rm_recursive", "remove_item_recurse", "find_delete":
	default:
		return false
	}
	if tempRedefined.MatchString(text) {
		return false // the command points $env:TEMP somewhere else first
	}
	targets := strings.Fields(d.Target)
	if len(targets) == 0 {
		return false
	}
	for _, t := range targets {
		if !inTemp(t, os.TempDir()) {
			return false
		}
	}
	return true
}

// tempVars name the temp folder. Only PowerShell's $env: form is safe: a
// bare $TEMP or $TMP can be a variable the same command set to any folder
// (PowerShell names ignore case), and the sink does not say which shell.
var tempVars = []string{"$env:temp/", "$env:tmp/"}

// tempRedefined finds a command that sets the temp variable itself.
// Any mention of env:TEMP other than "$env:TEMP" read as a value counts, so
// forms such as ${env:TEMP} = … and Set-Item Env:TEMP … are caught too.
var tempRedefined = regexp.MustCompile(`(?i)\$env:te?mp\s*=|[^$]env:\\?te?mp\b|\$\{env:te?mp\}|setenvironmentvariable`)

// inTemp: p is strictly inside tempDir, written as a literal path (also the
// Git Bash form /c/...) or as a temp variable followed by a plain name. No
// "..", no other variables, no globs: those can leave the folder.
func inTemp(p, tempDir string) bool {
	n := strings.ReplaceAll(strings.ToLower(strings.Trim(p, `'"`)), `\`, "/")
	if strings.Contains(n, "..") || strings.ContainsAny(n, "*?[`") {
		return false
	}
	for _, v := range tempVars {
		if rest, ok := strings.CutPrefix(n, v); ok {
			return rest != "" && !strings.ContainsAny(rest, "$")
		}
	}
	if strings.Contains(n, "$") || tempDir == "" {
		return false
	}
	if len(n) > 3 && n[0] == '/' && n[2] == '/' { // Git Bash: /c/users/… → c:/users/…
		n = n[1:2] + ":" + n[2:]
	}
	t := strings.TrimSuffix(strings.ReplaceAll(strings.ToLower(tempDir), `\`, "/"), "/")
	if t == "" || t == "/" || len(t) == 2 && t[1] == ':' {
		return false
	}
	c := path.Clean(n)
	return strings.HasPrefix(c, t+"/") && c != t
}

func isProjectDir(cwd string) bool {
	c := strings.TrimSuffix(path.Clean(strings.ReplaceAll(strings.ToLower(cwd), `\`, "/")), "/")
	if c == "" || c == "." || c == "/" || len(c) == 2 && c[1] == ':' { // "", "/", "c:"
		return false
	}
	if h, err := os.UserHomeDir(); err == nil {
		hn := strings.TrimSuffix(path.Clean(strings.ReplaceAll(strings.ToLower(h), `\`, "/")), "/")
		if c == hn || strings.HasPrefix(hn, c+"/") {
			return false
		}
	}
	return true
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
	return Result{Would: would, Rule: rule, sinks: sinks,
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
