package main

import (
	"context"
	"encoding/json"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/durgavarapraveen/provguard/internal/adapter/claudecode"
	"github.com/durgavarapraveen/provguard/internal/allowonce"
	"github.com/durgavarapraveen/provguard/internal/audit"
	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/doctor"
	"github.com/durgavarapraveen/provguard/internal/event"
	"github.com/durgavarapraveen/provguard/internal/fingerprint"
	"github.com/durgavarapraveen/provguard/internal/install"
	"github.com/durgavarapraveen/provguard/internal/label"
	"github.com/durgavarapraveen/provguard/internal/policy"
	"github.com/durgavarapraveen/provguard/internal/protect"
	"github.com/durgavarapraveen/provguard/internal/shell"
	"github.com/durgavarapraveen/provguard/internal/store"
)

// handle runs the per-event logic and fills rec. Errors go to rec.Error;
// they never block the agent. A non-PreToolUse event whose labels changed
// prints a one-time notice for the user (Claude Code's "systemMessage").
func handle(e event.Event, stdout io.Writer, rec *audit.Record) {
	var newTitle string
	defer func() {
		if e.Kind == event.PreTool {
			return // PreToolUse prints only decisions (respond)
		}
		out := map[string]any{}
		if rec.Notice != "" {
			out["systemMessage"] = rec.Notice
		}
		if newTitle != "" {
			out["hookSpecificOutput"] = map[string]any{"hookEventName": e.RawEvent, "sessionTitle": newTitle}
		}
		if len(out) > 0 {
			b, _ := json.Marshal(out)
			stdout.Write(b)
		}
	}()
	home, err := audit.Home()
	if err != nil {
		rec.Error = err.Error()
		return
	}
	cfg, err := config.Load(home)
	if err != nil {
		rec.Error = err.Error() + " (using the balanced profile until it is fixed)"
		cfg = config.FailSafe()
	}
	// SessionStart and UserPromptSubmit may retitle the session: put the trust
	// icon in front, so untrusted sessions stand out in the session list.
	if (e.Kind == event.SessionBeg || e.Kind == event.UserPrompt) && cfg.TitleIconOn() {
		defer func() {
			if s, err := store.Get(home, e.SessionID); err == nil {
				newTitle = titleWithIcon(e.Title, s.Tainted, s.Sensitive)
			}
		}()
	}

	switch e.Kind {
	case event.PreTool:
		var an *shell.Analysis
		var sinks []shell.Sink
		var text string
		if e.ToolName == "Bash" || e.ToolName == "PowerShell" {
			d := shell.Bash
			if e.ToolName == "PowerShell" {
				d = shell.PowerShell
			}
			text, _ = e.ToolInput["command"].(string)
			an = shell.Analyze(text, d)
			sinks = an.Sinks
		} else if cmd, ok := label.CommandTool(e); ok {
			// MCP tools that run shell commands (e.g. the desktop app's
			// terminal tool): unknown shell, so both readings count.
			text = cmd
			an = shell.AnalyzeUnknown(cmd)
			sinks = an.Sinks
		} else {
			sinks, text = policy.ToolSinks(e, cfg)
		}
		for _, s := range sinks {
			rec.Sinks = append(rec.Sinks, s.String())
		}

		// Self-protection runs in every profile, including audit.
		if cfg.SelfProtectOn() {
			if v := protect.Check(e, home, an); v.Deny {
				respond(stdout, rec, claudecode.Deny, v.Rule, v.Reason)
				return
			}
		}
		if len(sinks) == 0 {
			return
		}
		snap, err := store.Get(home, e.SessionID)
		if err != nil {
			rec.Error = err.Error()
			return
		}
		var key fingerprint.Key
		if len(snap.Fingerprints) > 0 {
			key, _ = fingerprint.LoadOrCreate(home)
		}
		in := policy.Input{
			Tool: e.ToolName, Sinks: sinks, Text: text, Session: snap, Key: key, Config: cfg,
			Cwd: e.Cwd, RemoteTrusted: remoteTrusted(cfg, e.Cwd),
			GHRepoTrusted: ghRepoTrusted(cfg, e.Cwd, ghRepoView),
		}
		if key != nil && e.Cwd != "" {
			in.OutgoingDiff = gitOutgoingDiff(e.Cwd)
		}
		r := policy.Evaluate(in)
		rec.Profile, rec.Would = cfg.ProfileName(), r.Would
		if r.Would != policy.None {
			rec.Rule, rec.Reason = r.Rule, r.Reason
		}
		if r.Decision == policy.None {
			return
		}
		// The user can let this exact call through once (provguard allow).
		// Only a deny gets a token: an ask is already the user's choice.
		token := ""
		if key == nil {
			key, _ = fingerprint.LoadOrCreate(home)
		}
		if key != nil {
			tok := allowonce.Token(key, e.SessionID, e.ToolName, text)
			if allowonce.Consume(home, tok, time.Now()) {
				rec.Override = "allow_once:" + tok
				return
			}
			if r.Decision == policy.Deny && allowonce.Record(home, tok, allowonce.Pending{
				Session: e.SessionID, Tool: e.ToolName, Command: text, Rule: r.Rule, Time: time.Now(),
			}) == nil {
				token = tok
			}
		}
		d := map[string]claudecode.Decision{policy.Deny: claudecode.Deny, policy.Ask: claudecode.Ask}[r.Decision]
		respond(stdout, rec, d, r.Rule, policy.Message(r, r.Decision, token))
		rec.Reason = r.Reason // the log keeps the technical reason
	case event.PostTool, event.UserPrompt:
		if err := applyLabels(home, cfg, e, rec); err != nil {
			rec.Error = err.Error()
		}
	case event.SessionBeg:
		store.GC(home)
		allowonce.GC(home, time.Now())
		days := cfg.AuditRetentionDays
		if days == 0 {
			days = audit.DefaultRetentionDays
		}
		audit.GC(home, days, time.Now())
		if err := untrustedRepoAtStart(home, cfg, e, rec); err != nil {
			rec.Error = err.Error()
		}
		if rec.Notice == "" {
			rec.Notice = auditNudge(home, cfg, time.Now())
		}
	default:
		if e.RawEvent == "ConfigChange" {
			if err := configChanged(home, e, rec); err != nil {
				rec.Error = err.Error()
			}
		}
	}
}

// configChanged re-checks hook integrity when settings change mid-session
// (finding F4: edits take effect at once). It cannot undo the change, so it
// records tampering and marks the session untrusted.
func configChanged(home string, e event.Event, rec *audit.Record) error {
	settings, err := install.DefaultSettingsPath()
	if err != nil {
		return err
	}
	var problems []string
	for _, f := range doctor.HookIntegrity(doctor.Options{Home: home, UserSettings: settings, Repo: e.Cwd, Events: claudecode.Events}) {
		if f.Severity == doctor.High {
			problems = append(problems, f.Message)
		}
	}
	if len(problems) == 0 || e.SessionID == "" {
		return nil
	}
	rec.Rule, rec.Labels = "config_tamper", problems
	rec.Notice = "provguard: hook settings changed during this session (" + strings.Join(problems, "; ") + "). The session is now marked untrusted."
	return store.Update(home, e.SessionID, func(s *store.Session) error {
		now := time.Now().UTC()
		s.MarkTainted(store.Source{At: now, Tool: "ConfigChange", Reason: "config_tamper"})
		s.AddStep(store.Step{At: now, Event: e.RawEvent, Labels: []string{"untrusted:config_tamper"}})
		rec.SessionTainted = true
		return nil
	})
}

// maxDiff caps the patch text scanned for secrets before a push.
const maxDiff = 2 << 20

// gitOutgoingDiff returns a function that lists the commits a push from cwd
// would send: commits not on the upstream, or the last 20 for a new branch.
func gitOutgoingDiff(cwd string) func() string {
	return func() string {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		run := func(args ...string) (string, error) {
			cmd := exec.CommandContext(ctx, "git", append([]string{"-C", cwd, "log", "-p", "--no-color", "--no-ext-diff"}, args...)...)
			out, err := cmd.Output()
			if len(out) > maxDiff {
				out = out[:maxDiff]
			}
			return string(out), err
		}
		if out, err := run("@{upstream}..HEAD"); err == nil {
			return out
		}
		out, _ := run("-n", "20")
		return out
	}
}

var titleIcons = []string{"🔴 ", "🟡 ", "🟠 ", "🟢 "}

// titleWithIcon returns the title with the icon for the session's state in
// front, or "" when no change is needed. A session without a title is left
// alone, so the app still names it from the first prompt.
func titleWithIcon(current string, tainted, sensitive bool) string {
	if strings.TrimSpace(current) == "" {
		return ""
	}
	base := current
	for again := true; again; {
		again = false
		for _, ic := range titleIcons {
			if strings.HasPrefix(base, ic) {
				base, again = strings.TrimPrefix(base, ic), true
			}
		}
	}
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

// transitionNotice describes a session that just became untrusted or
// sensitive, or returns "" when nothing new happened.
func transitionNotice(wasT, wasS bool, s *store.Session) string {
	reason := func(src []store.Source) string {
		if len(src) == 0 {
			return "unknown"
		}
		return src[len(src)-1].Tool + ": " + src[len(src)-1].Reason
	}
	switch {
	case s.Tainted && s.Sensitive && (!wasT || !wasS):
		last := reason(s.SensitiveSources)
		if !wasT {
			last = reason(s.TaintSources)
		}
		return "provguard: 🔴 this session has now read untrusted content AND secrets. Sending data out is blocked (balanced/strict). Last: " + last
	case s.Tainted && !wasT:
		return "provguard: 🟡 this session is now UNTRUSTED (" + reason(s.TaintSources) + "). Risky actions will ask first."
	case s.Sensitive && !wasS:
		return "provguard: 🟠 this session has now seen SECRETS (" + reason(s.SensitiveSources) + ")."
	}
	return ""
}

// remoteTrusted returns a lookup: does a git remote (name or URL) of the repo
// at cwd belong to a trusted owner?
func remoteTrusted(cfg config.Config, cwd string) func(string) bool {
	if len(cfg.TrustedRepoOwners) == 0 {
		return nil
	}
	return func(remote string) bool {
		owner := ""
		if strings.Contains(remote, "://") || strings.Contains(remote, "@") {
			owner = label.URLOwner(remote)
		} else if root := label.RepoRoot(cwd + "/x"); root != "" {
			owner = label.RemoteOwner(root, remote)
		}
		return owner != "" && cfg.RepoOwnerTrusted(owner)
	}
}

// untrustedRepoAtStart marks a session untrusted when it starts in a repo whose
// origin owner is not trusted. Claude Code loads that repo's CLAUDE.md /
// AGENTS.md into context without a tool call, so no later hook would see it
// (benchmark case 08).
func untrustedRepoAtStart(home string, cfg config.Config, e event.Event, rec *audit.Record) error {
	if len(cfg.TrustedRepoOwners) == 0 || e.Cwd == "" || e.SessionID == "" {
		return nil
	}
	root := label.RepoRoot(e.Cwd + "/x")
	if root == "" {
		return nil
	}
	owner := label.OriginOwner(root)
	if owner == "" || cfg.RepoOwnerTrusted(owner) {
		return nil
	}
	reason := "repo_owner_at_start:" + owner
	rec.Labels = []string{"untrusted:" + reason}
	return store.Update(home, e.SessionID, func(s *store.Session) error {
		wasT, wasS := s.Tainted, s.Sensitive
		defer func() { rec.Notice = transitionNotice(wasT, wasS, s) }()
		now := time.Now().UTC()
		s.MarkTainted(store.Source{At: now, Tool: "SessionStart", Reason: reason})
		s.AddStep(store.Step{At: now, Event: e.RawEvent, Labels: rec.Labels})
		rec.SessionTainted = true
		return nil
	})
}

// respond prints a PreToolUse decision and records it.
func respond(stdout io.Writer, rec *audit.Record, d claudecode.Decision, rule, reason string) {
	out, err := claudecode.PreToolResponse(d, reason)
	if err == nil {
		_, err = stdout.Write(out)
	}
	if err != nil {
		rec.Error = err.Error()
		return
	}
	rec.Decision, rec.Rule, rec.Reason = string(d), rule, reason
}

// applyLabels labels the event. Fast path: most events change nothing, so it
// reads the session without the lock and writes only when there is news.
func applyLabels(home string, cfg config.Config, e event.Event, rec *audit.Record) error {
	snap, err := store.Get(home, e.SessionID)
	if err != nil {
		return err
	}
	ownersBefore := len(snap.RepoOwners)
	env := label.Env{
		Config:       cfg,
		AgentTainted: snap.AgentTainted,
		RepoOwner:    func(f string) string { return repoOwner(snap, f) },
	}
	var res label.Result
	if e.Kind == event.UserPrompt {
		res = label.Prompt(e)
	} else {
		res = label.Post(e, env)
	}
	rec.Labels = res.Labels()
	rec.SessionTainted, rec.SessionSensitive = snap.Tainted, snap.Sensitive

	newOwners := len(snap.RepoOwners) > ownersBefore
	if !res.Untrusted && !res.Sensitive && len(res.Secrets) == 0 && !newOwners {
		return nil
	}

	var key fingerprint.Key
	var keyErr error
	if len(res.Secrets) > 0 {
		key, keyErr = fingerprint.LoadOrCreate(home)
	}
	return store.Update(home, e.SessionID, func(s *store.Session) error {
		wasT, wasS := s.Tainted, s.Sensitive
		defer func() { rec.Notice = transitionNotice(wasT, wasS, s) }()
		for k, v := range snap.RepoOwners {
			if s.RepoOwners == nil {
				s.RepoOwners = map[string]string{}
			}
			s.RepoOwners[k] = v
		}
		now := time.Now().UTC()
		if res.Untrusted {
			s.MarkTainted(store.Source{At: now, Tool: e.ToolName, Reason: res.UntrustedReason})
			s.AddValues(res.Values...)
			if e.AgentID != "" {
				s.AddTaintedAgent(e.AgentID)
			}
		}
		if res.Sensitive {
			s.MarkSensitive(store.Source{At: now, Tool: e.ToolName, Reason: res.SensitiveReason})
		}
		if keyErr == nil && key != nil {
			for _, m := range res.Secrets {
				s.AddFingerprints(key.Of(m.Value))
			}
		}
		if labels := res.Labels(); len(labels) > 0 {
			s.AddStep(store.Step{At: now, Event: e.RawEvent, Tool: e.ToolName, Labels: labels})
		}
		rec.SessionTainted, rec.SessionSensitive = s.Tainted, s.Sensitive
		if keyErr != nil {
			rec.Error = "fingerprint key: " + keyErr.Error()
		}
		return nil
	})
}

// repoOwner looks up a file's repo owner, cached per repo root in the session.
func repoOwner(s *store.Session, file string) string {
	root := label.RepoRoot(file)
	if root == "" {
		return ""
	}
	k := strings.ToLower(root)
	if o, ok := s.RepoOwners[k]; ok {
		return o
	}
	if s.RepoOwners == nil {
		s.RepoOwners = map[string]string{}
	}
	o := label.OriginOwner(root)
	s.RepoOwners[k] = o
	return o
}
