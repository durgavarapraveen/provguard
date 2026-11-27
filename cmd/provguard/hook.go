package main

import (
	"context"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/durgavarapraveen/provguard/internal/adapter/claudecode"
	"github.com/durgavarapraveen/provguard/internal/adapter/core"
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
// they never block the agent. ad writes every answer in the agent's own
// format: decisions on tool calls, and a one-time notice or a new session
// title when the session's trust state changed.
func handle(ad core.Adapter, e event.Event, out *hookOutput, rec *audit.Record) {
	var newTitle string
	defer func() {
		if e.Kind == event.PreTool {
			return // tool calls get only decisions (respond)
		}
		if b := ad.Feedback(e, rec.Notice, newTitle); b != nil {
			out.stdout.Write(b)
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
	// A repository's own policy can only add checks (config.RepoPolicy).
	if c, err := cfg.WithRepoPolicy(e.Cwd); err != nil {
		rec.Error = err.Error()
	} else {
		cfg = c
	}
	// SessionStart and UserPromptSubmit may retitle the session: put the trust
	// icon in front, so untrusted sessions stand out in the session list.
	if (e.Kind == event.SessionBeg || e.Kind == event.UserPrompt) && cfg.TitleIconOn() {
		defer func() {
			if s, err := store.Get(home, e.SessionID); err == nil {
				newTitle = titleWithIcon(e.Title, s.Tainted, s.Sensitive)
				// Remember marked titles, so uninstall can restore them.
				final := e.Title
				if newTitle != "" {
					final = newTitle
				}
				if strings.TrimSpace(final) != "" {
					markTitled(home, e.SessionID, final)
				}
			}
		}()
	}
	if e.Kind == event.SessionBeg || e.Kind == event.UserPrompt {
		noteSession(home, e)
	}

	switch e.Kind {
	case event.PreTool:
		an, sinks, text := callSinks(e, cfg)
		for _, s := range sinks {
			rec.Sinks = append(rec.Sinks, s.String())
		}

		// Self-protection runs in every profile, including audit.
		if cfg.SelfProtectOn() {
			if v := protect.Check(e, home, an); v.Deny {
				respond(out, rec, ad, core.Deny, v.Rule, v.Reason)
				return
			}
		}
		if len(sinks) == 0 && len(cfg.Rules) == 0 && len(cfg.Packs) == 0 {
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
			Tool: e.ToolName, Sinks: sinks, Cmds: cmdsOf(an), Text: text, Session: snap, Key: key, Config: cfg,
			Cwd: e.Cwd, RemoteTrusted: remoteTrusted(cfg, e.Cwd),
			GHRepoTrusted: ghRepoTrusted(cfg, e.Cwd, ghRepoView),
			PackageInfo: packageInfo(cfg, home, e.Cwd, text, func(err error) {
				rec.Error = "package lookup: " + err.Error() // allowed: the registry did not answer
			}),
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
		if r.Decision == policy.Ask && !ad.CanAsk() {
			// An agent that ignores "ask" would run the call, so it gets a
			// deny; the message offers provguard allow for the one call the
			// user wants.
			r.Decision = policy.Deny
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
		d := map[string]core.Decision{policy.Deny: core.Deny, policy.Ask: core.Ask}[r.Decision]
		respond(out, rec, ad, d, r.Rule, policy.Message(r, r.Decision, token))
		rec.Reason = r.Reason // the log keeps the technical reason
	case event.PostTool, event.UserPrompt:
		if err := applyLabels(home, cfg, e, rec); err != nil {
			rec.Error = err.Error()
		}
		if e.Kind == event.PostTool {
			warnClonedRepo(e, rec)
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
		if err := riskyInstructionsAtStart(home, e, rec); err != nil {
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

// cmdsOf returns the analyzed shell commands, or nil for other tools.
func cmdsOf(an *shell.Analysis) []shell.Cmd {
	if an == nil {
		return nil
	}
	return an.Cmds
}

// callSinks reads a tool call: the shell analysis (for shell commands), the
// sinks the call can reach, and the text matched against secrets.
func callSinks(e event.Event, cfg config.Config) (*shell.Analysis, []shell.Sink, string) {
	if e.ToolName == "Bash" || e.ToolName == "PowerShell" {
		d := shell.Bash
		if e.ToolName == "PowerShell" {
			d = shell.PowerShell
		}
		text, _ := e.ToolInput["command"].(string)
		an := shell.Analyze(text, d)
		return an, an.Sinks, text
	}
	if cmd, ok := label.CommandTool(e); ok {
		// A shell command whose shell is not known (an MCP terminal tool,
		// Cursor's Shell): both readings count.
		an := shell.AnalyzeUnknown(cmd)
		return an, an.Sinks, cmd
	}
	sinks, text := policy.ToolSinks(e, cfg)
	return nil, sinks, text
}

// configChanged re-checks hook integrity when settings change mid-session
// (agents reload settings edits at once). It cannot undo the change, so it
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

// transitionNotice describes a session that just became untrusted or
// sensitive, or returns "" when nothing new happened.
func transitionNotice(wasT, wasS, wasH bool, s *store.Session) string {
	reason := func(src []store.Source) string {
		if len(src) == 0 {
			return "unknown"
		}
		return src[len(src)-1].Tool + ": " + src[len(src)-1].Reason
	}
	if len(s.HiddenSources) > 0 && !wasH {
		src := s.HiddenSources[len(s.HiddenSources)-1]
		return "provguard: 🟡 content from " + src.Tool + " hides text from you (" + label.HiddenKindText(src.Reason) +
			"), a common way to slip instructions to an agent. This session is UNTRUSTED, and risky actions are now blocked, not only asked."
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
		wasT, wasS, wasH := s.Tainted, s.Sensitive, len(s.HiddenSources) > 0
		defer func() { rec.Notice = transitionNotice(wasT, wasS, wasH, s) }()
		now := time.Now().UTC()
		s.MarkTainted(store.Source{At: now, Tool: "SessionStart", Reason: reason})
		s.AddStep(store.Step{At: now, Event: e.RawEvent, Labels: rec.Labels})
		rec.SessionTainted = true
		return nil
	})
}

// riskyInstructionsAtStart marks a session untrusted when an instruction file
// that the agent loads without a tool call (CLAUDE.md, AGENTS.md, …) hides
// text or carries a strong sign of an attack. No hook sees those files load,
// so this is the one chance to check them. Hidden text also escalates the
// risky-action rules to deny, as it does for content read later.
func riskyInstructionsAtStart(home string, e event.Event, rec *audit.Record) error {
	if e.Cwd == "" || e.SessionID == "" {
		return nil
	}
	file, hidden, what := doctor.InstructionRisk(label.RepoRoot(e.Cwd+"/x"), e.Cwd)
	if file == "" {
		return nil
	}
	reason := "instruction_file:" + filepath.Base(file) + ":" + strings.ReplaceAll(what, " ", "_")
	if hidden != "" {
		reason = "hidden_text:" + hidden
	}
	rec.Labels = append(rec.Labels, "untrusted:"+reason)
	return store.Update(home, e.SessionID, func(s *store.Session) error {
		wasT, wasS, wasH := s.Tainted, s.Sensitive, len(s.HiddenSources) > 0
		defer func() {
			if n := transitionNotice(wasT, wasS, wasH, s); n != "" {
				rec.Notice = n + " (" + file + ")"
			}
		}()
		now := time.Now().UTC()
		src := store.Source{At: now, Tool: "SessionStart", Reason: reason}
		if hidden != "" {
			src.Reason = hidden
			s.MarkHidden(src)
		} else {
			s.MarkTainted(src)
		}
		s.AddStep(store.Step{At: now, Event: e.RawEvent, Labels: []string{"untrusted:" + reason}})
		rec.SessionTainted = true
		return nil
	})
}

// warnClonedRepo checks a repo the agent just cloned. A repo whose settings
// set disableAllHooks turns provguard off when you open it, before any hook
// can run, so this is the last moment provguard can say so.
func warnClonedRepo(e event.Event, rec *audit.Record) {
	cmd, _ := e.ToolInput["command"].(string)
	if !strings.Contains(cmd, "clone") {
		return
	}
	d := shell.Bash
	if e.ToolName == "PowerShell" {
		d = shell.PowerShell
	}
	an := shell.Analyze(cmd, d)
	for _, dir := range clonedDirs(an, e.Cwd) {
		for _, f := range doctor.RepoSettings(dir) {
			if f.Severity != doctor.High {
				continue
			}
			rec.Labels = append(rec.Labels, "cloned_repo_turns_hooks_off")
			n := "provguard: ⚠ the repo just cloned to " + dir + " turns provguard off when you open it (" + f.Message +
				"). Do not open it in an agent until you have checked " + filepath.Join(dir, ".claude") + "."
			if rec.Notice != "" {
				n = rec.Notice + " " + n
			}
			rec.Notice = n
			return
		}
	}
}

// clonedDirs: the folders `git clone` writes in a command.
func clonedDirs(an *shell.Analysis, cwd string) []string {
	var out []string
	for _, d := range an.Cds { // cd /src && git clone …
		if filepath.IsAbs(d) {
			cwd = d
		} else {
			cwd = filepath.Join(cwd, d)
		}
	}
	for _, c := range an.Cmds {
		if c.Name != "git" {
			continue
		}
		args := c.Args[1:]
		i := 0
		for i < len(args) && strings.HasPrefix(args[i], "-") { // git -C dir clone …
			if args[i] == "-C" || args[i] == "-c" {
				i++
			}
			i++
		}
		if i >= len(args) || args[i] != "clone" {
			continue
		}
		var plain []string
		for j := i + 1; j < len(args); j++ {
			a := args[j]
			switch {
			case a == "-b" || a == "--branch" || a == "--depth" || a == "-o" || a == "--origin" || a == "-c" || a == "--config" || a == "--reference":
				j++
			case strings.HasPrefix(a, "-"):
			default:
				plain = append(plain, a)
			}
		}
		if len(plain) == 0 {
			continue
		}
		dir := ""
		if len(plain) > 1 {
			dir = plain[1]
		} else {
			u := strings.TrimSuffix(strings.TrimRight(plain[0], "/\\"), ".git")
			dir = u[strings.LastIndexAny(u, "/\\:")+1:]
		}
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(cwd, dir)
		}
		out = append(out, dir)
	}
	return out
}

// respond gives a decision on a tool call in the agent's format (stdout,
// stderr and exit code, as its adapter says) and records it.
func respond(out *hookOutput, rec *audit.Record, ad core.Adapter, d core.Decision, rule, reason string) {
	r, err := ad.Reply(d, reason)
	if err == nil && len(r.Stdout) > 0 {
		_, err = out.stdout.Write(r.Stdout)
	}
	if err == nil && r.Stderr != "" {
		_, err = io.WriteString(out.stderr, r.Stderr)
	}
	if err != nil {
		rec.Error = err.Error()
		return
	}
	out.code = r.ExitCode
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
		// Save a clean session once, so `status` can tell it from one that
		// no provguard hook has seen ("not tracked").
		if e.SessionID != "" && !store.Exists(home, e.SessionID) {
			return store.Update(home, e.SessionID, func(*store.Session) error { return nil })
		}
		return nil
	}

	var key fingerprint.Key
	var keyErr error
	if len(res.Secrets) > 0 {
		key, keyErr = fingerprint.LoadOrCreate(home)
	}
	return store.Update(home, e.SessionID, func(s *store.Session) error {
		wasT, wasS, wasH := s.Tainted, s.Sensitive, len(s.HiddenSources) > 0
		defer func() { rec.Notice = transitionNotice(wasT, wasS, wasH, s) }()
		for k, v := range snap.RepoOwners {
			if s.RepoOwners == nil {
				s.RepoOwners = map[string]string{}
			}
			s.RepoOwners[k] = v
		}
		now := time.Now().UTC()
		if res.Hidden != "" {
			s.MarkHidden(store.Source{At: now, Tool: e.ToolName, Reason: "hidden_text:" + res.Hidden}) // the kind, not the first untrusted reason: the notice names it
		}
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
				s.AddChunks(key.Chunks(m.Value)...)
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
