package main

import (
	"io"
	"strings"
	"time"

	"github.com/durgavarapraveen/provguard/internal/adapter/claudecode"
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
// they never block the agent.
func handle(e event.Event, stdout io.Writer, rec *audit.Record) {
	home, err := audit.Home()
	if err != nil {
		rec.Error = err.Error()
		return
	}
	cfg, err := config.Load(home)
	if err != nil {
		rec.Error = err.Error() // continue with defaults
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
		r := policy.Evaluate(policy.Input{
			Tool: e.ToolName, Sinks: sinks, Text: text, Session: snap, Key: key, Config: cfg,
			Cwd: e.Cwd, RemoteTrusted: remoteTrusted(cfg, e.Cwd),
		})
		rec.Profile, rec.Would = cfg.ProfileName(), r.Would
		if r.Would != policy.None {
			rec.Rule, rec.Reason = r.Rule, r.Reason
		}
		switch r.Decision {
		case policy.Deny:
			respond(stdout, rec, claudecode.Deny, r.Rule, r.Reason)
		case policy.Ask:
			respond(stdout, rec, claudecode.Ask, r.Rule, r.Reason)
		}
	case event.PostTool, event.UserPrompt:
		if err := applyLabels(home, cfg, e, rec); err != nil {
			rec.Error = err.Error()
		}
	case event.SessionBeg:
		store.GC(home)
		if err := untrustedRepoAtStart(home, cfg, e, rec); err != nil {
			rec.Error = err.Error()
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
	return store.Update(home, e.SessionID, func(s *store.Session) error {
		now := time.Now().UTC()
		s.MarkTainted(store.Source{At: now, Tool: "ConfigChange", Reason: "config_tamper"})
		s.AddStep(store.Step{At: now, Event: e.RawEvent, Labels: []string{"untrusted:config_tamper"}})
		rec.SessionTainted = true
		return nil
	})
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
