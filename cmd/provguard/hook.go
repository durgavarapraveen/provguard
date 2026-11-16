package main

import (
	"io"
	"strings"
	"time"

	"github.com/durgavarapraveen/provguard/internal/adapter/claudecode"
	"github.com/durgavarapraveen/provguard/internal/audit"
	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/event"
	"github.com/durgavarapraveen/provguard/internal/fingerprint"
	"github.com/durgavarapraveen/provguard/internal/label"
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
		if e.ToolName == "Bash" || e.ToolName == "PowerShell" {
			d := shell.Bash
			if e.ToolName == "PowerShell" {
				d = shell.PowerShell
			}
			cmd, _ := e.ToolInput["command"].(string)
			an = shell.Analyze(cmd, d)
			rec.Sinks = an.SinkStrings()
		}
		if !cfg.SelfProtectOn() {
			return
		}
		if v := protect.Check(e, home, an); v.Deny {
			out, err := claudecode.PreToolResponse(claudecode.Deny, v.Reason)
			if err != nil {
				rec.Error = err.Error()
				return
			}
			if _, err := stdout.Write(out); err != nil {
				rec.Error = err.Error()
				return
			}
			rec.Decision, rec.Rule = "deny", v.Rule
		}
	case event.PostTool, event.UserPrompt:
		if err := applyLabels(home, cfg, e, rec); err != nil {
			rec.Error = err.Error()
		}
	case event.SessionBeg:
		store.GC(home)
	}
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
