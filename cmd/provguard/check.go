package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/durgavarapraveen/provguard/internal/audit"
	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/event"
	"github.com/durgavarapraveen/provguard/internal/fingerprint"
	"github.com/durgavarapraveen/provguard/internal/policy"
	"github.com/durgavarapraveen/provguard/internal/protect"
	"github.com/durgavarapraveen/provguard/internal/store"
)

// checkResult is what `provguard check` reports for one command.
type checkResult struct {
	Command  string   `json:"command"`
	Profile  string   `json:"profile"`
	Decision string   `json:"decision"`        // allow, ask or deny, under Profile
	Would    string   `json:"would,omitempty"` // what protect mode would do, when Profile is audit
	Rule     string   `json:"rule,omitempty"`
	Summary  string   `json:"summary,omitempty"` // one plain sentence
	Reason   string   `json:"reason,omitempty"`  // technical: rule, labels and sinks
	Sinks    []string `json:"sinks,omitempty"`
	// Notes: checks that could not run, e.g. a package lookup that failed.
	Notes []string `json:"notes,omitempty"`
}

// runCheck judges one shell command the way the PreToolUse hook would, and
// changes nothing: no session, audit log or allow-once token is written.
// Exit code: 0 allowed, 1 provguard would ask or deny, 2 usage error.
func runCheck(args []string, w, errOut io.Writer) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(errOut)
	shellName := fs.String("shell", "auto", "bash, powershell or auto (both readings on Windows, bash elsewhere)")
	untrusted := fs.Bool("untrusted", false, "judge as if the session had read untrusted content")
	secrets := fs.Bool("secrets", false, "judge as if the session had read secrets")
	sessionID := fs.String("session", "", "judge in a real session's state (read only)")
	profile := fs.String("profile", "", "balanced, strict or audit (default: your configured mode)")
	cwd := fs.String("cwd", "", "working folder of the command (default: this folder)")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	fs.Usage = func() {
		fmt.Fprint(errOut, "Usage: provguard check [flags] \"<command>\"\n\nShows what provguard would do with a shell command, without running it.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cmd := strings.Join(fs.Args(), " ")
	if strings.TrimSpace(cmd) == "" {
		fs.Usage()
		return 2
	}
	tool, ok := map[string]string{"bash": "Bash", "powershell": "PowerShell", "auto": event.ShellTool}[*shellName]
	if !ok {
		fmt.Fprintf(errOut, "provguard: unknown shell %q (use bash, powershell or auto)\n", *shellName)
		return 2
	}
	if tool == event.ShellTool && runtime.GOOS != "windows" {
		tool = "Bash"
	}
	if *cwd == "" {
		*cwd, _ = os.Getwd()
	}
	home, err := audit.Home()
	if err != nil {
		fmt.Fprintln(errOut, "provguard:", err)
		return 2
	}
	cfg, err := config.Load(home)
	if err != nil {
		fmt.Fprintln(errOut, "provguard:", err)
		return 2
	}
	if *profile != "" {
		if err := cfg.SetProfile(*profile); err != nil {
			fmt.Fprintln(errOut, "provguard:", err)
			return 2
		}
	}

	// The repository policy applies after --profile: it can only raise the mode.
	if c, err := cfg.WithRepoPolicy(*cwd); err != nil {
		fmt.Fprintln(errOut, "provguard:", err)
	} else {
		cfg = c
	}

	sess := &store.Session{}
	if *sessionID != "" {
		id, err := resolveSession(home, *sessionID)
		if err == nil {
			sess, err = store.Get(home, id)
		}
		if err != nil {
			fmt.Fprintln(errOut, "provguard:", err)
			return 2
		}
	}
	if *untrusted {
		sess.Tainted = true
		sess.TaintSources = append(sess.TaintSources, store.Source{Tool: "check", Reason: "--untrusted"})
	}
	if *secrets {
		sess.Sensitive = true
		sess.SensitiveSources = append(sess.SensitiveSources, store.Source{Tool: "check", Reason: "--secrets"})
	}

	e := event.Event{Agent: "check", Kind: event.PreTool, RawEvent: "PreToolUse", ToolName: tool,
		ToolInput: map[string]any{"command": cmd}, Cwd: *cwd}
	r := judge(e, home, cfg, sess)
	r.Command = cmd
	if *asJSON {
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
	} else {
		printCheck(w, r)
	}
	if r.Decision == "allow" && r.Would == "" {
		return 0
	}
	return 1
}

// judge runs self-protection and the policy on a PreToolUse event, without
// side effects.
func judge(e event.Event, home string, cfg config.Config, sess *store.Session) checkResult {
	r := checkResult{Profile: cfg.ProfileName(), Decision: "allow"}
	an, sinks, text := callSinks(e, cfg)
	for _, s := range sinks {
		r.Sinks = append(r.Sinks, s.String())
	}
	if cfg.SelfProtectOn() {
		if v := protect.Check(e, home, an); v.Deny {
			r.Decision, r.Rule, r.Summary, r.Reason = "deny", v.Rule, v.Reason, v.Reason
			return r
		}
	}
	var key fingerprint.Key
	if len(sess.Fingerprints) > 0 {
		key, _ = fingerprint.LoadOrCreate(home)
	}
	res := policy.Evaluate(policy.Input{
		Tool: e.ToolName, Sinks: sinks, Cmds: cmdsOf(an), Text: text, Session: sess, Key: key, Config: cfg,
		Cwd: e.Cwd, RemoteTrusted: remoteTrusted(cfg, e.Cwd),
		// The same package check as the hook (only the registry cache is
		// written). A failed lookup lets the call run there, so it is a note.
		PackageInfo: packageInfo(cfg, home, e.Cwd, text, func(err error) {
			r.Notes = append(r.Notes, "package lookup failed, so the package check did not run: "+err.Error())
		}),
	})
	if res.Decision != policy.None {
		r.Decision = res.Decision
	} else if res.Would != policy.None {
		r.Would = res.Would // audit mode: logged, not enforced
	}
	if res.Rule != "" {
		r.Rule, r.Summary, r.Reason = res.Rule, res.Summary, res.Reason
	}
	return r
}

func printCheck(w io.Writer, r checkResult) {
	verdict := map[string]string{"allow": "✔ allowed", "ask": "? asks you first", "deny": "✘ blocked"}[r.Decision]
	fmt.Fprintf(w, "%s  (mode: %s)\n", verdict, r.Profile)
	if r.Would != "" {
		fmt.Fprintf(w, "  Protect mode would %s this call. Watch-only mode logs it.\n", r.Would)
	}
	if r.Rule != "" {
		fmt.Fprintf(w, "  Why:     %s\n  Rule:    %s\n", r.Summary, r.Rule)
	}
	if len(r.Sinks) > 0 {
		fmt.Fprintf(w, "  Reaches: %s\n", strings.Join(r.Sinks, ", "))
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "  Note:    %s\n", n)
	}
}
