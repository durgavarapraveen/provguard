// Command provguard is a runtime firewall for AI coding agents.
package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/durgavarapraveen/provguard/internal/adapter/claudecode"
	"github.com/durgavarapraveen/provguard/internal/audit"
	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/store"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// maxPayload caps stdin. Larger tool responses are cut; the hook still logs.
const maxPayload = 64 << 20

const usage = `provguard - runtime firewall for AI coding agents (log-only)

Usage:
  provguard hook <EventName>                 run as a Claude Code hook (reads JSON on stdin)
  provguard init [--yes] [--settings P]      guided setup; --yes installs without questions
  provguard uninstall [--settings P] [--yes] remove hooks from Claude Code settings
  provguard explain [session|latest] [--all]  show labels and policy hits of a session
  provguard doctor [dir] [--json]            check hooks and scan a repo before you open it
  provguard demo                             show one normal task and two attacks (safe, temp folder)
  provguard status [--session ID] [--json]   a session's trust state; use as a Claude Code status line
  provguard reset [session|latest] [--yes]    clear a session's untrusted label (user only)
  provguard config [setting value]           show or change settings (user only)
  provguard allow <token>                   approve one blocked call once (user only)
  provguard bench [--profiles P] [--cases IDs] [--check] [--out F] [--live --runs N --model M]
                                             run the attack benchmark
  provguard version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "hook":
		ev := ""
		if len(os.Args) > 2 {
			ev = os.Args[2]
		}
		os.Exit(runHook(os.Stdin, os.Stdout, ev))
	case "init":
		os.Exit(runInstall(os.Args[2:], true))
	case "uninstall":
		os.Exit(runInstall(os.Args[2:], false))
	case "explain":
		os.Exit(runExplain(os.Args[2:], os.Stdout))
	case "reset":
		os.Exit(runReset(os.Args[2:], os.Stdout))
	case "allow":
		os.Exit(runAllow(os.Args[2:], os.Stdout))
	case "config":
		os.Exit(runConfig(os.Args[2:], os.Stdout, os.Stderr))
	case "bench":
		os.Exit(runBench(os.Args[2:], os.Stdout))
	case "doctor":
		os.Exit(runDoctor(os.Args[2:], os.Stdout))
	case "demo":
		os.Exit(runDemo(os.Stdout))
	case "status":
		os.Exit(runStatus(os.Args[2:], os.Stdin, os.Stdout))
	case "version", "--version", "-v":
		fmt.Println("provguard", version)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

// runHook always exits 0. It prints a decision only to deny or ask; it never
// prints "allow", because that would skip the user's permission prompts.
// On an internal error it fails open, except where failClosedReason says to
// deny: the strict profile, and a balanced session that already holds both
// untrusted content and secrets.
// failClosedReason says why a PreToolUse call whose check crashed must be
// denied, or returns "" to fail open. Strict denies everything it cannot
// check. Review finding (LOW): balanced failed open on every error, so a
// crash in the check was itself a way through; it now denies once the
// session is 🔴 (untrusted content and secrets both seen), where a missed
// check is what the lethal-trifecta rule exists to stop. Audit never denies.
func failClosedReason(cfg config.Config, home, session string) string {
	switch cfg.ProfileName() {
	case config.Strict:
		return "and the strict profile blocks calls it cannot check"
	case config.Audit:
		return ""
	}
	if session == "" {
		return ""
	}
	// The store reads JSON written by earlier hooks; never panic in here,
	// because this runs inside the recover that is already handling one.
	defer func() { _ = recover() }()
	s, err := store.Get(home, session)
	if err != nil || s == nil || !s.Tainted || !s.Sensitive {
		return ""
	}
	return "and this session has read both untrusted content and secrets, so provguard does not let a call it cannot check through"
}

func runHook(stdin io.Reader, stdout io.Writer, eventArg string) (code int) {
	start := time.Now()
	rec := audit.Record{Agent: claudecode.Agent, Event: eventArg, Decision: "none"}
	defer func() {
		if p := recover(); p != nil {
			rec.Error = fmt.Sprintf("panic: %v", p)
		}
		if rec.Error != "" && rec.Event == "PreToolUse" && rec.Decision == "none" {
			if home, err := audit.Home(); err == nil {
				if cfg, err := config.Load(home); err == nil {
					if why := failClosedReason(cfg, home, rec.SessionID); why != "" {
						respond(stdout, &rec, claudecode.Deny, "fail_closed",
							"provguard (fail_closed): the security check could not run ("+oneLine(rec.Error, 120)+"), "+why+".")
					}
				}
			}
		}
		rec.Time = start
		rec.LatencyMicros = time.Since(start).Microseconds()
		if home, err := audit.Home(); err == nil {
			_ = audit.Write(home, rec)
		}
		code = 0
	}()

	raw, err := io.ReadAll(io.LimitReader(stdin, maxPayload))
	if err != nil {
		rec.Error = "read stdin: " + err.Error()
		return 0
	}
	e, err := claudecode.Parse(raw, eventArg)
	if err != nil {
		rec.Error = err.Error()
		return 0
	}
	rec = audit.FromEvent(e)
	rec.Decision = "none"
	handle(e, stdout, &rec)
	return 0
}
