// Command provguard is a runtime firewall for AI coding agents.
package main

import (
	"fmt"
	"github.com/durgavarapraveen/provguard/internal/redact"
	"io"
	"os"
	"time"

	"github.com/durgavarapraveen/provguard/internal/adapter"
	"github.com/durgavarapraveen/provguard/internal/adapter/core"
	"github.com/durgavarapraveen/provguard/internal/audit"
	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/event"
	"github.com/durgavarapraveen/provguard/internal/install"
	"github.com/durgavarapraveen/provguard/internal/store"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// maxPayload caps stdin. Larger tool responses are cut; the hook still logs.
const maxPayload = 64 << 20

const usage = `provguard - a runtime firewall for AI coding agents

Start here:
  provguard init                    guided setup (--yes: no questions)
  provguard demo                    see it stop two attacks, in a temp folder
  provguard status                  this session's trust state (also a status line)
  provguard review [--days N]       what it stopped, and what to do next
  provguard config [setting value]  show or change settings

When something was blocked:
  provguard allow <token>           let one blocked call through once
  provguard explain [session|latest] [--all]
                                    why a session is untrusted, and every hit
  provguard reset [session|latest] [--yes]
                                    clear a session's untrusted label

More:
  provguard check "<command>"       what provguard would do with a command (--untrusted, --secrets)
  provguard doctor [dir] [--json]   check the hooks; scan a repo before you open it
  provguard doctor --live           send a test call through each installed agent's hook
  provguard uninstall [--yes] [--now] [--keep-data]
                                    remove provguard and ~/.provguard; marked session titles are restored
  provguard bench [--check] [--profiles P] [--cases IDs] [--out F] [--live --runs N --model M]
                                    the attack and false-positive benchmark
  provguard hook <EventName>        run as a Claude Code hook (JSON on stdin)
  provguard version

Commands that change provguard (init, uninstall, config, allow, reset)
are for you, not your agent: provguard blocks agents from running them.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "hook":
		// provguard hook [--agent NAME] <event>
		args, agent := os.Args[2:], ""
		if len(args) >= 2 && args[0] == "--agent" {
			agent, args = args[1], args[2:]
		}
		ev := ""
		if len(args) > 0 {
			ev = args[0]
		}
		if ev == install.CleanupEvent {
			home, err := audit.Home()
			if err != nil {
				os.Exit(0)
			}
			os.Exit(runCleanupHook(os.Stdin, os.Stdout, home, time.Now()))
		}
		os.Exit(runHookIO(os.Stdin, os.Stdout, os.Stderr, ev, agent))
	case "init":
		os.Exit(runInstall(os.Args[2:], true))
	case "uninstall":
		os.Exit(runInstall(os.Args[2:], false))
	case "explain":
		os.Exit(runExplain(os.Args[2:], os.Stdout))
	case "reset":
		os.Exit(runReset(os.Args[2:], os.Stdout))
	case "review":
		os.Exit(runReview(os.Args[2:], os.Stdout))
	case "allow":
		os.Exit(runAllow(os.Args[2:], os.Stdout))
	case "config":
		os.Exit(runConfig(os.Args[2:], os.Stdout, os.Stderr))
	case "bench":
		os.Exit(runBench(os.Args[2:], os.Stdout))
	case "check":
		os.Exit(runCheck(os.Args[2:], os.Stdout, os.Stderr))
	case "doctor":
		os.Exit(runDoctor(os.Args[2:], os.Stdout))
	case "demo":
		os.Exit(runDemo(os.Stdout))
	case "status":
		os.Exit(runStatus(os.Args[2:], os.Stdin, os.Stdout))
	case "version", "--version", "-v":
		fmt.Println("provguard", version)
	case "help", "--help", "-h":
		fmt.Print(usage)
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
// check. Balanced denies once the session is 🔴 (untrusted content and
// secrets both seen), so a crash in the check is not a way through where a
// missed check is what the lethal-trifecta rule exists to stop. Audit never
// denies.
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

// runHook runs one hook call, picking the agent from the payload.
func runHook(stdin io.Reader, stdout io.Writer, eventArg string) int {
	return runAgentHook(stdin, stdout, eventArg, "")
}

// runAgentHook runs one hook call. agent names the sender when the hook
// command says so (--agent); otherwise the payload decides.
func runAgentHook(stdin io.Reader, stdout io.Writer, eventArg, agent string) int {
	return runHookIO(stdin, stdout, io.Discard, eventArg, agent)
}

// hookOutput is where a hook call writes, and the exit code it ends with:
// the adapter decides (most agents read JSON on stdout and exit 0; Kiro
// blocks on a non-zero exit with the reason on stderr).
type hookOutput struct {
	stdout, stderr io.Writer
	code           int
}

// countWriter counts the bytes written through it.
type countWriter struct {
	w io.Writer
	n int
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += n
	return n, err
}

// runHookIO is runAgentHook with the hook's stderr. It returns the exit
// code the agent's adapter asked for; any internal error fails open, except
// where failClosedReason says to deny.
func runHookIO(stdin io.Reader, stdout, stderr io.Writer, eventArg, agent string) (code int) {
	start := time.Now()
	written := &countWriter{w: stdout}
	out := &hookOutput{stdout: written, stderr: stderr}
	ad := adapter.Default()
	preTool := eventArg == "PreToolUse"
	rec := audit.Record{Agent: ad.Name(), Event: eventArg, Decision: "none"}
	defer func() {
		if p := recover(); p != nil {
			rec.Error = fmt.Sprintf("panic: %v", p)
		}
		if rec.Error != "" && preTool && rec.Decision == "none" {
			if home, err := audit.Home(); err == nil {
				if cfg, err := config.Load(home); err == nil {
					if why := failClosedReason(cfg, home, rec.SessionID); why != "" {
						respond(out, &rec, ad, core.Deny, "fail_closed",
							"provguard (fail_closed): the security check could not run ("+redact.OneLine(rec.Error, 120)+"), "+why+".")
					}
				}
			}
		}
		if r, ok := ad.(core.AlwaysReplies); ok && written.n == 0 && out.code == 0 {
			written.Write(r.EmptyReply())
		}
		rec.Time = start
		rec.LatencyMicros = time.Since(start).Microseconds()
		if home, err := audit.Home(); err == nil {
			_ = audit.Write(home, rec)
		}
		code = out.code
	}()

	raw, err := io.ReadAll(io.LimitReader(stdin, maxPayload))
	if err != nil {
		rec.Error = "read stdin: " + err.Error()
		return 0
	}
	ad, raw = adapter.Select(agent, raw)
	rec.Agent = ad.Name()
	e, err := ad.Parse(raw, eventArg)
	if err != nil {
		rec.Error = err.Error()
		return 0
	}
	preTool = e.Kind == event.PreTool
	rec = audit.FromEvent(e)
	rec.Decision = "none"
	handle(ad, e, out, &rec)
	return 0
}
