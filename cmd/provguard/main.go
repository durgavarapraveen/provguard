// Command provguard is a runtime firewall for AI coding agents.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/durgavarapraveen/provguard/internal/adapter/claudecode"
	"github.com/durgavarapraveen/provguard/internal/audit"
	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/install"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// maxPayload caps stdin. Larger tool responses are cut; the hook still logs.
const maxPayload = 64 << 20

const usage = `provguard - runtime firewall for AI coding agents (log-only)

Usage:
  provguard hook <EventName>                 run as a Claude Code hook (reads JSON on stdin)
  provguard init [--settings P] [--yes]      add hooks to Claude Code settings
  provguard uninstall [--settings P] [--yes] remove hooks from Claude Code settings
  provguard explain [session|latest] [--all]  show labels and policy hits of a session
  provguard doctor [dir] [--json]            check hooks and scan a repo before you open it
  provguard demo                             show one normal task and two attacks (safe, temp folder)
  provguard status [--session ID] [--json]   a session's trust state; use as a Claude Code status line
  provguard reset [session|latest] [--yes]    clear a session's untrusted label (user only)
  provguard allow <token>                     approve one blocked call once (user only)
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
// On an internal error it fails open, except in the strict profile, where a
// PreToolUse check that could not run is denied (fails closed).
func runHook(stdin io.Reader, stdout io.Writer, eventArg string) (code int) {
	start := time.Now()
	rec := audit.Record{Agent: claudecode.Agent, Event: eventArg, Decision: "none"}
	defer func() {
		if p := recover(); p != nil {
			rec.Error = fmt.Sprintf("panic: %v", p)
		}
		if rec.Error != "" && rec.Event == "PreToolUse" && rec.Decision == "none" {
			if home, err := audit.Home(); err == nil {
				if cfg, err := config.Load(home); err == nil && cfg.ProfileName() == config.Strict {
					respond(stdout, &rec, claudecode.Deny, "fail_closed",
						"provguard (fail_closed): the security check could not run ("+oneLine(rec.Error, 120)+"), and the strict profile blocks calls it cannot check.")
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

func runInstall(args []string, add bool) int {
	name := "uninstall"
	if add {
		name = "init"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	settings := fs.String("settings", "", "settings file (default ~/.claude/settings.json)")
	yes := fs.Bool("yes", false, "write the change (without it, only show the change)")
	noCopy := fs.Bool("no-copy", false, "init: run hooks from this binary's location instead of the protected ~/.provguard/bin copy")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	path := *settings
	if path == "" {
		p, err := install.DefaultSettingsPath()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		path = p
	}
	s, err := install.Load(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	before := install.HooksJSON(s)

	if add {
		exe, err := os.Executable()
		if err == nil {
			exe, err = filepath.EvalSymlinks(exe)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: find provguard binary:", err)
			return 1
		}
		home, err := audit.Home()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		cfg, _ := config.Load(home)
		target := exe
		if !*noCopy {
			// Hooks run the copy in ~/.provguard/bin, which agents cannot write.
			target = filepath.Join(home, "bin", "provguard"+filepath.Ext(exe))
			if *yes {
				if target, err = install.CopyBinary(exe, home); err != nil {
					fmt.Fprintln(os.Stderr, "error: copy binary:", err)
					return 1
				}
				fmt.Println("Installed binary:", target)
			}
		}
		opts := install.Options{FailClosed: cfg.ProfileName() == config.Strict}
		if err := install.AddWith(s, target, claudecode.Events, opts); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		if opts.FailClosed {
			fmt.Println("Profile is strict: PreToolUse hook fails closed (onFailure: block).")
		}
	} else if install.Remove(s) == 0 {
		fmt.Println("No provguard hooks found in", path)
		return 0
	}

	after := install.HooksJSON(s)
	fmt.Printf("Settings file: %s\n\n--- hooks before ---\n%s\n\n--- hooks after ---\n%s\n\n", path, before, after)
	if !*yes {
		fmt.Println("No change written. Run again with --yes to apply.")
		return 0
	}
	backup, err := install.Save(path, s)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if backup != "" {
		fmt.Println("Backup:", backup)
	}
	fmt.Println("Written. Claude Code reloads hook settings without a restart.")
	return 0
}
