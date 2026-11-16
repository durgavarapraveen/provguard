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
	case "version", "--version", "-v":
		fmt.Println("provguard", version)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

// runHook always exits 0 (fail open). It prints a decision only to deny;
// it never prints "allow", because that would skip the user's permission prompts.
func runHook(stdin io.Reader, stdout io.Writer, eventArg string) (code int) {
	start := time.Now()
	rec := audit.Record{Agent: claudecode.Agent, Event: eventArg, Decision: "none"}
	defer func() {
		if p := recover(); p != nil {
			rec.Error = fmt.Sprintf("panic: %v", p)
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
		if err := install.Add(s, exe, claudecode.Events); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
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
