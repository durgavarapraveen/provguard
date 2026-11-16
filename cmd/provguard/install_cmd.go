package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/durgavarapraveen/provguard/internal/adapter/claudecode"
	"github.com/durgavarapraveen/provguard/internal/audit"
	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/doctor"
	"github.com/durgavarapraveen/provguard/internal/install"
)

// installRun holds what init and uninstall need. Fields are explicit so tests
// can run the commands without a terminal or the real home folder.
type installRun struct {
	settings    string // Claude Code settings file
	home        string // provguard home
	exe         string // the binary the hooks should run (before copying)
	write       bool   // --yes, or the user confirmed in the guided setup
	copyBinary  bool   // copy exe to <home>/bin (default)
	interactive bool   // ask the setup questions
	in          io.Reader
	out, errOut io.Writer
	detectUser  func() string // the user's GitHub name, "" if unknown
}

// runInstall parses init/uninstall flags. On a terminal, `provguard init`
// without --yes runs the guided setup; without a terminal it only shows the
// change (so scripts and CI never block on a question).
func runInstall(args []string, add bool) int {
	name := map[bool]string{true: "init", false: "uninstall"}[add]
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	settings := fs.String("settings", "", "settings file (default ~/.claude/settings.json)")
	yes := fs.Bool("yes", false, "write the change without questions")
	noCopy := fs.Bool("no-copy", false, "init: run hooks from this binary's location instead of the protected ~/.provguard/bin copy")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	r := installRun{
		settings: *settings, write: *yes, copyBinary: !*noCopy,
		interactive: add && !*yes && isTerminal(os.Stdin),
		in:          os.Stdin, out: os.Stdout, errOut: os.Stderr,
		detectUser: detectGitHubUser,
	}
	if r.settings == "" {
		p, err := install.DefaultSettingsPath()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		r.settings = p
	}
	home, err := audit.Home()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	r.home = home
	if !add {
		return r.uninstall()
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: find provguard binary:", err)
		return 1
	}
	r.exe = exe
	return r.init()
}

func (r installRun) fail(err error) int {
	fmt.Fprintln(r.errOut, "error:", err)
	return 1
}

func (r installRun) init() int {
	s, err := install.Load(r.settings)
	if err != nil {
		return r.fail(err)
	}
	before := install.HooksJSON(s)
	cfg, cfgErr := config.Load(r.home)

	if r.interactive {
		if cfgErr != nil {
			return r.fail(fmt.Errorf("%v\nFix or delete the file, then run provguard init again", cfgErr))
		}
		g := newGuide(r.in, r.out)
		choice := askSetup(g, cfg, r.detectUser)
		fmt.Fprintf(r.out, "\nprovguard will add its hooks to %s (a backup is kept).\n", r.settings)
		if !g.confirm("Install now?", true) {
			fmt.Fprintln(r.out, "Nothing changed.")
			return 0
		}
		if cfg, err = config.Update(r.home, choice.apply); err != nil {
			return r.fail(err)
		}
		r.write = true
	}

	target := r.exe
	if r.copyBinary {
		// Hooks run the copy in <home>/bin, which agents cannot write.
		target = filepath.Join(r.home, "bin", "provguard"+filepath.Ext(r.exe))
		if r.write {
			if target, err = install.CopyBinary(r.exe, r.home); err != nil {
				return r.fail(fmt.Errorf("copy binary: %w", err))
			}
		}
	}
	opts := install.Options{FailClosed: cfg.ProfileName() == config.Strict}
	if err := install.AddWith(s, target, claudecode.Events, opts); err != nil {
		return r.fail(err)
	}

	if !r.write {
		fmt.Fprintf(r.out, "Settings file: %s\n\n--- hooks before ---\n%s\n\n--- hooks after ---\n%s\n\n", r.settings, before, install.HooksJSON(s))
		fmt.Fprintln(r.out, "No change written. Run `provguard init` in a terminal for the guided setup, or add --yes.")
		return 0
	}
	backup, err := install.Save(r.settings, s)
	if err != nil {
		return r.fail(err)
	}
	if r.interactive {
		r.summary(cfg)
		return 0
	}
	fmt.Fprintln(r.out, "Installed binary:", target)
	if opts.FailClosed {
		fmt.Fprintln(r.out, "Profile is strict: PreToolUse hook fails closed (onFailure: block).")
	}
	if backup != "" {
		fmt.Fprintln(r.out, "Backup:", backup)
	}
	fmt.Fprintln(r.out, "Written. Claude Code reloads hook settings without a restart.")
	return 0
}

// summary tells a new user what is now on and the three commands they need.
func (r installRun) summary(cfg config.Config) {
	p := cfg.ProfileName()
	fmt.Fprintf(r.out, "\n✔ provguard is on. Mode: %s (%s).\n", p, config.Describe(p))
	for _, f := range doctor.HookIntegrity(doctor.Options{Home: r.home, UserSettings: r.settings, Events: claudecode.Events}) {
		if f.Severity == "HIGH" || f.Severity == "MED" {
			fmt.Fprintf(r.out, "  ! %s\n", f.Message)
		}
	}
	fmt.Fprint(r.out, `
  See a session's state   provguard status
  Change a setting        provguard config
  Turn it off             provguard uninstall --yes

It works from your next prompt. No restart needed.
`)
}

func (r installRun) uninstall() int {
	s, err := install.Load(r.settings)
	if err != nil {
		return r.fail(err)
	}
	before := install.HooksJSON(s)
	if install.Remove(s) == 0 {
		fmt.Fprintln(r.out, "No provguard hooks found in", r.settings)
		return 0
	}
	if !r.write {
		fmt.Fprintf(r.out, "Settings file: %s\n\n--- hooks before ---\n%s\n\n--- hooks after ---\n%s\n\n", r.settings, before, install.HooksJSON(s))
		fmt.Fprintln(r.out, "No change written. Run again with --yes to apply.")
		return 0
	}
	backup, err := install.Save(r.settings, s)
	if err != nil {
		return r.fail(err)
	}
	if backup != "" {
		fmt.Fprintln(r.out, "Backup:", backup)
	}
	fmt.Fprintln(r.out, "provguard hooks removed. Your settings and logs in", r.home, "are kept.")
	return 0
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
