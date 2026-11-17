package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	now         bool          // uninstall: skip the title cleanup and remove everything at once
	keepData    bool          // uninstall: keep the provguard folder (logs, config)
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
	now := fs.Bool("now", false, "uninstall: remove everything at once, without restoring session titles")
	keepData := fs.Bool("keep-data", false, "uninstall: keep ~/.provguard (logs and settings)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	r := installRun{
		settings: *settings, write: *yes, copyBinary: !*noCopy, now: *now, keepData: *keepData,
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
	addPath := false
	agents := presentAgents() // --yes protects every agent it finds
	claude := true            // Claude Code's hooks, which Cursor and Devin run too

	if r.interactive {
		if cfgErr != nil {
			return r.fail(fmt.Errorf("%v\nFix or delete the file, then run provguard init again", cfgErr))
		}
		g := newGuide(r.in, r.out)
		choice := askSetup(g, cfg, r.detectUser)
		if r.copyBinary && !userPath.has(r.binDir()) {
			fmt.Fprintln(r.out)
			addPath = g.confirm("Add provguard to your PATH, so the provguard command works in any folder?", true)
		}
		fmt.Fprintln(r.out)
		if claude, agents = askAgents(g, otherAgents); !claude && len(agents) == 0 {
			fmt.Fprintln(r.out, "No agent chosen. Nothing changed.")
			return 0
		}
		fmt.Fprintln(r.out)
		if claude {
			fmt.Fprintf(r.out, "provguard will add its hooks to %s (a backup is kept).\n", r.settings)
		}
		for _, a := range agents {
			fmt.Fprintf(r.out, "provguard will protect %s.\n", a.name)
		}
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
	backup := ""
	if claude {
		if backup, err = install.Save(r.settings, s); err != nil {
			return r.fail(err)
		}
	}
	_ = os.Remove(pendingPath(r.home)) // installed again: no uninstall in progress
	pathNote := r.pathNote(addPath)
	if notes := installAgents(agents, target, r.errOut); len(notes) > 0 {
		pathNote = strings.TrimSpace(pathNote + "\n" + strings.Join(notes, "\n"))
	}
	if r.interactive {
		r.summary(cfg, pathNote, claude)
		return 0
	}
	if pathNote != "" {
		fmt.Fprintln(r.out, pathNote)
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
func (r installRun) summary(cfg config.Config, pathNote string, claude bool) {
	p := cfg.ProfileName()
	fmt.Fprintf(r.out, "\n✔ provguard is on. Mode: %s (%s).\n", p, config.Describe(p))
	if pathNote != "" {
		fmt.Fprintln(r.out, pathNote)
	}
	if claude { // check the Claude Code hooks just written
		for _, f := range doctor.HookIntegrity(doctor.Options{Home: r.home, UserSettings: r.settings, Events: claudecode.Events}) {
			if f.Severity == "HIGH" || f.Severity == "MED" {
				fmt.Fprintf(r.out, "  ! %s\n", f.Message)
			}
		}
	}
	fmt.Fprint(r.out, `
  See a session's state   provguard status
  Change a setting        provguard config
  Turn it off             provguard uninstall --yes

It works from your next prompt. No restart needed.
`)
}

// uninstall turns protection off. Session titles that still carry a trust
// icon can be changed only by a hook answer inside each session, so unless
// --now is given, a cleanup hook stays until they are restored (cleanup.go).
func (r installRun) uninstall() int {
	s, err := install.Load(r.settings)
	if err != nil {
		return r.fail(err)
	}
	before := install.HooksJSON(s)
	exe := install.HookBinary(s)
	if install.Remove(s) == 0 {
		if _, ok := readPending(r.home); ok && r.write && r.now {
			// The cleanup was already pending in another settings file.
			return r.finishNow()
		}
		if r.write {
			uninstallAgents(r.out)
		}
		fmt.Fprintln(r.out, "No provguard hooks found in", r.settings)
		return 0
	}
	titled := titledSessions(r.home)
	cleanup := len(titled) > 0 && !r.now && exe != ""
	if cleanup {
		if err := install.AddCleanup(s, exe); err != nil {
			return r.fail(err)
		}
	}
	if !r.write {
		fmt.Fprintf(r.out, "Settings file: %s\n\n--- hooks before ---\n%s\n\n--- hooks after ---\n%s\n\n", r.settings, before, install.HooksJSON(s))
		fmt.Fprintln(r.out, "No change written. Run again with --yes to apply.")
		return 0
	}
	if cleanup {
		// Write the marker first: a cleanup hook without it does nothing.
		if err := writePending(r.home, pending{Since: time.Now(), Settings: r.settings, KeepData: r.keepData}); err != nil {
			return r.fail(err)
		}
	}
	if _, err := install.Save(r.settings, s); err != nil {
		return r.fail(err)
	}
	uninstallAgents(r.out)
	fmt.Fprintln(r.out, "provguard is off: nothing is checked or blocked any more.")
	if cleanup {
		fmt.Fprintf(r.out, `
%s still show a trust icon (🔴 🟡 🟠) in the title. Only a hook inside a
session can change its title, so one small cleanup hook stays: your next
message in each of those sessions removes the icon. When all are clean, or
after 30 days, the hook removes itself and %s.
To remove everything now instead (titles keep their icon): provguard uninstall --now --yes
`, plural(len(titled), "session"), r.dataNote())
		return 0
	}
	return r.finishNow()
}

// finishNow removes what is left: the pending marker and, unless --keep-data,
// the provguard folder.
func (r installRun) finishNow() int {
	if r.keepData {
		_ = os.Remove(pendingPath(r.home))
		fmt.Fprintln(r.out, "Your logs and settings in", r.home, "are kept.")
		return 0
	}
	if p, ok := readPending(r.home); ok && p.Settings != r.settings {
		_ = finishUninstall(r.home, p) // the cleanup hook lives in another settings file
	}
	if err := removeHome(r.home); err != nil {
		fmt.Fprintln(r.errOut, "provguard:", err)
		fmt.Fprintln(r.out, "Delete that folder yourself once no Claude Code session is running.")
		return 1
	}
	fmt.Fprintln(r.out, "Removed", r.home+".")
	removeFromPath(r.out, r.home)
	return 0
}

func (r installRun) dataNote() string {
	if r.keepData {
		return "leaves " + r.home + " in place"
	}
	return r.home
}

func (r installRun) binDir() string { return filepath.Join(r.home, "bin") }

// pathNote puts the provguard folder on PATH when the user agreed, and says
// what happened. Without a terminal (init --yes) it only says how.
func (r installRun) pathNote(add bool) string {
	if !r.copyBinary || userPath.has(r.binDir()) {
		return ""
	}
	if add {
		where, err := userPath.add(r.binDir())
		if err == nil {
			return "✔ Added " + r.binDir() + " to " + where + ". Open a new terminal to use the provguard command."
		}
		fmt.Fprintln(r.errOut, "provguard: could not change PATH:", err)
	}
	return "To use the provguard command in any folder, add " + r.binDir() + " to your PATH."
}

// removeFromPath takes provguard's folder off the user's PATH (uninstall).
func removeFromPath(w io.Writer, home string) {
	bin := filepath.Join(home, "bin")
	if !userPath.has(bin) {
		return
	}
	if err := userPath.remove(bin); err != nil {
		fmt.Fprintln(w, "Take", bin, "off your PATH yourself; provguard could not:", err)
		return
	}
	fmt.Fprintln(w, "Removed", bin, "from your PATH.")
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
