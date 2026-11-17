package main

import (
	"fmt"
	"io"

	"github.com/durgavarapraveen/provguard/internal/adapter/codex"
	"github.com/durgavarapraveen/provguard/internal/adapter/copilot"
	"github.com/durgavarapraveen/provguard/internal/adapter/droid"
	"github.com/durgavarapraveen/provguard/internal/adapter/gemini"
	"github.com/durgavarapraveen/provguard/internal/adapter/kiro"
	"github.com/durgavarapraveen/provguard/internal/adapter/opencode"
	"github.com/durgavarapraveen/provguard/internal/install"
)

// otherAgent is a coding agent that does not read Claude Code's settings
// and so needs its own hook file. init installs into each one it finds;
// uninstall removes them all.
type otherAgent struct {
	name      string // shown to the user
	present   func() bool
	install   func(exe string) (string, error)
	uninstall func() (bool, error)
	after     string // what the user must still do, if anything
}

var otherAgents = []otherAgent{
	{
		name:      "GitHub Copilot (VS Code, Copilot app, Copilot CLI)",
		present:   copilot.Present,
		install:   func(exe string) (string, error) { return copilot.Install(exe, install.HookTimeoutSeconds) },
		uninstall: copilot.Uninstall,
	},
	{
		name:      "OpenAI Codex",
		present:   codex.Present,
		install:   codex.Install,
		uninstall: codex.Uninstall,
		after:     "In Codex, run /hooks once and trust provguard's hooks: Codex skips new hooks until you do.",
	},
	{
		name:      "Gemini CLI",
		present:   gemini.Present,
		install:   gemini.Install,
		uninstall: gemini.Uninstall,
	},
	{
		name:      "Kiro (IDE and CLI)",
		present:   kiro.Present,
		install:   kiro.Install,
		uninstall: kiro.Uninstall,
	},
	{
		name:      "Factory Droid",
		present:   droid.Present,
		install:   droid.Install,
		uninstall: droid.Uninstall,
	},
	{
		name:      "OpenCode",
		present:   opencode.Present,
		install:   opencode.Install,
		uninstall: opencode.Uninstall,
	},
}

// presentAgents lists the other agents installed on this machine.
func presentAgents() []otherAgent {
	var out []otherAgent
	for _, a := range otherAgents {
		if a.present() {
			out = append(out, a)
		}
	}
	return out
}

// installAgents installs provguard's hooks for agents and returns one line
// per agent for the summary.
func installAgents(agents []otherAgent, exe string, errOut io.Writer) []string {
	var notes []string
	for _, a := range agents {
		p, err := a.install(exe)
		if err != nil {
			fmt.Fprintf(errOut, "provguard: could not protect %s: %v\n", a.name, err)
			continue
		}
		notes = append(notes, fmt.Sprintf("✔ %s is protected too (%s).", a.name, p))
		if a.after != "" {
			notes = append(notes, "  "+a.after)
		}
	}
	return notes
}

// uninstallAgents removes provguard's hooks from every other agent.
func uninstallAgents(w io.Writer) {
	for _, a := range otherAgents {
		removed, err := a.uninstall()
		switch {
		case err != nil:
			fmt.Fprintf(w, "provguard: could not remove its %s hooks: %v\n", a.name, err)
		case removed:
			fmt.Fprintf(w, "Removed provguard's %s hooks.\n", a.name)
		}
	}
}
