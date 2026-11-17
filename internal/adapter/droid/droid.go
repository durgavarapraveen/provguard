// Package droid connects provguard to Factory's Droid (CLI and IDE).
//
// Droid's hook payload and reply use Claude Code's names (session_id,
// tool_name, tool_input, tool_response, hookSpecificOutput), so parsing and
// replies reuse the claudecode package. The differences are handled here:
//   - Droid's tool names (Execute, Create, ApplyPatch, FetchUrl, ...) are
//     mapped to provguard's;
//   - Droid's "ask" only means "use the normal permissions" (a call they
//     allow runs without a prompt), so provguard denies instead;
//   - hooks live in ~/.factory/hooks.json, keyed directly by event name.
//
// Schema source (checked 2026-11-17): https://docs.factory.com/harness/hooks
package droid

import (
	"path/filepath"

	"github.com/durgavarapraveen/provguard/internal/adapter/claudecode"
	"github.com/durgavarapraveen/provguard/internal/adapter/core"
	"github.com/durgavarapraveen/provguard/internal/event"
	"github.com/durgavarapraveen/provguard/internal/install"
)

// Agent names events that came from Droid.
const Agent = "factory-droid"

// Events provguard registers for.
var Events = []string{"PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart"}

// tools maps Droid's tool names to provguard's. Read, Edit, Glob, Grep and
// WebSearch already match.
var tools = map[string]string{
	"Execute":    event.ShellTool, // the platform's shell
	"Create":     "Write",
	"ApplyPatch": core.PatchTool,
	"FetchUrl":   "WebFetch",
}

// Adapter implements core.Adapter for Droid.
type Adapter struct{}

func (Adapter) Name() string { return Agent }

// Detect is false: the hooks provguard installs name the agent
// (`--agent factory-droid`).
func (Adapter) Detect([]byte) bool { return false }

func (Adapter) Parse(raw []byte, eventArg string) (event.Event, error) {
	e, err := claudecode.Parse(raw, eventArg)
	if err != nil {
		return e, err
	}
	e.Agent = Agent
	if name, ok := tools[e.ToolName]; ok {
		e.ToolName = name
	}
	if e.ToolName == core.PatchTool && e.ToolInput != nil {
		for _, key := range []string{"patch", "input", "command"} {
			if _, ok := e.ToolInput[key].(string); ok {
				core.AddPatchPaths(e.ToolInput, key)
				break
			}
		}
	}
	return e, nil
}

// Reply uses the hookSpecificOutput shape Droid shares with Claude Code.
func (Adapter) Reply(d core.Decision, reason string) (core.Response, error) {
	return claudecode.Adapter{}.Reply(d, reason)
}

// Feedback: Droid shows systemMessage to the user as a hook warning.
func (Adapter) Feedback(e event.Event, notice, _ string) []byte {
	return claudecode.Adapter{}.Feedback(e, notice, "")
}

// CanAsk: see the package comment.
func (Adapter) CanAsk() bool { return false }

// Dir is Droid's home folder, ~/.factory. PROVGUARD_FACTORY_HOME
// (provguard's own variable, not Droid's) points elsewhere, for tests.
func Dir() (string, error) { return core.AgentDir("PROVGUARD_FACTORY_HOME", ".factory") }

// Present reports whether Droid's folder exists.
func Present() bool { return core.Exists(Dir) }

// HooksFile is Droid's user hook file.
func HooksFile() (string, error) {
	d, err := Dir()
	return filepath.Join(d, "hooks.json"), err
}

// Install adds provguard's hooks to Droid's hooks.json, keeping any other
// hooks there, and returns the file's path.
func Install(exe string) (string, error) {
	p, err := HooksFile()
	if err != nil {
		return "", err
	}
	return p, install.AddHooksFile(p, false, Events, func(ev string) map[string]any {
		return map[string]any{"type": "command", "command": core.HookCommandHere(exe, Agent, ev), "timeout": install.HookTimeoutSeconds}
	}, func(ev string) string {
		if ev == "PreToolUse" || ev == "PostToolUse" {
			return "*"
		}
		return ""
	})
}

// Uninstall removes provguard's hooks from Droid's hooks.json. It reports
// whether there were any.
func Uninstall() (bool, error) {
	p, err := HooksFile()
	if err != nil {
		return false, err
	}
	return install.RemoveHooksFile(p, false)
}
