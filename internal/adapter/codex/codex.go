// Package codex connects provguard to OpenAI Codex (CLI and IDE extension).
//
// Codex's hook payload and reply use Claude Code's names (session_id,
// tool_name, tool_input, tool_response, hookSpecificOutput), so parsing and
// replies reuse the claudecode package. The differences are handled here:
//   - Codex edits files with apply_patch; the patch text is in
//     tool_input.command, and the files it touches are listed for the checks;
//   - Bash is read as a shell of unknown dialect (Codex also runs on Windows);
//   - Codex does not support "ask" (it would run the call), so provguard
//     denies instead;
//   - hooks live in ~/.codex/hooks.json, and Codex runs a new or changed
//     hook only after the user trusts it once in /hooks.
//
// Schema source (checked 2026-11-17): https://developers.openai.com/codex/hooks
package codex

import (
	"path/filepath"
	"strings"

	"github.com/durgavarapraveen/provguard/internal/adapter/claudecode"
	"github.com/durgavarapraveen/provguard/internal/adapter/core"
	"github.com/durgavarapraveen/provguard/internal/event"
	"github.com/durgavarapraveen/provguard/internal/install"
)

// Agent names events that came from Codex.
const Agent = "codex"

// Events provguard registers for.
var Events = []string{"PreToolUse", "PostToolUse", "SessionStart", "UserPromptSubmit"}

// Adapter implements core.Adapter for Codex.
type Adapter struct{}

func (Adapter) Name() string { return Agent }

// Detect is false: Codex's payload looks like Claude Code's, so the hooks
// provguard installs for Codex name the agent (`--agent codex`).
func (Adapter) Detect([]byte) bool { return false }

func (Adapter) Parse(raw []byte, eventArg string) (event.Event, error) {
	e, err := claudecode.Parse(raw, eventArg)
	if err != nil {
		return e, err
	}
	e.Agent = Agent
	switch e.ToolName {
	case "Bash":
		e.ToolName = event.ShellTool
	case core.PatchTool:
		core.AddPatchPaths(e.ToolInput, "command")
	}
	return e, nil
}

// Reply uses the hookSpecificOutput shape Codex shares with Claude Code.
func (Adapter) Reply(d core.Decision, reason string) (core.Response, error) {
	return claudecode.Adapter{}.Reply(d, reason)
}

// Feedback: Codex shows systemMessage as a warning; it has no session title.
func (Adapter) Feedback(e event.Event, notice, _ string) []byte {
	return claudecode.Adapter{}.Feedback(e, notice, "")
}

// Probe: an apply_patch that adds a file, Codex's way to write one.
func (Adapter) Probe(path string) (string, []byte) {
	patch := strings.Join([]string{"*** Begin Patch", "*** Add File: " + path, "+x", "*** End Patch", ""}, "\n")
	return "PreToolUse", core.ProbePayload("PreToolUse", core.PatchTool, map[string]any{"command": patch}, nil)
}

// CanAsk: Codex parses "ask" but does not support it yet; it marks the
// hook as failed and runs the call.
func (Adapter) CanAsk() bool { return false }

// Dir is Codex's home folder: $CODEX_HOME, or ~/.codex.
func Dir() (string, error) { return core.AgentDir("CODEX_HOME", ".codex") }

// Present reports whether Codex's folder exists.
func Present() bool { return core.Exists(Dir) }

// HooksFile is Codex's user hook file.
func HooksFile() (string, error) {
	d, err := Dir()
	return filepath.Join(d, "hooks.json"), err
}

// Install adds provguard's hooks to Codex's hooks.json, keeping any other
// hooks there, and returns the file's path.
func Install(exe string) (string, error) {
	p, err := HooksFile()
	if err != nil {
		return "", err
	}
	return p, install.AddHooksFile(p, true, Events, func(ev string) map[string]any {
		unix, windows := core.HookCommand(exe, Agent, ev)
		return map[string]any{
			"type": "command", "command": unix, "commandWindows": windows,
			"timeout": install.HookTimeoutSeconds, "statusMessage": "provguard: checking",
		}
	}, func(string) string { return "" })
}

// Uninstall removes provguard's hooks from Codex's hooks.json. It reports
// whether there were any.
func Uninstall() (bool, error) {
	p, err := HooksFile()
	if err != nil {
		return false, err
	}
	return install.RemoveHooksFile(p, true)
}
