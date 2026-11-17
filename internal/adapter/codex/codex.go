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
	"errors"
	"os"
	"path/filepath"

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

// CanAsk: Codex parses "ask" but does not support it yet; it marks the
// hook as failed and runs the call.
func (Adapter) CanAsk() bool { return false }

// Dir is Codex's home folder: $CODEX_HOME, or ~/.codex.
func Dir() (string, error) {
	if h := os.Getenv("CODEX_HOME"); h != "" {
		return h, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".codex"), nil
}

// Present reports whether Codex's folder exists.
func Present() bool {
	d, err := Dir()
	if err != nil {
		return false
	}
	_, err = os.Stat(d)
	return err == nil
}

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
	s, err := install.Load(p)
	if err != nil {
		return "", err
	}
	err = install.AddHooks(s, Events, func(ev string) map[string]any {
		unix, windows := core.HookCommand(exe, Agent, ev)
		return map[string]any{
			"type": "command", "command": unix, "commandWindows": windows,
			"timeout": install.HookTimeoutSeconds, "statusMessage": "provguard: checking",
		}
	}, func(string) string { return "" })
	if err != nil {
		return "", err
	}
	_, err = install.Save(p, s)
	return p, err
}

// Uninstall removes provguard's hooks from Codex's hooks.json. It reports
// whether there were any.
func Uninstall() (bool, error) {
	p, err := HooksFile()
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	s, err := install.Load(p)
	if err != nil {
		return false, err
	}
	if install.Remove(s) == 0 {
		return false, nil
	}
	_, err = install.Save(p, s)
	return err == nil, err
}
