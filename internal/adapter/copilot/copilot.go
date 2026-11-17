// Package copilot connects provguard to GitHub Copilot's agent: Copilot in
// VS Code, the GitHub Copilot app and Copilot CLI share one hook runtime.
//
// provguard registers its hooks with PascalCase event names (PreToolUse).
// Copilot then sends its "VS Code compatible" payload: Claude Code's field
// names and Claude Code's tool names (Bash, Read, Write, Edit, ...), so
// parsing reuses the claudecode package. The differences are handled here:
// the tool result is tool_result.text_result_for_llm, Bash also stands for
// PowerShell on Windows, and replies use Copilot's flat format.
//
// Copilot does not read the user's ~/.claude/settings.json, so provguard
// installs its own hook file (see Install).
//
// Schema source (checked 2026-11-17):
// https://docs.github.com/en/copilot/reference/hooks-reference
package copilot

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/durgavarapraveen/provguard/internal/adapter/claudecode"
	"github.com/durgavarapraveen/provguard/internal/adapter/core"
	"github.com/durgavarapraveen/provguard/internal/event"
)

// Agent names events that came from Copilot.
const Agent = "copilot"

// Events provguard registers for, in the PascalCase form that selects the
// Claude-compatible payload.
var Events = []string{"PreToolUse", "PostToolUse", "SessionStart", "UserPromptSubmit"}

// Adapter implements core.Adapter for Copilot.
type Adapter struct{}

func (Adapter) Name() string { return Agent }

// Detect is false: Copilot's payload looks like Claude Code's, so the hooks
// provguard installs for Copilot name the agent on the command line
// (`provguard hook --agent copilot <event>`) instead.
func (Adapter) Detect([]byte) bool { return false }

func (Adapter) Parse(raw []byte, eventArg string) (event.Event, error) {
	e, err := claudecode.Parse(raw, eventArg)
	if err != nil {
		return e, err
	}
	e.Agent = Agent
	if e.ToolName == "Bash" {
		e.ToolName = event.ShellTool // bash, or powershell on Windows
	}
	if len(e.ToolOutput) == 0 {
		var p struct {
			Result struct {
				Text string `json:"text_result_for_llm"`
			} `json:"tool_result"`
		}
		if json.Unmarshal(raw, &p) == nil && p.Result.Text != "" {
			e.ToolOutput, _ = json.Marshal(p.Result.Text)
		}
	}
	return e, nil
}

// Reply uses Copilot's preToolUse output. The reason is required for deny.
func (Adapter) Reply(d core.Decision, reason string) (core.Response, error) {
	return core.JSONResponse(map[string]string{"permissionDecision": string(d), "permissionDecisionReason": reason})
}

// Feedback: Copilot's command hooks have no user notice or session title.
func (Adapter) Feedback(event.Event, string, string) []byte { return nil }

// Probe: a Write in Copilot's (Claude-Code-shaped) format.
func (Adapter) Probe(path string) (string, []byte) {
	return "PreToolUse", core.ProbePayload("PreToolUse", "Write", map[string]any{"file_path": path, "content": "x"}, nil)
}

// CanAsk: Copilot shows its hook-permission prompt for "ask". (In Copilot
// CLI autopilot and in the cloud it denies instead, which is safe.)
func (Adapter) CanAsk() bool { return true }

// HooksDir is Copilot's user hook folder: $COPILOT_HOME/hooks, or
// ~/.copilot/hooks.
func HooksDir() (string, error) {
	if h := os.Getenv("COPILOT_HOME"); h != "" {
		return filepath.Join(h, "hooks"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".copilot", "hooks"), nil
}

// Present reports whether Copilot's folder exists, i.e. Copilot is likely in
// use on this machine.
func Present() bool {
	dir, err := HooksDir()
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Dir(dir))
	return err == nil
}

// FileName is provguard's hook file in HooksDir.
const FileName = "provguard.json"

// hookFile is Copilot's hook configuration format (version 1).
type hookFile struct {
	Version int                    `json:"version"`
	Hooks   map[string][]hookEntry `json:"hooks"`
}

type hookEntry struct {
	Type       string `json:"type"`
	Bash       string `json:"bash"`
	PowerShell string `json:"powershell"`
	TimeoutSec int    `json:"timeoutSec"`
}

// Config returns provguard's hook file for Copilot, running exe. Copilot
// runs bash on macOS and Linux and PowerShell on Windows.
func Config(exe string, timeoutSec int) ([]byte, error) {
	f := hookFile{Version: 1, Hooks: map[string][]hookEntry{}}
	for _, ev := range Events {
		bash, powershell := core.HookCommand(exe, Agent, ev)
		f.Hooks[ev] = []hookEntry{{Type: "command", Bash: bash, PowerShell: powershell, TimeoutSec: timeoutSec}}
	}
	b, err := json.MarshalIndent(f, "", "  ")
	return append(b, '\n'), err
}

// Install writes provguard's hook file and returns its path.
func Install(exe string, timeoutSec int) (string, error) {
	dir, err := HooksDir()
	if err != nil {
		return "", err
	}
	b, err := Config(exe, timeoutSec)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(dir, FileName)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return p, nil
}

// Uninstall removes provguard's hook file. It reports whether there was one.
func Uninstall() (bool, error) {
	dir, err := HooksDir()
	if err != nil {
		return false, err
	}
	err = os.Remove(filepath.Join(dir, FileName))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}
