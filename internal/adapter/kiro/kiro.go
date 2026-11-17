// Package kiro connects provguard to Kiro (IDE and CLI V3).
//
// Kiro's hook payload uses Claude Code's field names (hook_event_name,
// session_id, cwd, tool_name, tool_input), so parsing reuses the claudecode
// package. The differences are handled here:
//   - Kiro's tool names (shell, read, write, grep, glob, web_fetch,
//     web_search, mcp_<server>_<tool>, and older aliases) are mapped;
//   - a hook blocks a tool call only by exiting non-zero, with the reason on
//     stderr; on exit 0 its stdout is added to the agent's context, so
//     provguard prints nothing then;
//   - there is no "ask";
//   - hooks live in ~/.kiro/hooks/*.json ("version": "v1", a list of hooks
//     with trigger, matcher and action), shared by the IDE and the CLI.
//
// Schema sources (checked 2026-11-17):
//   - https://kiro.dev/docs/hooks/types
//   - https://kiro.dev/docs/hooks/actions
//   - https://kiro.dev/docs/reference/built-in-tools
package kiro

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/durgavarapraveen/provguard/internal/adapter/claudecode"
	"github.com/durgavarapraveen/provguard/internal/adapter/core"
	"github.com/durgavarapraveen/provguard/internal/event"
	"github.com/durgavarapraveen/provguard/internal/install"
)

// Agent names events that came from Kiro.
const Agent = "kiro"

// Events provguard registers for (Kiro's V3 trigger names).
var Events = []string{"PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart"}

// tools maps Kiro's tool names and their CLI 2.x aliases to provguard's.
var tools = map[string]string{
	"shell": event.ShellTool, "execute_bash": event.ShellTool, "execute_cmd": event.ShellTool,
	"read": "Read", "fs_read": "Read", "read_file": "Read",
	"write": "Write", "fs_write": "Write", "fsWrite": "Write",
	"grep": "Grep", "glob": "Glob",
	"web_fetch": "WebFetch", "web_search": "WebSearch",
}

// Adapter implements core.Adapter for Kiro.
type Adapter struct{}

func (Adapter) Name() string { return Agent }

// Detect is false: the hooks provguard installs name the agent
// (`--agent kiro`).
func (Adapter) Detect([]byte) bool { return false }

func (Adapter) Parse(raw []byte, eventArg string) (event.Event, error) {
	e, err := claudecode.Parse(raw, eventArg)
	if err != nil {
		return e, err
	}
	e.Agent = Agent
	if name, ok := tools[e.ToolName]; ok {
		e.ToolName = name
	} else if rest, ok := strings.CutPrefix(e.ToolName, "mcp_"); ok {
		e.ToolName = "mcp__" + rest
		if e.MCPServer == "" {
			e.MCPServer = rest // server and tool are joined by "_"
		}
	}
	if in := e.ToolInput; in != nil {
		// Kiro's file tools take "path"; write takes "file_text" or "new_str".
		if _, ok := in["file_path"]; !ok {
			if p, ok := in["path"]; ok {
				in["file_path"] = p
			}
		}
		if _, ok := in["content"]; !ok {
			for _, k := range []string{"file_text", "new_str"} {
				if v, ok := in[k]; ok {
					in["content"] = v
					break
				}
			}
		}
	}
	return e, nil
}

// Reply blocks the only way Kiro allows: a non-zero exit, with the reason
// on stderr (Kiro sends it to the agent).
func (Adapter) Reply(_ core.Decision, reason string) (core.Response, error) {
	return core.Response{Stderr: reason + "\n", ExitCode: 2}, nil
}

// Feedback: stdout on exit 0 goes into the agent's context, not to the user.
func (Adapter) Feedback(event.Event, string, string) []byte { return nil }

// CanAsk: Kiro hooks can only block.
func (Adapter) CanAsk() bool { return false }

// Dir is Kiro's home folder, ~/.kiro. PROVGUARD_KIRO_HOME (provguard's
// own variable, not Kiro's) points elsewhere, for tests.
func Dir() (string, error) { return core.AgentDir("PROVGUARD_KIRO_HOME", ".kiro") }

// Present reports whether Kiro's folder exists.
func Present() bool { return core.Exists(Dir) }

// HooksFile is provguard's file among Kiro's global hooks.
func HooksFile() (string, error) {
	d, err := Dir()
	return filepath.Join(d, "hooks", "provguard.json"), err
}

type hookFile struct {
	Version string `json:"version"`
	Hooks   []hook `json:"hooks"`
}

type hook struct {
	Name    string `json:"name"`
	Trigger string `json:"trigger"`
	Action  action `json:"action"`
	Timeout int    `json:"timeout"`
	Enabled bool   `json:"enabled"`
}

type action struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

// Install writes provguard's hook file and returns its path.
func Install(exe string) (string, error) {
	p, err := HooksFile()
	if err != nil {
		return "", err
	}
	f := hookFile{Version: "v1"}
	for _, ev := range Events {
		f.Hooks = append(f.Hooks, hook{
			Name: "provguard " + ev, Trigger: ev, Enabled: true, Timeout: install.HookTimeoutSeconds,
			Action: action{Type: "command", Command: core.HookCommandHere(exe, Agent, ev)},
		})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // keep "&" in a PowerShell command readable
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	return p, os.WriteFile(p, buf.Bytes(), 0o600)
}

// Uninstall removes provguard's hook file. It reports whether there was one.
func Uninstall() (bool, error) {
	p, err := HooksFile()
	if err != nil {
		return false, err
	}
	err = os.Remove(p)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}
