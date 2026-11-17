// Package gemini connects provguard to Google's Gemini CLI.
//
// Gemini CLI's hook payload uses Claude Code's field names (session_id,
// cwd, tool_name, tool_input, tool_response), so parsing reuses the
// claudecode package. The differences are handled here:
//   - events are BeforeTool, AfterTool, BeforeAgent and SessionStart;
//   - tools have Gemini's names (run_shell_command, read_file, write_file,
//     replace, grep_search, web_fetch, google_web_search, mcp_<server>_<tool>),
//     mapped to provguard's;
//   - replies are {"decision": "deny", "reason": ...}; there is no "ask";
//   - hooks live in ~/.gemini/settings.json, timeouts in milliseconds.
//
// Schema sources (checked 2026-11-17):
//   - https://geminicli.com/docs/hooks/reference
//   - https://github.com/google-gemini/gemini-cli/tree/main/docs/tools
package gemini

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/durgavarapraveen/provguard/internal/adapter/claudecode"
	"github.com/durgavarapraveen/provguard/internal/adapter/core"
	"github.com/durgavarapraveen/provguard/internal/event"
	"github.com/durgavarapraveen/provguard/internal/install"
)

// Agent names events that came from Gemini CLI.
const Agent = "gemini-cli"

// kinds maps Gemini CLI's events to provguard's.
var kinds = map[string]event.Kind{
	"BeforeTool":   event.PreTool,
	"AfterTool":    event.PostTool,
	"BeforeAgent":  event.UserPrompt,
	"SessionStart": event.SessionBeg,
}

// Events provguard registers for.
var Events = []string{"BeforeTool", "AfterTool", "BeforeAgent", "SessionStart"}

// tools maps Gemini CLI's built-in tool names to provguard's. Unlisted
// tools (glob, list_directory, ...) keep their names.
var tools = map[string]string{
	"run_shell_command": event.ShellTool, // the platform's shell
	"read_file":         "Read",
	"read_many_files":   "Read",
	"write_file":        "Write",
	"replace":           "Edit",
	"grep_search":       "Grep",
	"web_fetch":         "WebFetch",
	"google_web_search": "WebSearch",
}

// Adapter implements core.Adapter for Gemini CLI.
type Adapter struct{}

func (Adapter) Name() string { return Agent }

// Detect is false: the hooks provguard installs name the agent
// (`--agent gemini-cli`).
func (Adapter) Detect([]byte) bool { return false }

var urlRe = regexp.MustCompile(`https?://[^\s"'<>]+`)

func (Adapter) Parse(raw []byte, eventArg string) (event.Event, error) {
	e, err := claudecode.Parse(raw, eventArg)
	if err != nil {
		return e, err
	}
	e.Agent = Agent
	if k, ok := kinds[e.RawEvent]; ok {
		e.Kind = k
	}
	if name, ok := tools[e.ToolName]; ok {
		e.ToolName = name
	} else if rest, ok := strings.CutPrefix(e.ToolName, "mcp_"); ok {
		e.ToolName = "mcp__" + rest // server and tool are joined by "_": the whole rest names the server
		if e.MCPServer == "" {
			e.MCPServer = rest
		}
	}
	if e.ToolInput != nil {
		// web_fetch takes a prompt with up to 20 URLs; the checks read "url".
		if p, _ := e.ToolInput["prompt"].(string); e.ToolName == "WebFetch" && p != "" {
			if u := urlRe.FindString(p); u != "" {
				e.ToolInput["url"] = u
			}
		}
		if _, ok := e.ToolInput["path"]; !ok {
			if d, ok := e.ToolInput["dir_path"]; ok {
				e.ToolInput["path"] = d
			}
		}
	}
	return e, nil
}

// Reply uses Gemini CLI's decision fields. The reason goes to the agent as
// the tool error.
func (Adapter) Reply(d core.Decision, reason string) (core.Response, error) {
	return core.JSONResponse(map[string]string{"decision": string(d), "reason": reason})
}

// Feedback: systemMessage is shown to the user; there is no session title.
func (Adapter) Feedback(e event.Event, notice, _ string) []byte {
	if e.Kind == event.PreTool || notice == "" {
		return nil
	}
	b, _ := json.Marshal(map[string]string{"systemMessage": notice})
	return b
}

// CanAsk: Gemini CLI hooks can only allow or deny.
func (Adapter) CanAsk() bool { return false }

// Dir is Gemini CLI's home folder: $GEMINI_CLI_HOME/.gemini, or ~/.gemini.
func Dir() (string, error) {
	home := os.Getenv("GEMINI_CLI_HOME")
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		home = h
	}
	return filepath.Join(home, ".gemini"), nil
}

// Present reports whether Gemini CLI's folder exists.
func Present() bool {
	d, err := Dir()
	if err != nil {
		return false
	}
	_, err = os.Stat(d)
	return err == nil
}

// SettingsFile is Gemini CLI's user settings file, which holds its hooks.
func SettingsFile() (string, error) {
	d, err := Dir()
	return filepath.Join(d, "settings.json"), err
}

// Install adds provguard's hooks to Gemini CLI's settings.json, keeping
// every other setting and hook, and returns the file's path.
func Install(exe string) (string, error) {
	p, err := SettingsFile()
	if err != nil {
		return "", err
	}
	return p, install.AddHooksFile(p, true, Events, func(ev string) map[string]any {
		return map[string]any{
			"type": "command", "name": "provguard-" + strings.ToLower(ev), "command": core.HookCommandHere(exe, Agent, ev),
			"timeout": install.HookTimeoutSeconds * 1000, // milliseconds
		}
	}, func(ev string) string {
		if ev == "BeforeTool" || ev == "AfterTool" {
			return ".*"
		}
		return ""
	})
}

// Uninstall removes provguard's hooks from Gemini CLI's settings.json. It
// reports whether there were any.
func Uninstall() (bool, error) {
	p, err := SettingsFile()
	if err != nil {
		return false, err
	}
	return install.RemoveHooksFile(p, true)
}
