// Package opencode connects provguard to OpenCode (terminal, desktop and IDE).
//
// OpenCode has no command hooks; it loads JavaScript plugins. provguard
// installs one small plugin, ~/.config/opencode/plugins/provguard.js, that
// runs `provguard hook --agent opencode <event>` for each tool call and
// prompt, sending a Claude-Code-shaped payload (session_id, tool_name,
// tool_input, tool_response). A non-zero exit blocks the tool call: the plugin
// throws an Error with the reason, which OpenCode gives to the model. The
// plugin supports OpenCode's V1 (`server()`) and V2 (`setup()`) plugin APIs.
//
// Sources (checked 2026-11-17): https://opencode.ai/docs/plugins,
// https://opencode.ai/docs/build/plugins/server
package opencode

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/durgavarapraveen/provguard/internal/adapter/claudecode"
	"github.com/durgavarapraveen/provguard/internal/adapter/core"
	"github.com/durgavarapraveen/provguard/internal/event"
	"github.com/durgavarapraveen/provguard/internal/install"
)

// Agent names events that came from OpenCode.
const Agent = "opencode"

// tools maps OpenCode's built-in tool names to provguard's.
var tools = map[string]string{
	"bash": event.ShellTool, "shell": event.ShellTool,
	"read": "Read", "write": "Write", "edit": "Edit",
	"patch": core.PatchTool, "apply_patch": core.PatchTool,
	"grep": "Grep", "glob": "Glob", "list": "Glob",
	"webfetch": "WebFetch", "websearch": "WebSearch",
}

// keys maps OpenCode's camelCase argument names to provguard's.
var keys = map[string]string{
	"filePath": "file_path", "oldString": "old_string", "newString": "new_string", "patchText": "patch",
}

// Adapter implements core.Adapter for OpenCode.
type Adapter struct{}

func (Adapter) Name() string { return Agent }

// Detect is false: the plugin names the agent (`--agent opencode`).
func (Adapter) Detect([]byte) bool { return false }

func (Adapter) Parse(raw []byte, eventArg string) (event.Event, error) {
	e, err := claudecode.Parse(raw, eventArg)
	if err != nil {
		return e, err
	}
	e.Agent = Agent
	// MCP tools ("<server>_<tool>") cannot be told from a plugin's own tools,
	// so names not in the map are kept.
	if name, ok := tools[e.ToolName]; ok {
		e.ToolName = name
	}
	if in := e.ToolInput; in != nil {
		for from, to := range keys {
			if v, ok := in[from]; ok {
				if _, set := in[to]; !set {
					in[to] = v
				}
			}
		}
		if e.ToolName == core.PatchTool {
			if _, ok := in["patch"].(string); ok {
				core.AddPatchPaths(in, "patch")
			}
		}
	}
	return e, nil
}

// Reply: a non-zero exit makes the plugin throw, with stderr as the reason.
func (Adapter) Reply(_ core.Decision, reason string) (core.Response, error) {
	return core.Response{Stderr: reason + "\n", ExitCode: 2}, nil
}

// Feedback: the plugin does not show stdout to the user.
func (Adapter) Feedback(event.Event, string, string) []byte { return nil }

// CanAsk: a plugin hook can only let a tool call run or block it.
func (Adapter) CanAsk() bool { return false }

// Dir is OpenCode's global config folder: $XDG_CONFIG_HOME/opencode, else
// ~/.config/opencode (on Windows too). PROVGUARD_OPENCODE_HOME (provguard's
// own variable, not OpenCode's) points elsewhere, for tests.
func Dir() (string, error) {
	if h := os.Getenv("PROVGUARD_OPENCODE_HOME"); h != "" {
		return h, nil
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "opencode"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "opencode"), nil
}

// Present reports whether OpenCode's config folder exists.
func Present() bool {
	d, err := Dir()
	if err != nil {
		return false
	}
	_, err = os.Stat(d)
	return err == nil
}

// PluginFile is the plugin provguard installs.
func PluginFile() (string, error) {
	d, err := Dir()
	return filepath.Join(d, "plugins", "provguard.js"), err
}

// Install writes the plugin and returns its path.
func Install(exe string) (string, error) {
	p, err := PluginFile()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	return p, os.WriteFile(p, []byte(Plugin(exe)), 0o600)
}

// Uninstall removes the plugin. It reports whether there was one.
func Uninstall() (bool, error) {
	p, err := PluginFile()
	if err != nil {
		return false, err
	}
	err = os.Remove(p)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// Plugin is the plugin's source for the provguard binary at exe. The binary
// runs with an argument list, not through a shell, so its path needs no
// quoting beyond JSON's.
func Plugin(exe string) string {
	q, _ := json.Marshal(exe)
	return strings.ReplaceAll(fmt.Sprintf(pluginSource, q, install.HookTimeoutSeconds*1000), "\t", "  ")
}

const pluginSource = `// provguard: written by "provguard init"; "provguard uninstall" removes it.
// Sends each tool call and prompt to provguard, and blocks the tool calls it
// denies. Do not edit: "provguard init" writes it again.
import { spawnSync } from "node:child_process"

const PROVGUARD = %s
const TIMEOUT_MS = %d

function check(event, payload, canBlock) {
	const r = spawnSync(PROVGUARD, ["hook", "--agent", "opencode", event], {
		input: JSON.stringify({ hook_event_name: event, ...payload }),
		encoding: "utf8",
		timeout: TIMEOUT_MS,
		windowsHide: true,
	})
	if (!canBlock || (!r.error && r.status === 0)) return
	// Blocked, or provguard could not run: fail closed.
	const reason = (r.stderr || "").trim()
	throw new Error(reason || "provguard could not check this tool call (" + (r.error ? r.error.message : "exit " + r.status) + ")")
}

const text = (v) => (typeof v === "string" ? v : JSON.stringify(v ?? ""))

export default {
	// OpenCode V2
	id: "provguard",
	async setup(ctx) {
		const cwd = ctx.location?.directory ?? process.cwd()
		await ctx.tool.hook("execute.before", (e) =>
			check("PreToolUse", { session_id: e.sessionID, cwd, tool_name: e.tool, tool_input: e.input ?? {} }, true))
		await ctx.tool.hook("execute.after", (e) =>
			check("PostToolUse", { session_id: e.sessionID, cwd, tool_name: e.tool, tool_input: e.input ?? {},
				tool_response: text(e.status === "error" ? e.error?.message : e.result) }, false))
		await ctx.session.hook("prompt", (e) =>
			check("UserPromptSubmit", { session_id: e.sessionID, cwd, prompt: e.prompt?.text ?? "" }, false))
	},
	// OpenCode V1
	async server(ctx) {
		const cwd = ctx?.directory ?? process.cwd()
		return {
			"tool.execute.before": async (input, output) =>
				check("PreToolUse", { session_id: input.sessionID, cwd, tool_name: input.tool, tool_input: output.args ?? {} }, true),
			"tool.execute.after": async (input, output) =>
				check("PostToolUse", { session_id: input.sessionID, cwd, tool_name: input.tool, tool_input: input.args ?? {},
					tool_response: text(output.output) }, false),
			"chat.message": async (input, output) =>
				check("UserPromptSubmit", { session_id: input.sessionID, cwd,
					prompt: (output.parts ?? []).filter((p) => p.type === "text").map((p) => p.text).join("\n") }, false),
		}
	},
}
`
