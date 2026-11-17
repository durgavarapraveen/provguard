// Package devin connects provguard to Devin's local agent: Devin Desktop
// (formerly Windsurf, whose Cascade agent it replaces) and Devin CLI.
//
// Devin runs the hooks in ~/.claude/settings.json ("read_config_from.claude",
// on by default), so the installed `provguard hook` command also receives
// Devin's payloads, like Cursor's. They use Claude Code's field names and
// event names, so parsing reuses the claudecode package. The differences
// are handled here:
//   - Devin's tool names (exec, read, write, edit, apply_patch, grep, glob,
//     webfetch, notebook_*) are mapped to provguard's;
//   - every payload carries prompt_id after the first prompt, which is how
//     Detect recognizes Devin;
//   - replies are {"decision": "block", "reason": ...}; there is no "ask".
//
// Schema sources (checked 2026-11-17):
//   - https://docs.devin.ai/cli/extensibility/hooks/overview
//   - https://docs.devin.ai/cli/extensibility/hooks/lifecycle-hooks
package devin

import (
	"encoding/json"

	"github.com/durgavarapraveen/provguard/internal/adapter/claudecode"
	"github.com/durgavarapraveen/provguard/internal/adapter/core"
	"github.com/durgavarapraveen/provguard/internal/event"
)

// Agent names events that came from Devin.
const Agent = "devin"

// tools maps Devin's tool names to provguard's.
var tools = map[string]string{
	"exec":          event.ShellTool, // the platform's shell
	"read":          "Read",
	"write":         "Write",
	"edit":          "Edit",
	"grep":          "Grep",
	"glob":          "Glob",
	"webfetch":      "WebFetch",
	"notebook_read": "NotebookRead",
	"notebook_edit": "NotebookEdit",
	"apply_patch":   core.PatchTool,
}

// Adapter implements core.Adapter for Devin.
type Adapter struct{}

func (Adapter) Name() string { return Agent }

// Detect recognizes Devin's payload: prompt_id (absent before the first
// prompt) or one of Devin's lower-case tool names, which Claude Code never
// sends.
func (Adapter) Detect(raw []byte) bool {
	var p struct {
		PromptID *string `json:"prompt_id"`
		ToolName string  `json:"tool_name"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return false
	}
	_, devinTool := tools[p.ToolName]
	return p.PromptID != nil || devinTool
}

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

// Reply uses Devin's decision fields; the reason is shown to the agent.
func (Adapter) Reply(d core.Decision, reason string) (core.Response, error) {
	return core.JSONResponse(map[string]string{"decision": "block", "reason": reason})
}

// Feedback: Devin's hook output reaches the agent, not the user.
func (Adapter) Feedback(event.Event, string, string) []byte { return nil }

// CanAsk: Devin hooks can only approve or block.
func (Adapter) CanAsk() bool { return false }
