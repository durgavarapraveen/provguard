// Package claudecode converts Claude Code hook payloads to event.Event and
// builds Claude Code hook responses.
//
// Schema source: https://code.claude.com/docs/en/hooks (checked 2026-11-16).
package claudecode

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/durgavarapraveen/provguard/internal/adapter/core"
	"github.com/durgavarapraveen/provguard/internal/event"
)

const Agent = "claude-code"

// Events that provguard registers for.
var Events = []string{"PreToolUse", "PostToolUse", "SessionStart", "UserPromptSubmit", "ConfigChange"}

type payload struct {
	SessionID      string          `json:"session_id"`
	TranscriptPath string          `json:"transcript_path"`
	Cwd            string          `json:"cwd"`
	PermissionMode string          `json:"permission_mode"`
	HookEventName  string          `json:"hook_event_name"`
	ToolName       string          `json:"tool_name"`
	ToolUseID      string          `json:"tool_use_id"`
	ToolInput      map[string]any  `json:"tool_input"`
	ToolResponse   json.RawMessage `json:"tool_response"`
	Source         string          `json:"source"`
	Prompt         string          `json:"prompt"`
	SessionTitle   string          `json:"session_title"` // SessionStart, UserPromptSubmit
	AgentID        string          `json:"agent_id"`      // set on subagent tool calls
	AgentType      string          `json:"agent_type"`    // set on subagent tool calls
	MCPServer      *mcpServer      `json:"mcp_server"`    // set on MCP tool calls (seen live, not in docs)
}

// mcpServer was seen live as {"name":"ccd_turn","source":"sdk"}.
type mcpServer struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

var kinds = map[string]event.Kind{
	"PreToolUse":       event.PreTool,
	"PostToolUse":      event.PostTool,
	"SessionStart":     event.SessionBeg,
	"UserPromptSubmit": event.UserPrompt,
}

// Parse decodes one hook payload. eventArg is the event name from the
// command line; the payload's hook_event_name wins when present.
func Parse(raw []byte, eventArg string) (event.Event, error) {
	// Some shells (for example PowerShell pipes) prepend a UTF-8 BOM.
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	var p payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return event.Event{}, fmt.Errorf("decode claude code payload: %w", err)
	}
	name := p.HookEventName
	if name == "" {
		name = eventArg
	}
	kind, ok := kinds[name]
	if !ok {
		kind = event.Other
	}
	return event.Event{
		Agent:      Agent,
		Kind:       kind,
		RawEvent:   name,
		SessionID:  p.SessionID,
		ToolUseID:  p.ToolUseID,
		ToolName:   p.ToolName,
		Cwd:        p.Cwd,
		Transcript: p.TranscriptPath,
		Source:     p.Source,
		Prompt:     p.Prompt,
		Title:      p.SessionTitle,
		AgentID:    p.AgentID,
		AgentType:  p.AgentType,
		MCPServer:  p.MCPServer.name(),
		MCPSource:  p.MCPServer.source(),
		ToolInput:  p.ToolInput,
		ToolOutput: p.ToolResponse,
	}, nil
}

func (m *mcpServer) name() string {
	if m == nil {
		return ""
	}
	return m.Name
}

func (m *mcpServer) source() string {
	if m == nil {
		return ""
	}
	return m.Source
}

// Adapter implements core.Adapter for Claude Code. It is also the fallback
// for payloads no other adapter recognizes.
type Adapter struct{}

func (Adapter) Name() string { return Agent }

// Detect accepts any JSON object: Claude Code's payload has no field that
// other agents never send, so it is tried last.
func (Adapter) Detect(raw []byte) bool { return json.Valid(raw) }

func (Adapter) Parse(raw []byte, eventArg string) (event.Event, error) { return Parse(raw, eventArg) }

func (Adapter) Reply(d core.Decision, reason string) (core.Response, error) {
	b, err := PreToolResponse(d, reason)
	return core.Response{Stdout: b}, err
}

// Probe: a Write in Claude Code's format.
func (Adapter) Probe(path string) (string, []byte) {
	return "PreToolUse", core.ProbePayload("PreToolUse", "Write", map[string]any{"file_path": path, "content": "x"}, nil)
}

func (Adapter) CanAsk() bool { return true }

// contextEvents take hookSpecificOutput.additionalContext.
var contextEvents = map[string]bool{"PostToolUse": true, "UserPromptSubmit": true, "SessionStart": true}

// Feedback uses "systemMessage" (shown to the user) and
// hookSpecificOutput.sessionTitle (SessionStart and UserPromptSubmit).
// PreToolUse answers only with decisions.
func (Adapter) Feedback(e event.Event, notice, title string) []byte {
	if e.Kind == event.PreTool {
		return nil
	}
	out := map[string]any{}
	spec := map[string]any{"hookEventName": e.RawEvent}
	if notice != "" {
		out["systemMessage"] = notice
		// The desktop app does not show systemMessage, so the agent gets the
		// notice too and passes it on (additionalContext reaches the model:
		// docs/FINDINGS.md F5).
		if contextEvents[e.RawEvent] {
			spec["additionalContext"] = "Message from provguard, the user's security hook, for the user: \"" + notice +
				"\" Tell the user this in one short line in your reply, unless you already did."
		}
	}
	if title != "" {
		spec["sessionTitle"] = title
	}
	if len(spec) > 1 {
		out["hookSpecificOutput"] = spec
	}
	if len(out) == 0 {
		return nil
	}
	b, _ := json.Marshal(out)
	return b
}

// PreToolResponse builds the stdout JSON for a PreToolUse decision.
func PreToolResponse(d core.Decision, reason string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       string(d),
			"permissionDecisionReason": reason,
		},
	})
}
