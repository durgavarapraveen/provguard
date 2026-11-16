// Package claudecode converts Claude Code hook payloads to event.Event and
// builds Claude Code hook responses.
//
// Schema source: https://code.claude.com/docs/en/hooks (checked 2026-11-16).
package claudecode

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/durgavarapraveen/provguard/internal/event"
)

const Agent = "claude-code"

// Events that provguard registers for.
var Events = []string{"PreToolUse", "PostToolUse", "SessionStart", "UserPromptSubmit"}

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
	AgentID        string          `json:"agent_id"`   // set on subagent tool calls
	AgentType      string          `json:"agent_type"` // set on subagent tool calls
	MCPServer      *mcpServer      `json:"mcp_server"` // set on MCP tool calls (seen live, not in docs)
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

// Decision is a PreToolUse permission decision.
type Decision string

const (
	Allow Decision = "allow"
	Deny  Decision = "deny"
	Ask   Decision = "ask"
)

// PreToolResponse builds the stdout JSON for a PreToolUse decision.
// Do not send Allow unless policy requires it: "allow" skips the user's
// normal permission prompt.
func PreToolResponse(d Decision, reason string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       string(d),
			"permissionDecisionReason": reason,
		},
	})
}
