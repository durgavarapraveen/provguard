// Package cursor converts Cursor hook payloads to event.Event.
//
// Cursor runs the hooks in ~/.claude/settings.json as well as its own
// ("third-party hooks", on by default), so the installed `provguard hook`
// command also receives Cursor's payloads. They differ from Claude Code's:
// camelCase event names (preToolUse), conversation_id instead of
// session_id, Cursor's tool names (Shell, MCP:<tool>, Delete), and
// tool_output as a JSON string.
//
// Schema sources (checked 2026-11-17):
//   - https://cursor.com/docs/agent/hooks
//   - https://cursor.com/docs/reference/third-party-hooks
package cursor

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/durgavarapraveen/provguard/internal/adapter/core"
	"github.com/durgavarapraveen/provguard/internal/event"
)

// Agent names events that came from Cursor.
const Agent = "cursor"

// payload holds the fields provguard reads from a Cursor hook call.
type payload struct {
	CursorVersion  string          `json:"cursor_version"`
	ConversationID string          `json:"conversation_id"`
	SessionID      string          `json:"session_id"` // sessionStart only
	HookEventName  string          `json:"hook_event_name"`
	WorkspaceRoots []string        `json:"workspace_roots"`
	TranscriptPath string          `json:"transcript_path"`
	Cwd            string          `json:"cwd"`
	ToolName       string          `json:"tool_name"`
	ToolUseID      string          `json:"tool_use_id"`
	ToolInput      map[string]any  `json:"tool_input"`
	ToolOutput     json.RawMessage `json:"tool_output"` // a JSON string holding the result
	Prompt         string          `json:"prompt"`
}

// kinds maps Cursor's event names, and the names it gives imported Claude
// Code hooks, to provguard's.
var kinds = map[string]event.Kind{
	"pretooluse":         event.PreTool,
	"posttooluse":        event.PostTool,
	"beforesubmitprompt": event.UserPrompt,
	"userpromptsubmit":   event.UserPrompt,
	"sessionstart":       event.SessionBeg,
}

// claudeNames are the Claude Code event names, used as RawEvent so that
// responses name the event the way Claude Code's format expects.
var claudeNames = map[event.Kind]string{
	event.PreTool:    "PreToolUse",
	event.PostTool:   "PostToolUse",
	event.UserPrompt: "UserPromptSubmit",
	event.SessionBeg: "SessionStart",
}

// isCursor reports whether raw is a Cursor payload: Cursor sends cursor_version
// with every hook call.
func isCursor(raw []byte) bool {
	var p struct {
		CursorVersion string `json:"cursor_version"`
	}
	return json.Unmarshal(raw, &p) == nil && p.CursorVersion != ""
}

// parse decodes one Cursor hook payload. eventArg is the event name from the
// command line; the payload's hook_event_name wins when present.
func parse(raw []byte, eventArg string) (event.Event, error) {
	var p payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return event.Event{}, fmt.Errorf("decode cursor payload: %w", err)
	}
	name := p.HookEventName
	if name == "" {
		name = eventArg
	}
	kind, ok := kinds[strings.ToLower(name)]
	if !ok {
		kind = event.Other
	}
	raw0 := name
	if n, ok := claudeNames[kind]; ok {
		raw0 = n
	}
	session := p.SessionID
	if session == "" {
		session = p.ConversationID
	}
	cwd := p.Cwd
	if cwd == "" && len(p.WorkspaceRoots) > 0 {
		cwd = p.WorkspaceRoots[0]
	}
	e := event.Event{
		Agent:      Agent,
		Kind:       kind,
		RawEvent:   raw0,
		SessionID:  session,
		ToolUseID:  p.ToolUseID,
		ToolName:   toolName(p.ToolName),
		Cwd:        cwd,
		Transcript: p.TranscriptPath,
		Prompt:     p.Prompt,
		ToolInput:  input(p.ToolInput),
		ToolOutput: unwrap(p.ToolOutput),
	}
	if tool, ok := strings.CutPrefix(p.ToolName, "MCP:"); ok {
		// preToolUse does not name the server, so the call counts as one to
		// an unknown third-party server: its output marks the session
		// untrusted and its writes are checked.
		e.ToolName = "mcp__cursor__" + tool
		e.MCPServer = "cursor-mcp"
	}
	return e, nil
}

// unwrap turns a JSON string that holds JSON ("\"{...}\"") into that JSON,
// and other text into a plain JSON string.
func unwrap(v json.RawMessage) json.RawMessage {
	if len(v) == 0 {
		return nil
	}
	var s string
	if json.Unmarshal(v, &s) != nil {
		return v // already an object
	}
	if json.Valid([]byte(s)) {
		return json.RawMessage(s)
	}
	b, _ := json.Marshal(s)
	return b
}

// input copies Cursor's field names to the ones provguard's checks read
// (file_path, content). Original keys are kept.
func input(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	alias := func(to string, from ...string) {
		if _, ok := in[to]; ok {
			return
		}
		for _, f := range from {
			if v, ok := in[f]; ok {
				in[to] = v
				return
			}
		}
	}
	alias("file_path", "target_file", "filePath", "path")
	alias("content", "contents", "code_edit", "streamingContent")
	return in
}

// Adapter implements core.Adapter for Cursor.
type Adapter struct{}

func (Adapter) Name() string { return Agent }

func (Adapter) Detect(raw []byte) bool { return isCursor(raw) }

func (Adapter) Parse(raw []byte, eventArg string) (event.Event, error) { return parse(raw, eventArg) }

// Reply uses Cursor's own format. The message goes to both the user and the
// agent, so the agent can explain the block instead of retrying.
func (Adapter) Reply(d core.Decision, reason string) ([]byte, error) {
	return json.Marshal(map[string]string{
		"permission": string(d), "user_message": reason, "agent_message": reason,
	})
}

// Feedback: Cursor has no notice or session-title output for hooks.
func (Adapter) Feedback(event.Event, string, string) []byte { return nil }

// CanAsk: preToolUse accepts "ask" but does not act on it today, so the
// call would run ("ask is accepted by the schema but not enforced").
func (Adapter) CanAsk() bool { return false }

// toolName maps Cursor's tool names to provguard's where they differ.
// Cursor's Shell runs PowerShell on Windows and the user's shell elsewhere.
func toolName(n string) string {
	if n == "Shell" {
		return event.ShellTool
	}
	return n
}
