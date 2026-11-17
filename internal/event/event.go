// Package event defines the agent-neutral form of a hook call.
package event

import "encoding/json"

// Kind is the normalized hook event.
type Kind string

const (
	PreTool    Kind = "pre_tool"
	PostTool   Kind = "post_tool"
	SessionBeg Kind = "session_start"
	UserPrompt Kind = "user_prompt"
	Other      Kind = "other"
)

// Event is one hook call from any agent, after the adapter converts it.
type Event struct {
	Agent      string // "claude-code"
	Kind       Kind   // normalized event
	RawEvent   string // agent's own event name
	SessionID  string
	ToolUseID  string
	ToolName   string
	Cwd        string
	Transcript string
	Source     string          // SessionStart source, if any
	Prompt     string          // UserPromptSubmit prompt, if any
	Title      string          // current session title (SessionStart, UserPromptSubmit)
	AgentID    string          // subagent id; subagents share the parent's SessionID
	AgentType  string          // subagent type
	MCPServer  string          // MCP server name for MCP tools
	MCPSource  string          // MCP server source, e.g. "sdk" for in-process servers
	ToolInput  map[string]any  // decoded tool input
	ToolOutput json.RawMessage // raw tool response, never logged as-is
}

// ShellTool is the tool name adapters give a shell command whose shell is
// not known: Cursor's Shell tool, and Copilot's Bash tool (PowerShell on
// Windows). Checks read its command as both Bash and PowerShell.
const ShellTool = "Shell"
