// Package audit writes one redacted JSON line per hook call.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"provguard/internal/event"
	"provguard/internal/redact"
)

// maxString caps each logged string, in runes, after redaction.
const maxString = 2048

// Record is one audit log line.
type Record struct {
	Time          time.Time      `json:"ts"`
	Agent         string         `json:"agent"`
	Event         string         `json:"event"`
	SessionID     string         `json:"session_id,omitempty"`
	ToolUseID     string         `json:"tool_use_id,omitempty"`
	ToolName      string         `json:"tool_name,omitempty"`
	AgentID       string         `json:"agent_id,omitempty"`
	AgentType     string         `json:"agent_type,omitempty"`
	MCPServer     string         `json:"mcp_server,omitempty"`
	Cwd           string         `json:"cwd,omitempty"`
	Source        string         `json:"source,omitempty"`
	Prompt        string         `json:"prompt,omitempty"`
	PromptChars   int            `json:"prompt_chars,omitempty"`
	ToolInput     map[string]any `json:"tool_input,omitempty"`
	OutputBytes   int            `json:"output_bytes,omitempty"`
	OutputSHA256  string         `json:"output_sha256,omitempty"`
	Decision      string         `json:"decision"`
	Error         string         `json:"error,omitempty"`
	LatencyMicros int64          `json:"latency_us"`
}

// FromEvent builds a redacted record. Tool output is kept as size and hash only.
func FromEvent(e event.Event) Record {
	r := Record{
		Agent:     e.Agent,
		Event:     e.RawEvent,
		SessionID: e.SessionID,
		ToolUseID: e.ToolUseID,
		ToolName:  e.ToolName,
		AgentID:   e.AgentID,
		AgentType: e.AgentType,
		MCPServer: e.MCPServer,
		Cwd:       e.Cwd,
		Source:    e.Source,
	}
	if e.Prompt != "" {
		r.Prompt = redact.Value(e.Prompt, maxString).(string)
		r.PromptChars = len([]rune(e.Prompt))
	}
	if e.ToolInput != nil {
		r.ToolInput = redact.Value(e.ToolInput, maxString).(map[string]any)
	}
	if n := len(e.ToolOutput); n > 0 && string(e.ToolOutput) != "null" {
		sum := sha256.Sum256(e.ToolOutput)
		r.OutputBytes = n
		r.OutputSHA256 = hex.EncodeToString(sum[:])
	}
	return r
}

// Home returns the provguard data directory.
func Home() (string, error) {
	if h := os.Getenv("PROVGUARD_HOME"); h != "" {
		return h, nil
	}
	u, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(u, ".provguard"), nil
}

// Write appends r to today's log file under home/audit.
// It uses one write call per line so parallel hook processes do not interleave lines.
func Write(home string, r Record) error {
	dir := filepath.Join(home, "audit")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	name := filepath.Join(dir, r.Time.UTC().Format("2006-01-02")+".jsonl")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(line); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
