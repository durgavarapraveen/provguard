// Package audit writes one redacted JSON line per hook call.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/durgavarapraveen/provguard/internal/event"
	"github.com/durgavarapraveen/provguard/internal/redact"
)

// maxString caps each logged string, in runes, after redaction.
const maxString = 2048

// Record is one audit log line.
type Record struct {
	Time         time.Time      `json:"ts"`
	Agent        string         `json:"agent"`
	Event        string         `json:"event"`
	SessionID    string         `json:"session_id,omitempty"`
	ToolUseID    string         `json:"tool_use_id,omitempty"`
	ToolName     string         `json:"tool_name,omitempty"`
	AgentID      string         `json:"agent_id,omitempty"`
	AgentType    string         `json:"agent_type,omitempty"`
	MCPServer    string         `json:"mcp_server,omitempty"`
	Cwd          string         `json:"cwd,omitempty"`
	Source       string         `json:"source,omitempty"`
	Prompt       string         `json:"prompt,omitempty"`
	PromptChars  int            `json:"prompt_chars,omitempty"`
	ToolInput    map[string]any `json:"tool_input,omitempty"`
	OutputBytes  int            `json:"output_bytes,omitempty"`
	OutputSHA256 string         `json:"output_sha256,omitempty"`
	Decision     string         `json:"decision"`
	Rule         string         `json:"rule,omitempty"`
	Reason       string         `json:"reason,omitempty"`
	Profile      string         `json:"profile,omitempty"`
	// Would is the policy decision under balanced/strict. In audit mode
	// Decision stays "none" and Would shows what would have happened.
	Would string `json:"would,omitempty"`
	// Override is set when the user approved this call with provguard allow.
	Override string `json:"override,omitempty"`
	// Notice is the one-time message shown to the user when the session's
	// labels changed (Claude Code systemMessage).
	Notice string   `json:"notice,omitempty"`
	Labels []string `json:"labels,omitempty"`
	Sinks  []string `json:"sinks,omitempty"` // shell sink classes (PreToolUse Bash/PowerShell)
	// Session state after this event (PostToolUse / UserPromptSubmit only).
	SessionTainted   bool   `json:"session_tainted,omitempty"`
	SessionSensitive bool   `json:"session_sensitive,omitempty"`
	Error            string `json:"error,omitempty"`
	LatencyMicros    int64  `json:"latency_us"`
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

// DefaultRetentionDays is how long daily audit logs are kept.
const DefaultRetentionDays = 30

// GC deletes daily log files older than days (by the date in the file name).
// days <= 0 keeps everything. It returns the number of files removed.
// Old logs are deleted so the log folder does not grow without limit.
func GC(home string, days int, now time.Time) int {
	if days <= 0 {
		return 0
	}
	files, _ := filepath.Glob(filepath.Join(home, "audit", "*.jsonl"))
	y, m, d := now.UTC().AddDate(0, 0, -days).Date()
	cutoff := time.Date(y, m, d, 0, 0, 0, 0, time.UTC) // whole days: keep the day exactly N days ago
	n := 0
	for _, f := range files {
		day, err := time.Parse("2006-01-02", strings.TrimSuffix(filepath.Base(f), ".jsonl"))
		if err != nil || !day.Before(cutoff) {
			continue
		}
		if os.Remove(f) == nil {
			n++
		}
	}
	return n
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

// redactStrings redacts the fields that callers fill in after FromEvent.
// A policy reason and a sink name quote the call, so without this a URL or a
// command that carries a secret would reach the log unredacted, although
// FromEvent redacted the same text in tool_input.
func redactStrings(r *Record) {
	for _, p := range []*string{&r.Reason, &r.Notice, &r.Error, &r.Prompt} {
		if *p != "" {
			*p = redact.String(*p)
		}
	}
	r.Sinks = redactEach(r.Sinks)
	r.Labels = redactEach(r.Labels)
}

// redactEach copies the list, so redacting the record does not change the
// strings its caller still holds.
func redactEach(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = redact.String(s)
	}
	return out
}

// Write appends r to today's log file under home/audit.
// It uses one write call per line so parallel hook processes do not interleave lines.
func Write(home string, r Record) error {
	dir := filepath.Join(home, "audit")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	redactStrings(&r)
	// No HTML escaping: keep "->" and "<" readable in the log.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil { // Encode adds the newline
		return err
	}
	line := buf.Bytes()
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
