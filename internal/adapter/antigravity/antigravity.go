// Package antigravity connects provguard to Google Antigravity (app, CLI and
// IDE), which share one global hook file, ~/.gemini/config/hooks.json.
//
// Antigravity's hooks differ from Claude Code's:
//   - the hook file maps hook names to events ({"provguard": {"PreToolUse":
//     [...]}}), and tool events wrap handlers in {matcher, hooks};
//   - the payload is camelCase (conversationId, toolCall.name, toolCall.args,
//     workspacePaths) and does not name its event, so the hook command does;
//   - the tool and argument names are its own (run_command, CommandLine,
//     view_file, AbsolutePath, ...);
//   - PostToolUse carries no tool output, so provguard labels by the tool
//     and its arguments only (no secret scanning of output);
//   - there is no prompt event; PreInvocation, before every model call,
//     carries the last user prompt (lastUserInput);
//   - a PreToolUse reply is {"decision", "reason"}, and a hook that fails or
//     prints no valid JSON blocks the call, so every call gets a JSON reply.
//
// Schema source (checked 2026-11-17): https://antigravity.google/docs/hooks
package antigravity

import (
	"encoding/json"
	"path/filepath"

	"github.com/durgavarapraveen/provguard/internal/adapter/core"
	"github.com/durgavarapraveen/provguard/internal/event"
	"github.com/durgavarapraveen/provguard/internal/install"
)

// Agent names events that came from Antigravity.
const Agent = "antigravity"

// HookName is provguard's entry in hooks.json.
const HookName = "provguard"

// Events provguard registers for, by Antigravity's names.
var Events = []string{"SessionStart", "PreInvocation", "PreToolUse", "PostToolUse"}

var kinds = map[string]event.Kind{
	"SessionStart":  event.SessionBeg,
	"PreInvocation": event.UserPrompt,
	"PreToolUse":    event.PreTool,
	"PostToolUse":   event.PostTool,
}

// tool is how one Antigravity tool maps to provguard: its name, and its
// arguments renamed to provguard's.
type tool struct {
	name string
	args map[string]string
}

var tools = map[string]tool{
	"run_command":                {event.ShellTool, map[string]string{"CommandLine": "command"}},
	"view_file":                  {"Read", map[string]string{"AbsolutePath": "file_path"}},
	"write_to_file":              {"Write", map[string]string{"TargetFile": "file_path", "CodeContent": "content"}},
	"replace_file_content":       {"Edit", map[string]string{"TargetFile": "file_path", "TargetContent": "old_string", "ReplacementContent": "new_string"}},
	"multi_replace_file_content": {"MultiEdit", map[string]string{"TargetFile": "file_path"}},
	"list_dir":                   {"Glob", map[string]string{"DirectoryPath": "path"}},
	"find_by_name":               {"Glob", map[string]string{"SearchDirectory": "path", "Pattern": "pattern"}},
	"grep_search":                {"Grep", map[string]string{"SearchPath": "path", "Query": "pattern"}},
	"search_web":                 {"WebSearch", nil},
	"read_url_content":           {"WebFetch", map[string]string{"Url": "url"}},
}

type payload struct {
	ConversationID string   `json:"conversationId"`
	WorkspacePaths []string `json:"workspacePaths"`
	TranscriptPath string   `json:"transcriptPath"`
	LastUserInput  string   `json:"lastUserInput"`
	ToolCall       *struct {
		Name string         `json:"name"`
		Args map[string]any `json:"args"`
	} `json:"toolCall"`
	Error string `json:"error"`
}

// Adapter implements core.Adapter for Antigravity.
type Adapter struct{}

func (Adapter) Name() string { return Agent }

// Detect is false: the hooks provguard installs name the agent
// (`--agent antigravity`).
func (Adapter) Detect([]byte) bool { return false }

func (Adapter) Parse(raw []byte, eventArg string) (event.Event, error) {
	var p payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return event.Event{}, err
	}
	e := event.Event{
		Agent: Agent, RawEvent: eventArg, Kind: event.Other,
		SessionID: p.ConversationID, Transcript: p.TranscriptPath,
	}
	if k, ok := kinds[eventArg]; ok {
		e.Kind = k
	}
	if len(p.WorkspacePaths) > 0 {
		e.Cwd = p.WorkspacePaths[0]
	}
	switch e.Kind {
	case event.UserPrompt:
		e.Prompt = p.LastUserInput
	case event.PreTool, event.PostTool:
		// PostToolUse also fires for steps that are not tool calls, with
		// toolCall null: there is nothing to label.
		if p.ToolCall == nil {
			e.Kind = event.Other
			break
		}
		e.ToolName, e.ToolInput = mapTool(p.ToolCall.Name, p.ToolCall.Args)
		if c, ok := e.ToolInput["Cwd"].(string); ok && c != "" {
			e.Cwd = c // run_command's own working folder
		}
	}
	return e, nil
}

func mapTool(name string, args map[string]any) (string, map[string]any) {
	if args == nil {
		args = map[string]any{}
	}
	t, ok := tools[name]
	if !ok {
		return name, args
	}
	for from, to := range t.args {
		if v, ok := args[from]; ok {
			args[to] = v
		}
	}
	if t.name == "MultiEdit" {
		args["edits"] = edits(args["ReplacementChunks"])
	}
	return t.name, args
}

// edits turns ReplacementChunks into MultiEdit's edits.
func edits(chunks any) []any {
	list, _ := chunks.([]any)
	out := make([]any, 0, len(list))
	for _, c := range list {
		m, _ := c.(map[string]any)
		out = append(out, map[string]any{"old_string": m["TargetContent"], "new_string": m["ReplacementContent"]})
	}
	return out
}

// Reply: provguard's ask is "force_ask", which a cached "Always Allow"
// cannot answer.
func (Adapter) Reply(d core.Decision, reason string) (core.Response, error) {
	decision := "deny"
	if d == core.Ask {
		decision = "force_ask"
	}
	return core.JSONResponse(map[string]string{"decision": decision, "reason": reason})
}

// Feedback: Antigravity has no hook channel for a notice to the user.
func (Adapter) Feedback(event.Event, string, string) []byte { return nil }

// EmptyReply is what a call prints when provguard has no decision. A
// PreToolUse reply without a decision counts as a denial, so it says
// "allow", which hands the call to the next hook and Antigravity's own
// permission rules (it approves nothing by itself). Other events take an
// empty object.
func (Adapter) EmptyReply(eventName string) []byte {
	if eventName == "PreToolUse" {
		return []byte(`{"decision":"allow"}` + "\n")
	}
	return []byte("{}\n")
}

// Probe: a write_to_file in Antigravity's camelCase format.
func (Adapter) Probe(path string) (string, []byte) {
	b, _ := json.Marshal(map[string]any{
		"conversationId": core.ProbeSession,
		"toolCall":       map[string]any{"name": "write_to_file", "args": map[string]any{"TargetFile": path, "CodeContent": "x"}},
	})
	return "PreToolUse", b
}

func (Adapter) CanAsk() bool { return true }

// Dir is Antigravity's folder, ~/.gemini. PROVGUARD_ANTIGRAVITY_HOME
// (provguard's own variable, not Antigravity's) points elsewhere, for tests.
func Dir() (string, error) { return core.AgentDir("PROVGUARD_ANTIGRAVITY_HOME", ".gemini") }

// Present reports whether Antigravity's app, CLI or IDE has run here
// (~/.gemini also belongs to Gemini CLI).
func Present() bool {
	return core.Exists(Dir, "antigravity") || core.Exists(Dir, "antigravity-cli") || core.Exists(Dir, "antigravity-ide")
}

// HooksFile is Antigravity's global hook file.
func HooksFile() (string, error) {
	d, err := Dir()
	return filepath.Join(d, "config", "hooks.json"), err
}

// Install adds provguard's entry to hooks.json, keeping the other entries,
// and returns the file's path.
func Install(exe string) (string, error) {
	p, err := HooksFile()
	if err != nil {
		return "", err
	}
	s, err := install.Load(p)
	if err != nil {
		return "", err
	}
	def := map[string]any{"enabled": true}
	for _, ev := range Events {
		h := map[string]any{"type": "command", "command": core.HookCommandHere(exe, Agent, ev), "timeout": install.HookTimeoutSeconds}
		if ev == "PreToolUse" || ev == "PostToolUse" {
			def[ev] = []any{map[string]any{"matcher": "*", "hooks": []any{h}}}
		} else {
			def[ev] = []any{h}
		}
	}
	s[HookName] = def
	_, err = install.Save(p, s)
	return p, err
}

// Uninstall removes provguard's entry from hooks.json. It reports whether
// there was one.
func Uninstall() (bool, error) {
	p, err := HooksFile()
	if err != nil {
		return false, err
	}
	s, err := install.Load(p)
	if err != nil {
		return false, err
	}
	if _, ok := s[HookName]; !ok {
		return false, nil
	}
	delete(s, HookName)
	_, err = install.Save(p, s)
	return err == nil, err
}
