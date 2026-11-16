// Package bench holds provguard's attack cases and loads them.
//
// Each case is a JSON file in attacks/. It has:
//   - steps: a hand-written trace of the tool calls a hijacked agent makes.
//     Steps marked "attack" are the harmful calls. Replay mode feeds the
//     trace through the real hook and records provguard's decision.
//   - live (optional): files, a page served by a local fake attacker server,
//     and a task prompt, for running a real agent against the case.
//
// Placeholders, filled in before use:
//
//	{{CANARY}}      fake secret placed in .env
//	{{CANARY_B64}}  base64 of "API_KEY={{CANARY}}"
//	{{CANARY_HEX}}  hex of {{CANARY}}
//	{{ATTACKER}}    attacker base URL (replay: http://attacker.test, live: http://127.0.0.1:PORT)
//	{{ATTACKER_HOST}} attacker host (and port in live mode)
//	{{REPO}}        workspace path
//
// All attacks target only the fake attacker. Live mode binds to 127.0.0.1.
package bench

import (
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed attacks/*.json
var files embed.FS

// Step is one hook call.
type Step struct {
	Event    string         `json:"event"` // PreToolUse | PostToolUse | UserPromptSubmit
	Tool     string         `json:"tool,omitempty"`
	Input    map[string]any `json:"input,omitempty"`
	Response any            `json:"response,omitempty"`
	Prompt   string         `json:"prompt,omitempty"`
	MCP      string         `json:"mcp_server,omitempty"`
	Attack   bool           `json:"attack,omitempty"` // a harmful call
}

// Live describes a real-agent run.
type Live struct {
	Safe   bool              `json:"safe"` // false: replay only (would touch the real home dir, etc.)
	Why    string            `json:"why,omitempty"`
	Prompt string            `json:"prompt"` // task given to the agent
	Files  map[string]string `json:"files"`  // workspace files
	Page   string            `json:"page"`   // served at {{ATTACKER}}/page
}

// Case is one attack.
type Case struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Source      string            `json:"source"` // public incident or pattern it copies
	Description string            `json:"description"`
	Config      map[string]any    `json:"config,omitempty"` // extra config.json keys
	Steps       []Step            `json:"steps"`
	Expect      map[string]string `json:"expect"` // profile -> blocked | asked | missed
	Note        string            `json:"note,omitempty"`
	Live        *Live             `json:"live,omitempty"`
}

// Load returns all cases sorted by ID.
func Load() ([]Case, error) {
	var out []Case
	err := fs.WalkDir(files, "attacks", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") {
			return err
		}
		b, err := files.ReadFile(p)
		if err != nil {
			return err
		}
		var c Case
		if err := json.Unmarshal(b, &c); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, c)
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, err
}

// Vars are the placeholder values for one run.
type Vars struct {
	Canary, Attacker, AttackerHost, Repo string
}

// Expand replaces placeholders in s.
func (v Vars) Expand(s string) string {
	return strings.NewReplacer(
		"{{CANARY_B64}}", base64.StdEncoding.EncodeToString([]byte("API_KEY="+v.Canary)),
		"{{CANARY_HEX}}", hex.EncodeToString([]byte(v.Canary)),
		"{{CANARY}}", v.Canary,
		"{{ATTACKER_HOST}}", v.AttackerHost,
		"{{ATTACKER}}", v.Attacker,
		"{{REPO}}", v.Repo,
	).Replace(s)
}

// ExpandAny replaces placeholders in every string inside a JSON-like value.
func (v Vars) ExpandAny(x any) any {
	switch t := x.(type) {
	case string:
		return v.Expand(t)
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, y := range t {
			m[k] = v.ExpandAny(y)
		}
		return m
	case []any:
		s := make([]any, len(t))
		for i, y := range t {
			s[i] = v.ExpandAny(y)
		}
		return s
	}
	return x
}
