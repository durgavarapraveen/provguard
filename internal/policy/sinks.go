package policy

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/event"
	"github.com/durgavarapraveen/provguard/internal/shell"
)

// PlainFetch marks a WebFetch that carries no obvious data (no query string,
// no long path token). It is checked only for secrets (rule 1), because
// following links is normal work.
const PlainFetch = "web_fetch"

var (
	mcpWriteVerb = regexp.MustCompile(`(?i)(?:^|_)(?:create|send|post|comment|reply|write|push|upload|publish|update|add|set|put|edit|share|submit|merge|delete|remove|fork|invite|message|email|notify)(?:_|$)`)
	longToken    = regexp.MustCompile(`[A-Za-z0-9+/_=-]{32,}`)
)

// ToolSinks returns sinks and scan text for tools that are not shells.
func ToolSinks(e event.Event, cfg config.Config) ([]shell.Sink, string) {
	switch {
	case e.ToolName == "WebFetch":
		raw, _ := e.ToolInput["url"].(string)
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return nil, ""
		}
		detail := PlainFetch
		if u.RawQuery != "" || u.Fragment != "" || longToken.MatchString(u.Path) {
			detail = "web_fetch_data"
		}
		return []shell.Sink{{Class: shell.Egress, Detail: detail, Target: raw}}, raw

	case e.ToolName == "Write" || e.ToolName == "Edit" || e.ToolName == "NotebookEdit":
		p, _ := e.ToolInput["file_path"].(string)
		if p == "" {
			p, _ = e.ToolInput["notebook_path"].(string)
		}
		where := shell.PersistPath(p)
		if where == "" {
			return nil, ""
		}
		text, _ := e.ToolInput["content"].(string)
		if text == "" {
			text, _ = e.ToolInput["new_string"].(string)
		}
		return []shell.Sink{{Class: shell.Persist, Detail: "path:" + where, Target: p}}, text

	case e.ToolName == "Delete":
		// Cursor's file delete tool. Inside the project it is ordinary
		// work; riskyDestroy and the untrusted rule decide like for rm.
		p, _ := e.ToolInput["file_path"].(string)
		if p == "" {
			return nil, ""
		}
		return []shell.Sink{{Class: shell.Destroy, Detail: "rm_recursive", Target: p}}, p

	case strings.HasPrefix(e.ToolName, "mcp__"):
		if e.MCPSource == "sdk" && cfg.TrustSDK() {
			return nil, "" // in-process tools of the host app
		}
		parts := strings.Split(e.ToolName, "__")
		tool := parts[len(parts)-1]
		if !mcpWriteVerb.MatchString(tool) {
			return nil, ""
		}
		b, _ := json.Marshal(e.ToolInput)
		server := e.MCPServer
		if server == "" && len(parts) > 1 {
			server = parts[1]
		}
		return []shell.Sink{{Class: shell.Egress, Detail: "mcp_write:" + server, Target: tool}}, string(b)
	}
	return nil, ""
}
