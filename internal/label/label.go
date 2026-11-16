// Package label decides where a tool result came from: trusted, untrusted
// (attacker-controllable) or sensitive (holds secrets).
package label

import (
	"encoding/json"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/event"
	"github.com/durgavarapraveen/provguard/internal/redact"
)

// maxScan caps how much tool output is scanned, to keep hook latency low.
const maxScan = 1 << 20

// maxValuesPerCall caps values taken from one tool result.
const maxValuesPerCall = 500

// Result is the label for one event.
type Result struct {
	Untrusted       bool
	UntrustedReason string
	Sensitive       bool
	SensitiveReason string
	Secrets         []redact.Match // raw values: fingerprint them, never store them
	Values          []string       // URLs, hosts, IPs from untrusted content
}

// Labels returns short tags for logs.
func (r Result) Labels() []string {
	var l []string
	if r.Untrusted {
		l = append(l, "untrusted:"+r.UntrustedReason)
	}
	if r.Sensitive {
		l = append(l, "sensitive:"+r.SensitiveReason)
	}
	return l
}

// Env gives the labeler facts it cannot get from the event alone.
type Env struct {
	Config config.Config
	// RepoOwner returns the git origin owner for a file path ("" if none).
	RepoOwner func(file string) string
	// AgentTainted reports whether a subagent read untrusted content.
	AgentTainted func(agentID string) bool
}

// Post labels a PostToolUse event.
func Post(e event.Event, env Env) Result {
	var r Result
	text := outputText(e.ToolOutput)

	switch {
	case e.ToolName == "WebFetch":
		if !hostAllowed(str(e.ToolInput, "url"), env.Config.AllowedHosts) {
			r.untrusted("web_fetch")
		}
	case e.ToolName == "WebSearch":
		r.untrusted("web_search")
	case strings.HasPrefix(e.ToolName, "mcp__"):
		name := e.MCPServer
		if name == "" {
			name = mcpServerFromTool(e.ToolName)
		}
		sdk := e.MCPSource == "sdk" && env.Config.TrustSDK()
		if !sdk && !env.Config.MCPServerTrusted(name) {
			r.untrusted("mcp:" + name)
		}
	case e.ToolName == "Bash" || e.ToolName == "PowerShell":
		cmd := str(e.ToolInput, "command")
		if why := fetchCommand(cmd); why != "" && !trustedGitHubRead(why, cmd, e.Cwd, env) {
			r.untrusted("shell_fetch:" + why)
		}
		if why := secretCommand(cmd); why != "" {
			r.sensitive("shell_secret:" + why)
		}
	case e.ToolName == "Read" || e.ToolName == "Grep":
		p := str(e.ToolInput, "file_path")
		if p == "" {
			p = str(e.ToolInput, "path")
		}
		if p != "" {
			if why := vendorPath(p); why != "" {
				r.untrusted("vendor:" + why)
			} else if env.RepoOwner != nil && len(env.Config.TrustedRepoOwners) > 0 {
				if owner := env.RepoOwner(p); owner != "" && !env.Config.RepoOwnerTrusted(owner) {
					r.untrusted("repo_owner:" + owner)
				}
			}
			if e.ToolName == "Read" && SensitivePath(p) {
				r.sensitive("file:" + path.Base(norm(p)))
			}
		}
	case e.ToolName == "Agent":
		if id := agentID(e.ToolOutput); id != "" && env.AgentTainted != nil && env.AgentTainted(id) {
			r.untrusted("subagent:" + id)
		}
	}

	// Secrets: all patterns for known-sensitive content, strong patterns elsewhere.
	r.Secrets = redact.Find(text, r.Sensitive)
	if !r.Sensitive && len(r.Secrets) > 0 {
		r.sensitive("secret_in_output:" + r.Secrets[0].Kind)
	}
	if r.Untrusted {
		r.Values = Values(text)
	}
	return r
}

// Prompt labels a UserPromptSubmit event. The prompt is trusted, but a
// pasted secret makes the session sensitive.
func Prompt(e event.Event) Result {
	var r Result
	r.Secrets = redact.Find(e.Prompt, false)
	if len(r.Secrets) > 0 {
		r.sensitive("secret_in_prompt:" + r.Secrets[0].Kind)
	}
	return r
}

func (r *Result) untrusted(why string) {
	if !r.Untrusted {
		r.Untrusted, r.UntrustedReason = true, why
	}
}

func (r *Result) sensitive(why string) {
	if !r.Sensitive {
		r.Sensitive, r.SensitiveReason = true, why
	}
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// norm lower-cases and uses forward slashes so rules work on Windows paths.
func norm(p string) string { return strings.ToLower(strings.ReplaceAll(p, `\`, "/")) }

func mcpServerFromTool(tool string) string {
	rest := strings.TrimPrefix(tool, "mcp__")
	if i := strings.Index(rest, "__"); i > 0 {
		return rest[:i]
	}
	return rest
}

func hostAllowed(raw string, allowed []string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return false
	}
	h := strings.ToLower(u.Hostname())
	for _, a := range allowed {
		a = strings.ToLower(a)
		if h == a || strings.HasSuffix(h, "."+a) {
			return true
		}
	}
	return false
}

func agentID(out json.RawMessage) string {
	var v struct {
		AgentID string `json:"agentId"`
	}
	_ = json.Unmarshal(out, &v)
	return v.AgentID
}

// outputText joins all strings in a JSON tool response, up to maxScan bytes.
func outputText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	if len(raw) > maxScan*2 {
		raw = raw[:maxScan*2]
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return truncate(string(raw))
	}
	var b strings.Builder
	var walk func(any)
	walk = func(x any) {
		if b.Len() >= maxScan {
			return
		}
		switch t := x.(type) {
		case string:
			b.WriteString(t)
			b.WriteByte('\n')
		case map[string]any:
			for _, y := range t {
				walk(y)
			}
		case []any:
			for _, y := range t {
				walk(y)
			}
		}
	}
	walk(v)
	return truncate(b.String())
}

func truncate(s string) string {
	if len(s) > maxScan {
		return s[:maxScan]
	}
	return s
}

// --- shell commands ---

var fetchRules = []struct {
	name string
	re   *regexp.Regexp
}{
	{"http_client", regexp.MustCompile(`(?i)(?:^|[\s;|&(])(?:curl|wget|http|https|xh|aria2c)(?:\.exe)?(?:\s|$)`)},
	{"powershell_web", regexp.MustCompile(`(?i)\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Net\.WebClient|Start-BitsTransfer)\b`)},
	{"netcat", regexp.MustCompile(`(?i)(?:^|[\s;|&(])(?:nc|ncat|netcat|socat)(?:\.exe)?\s`)},
	{"github_cli", regexp.MustCompile(`(?i)\bgh\s+(?:issue|pr|api|release|run|search|gist|discussion|repo\s+view)\b`)},
	{"glab_cli", regexp.MustCompile(`(?i)\bglab\s+(?:issue|mr|api)\b`)},
}

var (
	ghRepoFlag = regexp.MustCompile(`(?:-R|--repo)[\s=]+["']?([A-Za-z0-9_.-]+)/`)
	ghURL      = regexp.MustCompile(`(?i)github\.com[/:]([A-Za-z0-9_.-]+)/`)
	ghAPIRepo  = regexp.MustCompile(`\bgh\s+api\s+["']?/?repos/([A-Za-z0-9_.-]+)/`)
)

// trustedGitHubRead reports whether a gh/glab read targets a repo whose owner
// is in trusted_repo_owners. Found live: gh commands on the user's own repo
// were the main source of untrusted labels (10 of 13).
func trustedGitHubRead(why, cmd, cwd string, env Env) bool {
	if why != "github_cli" && why != "glab_cli" || len(env.Config.TrustedRepoOwners) == 0 {
		return false
	}
	owner := ""
	for _, re := range []*regexp.Regexp{ghRepoFlag, ghAPIRepo, ghURL} {
		if m := re.FindStringSubmatch(cmd); m != nil {
			owner = m[1]
			break
		}
	}
	if owner == "" && cwd != "" && env.RepoOwner != nil {
		owner = env.RepoOwner(cwd + "/x") // the repo of the working directory
	}
	return owner != "" && env.Config.RepoOwnerTrusted(owner)
}

func fetchCommand(cmd string) string {
	for _, r := range fetchRules {
		if r.re.MatchString(cmd) {
			return r.name
		}
	}
	return ""
}

var secretCmdRules = []struct {
	name string
	re   *regexp.Regexp
}{
	{"env_dump", regexp.MustCompile(`(?i)(?:^|[;|&(]\s*)(?:env|printenv|set|export\s+-p)\s*(?:$|[|;&>])`)},
	{"printenv", regexp.MustCompile(`(?i)\bprintenv\b`)},
	{"ps_env", regexp.MustCompile(`(?i)\b(?:Get-ChildItem|gci|ls|dir|Get-Item)\s+env:`)},
	{"ps_env_var", regexp.MustCompile(`(?i)\$env:[A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASS|CRED)`)},
	{"gh_token", regexp.MustCompile(`(?i)\bgh\s+auth\s+(?:token|status\s+(?:-t|--show-token))`)},
	{"cloud_token", regexp.MustCompile(`(?i)\b(?:aws\s+configure\s+(?:get|export-credentials)|aws\s+sts\s+get-session-token|gcloud\s+auth\s+(?:print-access-token|print-identity-token)|az\s+account\s+get-access-token)\b`)},
}

var tokenSplit = regexp.MustCompile(`[\s;|&<>()"'=]+`)

func secretCommand(cmd string) string {
	for _, r := range secretCmdRules {
		if r.re.MatchString(cmd) {
			return r.name
		}
	}
	for _, tok := range tokenSplit.Split(cmd, -1) {
		if tok != "" && SensitivePath(tok) {
			return "file:" + path.Base(norm(tok))
		}
	}
	return ""
}

// --- paths ---

var vendorDirs = []string{
	"/node_modules/", "/vendor/", "/.venv/", "/venv/", "/site-packages/",
	"/third_party/", "/.cargo/registry/", "/go/pkg/mod/", "/bower_components/",
}

func vendorPath(p string) string {
	n := "/" + strings.TrimPrefix(norm(p), "/")
	for _, d := range vendorDirs {
		if strings.Contains(n, d) {
			return strings.Trim(d, "/")
		}
	}
	return ""
}

var sensitiveNames = map[string]bool{
	"credentials": true, "credentials.json": true, ".netrc": true, "_netrc": true,
	".npmrc": true, ".pypirc": true, ".git-credentials": true, ".pgpass": true,
	"secrets.json": true, "secrets.yaml": true, "secrets.yml": true,
	"service-account.json": true,
}

var sensitiveExt = map[string]bool{".pem": true, ".key": true, ".p12": true, ".pfx": true, ".jks": true, ".keystore": true}

var safeEnvSuffix = map[string]bool{"example": true, "sample": true, "template": true, "dist": true, "defaults": true}

var sshKey = regexp.MustCompile(`^id_(?:rsa|dsa|ecdsa|ed25519)(?:_[a-z0-9]+)?$`)

// SensitivePath reports whether a file path usually holds secrets.
func SensitivePath(p string) bool {
	n := norm(p)
	base := path.Base(n)
	switch {
	case base == ".env":
		return true
	case strings.HasPrefix(base, ".env."):
		return !safeEnvSuffix[strings.TrimPrefix(base, ".env.")]
	case sensitiveNames[base]:
		return true
	case sensitiveExt[path.Ext(base)]:
		return true
	case sshKey.MatchString(base):
		return true
	}
	for _, d := range []string{"/.kube/config", "/.docker/config.json", "/.config/gh/hosts.yml", "/.aws/credentials"} {
		if strings.HasSuffix(n, d) {
			return true
		}
	}
	return false
}

// --- untrusted values ---

var (
	urlRe = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>()\[\]{}\\` + "`" + `]+`)
	ipRe  = regexp.MustCompile(`\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b`)
)

// Values extracts URLs, their hosts, and IPv4 addresses from text.
func Values(text string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		if v != "" && !seen[v] && len(out) < maxValuesPerCall {
			seen[v] = true
			out = append(out, v)
		}
	}
	for _, m := range urlRe.FindAllString(text, -1) {
		m = strings.TrimRight(m, ".,;:!?")
		add(m)
		if u, err := url.Parse(m); err == nil {
			add(strings.ToLower(u.Hostname()))
		}
	}
	for _, m := range ipRe.FindAllString(text, -1) {
		add(m)
	}
	return out
}
