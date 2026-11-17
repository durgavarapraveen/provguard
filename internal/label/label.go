// Package label decides where a tool result came from: trusted, untrusted
// (attacker-controllable) or sensitive (holds secrets).
package label

import (
	"encoding/json"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/event"
	"github.com/durgavarapraveen/provguard/internal/realpath"
	"github.com/durgavarapraveen/provguard/internal/redact"
	"github.com/durgavarapraveen/provguard/internal/shell"
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
	Hidden          string         // kind of hidden text in the output (HiddenText)
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
	if r.Hidden != "" {
		l = append(l, "hidden:"+r.Hidden)
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

var commandToolName = regexp.MustCompile(`(?i)(?:^|_)(?:run_in_terminal|run_command|run_shell|exec(?:ute)?(?:_command)?|terminal|shell|bash|powershell|cmd)(?:_|$)`)

// CommandTool returns the shell command of an MCP tool that runs commands
// (for example the desktop app's mcp__terminal__run_in_terminal). Such tools
// must be checked like Bash, or they bypass every shell rule.
func CommandTool(e event.Event) (string, bool) {
	if e.ToolName == event.ShellTool {
		// A shell command whose shell the agent does not say (see
		// event.ShellTool): read like any command of unknown shell.
		s, _ := e.ToolInput["command"].(string)
		return s, s != ""
	}
	if !strings.HasPrefix(e.ToolName, "mcp__") {
		return "", false
	}
	parts := strings.Split(e.ToolName, "__")
	if !commandToolName.MatchString(parts[len(parts)-1]) && (len(parts) < 2 || !commandToolName.MatchString(parts[1])) {
		return "", false
	}
	for _, k := range []string{"command", "cmd", "script", "commandLine"} {
		if s, ok := e.ToolInput[k].(string); ok && s != "" {
			return s, true
		}
	}
	return "", false
}

// Post labels a PostToolUse event.
func Post(e event.Event, env Env) Result {
	var r Result
	text := outputText(e.ToolOutput)

	if cmd, ok := CommandTool(e); ok {
		// Same rules as Bash: fetch commands taint, secret commands are sensitive.
		if why := fetchCommand(cmd); why != "" && !trustedGitHubRead(why, cmd, e.Cwd, env) {
			r.untrusted("shell_fetch:" + why)
		}
		if why := secretCommand(cmd); why != "" {
			r.sensitive("shell_secret:" + why)
		}
		r.Secrets = redact.Find(text, r.Sensitive)
		if !r.Sensitive && len(r.Secrets) > 0 {
			r.sensitive("secret_in_output:" + r.Secrets[0].Kind)
		}
		if r.Untrusted {
			r.Values = Values(text)
		}
		return r
	}

	switch {
	case e.ToolName == "WebFetch":
		if !contentTrusted(str(e.ToolInput, "url"), env.Config) {
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
			// Grep prints matching lines of the files it searches, so grepping
			// .env exposes its values like Read does.
			if SensitivePath(p) || env.Config.SensitivePathMatch(p) {
				r.sensitive("file:" + path.Base(shell.NormPath(p)))
			}
		}
		if g := str(e.ToolInput, "glob"); e.ToolName == "Grep" && g != "" && sensitiveArg(g) {
			r.sensitive("file:" + path.Base(shell.NormPath(g)))
		}
	case e.ToolName == "Agent":
		if id := agentID(e.ToolOutput); id != "" && env.AgentTainted != nil && env.AgentTainted(id) {
			r.untrusted("subagent:" + id)
		}
	}

	// Secrets: all patterns for known-sensitive content, strong patterns elsewhere.
	// Test fixtures hold fake tokens on purpose, so a token
	// found while reading or editing one file of tests does not count.
	// The tokens are still fingerprinted, so a real token committed to a
	// test file cannot be sent out unnoticed (rule 1); only the session
	// label is skipped.
	r.Secrets = redact.Find(text, r.Sensitive)
	if !r.Sensitive && len(r.Secrets) > 0 && !testFixture(e) {
		r.sensitive("secret_in_output:" + r.Secrets[0].Kind)
	}
	// Text hidden from the reader makes any content untrusted, even a file
	// in a trusted repository: rules files with invisible instructions are
	// a known attack.
	if r.Hidden = HiddenText(text); r.Hidden != "" {
		r.untrusted("hidden_text:" + r.Hidden)
	}
	if r.Untrusted {
		r.Values = Values(text)
	}
	return r
}

// fileTools read or change exactly one file, named by file_path.
var fileTools = map[string]bool{"Read": true, "Edit": true, "MultiEdit": true, "Write": true, "NotebookEdit": true}

// testFixture: a one-file tool on a test file or a file under a test-data
// folder. A path that is sensitive by name (.env, keys) never qualifies.
func testFixture(e event.Event) bool {
	if !fileTools[e.ToolName] {
		return false
	}
	p := str(e.ToolInput, "file_path")
	if p == "" {
		p = str(e.ToolInput, "notebook_path")
	}
	if p == "" || SensitivePath(p) {
		return false
	}
	// Judge the file the OS opens, not the name: a link
	// testdata/c → ~/.aws/credentials is not a fixture. A file that does
	// not exist yet (Write) is judged by its name.
	if !filepath.IsAbs(p) && e.Cwd != "" {
		p = filepath.Join(e.Cwd, p)
	}
	if real, err := realpath.Final(p); err == nil {
		if SensitivePath(real) || !fixturePath(real) {
			return false
		}
	}
	return fixturePath(p)
}

// fixturePath: the path names a test file or a file under a test-data folder.
func fixturePath(p string) bool {
	n := shell.NormPath(p)
	base := path.Base(n)
	for _, dir := range strings.Split(path.Dir(n), "/") {
		switch dir {
		case "testdata", "fixtures", "__fixtures__", "__tests__", "__mocks__":
			return true
		}
	}
	stem := strings.TrimSuffix(base, path.Ext(base))
	return strings.HasSuffix(stem, "_test") || strings.HasPrefix(stem, "test_") ||
		strings.HasSuffix(stem, ".test") || strings.HasSuffix(stem, ".spec")
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

func mcpServerFromTool(tool string) string {
	rest := strings.TrimPrefix(tool, "mcp__")
	if i := strings.Index(rest, "__"); i > 0 {
		return rest[:i]
	}
	return rest
}

// contentTrusted reports whether a fetched URL's host is one whose content
// the user trusts. It does not use allowed_hosts, the egress list:
// permitting uploads to a host must not trust everything it serves.
func contentTrusted(raw string, cfg config.Config) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return false
	}
	return cfg.ContentTrusted(u.Hostname())
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
	ghURL     = regexp.MustCompile(`(?i)github\.com[/:]([A-Za-z0-9_.-]+)/`)
	ghAPIRepo = regexp.MustCompile(`^/?repos/([A-Za-z0-9_.-]+)/`)
	// ghAPIPublic: API paths whose response holds text or code an outsider
	// can write. A pull request's own content
	// (/pulls/N/files, /commits, /compare) comes from the contributor's
	// branch, which is attacker-written even in the user's own repository.
	ghAPIPublic = regexp.MustCompile(`(?i)issues|comments|discussions|search|reviews|graphql|notifications|events|gists|pulls?/|/pulls?$|compare|commits|/contents|branches|refs/|/tags|forks`)
)

// ghSafeJSON are `gh pr view --json` fields that outsiders cannot write.
// "headrefname" is left out: it is a branch name a contributor chooses,
// so it carries their text into the context.
var ghSafeJSON = map[string]bool{
	"state": true, "url": true, "number": true, "mergedat": true, "mergeable": true, "mergestatestatus": true,
	"baserefname": true, "isdraft": true, "statuscheckrollup": true, "createdat": true,
	"updatedat": true, "closed": true, "id": true, "reviewdecision": true, "additions": true, "deletions": true,
	"changedfiles": true, "mergecommit": true, "closedat": true,
}

// trustedGitHubRead reports whether every gh/glab call in cmd only reads
// content the user's own accounts wrote, because gh commands on the user's
// own repo are a common source of needless untrusted labels. Every call must
// qualify, not just one trusted -R. Issue/PR/discussion text is
// attacker-written even in your own public repo, so it is never trusted by
// repo owner alone.
func trustedGitHubRead(why, cmd, cwd string, env Env) bool {
	if why != "github_cli" && why != "glab_cli" || len(env.Config.TrustedRepoOwners) == 0 {
		return false
	}
	seen := false
	for _, c := range shell.AnalyzeUnknown(cmd).Cmds {
		if c.Name != "gh" && c.Name != "glab" || len(c.Args) == 0 {
			continue
		}
		seen = true
		owner, safe := ghCall(c.Args[1:])
		if !safe {
			return false
		}
		if owner == "" && cwd != "" && env.RepoOwner != nil {
			owner = env.RepoOwner(cwd + "/x") // the repo of the working directory
		}
		if owner == "" || !env.Config.RepoOwnerTrusted(owner) {
			return false
		}
	}
	return seen
}

// ghCall returns the repo owner a gh call targets ("" = the cwd repo) and
// whether its output is free of text that outsiders can write.
func ghCall(args []string) (owner string, safe bool) {
	var pos []string
	jsonFields := ""
	for i := 0; i < len(args); i++ {
		x := args[i]
		next := ""
		if i+1 < len(args) {
			next = args[i+1]
		}
		switch {
		case x == "-R" || x == "--repo":
			owner, _, _ = strings.Cut(next, "/")
			i++
		case strings.HasPrefix(x, "--repo="):
			owner, _, _ = strings.Cut(strings.TrimPrefix(x, "--repo="), "/")
		case x == "--json":
			jsonFields = strings.ToLower(next)
			i++
		case x == "-q" || x == "--jq" || x == "-t" || x == "--template" || x == "-X" || x == "--method":
			i++
		case strings.HasPrefix(x, "-"):
		default:
			pos = append(pos, x)
			if m := ghURL.FindStringSubmatch(x); m != nil {
				owner = m[1]
			}
		}
	}
	if len(pos) == 0 {
		return owner, false
	}
	sub := ""
	if len(pos) > 1 {
		sub = pos[1]
	}
	switch pos[0] {
	case "api":
		if len(pos) < 2 || ghAPIPublic.MatchString(pos[1]) {
			return owner, false
		}
		if m := ghAPIRepo.FindStringSubmatch(pos[1]); m != nil {
			owner = m[1]
		}
		return owner, true
	case "pr":
		switch sub {
		// "checkout" is not listed: it puts a contributor's branch in the
		// working tree, where every later Read of it would look like the
		// user's own trusted repository.
		case "create", "merge", "close", "ready", "edit", "checks", "reopen":
			return owner, true
		case "view", "list", "status":
			if jsonFields == "" {
				return owner, false // titles, bodies and comments
			}
			for _, f := range strings.Split(jsonFields, ",") {
				if !ghSafeJSON[strings.TrimSpace(f)] {
					return owner, false
				}
			}
			return owner, true
		}
	case "repo":
		return owner, sub == "view" || sub == "create" || sub == "clone"
	case "run":
		return owner, (sub == "list" || sub == "view" || sub == "watch") && !containsStr(args, "--log") && !containsStr(args, "--log-failed")
	case "release":
		return owner, sub == "view" || sub == "list" || sub == "create"
	}
	return owner, false // search, issue, discussion, gist, …: outsiders write these
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// fetchDetails are EGRESS sink details whose command output is remote content.
var fetchDetails = []string{"curl", "wget", "http", "https", "xh", "aria2c", "invoke-webrequest", "invoke-restmethod",
	"start-bitstransfer", "nc", "ncat", "netcat", "socat", "telnet", "interpreter_network:", "dotnet_network",
	"openssl_s_client", "certutil_download", "bitsadmin", "pip_download", "pip3_download", "uv_download"}

// fetchCommand names the reason a command's output is remote content. The
// regex rules catch gh/glab; the shell analyzer catches clients called by
// path (/usr/bin/curl, "C:\…\curl.exe") and inline-code fetches.
func fetchCommand(cmd string) string {
	for _, r := range fetchRules {
		if r.re.MatchString(cmd) {
			return r.name
		}
	}
	for _, s := range shell.AnalyzeUnknown(cmd).Sinks {
		if s.Class != shell.Egress {
			continue
		}
		for _, d := range fetchDetails {
			if s.Detail == d || strings.HasSuffix(d, ":") && strings.HasPrefix(s.Detail, d) {
				return s.Detail
			}
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
			return "file:" + path.Base(shell.NormPath(tok))
		}
	}
	// Quotes and globs hide names from the token split (cat .en''v, cat .e?v):
	// use the analyzer's resolved arguments.
	for _, c := range shell.AnalyzeUnknown(cmd).Cmds {
		if len(c.Args) == 0 {
			continue // a command whose name is known only at run time
		}
		for _, a := range c.Args[1:] {
			if sensitiveArg(a) {
				return "file:" + path.Base(shell.NormPath(a))
			}
		}
	}
	return ""
}

// sensitiveCandidates are file names that a glob argument might expand to.
var sensitiveCandidates = []string{".env", ".env.local", ".env.production", "id_rsa", "id_ed25519", "credentials",
	".netrc", ".git-credentials", ".credentials.json", "secrets.json", "terraform.tfstate"}

// sensitiveArg: a sensitive path, or a glob that can match one.
func sensitiveArg(a string) bool {
	if SensitivePath(a) {
		return true
	}
	if !strings.ContainsAny(a, "*?[") {
		return false
	}
	base := path.Base(shell.NormPath(a))
	for _, c := range sensitiveCandidates {
		if ok, _ := path.Match(base, c); ok {
			return true
		}
	}
	return false
}

// --- paths ---

var vendorDirs = []string{
	"/node_modules/", "/vendor/", "/.venv/", "/venv/", "/site-packages/",
	"/third_party/", "/.cargo/registry/", "/go/pkg/mod/", "/bower_components/",
}

func vendorPath(p string) string {
	n := "/" + strings.TrimPrefix(shell.NormPath(p), "/")
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
	// Claude's own OAuth token, gcloud ADC, and other credential stores
	".credentials.json": true, "application_default_credentials.json": true, ".htpasswd": true,
	".dockercfg": true, ".vault-token": true, ".boto": true, ".s3cfg": true, ".terraformrc": true,
	"terraform.tfstate": true, "terraform.tfstate.backup": true,
}

var sensitiveExt = map[string]bool{".pem": true, ".key": true, ".p12": true, ".pfx": true, ".jks": true, ".keystore": true,
	".tfstate": true, ".tfvars": true}

var safeEnvSuffix = map[string]bool{"example": true, "sample": true, "template": true, "dist": true, "defaults": true}

var sshKey = regexp.MustCompile(`^id_(?:rsa|dsa|ecdsa|ed25519)(?:_[a-z0-9]+)?$`)

// SensitivePath reports whether a file path usually holds secrets.
func SensitivePath(p string) bool {
	n := shell.NormPath(p)
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
