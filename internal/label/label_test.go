package label

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/event"
)

var fakeGitHub = "ghp_" + strings.Repeat("a1B2", 9)

func post(tool string, input map[string]any, output any) event.Event {
	out, _ := json.Marshal(output)
	return event.Event{Kind: event.PostTool, ToolName: tool, ToolInput: input, ToolOutput: out}
}

func bash(cmd, stdout string) event.Event {
	return post("Bash", map[string]any{"command": cmd}, map[string]any{"stdout": stdout, "stderr": ""})
}

func TestPostLabels(t *testing.T) {
	cases := []struct {
		name      string
		e         event.Event
		untrusted string // expected reason prefix, "" = trusted
		sensitive string
	}{
		{"webfetch", post("WebFetch", map[string]any{"url": "https://evil.test/x"}, map[string]any{"result": "hi"}), "web_fetch", ""},
		{"websearch", post("WebSearch", map[string]any{"query": "x"}, map[string]any{"results": []any{}}), "web_search", ""},
		{"mcp third party", event.Event{Kind: event.PostTool, ToolName: "mcp__github__get_issue", MCPServer: "github", ToolOutput: json.RawMessage(`{"body":"x"}`)}, "mcp:github", ""},
		{"mcp name from tool", post("mcp__jira__get", nil, "x"), "mcp:jira", ""},
		{"mcp sdk trusted", event.Event{Kind: event.PostTool, ToolName: "mcp__ccd_turn__update_plan", MCPServer: "ccd_turn", MCPSource: "sdk", ToolOutput: json.RawMessage(`[]`)}, "", ""},
		{"curl", bash("curl -s https://x.test/a", "data"), "shell_fetch:http_client", ""},
		{"wget in pipe", bash("cd /tmp && wget -qO- https://x.test", ""), "shell_fetch:http_client", ""},
		{"powershell iwr", post("PowerShell", map[string]any{"command": "iwr https://x.test -UseBasicParsing"}, map[string]any{"stdout": ""}), "shell_fetch:powershell_web", ""},
		{"gh issue view", bash("gh issue view 12 --comments", "body"), "shell_fetch:github_cli", ""},
		{"gh api", bash("gh api repos/o/r/issues", "[]"), "shell_fetch:github_cli", ""},
		{"go test is trusted", bash("go test ./...", "ok"), "", ""},
		{"curly word not curl", bash("echo curly", "curly"), "", ""},
		{"env dump", bash("env", "PATH=/bin"), "", "shell_secret:env_dump"},
		{"env piped", bash("env | sort", ""), "", "shell_secret:env_dump"},
		{"printenv", bash("printenv HOME", ""), "", "shell_secret:printenv"},
		{"ps env", post("PowerShell", map[string]any{"command": "Get-ChildItem env:"}, map[string]any{"stdout": ""}), "", "shell_secret:ps_env"},
		{"gh token", bash("gh auth token", "x"), "", "shell_secret:gh_token"},
		{"cat dotenv", bash("cat .env", "A=1"), "", "shell_secret:file:.env"},
		{"cat aws creds", bash("cat ~/.aws/credentials", ""), "", "shell_secret:file:credentials"},
		{"read dotenv", post("Read", map[string]any{"file_path": `C:\proj\.env.local`}, map[string]any{"file": map[string]any{"content": "X=1"}}), "", "file:.env.local"},
		{"read env example is fine", post("Read", map[string]any{"file_path": "/p/.env.example"}, map[string]any{"file": map[string]any{"content": "X="}}), "", ""},
		{"read ssh key", post("Read", map[string]any{"file_path": "/home/u/.ssh/id_ed25519"}, map[string]any{}), "", "file:id_ed25519"},
		{"read ssh pub is fine", post("Read", map[string]any{"file_path": "/home/u/.ssh/id_ed25519.pub"}, map[string]any{}), "", ""},
		{"read pem", post("Read", map[string]any{"file_path": "/p/server.pem"}, map[string]any{}), "", "file:server.pem"},
		{"read node_modules", post("Read", map[string]any{"file_path": `C:\p\node_modules\x\README.md`}, map[string]any{}), "vendor:node_modules", ""},
		{"grep vendor", post("Grep", map[string]any{"path": "/p/vendor/lib"}, map[string]any{}), "vendor:vendor", ""},
		{"read normal", post("Read", map[string]any{"file_path": "/p/main.go"}, map[string]any{"file": map[string]any{"content": "package main"}}), "", ""},
		{"token in any output", bash("cat config.txt", "token "+fakeGitHub), "", "secret_in_output:github_token"},
		{"write is trusted", post("Write", map[string]any{"file_path": "/p/a.go", "content": "x"}, map[string]any{}), "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Post(c.e, Env{})
			if got := r.UntrustedReason; !strings.HasPrefix(got, c.untrusted) || (c.untrusted == "") == r.Untrusted {
				t.Errorf("untrusted: got %v %q, want %q", r.Untrusted, got, c.untrusted)
			}
			if got := r.SensitiveReason; !strings.HasPrefix(got, c.sensitive) || (c.sensitive == "") == r.Sensitive {
				t.Errorf("sensitive: got %v %q, want %q", r.Sensitive, got, c.sensitive)
			}
		})
	}
}

func TestWebFetchAllowedHost(t *testing.T) {
	e := post("WebFetch", map[string]any{"url": "https://docs.example.com/a"}, map[string]any{"result": "x"})
	r := Post(e, Env{Config: config.Config{AllowedHosts: []string{"example.com"}}})
	if r.Untrusted {
		t.Fatal("subdomain of allowed host should be trusted")
	}
	e = post("WebFetch", map[string]any{"url": "https://example.com.evil.test/a"}, map[string]any{"result": "x"})
	if r := Post(e, Env{Config: config.Config{AllowedHosts: []string{"example.com"}}}); !r.Untrusted {
		t.Fatal("look-alike host must stay untrusted")
	}
}

func TestTrustedMCPServerConfig(t *testing.T) {
	e := post("mcp__github__get_issue", nil, "x")
	if r := Post(e, Env{Config: config.Config{TrustedMCPServers: []string{"GitHub"}}}); r.Untrusted {
		t.Fatal("configured MCP server should be trusted")
	}
	off := false
	sdk := event.Event{Kind: event.PostTool, ToolName: "mcp__x__y", MCPServer: "x", MCPSource: "sdk"}
	if r := Post(sdk, Env{Config: config.Config{TrustSDKMCPServers: &off}}); !r.Untrusted {
		t.Fatal("sdk trust turned off should make it untrusted")
	}
}

func TestSubagentOutputInheritsTaint(t *testing.T) {
	e := post("Agent", map[string]any{"prompt": "x"}, map[string]any{"agentId": "a1", "content": "see https://evil.test/p"})
	r := Post(e, Env{AgentTainted: func(id string) bool { return id == "a1" }})
	if !r.Untrusted || r.UntrustedReason != "subagent:a1" {
		t.Fatalf("got %+v", r)
	}
	if len(r.Values) == 0 {
		t.Fatal("values not extracted from tainted subagent output")
	}
	if r := Post(e, Env{AgentTainted: func(string) bool { return false }}); r.Untrusted {
		t.Fatal("clean subagent output must be trusted")
	}
}

func TestRepoOwnerTrust(t *testing.T) {
	e := post("Read", map[string]any{"file_path": "/r/a.go"}, map[string]any{})
	env := Env{
		Config:    config.Config{TrustedRepoOwners: []string{"me"}},
		RepoOwner: func(string) string { return "stranger" },
	}
	if r := Post(e, env); r.UntrustedReason != "repo_owner:stranger" {
		t.Fatalf("got %+v", r)
	}
	env.RepoOwner = func(string) string { return "ME" }
	if r := Post(e, env); r.Untrusted {
		t.Fatal("own repo should be trusted")
	}
	env.Config.TrustedRepoOwners = nil
	env.RepoOwner = func(string) string { return "stranger" }
	if r := Post(e, env); r.Untrusted {
		t.Fatal("empty trusted list turns the check off")
	}
}

// Regression: gh reads of the user's own repos tainted sessions (live data).
func TestGitHubReadOfTrustedRepo(t *testing.T) {
	env := Env{
		Config:    config.Config{TrustedRepoOwners: []string{"me"}},
		RepoOwner: func(string) string { return "me" }, // cwd repo is mine
	}
	cases := []struct {
		cmd       string
		untrusted bool
	}{
		{"gh issue view 12", false},                   // cwd repo, owner me
		{"gh pr view 3 -R me/app", false},             // explicit own repo
		{"gh issue view 9 --repo stranger/lib", true}, // someone else's repo
		{"gh api repos/stranger/lib/issues/1", true},  // someone else's repo
		{"gh api repos/me/app/pulls", false},          // own repo via API
		{"gh pr view https://github.com/stranger/x/pull/2", true},
		{"curl https://api.github.com/repos/me/app", true}, // not gh: still a fetch
	}
	for _, c := range cases {
		e := bash(c.cmd, "body")
		e.Cwd = "/work/app"
		if r := Post(e, env); r.Untrusted != c.untrusted {
			t.Errorf("%q: untrusted=%v want %v (%s)", c.cmd, r.Untrusted, c.untrusted, r.UntrustedReason)
		}
	}
	// No trusted owners configured: gh reads stay untrusted.
	e := bash("gh issue view 12", "body")
	if r := Post(e, Env{RepoOwner: func(string) string { return "me" }}); !r.Untrusted {
		t.Fatal("without trusted_repo_owners gh reads must stay untrusted")
	}
}

func TestSecretsAndValues(t *testing.T) {
	e := post("Read", map[string]any{"file_path": "/p/.env"}, map[string]any{"file": map[string]any{"content": "DB_PASSWORD=sup3rS3cret!\nGH=" + fakeGitHub}})
	r := Post(e, Env{})
	got := map[string]bool{}
	for _, m := range r.Secrets {
		got[m.Value] = true
	}
	if !got["sup3rS3cret!"] || !got[fakeGitHub] {
		t.Fatalf("secrets not found: %+v", r.Secrets)
	}

	v := Values("go to https://Evil.test/a?b=1, or 10.0.0.5. Not 999.1.1.1")
	want := []string{"https://Evil.test/a?b=1", "evil.test", "10.0.0.5"}
	if strings.Join(v, " ") != strings.Join(want, " ") {
		t.Fatalf("values: %v", v)
	}
}

func TestPromptSecret(t *testing.T) {
	r := Prompt(event.Event{Kind: event.UserPrompt, Prompt: "use " + fakeGitHub})
	if !r.Sensitive || len(r.Secrets) != 1 {
		t.Fatalf("got %+v", r)
	}
	if r := Prompt(event.Event{Kind: event.UserPrompt, Prompt: "fix the bug"}); r.Sensitive {
		t.Fatal("plain prompt marked sensitive")
	}
}

func TestOriginOwner(t *testing.T) {
	for url, want := range map[string]string{
		"https://github.com/octocat/hello.git": "octocat",
		"git@github.com:octo-org/repo.git":     "octo-org",
		"https://gitlab.com/grp/proj":          "grp",
	} {
		root := t.TempDir()
		os.MkdirAll(filepath.Join(root, ".git"), 0o700)
		cfg := "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = " + url + "\n"
		os.WriteFile(filepath.Join(root, ".git", "config"), []byte(cfg), 0o600)
		os.MkdirAll(filepath.Join(root, "sub"), 0o700)
		file := filepath.Join(root, "sub", "a.go")
		if got := RepoRoot(file); got != root {
			t.Fatalf("root %q want %q", got, root)
		}
		if got := OriginOwner(root); got != want {
			t.Errorf("%s: owner %q want %q", url, got, want)
		}
	}
}
