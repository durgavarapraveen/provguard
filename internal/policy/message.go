package policy

import (
	"strings"

	"github.com/durgavarapraveen/provguard/internal/shell"
	"github.com/durgavarapraveen/provguard/internal/store"
)

// This file turns a decision into words for the person at the keyboard.
// Result.Reason stays technical (rule, labels, sinks) for the audit log and
// `provguard explain`; Result.Summary is one plain sentence for the prompt.

// SourceText describes where a label came from, in plain words.
// Unknown label reasons are returned as they are.
func SourceText(s store.Source) string {
	kind, detail, _ := strings.Cut(s.Reason, ":")
	switch kind {
	case "web_fetch":
		return "a web page"
	case "web_search":
		return "web search results"
	case "shell_fetch":
		if detail == "github_cli" {
			return "GitHub content (gh)"
		}
		return "downloaded content (" + detail + ")"
	case "mcp":
		return "the MCP server " + detail
	case "repo_owner", "repo_owner_at_start":
		return "a repo owned by " + detail
	case "subagent":
		return "a subagent that read untrusted content"
	case "vendor":
		return "vendored third-party code"
	case "file":
		return detail
	case "secret_in_output":
		return "a " + detail + " in tool output"
	case "secret_in_prompt":
		return "a " + detail + " in your prompt"
	case "shell_secret":
		return "secrets shown by a command (" + detail + ")"
	}
	return s.Reason
}

func firstText(src []store.Source) string {
	if len(src) == 0 {
		return "an earlier step"
	}
	return SourceText(src[0])
}

// summary is the plain sentence for each rule. It completes
// "provguard stopped this: …".
func summary(rule string, s *store.Session, sinks []shell.Sink, dest string) string {
	untrusted, secrets := firstText(s.TaintSources), firstText(s.SensitiveSources)
	switch rule {
	case "secret_in_sink":
		return "this call contains a secret the agent read earlier (" + secrets + ")"
	case "secret_in_push":
		return "the commits to push contain a secret the agent read earlier (" + secrets + ")"
	case "lethal_trifecta":
		return "this call can send data out, and the agent has read both untrusted content (" + untrusted + ") and secrets (" + secrets + ")"
	case "untrusted_destination":
		return "this call sends data to " + dest + ", an address taken from untrusted content (" + untrusted + ")"
	case "remote_shell":
		return "this call connects a shell to the network (a reverse shell)"
	case "destroy":
		return "this call can delete data or history"
	}
	if strings.HasPrefix(rule, "tainted_") {
		what := "make a lasting change"
		if len(sinks) > 0 {
			switch sinks[0].Class {
			case shell.ExecRemote:
				what = "run code from the internet"
			case shell.Opaque:
				what = "run code provguard cannot read"
			}
		}
		return "after reading untrusted content (" + untrusted + "), the agent wants to " + what
	}
	return rule
}

// safeHosts returns the hosts of the egress sinks that the user could add to
// allowed_hosts. A host taken from untrusted content is never offered: that
// is the attacker's address, and one click must not trust it for good.
func safeHosts(sinks []shell.Sink, untrustedValues []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, x := range sinks {
		if x.Class != shell.Egress {
			continue
		}
		h := targetHost(x.Target)
		if h == "" || seen[h] || isLocal(h) || fromUntrusted(h, untrustedValues) {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

//
// Review finding: values without a scheme ("evil.com/drop") and subdomains
// of an untrusted host were missed. A host now counts as untrusted when it
// appears in a value at all, or shares its last two labels with the host of
// one (a.evil.org and evil.org; for co.uk-style names this is stricter than
// needed, which only hides the hint).
func fromUntrusted(host string, values []string) bool {
	for _, v := range values {
		v = strings.ToLower(v)
		if strings.Contains(v, host) {
			return true
		}
		if vh := targetHost(v); vh != "" && siteOf(vh) == siteOf(host) {
			return true
		}
	}
	return false
}

// siteOf returns the last two labels of a host name.
func siteOf(h string) string {
	p := strings.Split(strings.TrimSuffix(h, "."), ".")
	if len(p) < 2 {
		return h
	}
	return p[len(p)-2] + "." + p[len(p)-1]
}

// Message is the text shown in Claude Code for a decision. token is the
// allow-once token, or "" when none was recorded.
func Message(r Result, decision, token string) string {
	if decision == Ask {
		return "provguard: " + r.Summary + ". Approve only if you expected this. Details: provguard explain latest"
	}
	var b strings.Builder
	b.WriteString("provguard stopped this: " + r.Summary + ".")
	if token != "" {
		b.WriteString("\nIf you trust it, run in your own terminal: provguard allow " + token + " (this exact call, once, within 10 minutes)")
		if len(r.Hosts) > 0 {
			b.WriteString(", or: provguard config allow-host " + r.Hosts[0] + " (always)")
		}
		b.WriteString(".")
	}
	b.WriteString("\nDetails: provguard explain latest.")
	b.WriteString("\nAgent: do not look for another way to do this; tell the user what was stopped and why.")
	return b.String()
}
