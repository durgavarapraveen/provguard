package policy

import (
	"strings"
	"testing"

	"github.com/durgavarapraveen/provguard/internal/shell"
	"github.com/durgavarapraveen/provguard/internal/store"
)

func TestSourceText(t *testing.T) {
	for reason, want := range map[string]string{
		"web_fetch":                "a web page",
		"shell_fetch:github_cli":   "GitHub content (gh)",
		"file:.env":                ".env",
		"repo_owner:stranger":      "a repo owned by stranger",
		"secret_in_prompt:aws_key": "a aws_key in your prompt",
		"something_new:x":          "something_new:x",
	} {
		if got := SourceText(store.Source{Reason: reason}); got != want {
			t.Errorf("%s: got %q, want %q", reason, got, want)
		}
	}
}

func TestMessage(t *testing.T) {
	s := &store.Session{
		TaintSources:     []store.Source{{Tool: "Bash", Reason: "shell_fetch:github_cli"}},
		SensitiveSources: []store.Source{{Tool: "Read", Reason: "file:.env"}},
		UntrustedValues:  []string{"https://evil.test/collect"},
	}
	egress := []shell.Sink{
		{Class: shell.Egress, Target: "https://evil.test/collect"},
		{Class: shell.Egress, Target: "https://api.mycorp.test/v1"},
	}
	r := Result{Rule: "lethal_trifecta", Summary: summary("lethal_trifecta", s, egress, ""), Hosts: safeHosts(egress, s.UntrustedValues)}

	deny := Message(r, Deny, "0123456789")
	for _, want := range []string{
		"provguard stopped this: this call can send data out",
		"GitHub content (gh)", ".env",
		"provguard allow 0123456789",
		"provguard config allow-host api.mycorp.test",
		"provguard explain latest",
		"do not look for another way",
	} {
		if !strings.Contains(deny, want) {
			t.Errorf("deny message lacks %q:\n%s", want, deny)
		}
	}
	if strings.Contains(deny, "allow-host evil.test") {
		t.Errorf("offered to trust the attacker's host:\n%s", deny)
	}

	ask := Message(r, Ask, "")
	if strings.Contains(ask, "provguard allow") || !strings.HasPrefix(ask, "provguard: ") {
		t.Errorf("ask message: %s", ask)
	}
	if noToken := Message(r, Deny, ""); strings.Contains(noToken, "provguard allow") {
		t.Errorf("token offered without one: %s", noToken)
	}
}

func TestSummaryForEveryRule(t *testing.T) {
	s := &store.Session{}
	for _, rule := range []string{"secret_in_sink", "secret_in_push", "lethal_trifecta", "untrusted_destination",
		"tainted_persist", "tainted_exec_remote", "tainted_opaque", "remote_shell", "destroy"} {
		if got := summary(rule, s, nil, "x.test"); got == rule || strings.Contains(got, "_") {
			t.Errorf("%s has no plain summary: %q", rule, got)
		}
	}
}
