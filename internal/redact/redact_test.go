package redact

import (
	"strings"
	"testing"
)

// Fake secrets are built by concatenation so repo secret scanners do not flag this file.
var (
	fakeGitHub    = "ghp_" + strings.Repeat("a1B2", 9)
	fakeAWS       = "AKIA" + "IOSFODNN7EXAMPLE"
	fakeAnthropic = "sk-ant-" + "api03-" + strings.Repeat("xY9_", 8)
	fakeOpenAI    = "sk-proj-" + strings.Repeat("Qw3r", 8)
	fakeJWT       = "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0" + ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	fakeKeyBlock  = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEow\nabc\n-----END RSA " + "PRIVATE KEY-----"
	fakeEntropy   = "q8Zt3+Lw9/Vb2Nk7Rx4Hm1Pj6Yc0Gs5Ue_Ad-Fo"
	fakeAWSSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfi" + "CYEXAMPLEKEY"
)

func TestStringRedactsSecrets(t *testing.T) {
	cases := []struct {
		name, in, secret string
	}{
		{"github", "token " + fakeGitHub + " end", fakeGitHub},
		{"aws", "export AWS=" + fakeAWS, fakeAWS},
		{"anthropic", "key: " + fakeAnthropic, fakeAnthropic},
		{"openai", fakeOpenAI, fakeOpenAI},
		{"jwt", "Cookie: s=" + fakeJWT, fakeJWT},
		{"private key", "x\n" + fakeKeyBlock + "\ny", "MIIEow"},
		{"bearer", "curl -H 'Authorization: Bearer abcdefghijklmnop1234'", "abcdefghijklmnop1234"},
		{"url password", "git clone https://bob:hunter2pass@example.com/r.git", "hunter2pass"},
		{"env assignment", "DB_PASSWORD=sup3rS3cret!", "sup3rS3cret!"},
		{"json assignment", `{"api_key": "abcd1234efgh"}`, "abcd1234efgh"},
		{"high entropy", "blob " + fakeEntropy, fakeEntropy},
		{"aws secret with slashes", "aws_secret_access_key = " + fakeAWSSecret, fakeAWSSecret},
		// Review (MED): no key=value around it; the path exemption leaked it.
		{"aws secret as cli arg", "aws configure set aws_secret_access_key " + fakeAWSSecret, fakeAWSSecret},
		{"aws secret piped", "echo " + fakeAWSSecret + " | aws sts", fakeAWSSecret},
		{"auth token", "AUTH_TOKEN=abcd1234efgh", "abcd1234efgh"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := String(c.in)
			if strings.Contains(got, c.secret) {
				t.Fatalf("secret not redacted:\n in:  %q\n out: %q", c.in, got)
			}
			if !strings.Contains(got, "[REDACTED:") {
				t.Fatalf("no redaction tag in %q", got)
			}
		})
	}
}

func TestStringKeepsNormalText(t *testing.T) {
	keep := []string{
		"git log 3f786850e387550fdab836ed7e6dc881de23001b", // hex SHA stays visible
		"go test ./internal/redact/...",
		"C:/Users/dev/Projects/provguard/internal/audit/audit.go",
		"password reset flow is in auth.go", // word without assignment
		"author: Johnson wrote it",          // review NIT: "author" is not a credential
		"authors = [\"Ann Lee\"]",
		// Regression: long temp paths were redacted in the live audit log.
		"C:/Users/dev/AppData/Local/Temp/claude/6d6f306987e1cd9c/d3f6b33e-8022-4234-9074-e403a9d531cb/scratchpad/pg-del",
		"/home/dev/.cache/go-build/3f/3f786850e387550fdab836ed7e6dc881de23001b-d",
	}
	for _, s := range keep {
		if got := String(s); got != s {
			t.Errorf("changed normal text:\n in:  %q\n out: %q", s, got)
		}
	}
}

func TestValueWalksNestedJSON(t *testing.T) {
	in := map[string]any{
		"command": "echo " + fakeGitHub,
		"list":    []any{"ok", "AWS " + fakeAWS},
		"n":       3.0,
	}
	out := Value(in, 0).(map[string]any)
	if strings.Contains(out["command"].(string), fakeGitHub) {
		t.Fatal("nested string not redacted")
	}
	if strings.Contains(out["list"].([]any)[1].(string), fakeAWS) {
		t.Fatal("string in list not redacted")
	}
	if out["n"].(float64) != 3 {
		t.Fatal("number changed")
	}
}

func TestValueTruncates(t *testing.T) {
	got := Value(strings.Repeat("ab ", 100), 10).(string)
	if !strings.HasSuffix(got, "[truncated]") || len([]rune(got)) > 30 {
		t.Fatalf("bad truncation: %q", got)
	}
}
