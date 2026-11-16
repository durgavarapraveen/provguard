package label

import "testing"

// F16: fake tokens in test fixtures do not make a session sensitive; the
// same token anywhere else, or in a secret file, still does.
func TestFixtureTokensIgnored(t *testing.T) {
	out := map[string]any{"file": map[string]any{"content": "auth := \"" + fakeGitHub + "\""}}
	for p, sensitive := range map[string]bool{
		"/proj/internal/api/client_test.go":   false,
		"/proj/tests/test_auth.py":            false,
		"/proj/src/auth.spec.ts":              false,
		"/proj/src/__tests__/auth.ts":         false,
		"/proj/internal/x/testdata/resp.json": false,
		"/proj/internal/api/client.go":        true,
		"/proj/testdata/.env":                 true, // sensitive by name
		"/proj/contest.go":                    true,
	} {
		r := Post(post("Read", map[string]any{"file_path": p}, out), Env{})
		if r.Sensitive != sensitive {
			t.Errorf("%s: sensitive=%v, want %v (%s)", p, r.Sensitive, sensitive, r.SensitiveReason)
		}
	}
	// Bash output is not exempt, even when it prints a test file.
	if r := Post(bash("cat client_test.go", fakeGitHub), Env{}); !r.Sensitive {
		t.Error("cat of a test file must still count")
	}
}
