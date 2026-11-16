package label

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

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

// Review finding 12: a token in a real fixture is still fingerprinted, and
// a link inside testdata/ to a file elsewhere is not a fixture.
func TestFixtureFingerprinted(t *testing.T) {
	out := map[string]any{"file": map[string]any{"content": fakeGitHub}}
	r := Post(post("Read", map[string]any{"file_path": "/proj/x_test.go"}, out), Env{})
	if r.Sensitive || len(r.Secrets) == 0 {
		t.Errorf("fixture: sensitive=%v secrets=%d; want false, >0", r.Sensitive, len(r.Secrets))
	}
}

func TestFixtureLinkIsNotAFixture(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	os.MkdirAll(home, 0o700)
	os.WriteFile(filepath.Join(home, "token.txt"), []byte("x"), 0o600)
	os.MkdirAll(filepath.Join(dir, "proj"), 0o700)
	link := filepath.Join(dir, "proj", "testdata") // testdata/ → home/
	if err := os.Symlink(home, link); err != nil {
		if runtime.GOOS != "windows" || exec.Command("cmd", "/c", "mklink", "/J", link, home).Run() != nil {
			t.Skip("links not available:", err)
		}
	}
	out := map[string]any{"file": map[string]any{"content": fakeGitHub}}
	p := filepath.Join(link, "token.txt")
	if r := Post(post("Read", map[string]any{"file_path": p}, out), Env{}); !r.Sensitive {
		t.Error("a file reached through a link in testdata/ was treated as a fixture")
	}
}
