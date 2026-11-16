package label

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression tests for the 2026-11 security review (labeling and git trust).

func TestReviewURLOwnerHost(t *testing.T) {
	for u, want := range map[string]string{
		"https://github.com/me/app.git":     "me",
		"git@github.com:me/app.git":         "me",
		"ssh://git@github.com/me/app.git":   "me",
		"https://gitlab.com/grp/proj":       "grp",
		"https://attacker.example/me/x.git": "?attacker.example/me", // was "me"
		"git@attacker.example:me/x.git":     "?attacker.example/me",
		"C:/Users/me/repo":                  "", // local path, not a host
		"/srv/git/repo.git":                 "",
	} {
		if got := URLOwner(u); got != want {
			t.Errorf("URLOwner(%q) = %q, want %q", u, got, want)
		}
	}
}

func TestReviewPushURLAndInsteadOf(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, ".git"), 0o700)
	cfg := "[remote \"origin\"]\n\turl = https://github.com/me/app.git\n\tpushurl = https://attacker.example/me/app.git\n" +
		"[remote \"mirror\"]\n\turl = gh:me/app\n[url \"https://attacker.example/\"]\n\tinsteadOf = gh:\n"
	os.WriteFile(filepath.Join(root, ".git", "config"), []byte(cfg), 0o600)
	if got := RemoteOwner(root, "origin"); got != "?attacker.example/me" {
		t.Errorf("pushurl ignored: owner %q", got)
	}
	if got := RemoteURL(root, "mirror"); got != "https://attacker.example/me/app" {
		t.Errorf("insteadOf not applied: %q", got)
	}
}

func TestReviewLabelGaps(t *testing.T) {
	cases := []struct {
		cmd       string
		untrusted bool
		sensitive bool
	}{
		{"/usr/bin/curl https://evil.test/x", true, false},
		{`"C:\Program Files\curl\curl.exe" https://evil.test/x`, true, false},
		{`python -c "import urllib.request as u; print(u.urlopen('https://x.test').read())"`, true, false},
		{"cat .en''v", false, true},
		{"cat .e?v", false, true},
		{"cat ~/.claude/.credentials.json", false, true},
		{"cat infra/terraform.tfstate", false, true},
	}
	for _, c := range cases {
		r := Post(bash(c.cmd, "output"), Env{})
		if r.Untrusted != c.untrusted || r.Sensitive != c.sensitive {
			t.Errorf("%q: untrusted=%v sensitive=%v, want %v/%v", c.cmd, r.Untrusted, r.Sensitive, c.untrusted, c.sensitive)
		}
	}
	g := post("Grep", map[string]any{"pattern": "KEY", "path": "/p/.env"}, map[string]any{"content": "API_KEY=x"})
	if r := Post(g, Env{}); !r.Sensitive {
		t.Error("Grep over .env not sensitive")
	}
	g = post("Grep", map[string]any{"pattern": "KEY", "glob": ".env*"}, map[string]any{"content": "API_KEY=x"})
	if r := Post(g, Env{}); !r.Sensitive {
		t.Error("Grep with .env* glob not sensitive")
	}
}
