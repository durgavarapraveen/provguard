package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/durgavarapraveen/provguard/internal/config"
)

// gitRepo makes a folder with a .git/config holding the given remotes
// (name → URL) and extra config lines.
func gitRepo(t *testing.T, remotes map[string]string, extra string) string {
	t.Helper()
	dir := t.TempDir()
	cfg := ""
	for n, u := range remotes {
		cfg += "[remote \"" + n + "\"]\n\turl = " + u + "\n"
	}
	os.MkdirAll(filepath.Join(dir, ".git"), 0o700)
	if err := os.WriteFile(filepath.Join(dir, ".git", "config"), []byte(cfg+extra), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func fakeView(info repoInfo, err error) func(string) (repoInfo, error) {
	return func(string) (repoInfo, error) { return info, err }
}

func TestGHRepoTrusted(t *testing.T) {
	cfg := config.Config{TrustedRepoOwners: []string{"me", "my-org"}}
	mine := map[string]string{"origin": "https://github.com/me/app.git"}
	ok := fakeView(repoInfo{owner: "me"}, nil)

	cases := []struct {
		name    string
		dir     string
		command string
		view    func(string) (repoInfo, error)
		repo    string
		want    bool
	}{
		{"own repo", gitRepo(t, mine, ""), "gh pr create --fill", ok, ".", true},
		{"own org via -R", t.TempDir(), "", ok, "my-org/app", true},
		{"-R with host", t.TempDir(), "", ok, "github.com/me/app", true},
		{"-R stranger", t.TempDir(), "", ok, "stranger/app", false},
		{"-R other host", t.TempDir(), "", ok, "ghe.corp.test/me/app", false},
		{"-R set at run time", t.TempDir(), "", ok, "?", false},
		{"no git repo", t.TempDir(), "", ok, ".", false},
		{"no remotes", gitRepo(t, nil, ""), "", ok, ".", false},
		{"stranger upstream remote", gitRepo(t, map[string]string{
			"origin": "https://github.com/me/app.git", "upstream": "https://github.com/stranger/app.git"}, ""), "", ok, ".", false},
		{"set-default to stranger", gitRepo(t, mine, "[remote \"origin\"]\n\tgh-resolved = stranger/app\n"), "", ok, ".", false},
		{"set-default base", gitRepo(t, mine, "[remote \"origin\"]\n\tgh-resolved = base\n"), "", ok, ".", true},
		{"fork of a stranger's repo", gitRepo(t, mine, ""), "", fakeView(repoInfo{owner: "me", parent: "stranger"}, nil), ".", false},
		{"fork of own org's repo", gitRepo(t, mine, ""), "", fakeView(repoInfo{owner: "me", parent: "my-org"}, nil), ".", true},
		{"GitHub says another owner", gitRepo(t, mine, ""), "", fakeView(repoInfo{owner: "stranger"}, nil), ".", false},
		{"gh fails", gitRepo(t, mine, ""), "", fakeView(repoInfo{}, errors.New("offline")), ".", false},
		{"GH_REPO in command", gitRepo(t, mine, ""), "GH_REPO=stranger/app gh pr create", ok, ".", false},
	}
	for _, c := range cases {
		f := ghRepoTrusted(cfg, c.dir, c.command, c.view)
		if got := f != nil && f(c.repo); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if ghRepoTrusted(config.Config{}, t.TempDir(), "", ok) != nil {
		t.Error("no trusted owners must trust no repository")
	}
}
