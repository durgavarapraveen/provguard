package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/label"
)

// repoInfo is what GitHub says about the repository gh would use.
type repoInfo struct {
	owner, parent string // parent is the owner of the forked-from repo, or ""
}

// ghRepoView asks the GitHub CLI which repository it uses in dir, and
// whether that repository is a fork.
func ghRepoView(dir string) (repoInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "gh", "repo", "view", "--json", "owner,parent")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return repoInfo{}, err
	}
	var v struct {
		Owner  struct{ Login string } `json:"owner"`
		Parent *struct {
			Owner struct{ Login string } `json:"owner"`
		} `json:"parent"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return repoInfo{}, err
	}
	info := repoInfo{owner: v.Owner.Login}
	if v.Parent != nil {
		info.parent = v.Parent.Owner.Login
	}
	return info, nil
}

// ghRepoTrusted builds policy.Input.GHRepoTrusted: whether a gh write goes
// to a repository the user owns. Every doubt answers "no", because a "yes"
// lets data leave a 🔴 session:
//   - GH_* settings and changes to the folder in the same command are
//     handled by the analyzer and the policy (shell.scopeGHTargets);
//   - "OWNER/REPO" (from -R) must have a trusted owner on github.com;
//   - the current folder's repository needs every remote, and every
//     `gh repo set-default` choice, owned by a trusted owner, and GitHub
//     must confirm the owner and that it is not a fork of someone else's
//     repository (in a fork, gh can send a pull request to the parent).
func ghRepoTrusted(cfg config.Config, cwd string, view func(dir string) (repoInfo, error)) func(string) bool {
	if len(cfg.TrustedRepoOwners) == 0 {
		return nil
	}
	cache := map[string]bool{}
	return func(repo string) bool {
		if v, ok := cache[repo]; ok {
			return v
		}
		var v bool
		switch {
		case repo == "?":
		case repo == ".":
			v = currentRepoTrusted(cfg, cwd, view)
		case strings.HasPrefix(repo, "@"):
			v = currentRepoTrusted(cfg, resolveDir(repo[1:], cwd), view)
		default:
			v = cfg.RepoOwnerTrusted(ghRepoOwner(repo))
		}
		cache[repo] = v
		return v
	}
}

// resolveDir makes a cd target absolute: ~ is the home folder, a relative
// path is relative to cwd.
func resolveDir(dir, cwd string) string {
	if rest, ok := strings.CutPrefix(dir, "~"); ok {
		if h, err := os.UserHomeDir(); err == nil && (rest == "" || rest[0] == '/' || rest[0] == '\\') {
			return filepath.Join(h, rest)
		}
		return ""
	}
	if filepath.IsAbs(dir) || len(dir) > 1 && dir[1] == ':' {
		return dir
	}
	if len(dir) > 2 && dir[0] == '/' && dir[2] == '/' && runtime.GOOS == "windows" { // Git Bash /c/…
		return dir[1:2] + ":" + dir[2:]
	}
	return filepath.Join(cwd, dir)
}

// ghRepoOwner returns the owner in "OWNER/REPO", "github.com/OWNER/REPO" or
// a URL, or "" for anything else (another host, a bad value).
func ghRepoOwner(repo string) string {
	if strings.Contains(repo, "://") || strings.HasPrefix(repo, "git@") {
		return label.URLOwner(repo) // "?host/owner" for unknown hosts: never trusted
	}
	p := strings.Split(repo, "/")
	switch {
	case len(p) == 2 && p[0] != "" && p[1] != "":
		return p[0]
	case len(p) == 3 && strings.EqualFold(p[0], "github.com") && p[1] != "" && p[2] != "":
		return p[1]
	}
	return ""
}

func currentRepoTrusted(cfg config.Config, cwd string, view func(string) (repoInfo, error)) bool {
	if cwd == "" {
		return false
	}
	root := label.RepoRoot(cwd + "/x")
	if root == "" {
		return false
	}
	names, defaults := label.Remotes(root)
	if len(names) == 0 {
		return false
	}
	for _, n := range names {
		if !cfg.RepoOwnerTrusted(label.RemoteOwner(root, n)) {
			return false
		}
	}
	for _, d := range defaults {
		if d != "" && d != "base" && !cfg.RepoOwnerTrusted(ghRepoOwner(d)) {
			return false
		}
	}
	info, err := view(root)
	if err != nil || !cfg.RepoOwnerTrusted(info.owner) {
		return false
	}
	return info.parent == "" || cfg.RepoOwnerTrusted(info.parent)
}
