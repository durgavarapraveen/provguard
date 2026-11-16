package label

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// RepoRoot returns the nearest parent directory of file that holds .git, or "".
func RepoRoot(file string) string {
	dir := filepath.Dir(filepath.Clean(file))
	for i := 0; i < 64; i++ {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
	return ""
}

var ownerRe = regexp.MustCompile(`(?:[:/])([A-Za-z0-9._-]+)/[A-Za-z0-9._-]+?(?:\.git)?/?$`)

// OriginOwner returns the owner part of the "origin" remote URL of the repo
// at root, for example "octocat" for https://github.com/octocat/hello.git.
// It returns "" when there is no origin.
func OriginOwner(root string) string {
	cfg := filepath.Join(root, ".git", "config")
	// Worktrees and submodules use a .git file: "gitdir: <path>".
	if b, err := os.ReadFile(filepath.Join(root, ".git")); err == nil {
		if gd, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "gitdir:"); ok {
			gd = strings.TrimSpace(gd)
			if !filepath.IsAbs(gd) {
				gd = filepath.Join(root, gd)
			}
			cfg = filepath.Join(gd, "config")
			if _, err := os.Stat(cfg); err != nil {
				// Linked worktree: config lives in the common dir, two levels up.
				cfg = filepath.Join(gd, "..", "..", "config")
			}
		}
	}
	f, err := os.Open(cfg)
	if err != nil {
		return ""
	}
	defer f.Close()
	inOrigin := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			inOrigin = line == `[remote "origin"]`
			continue
		}
		if !inOrigin {
			continue
		}
		if v, ok := strings.CutPrefix(line, "url"); ok {
			v = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "="))
			if m := ownerRe.FindStringSubmatch(v); m != nil {
				return m[1]
			}
		}
	}
	return ""
}
