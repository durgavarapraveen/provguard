package label

import (
	"bufio"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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

// KnownGitHosts are forges where "owner" in host/owner/repo means an account.
// The owner counts only on these hosts, so
// https://attacker.example/<trusted-owner>/x.git is not trusted.
var KnownGitHosts = map[string]bool{
	"github.com": true, "ssh.github.com": true, "gitlab.com": true, "bitbucket.org": true,
	"codeberg.org": true, "dev.azure.com": true, "ssh.dev.azure.com": true,
}

var scpLike = regexp.MustCompile(`^(?:[A-Za-z0-9._-]+@)?([A-Za-z0-9.-]+):(.+)$`)

// URLOwner returns the account that owns a git remote URL. For a host not in
// KnownGitHosts it returns "?host/owner", which never matches a trusted owner
// but is not empty (so callers treat the repo as someone else's).
func URLOwner(raw string) string {
	raw = strings.TrimSpace(raw)
	host, p := "", ""
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		host, p = u.Hostname(), u.Path
	} else if m := scpLike.FindStringSubmatch(raw); m != nil && !strings.Contains(m[1], "/") && len(m[1]) > 1 {
		// (a one-letter "host" is a Windows drive: C:/repo is a local path)
		host, p = m[1], m[2] // git@github.com:owner/repo.git
	} else {
		return "" // a local path
	}
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) < 2 || parts[0] == "" {
		return ""
	}
	owner := parts[0]
	if strings.EqualFold(host, "dev.azure.com") || strings.EqualFold(host, "ssh.dev.azure.com") {
		if parts[0] == "v3" && len(parts) > 1 {
			owner = parts[1]
		}
	}
	if !KnownGitHosts[strings.ToLower(host)] {
		return "?" + strings.ToLower(host) + "/" + owner
	}
	return owner
}

// OriginOwner returns the owner of the repo's "origin" push URL, or "" when
// there is no origin.
func OriginOwner(root string) string { return RemoteOwner(root, "origin") }

// RemoteOwner returns the owner of the URL that "git push <remote>" uses.
func RemoteOwner(root, remote string) string {
	if u := RemoteURL(root, remote); u != "" {
		return URLOwner(u)
	}
	return ""
}

// RemoteURL returns the URL git pushes to for remote: pushurl before url,
// with url.<base>.pushInsteadOf / insteadOf rewrites applied, because a
// pushurl or rewrite can send data somewhere other than "url".
func RemoteURL(root, remote string) string {
	cfg := gitConfig(root)
	u := cfg["remote."+remote+".pushurl"]
	if u == "" {
		u = cfg["remote."+remote+".url"]
	}
	if u == "" {
		return ""
	}
	best, bestLen := "", 0
	for k, v := range cfg {
		base, ok := strings.CutPrefix(k, "url.")
		if !ok {
			continue
		}
		for _, suffix := range []string{".pushinsteadof", ".insteadof"} {
			if b, ok := strings.CutSuffix(base, suffix); ok && strings.HasPrefix(u, v) && len(v) > bestLen {
				best, bestLen = b+u[len(v):], len(v)
			}
		}
	}
	if best != "" {
		return best
	}
	return u
}

// Remotes returns the repo's remote names and, for each, the repository
// that `gh repo set-default` chose ("" when unset), from .git/config.
func Remotes(root string) (names []string, ghDefault map[string]string) {
	cfg := gitConfig(root)
	ghDefault = map[string]string{}
	for k, v := range cfg {
		rest, ok := strings.CutPrefix(k, "remote.")
		if !ok {
			continue
		}
		if name, ok := strings.CutSuffix(rest, ".url"); ok {
			names = append(names, name)
		}
		if name, ok := strings.CutSuffix(rest, ".gh-resolved"); ok {
			ghDefault[name] = v
		}
	}
	sort.Strings(names)
	return names, ghDefault
}

// gitConfig reads the repo's .git/config into "section.sub.key" → value
// (keys lower-case, subsection kept as written).
func gitConfig(root string) map[string]string {
	path := filepath.Join(root, ".git", "config")
	// Worktrees and submodules use a .git file: "gitdir: <path>".
	if b, err := os.ReadFile(filepath.Join(root, ".git")); err == nil {
		if gd, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "gitdir:"); ok {
			gd = strings.TrimSpace(gd)
			if !filepath.IsAbs(gd) {
				gd = filepath.Join(root, gd)
			}
			path = filepath.Join(gd, "config")
			if _, err := os.Stat(path); err != nil {
				// Linked worktree: config lives in the common dir, two levels up.
				path = filepath.Join(gd, "..", "..", "config")
			}
		}
	}
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if strings.HasPrefix(line, "[") {
			s := strings.Trim(line, "[]")
			name, sub, hasSub := strings.Cut(s, " ")
			section = strings.ToLower(name)
			if hasSub {
				section += "." + strings.Trim(strings.TrimSpace(sub), `"`)
			}
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		out[section+"."+strings.ToLower(strings.TrimSpace(k))] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	return out
}
