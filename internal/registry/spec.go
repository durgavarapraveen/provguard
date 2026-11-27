package registry

import (
	"strings"
)

// Pkg is a package name to look up.
type Pkg struct {
	Eco  Eco
	Name string
}

// ToolEco maps an install tool (from a "package_install:<tool>" or
// "run_remote_package:<tool>" sink) to its ecosystem. ok is false for tools
// this package cannot check (go, gem).
func ToolEco(tool string) (Eco, bool) {
	switch tool {
	case "npm", "pnpm", "yarn", "bun", "npx", "bunx":
		return NPM, true
	case "pip", "pip3", "uv", "uvx", "pipx", "poetry":
		return PyPI, true
	case "cargo":
		return Crates, true
	}
	return "", false
}

// Parse turns one install argument into a registry name. ok is false for
// anything that does not come from the registry by name: flags, URLs, git
// specs, local paths and archives.
func Parse(eco Eco, spec string) (Pkg, bool) {
	s := strings.Trim(spec, `"'`)
	if s == "" || s[0] == '-' || notRegistry(s) {
		return Pkg{}, false
	}
	var name string
	switch eco {
	case NPM:
		name = npmName(s)
	case PyPI:
		name = pypiName(s)
	case Crates:
		name = crateName(s)
	}
	if name == "" {
		return Pkg{}, false
	}
	return Pkg{Eco: eco, Name: name}, true
}

func notRegistry(s string) bool {
	l := strings.ToLower(s)
	if strings.Contains(l, "://") || strings.HasPrefix(l, "git+") || strings.HasPrefix(l, "git@") {
		return true
	}
	for _, p := range []string{"git:", "github:", "gitlab:", "bitbucket:", "file:", "link:", "workspace:", "portal:", "patch:"} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	if l[0] == '.' || l[0] == '/' || l[0] == '\\' || l[0] == '~' || len(l) > 1 && l[1] == ':' {
		return true
	}
	for _, x := range []string{".tgz", ".tar.gz", ".tar", ".zip", ".whl"} {
		if strings.HasSuffix(l, x) {
			return true
		}
	}
	return false
}

// npmName: "pkg", "pkg@1.2", "@scope/pkg@^1", "alias@npm:real@1".
// "user/repo" is GitHub shorthand, not a registry name.
func npmName(s string) string {
	var name, ver string
	if s[0] == '@' {
		i := strings.IndexByte(s[1:], '@')
		if i < 0 {
			name = s
		} else {
			name, ver = s[:i+1], s[i+2:]
		}
		if sc, pkg, ok := strings.Cut(name, "/"); !ok || len(sc) < 2 || pkg == "" || strings.Contains(pkg, "/") {
			return ""
		}
	} else {
		name, ver, _ = strings.Cut(s, "@")
		if strings.Contains(name, "/") {
			return ""
		}
	}
	if real, ok := strings.CutPrefix(ver, "npm:"); ok {
		return npmName(real)
	}
	if !validChars(strings.TrimPrefix(strings.Replace(name, "/", "", 1), "@"), "-._~") {
		return ""
	}
	return name
}

// pypiName: "pkg", "pkg==1.0", "pkg[extra]>=2", "pkg; python_version<'3'",
// poetry's "pkg@^1.0". A direct reference ("pkg@https://…", "pkg @ ./x")
// does not come from PyPI. The name is normalized (PEP 503).
func pypiName(s string) string {
	end := len(s)
	for i, r := range s {
		if !(isAlnum(r) || r == '-' || r == '_' || r == '.') {
			end = i
			break
		}
	}
	name, rest := s[:end], strings.TrimSpace(s[end:])
	if v, ok := strings.CutPrefix(rest, "@"); ok {
		if v = strings.TrimSpace(v); v == "" || notRegistry(v) {
			return ""
		}
	}
	if name == "" || !isAlnum(rune(name[0])) || !isAlnum(rune(name[len(name)-1])) {
		return ""
	}
	if rest != "" && !strings.ContainsAny(rest[:1], "=<>!~;@[(,") {
		return ""
	}
	return normPyPI(name)
}

func normPyPI(name string) string {
	var b strings.Builder
	sep := false
	for _, r := range strings.ToLower(name) {
		if r == '-' || r == '_' || r == '.' {
			sep = true
			continue
		}
		if sep {
			b.WriteByte('-')
			sep = false
		}
		b.WriteRune(r)
	}
	return b.String()
}

// crateName: "foo", "foo@1.2".
func crateName(s string) string {
	name, _, _ := strings.Cut(s, "@")
	if name == "" || !(name[0] >= 'a' && name[0] <= 'z' || name[0] >= 'A' && name[0] <= 'Z') || !validChars(name, "-_") {
		return ""
	}
	return strings.ToLower(name)
}

func validChars(s, extra string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !isAlnum(r) && !strings.ContainsRune(extra, r) {
			return false
		}
	}
	return true
}

func isAlnum(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}
