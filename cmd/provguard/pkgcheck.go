package main

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/registry"
)

// pkgBudget caps the time all lookups of one call may take. A slow
// registry then costs at most this much, and the call is allowed.
const pkgBudget = 3 * time.Second

// packageInfo builds policy.Input.PackageInfo, or nil when package_check is
// off. It skips names a private registry may serve (a custom registry is
// set up) and npx names that run a binary already in node_modules. A
// failed lookup is reported through onErr and counts as no answer.
func packageInfo(cfg config.Config, home, cwd, text string, onErr func(error)) func(registry.Pkg, bool) (registry.Info, bool) {
	if !cfg.PackageCheck || registryFlagRe.MatchString(text) {
		return nil
	}
	c := &registry.Client{Dir: home, HTTP: &http.Client{Timeout: 2 * time.Second}, Base: registryBase}
	var deadline time.Time
	custom := map[registry.Eco]bool{}
	checked := map[registry.Eco]bool{}
	return func(p registry.Pkg, remote bool) (registry.Info, bool) {
		if !checked[p.Eco] {
			custom[p.Eco], checked[p.Eco] = customRegistry(p.Eco, cwd), true
		}
		if custom[p.Eco] || remote && p.Eco == registry.NPM && localBin(cwd, p.Name) {
			return registry.Info{}, false
		}
		if deadline.IsZero() {
			deadline = time.Now().Add(pkgBudget)
		}
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		info, err := c.Lookup(ctx, p.Eco, p.Name)
		if err != nil {
			if onErr != nil {
				onErr(err)
			}
			return registry.Info{}, false
		}
		return info, true
	}
}

// registryFlagRe: the command itself picks another registry or index.
var registryFlagRe = regexp.MustCompile(`(?i)--registry\b|--index(-url)?\b|--extra-index-url\b|--default-index\b|--find-links\b|\s-[if]\s|_registry\w*=|index_url=`)

// localBin: node_modules/.bin/name exists in cwd or a parent folder, so
// npx runs that binary and fetches nothing.
func localBin(cwd, name string) bool {
	for d := cwd; d != ""; {
		for _, ext := range []string{"", ".cmd"} {
			if _, err := os.Stat(filepath.Join(d, "node_modules", ".bin", name+ext)); err == nil {
				return true
			}
		}
		up := filepath.Dir(d)
		if up == d {
			break
		}
		d = up
	}
	return false
}

// registryEnv: environment variables that point an installer at another
// registry or index.
var registryEnv = map[registry.Eco][]string{
	registry.NPM:    {"NPM_CONFIG_REGISTRY", "npm_config_registry", "YARN_NPM_REGISTRY_SERVER"},
	registry.PyPI:   {"PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_INDEX", "UV_DEFAULT_INDEX", "POETRY_REPOSITORIES"},
	registry.Crates: {"CARGO_REGISTRIES_DEFAULT", "CARGO_REGISTRY_DEFAULT"},
}

// registryFiles: config files, and the text in them, that set up another
// registry. .npmrc is read line by line instead (npmrcCustom).
var registryFiles = map[registry.Eco][]struct{ name, marker string }{
	registry.NPM:    {{".yarnrc.yml", "npmRegistryServer"}, {".yarnrc.yml", "npmScopes"}, {".yarnrc", "registry "}, {"bunfig.toml", "registry"}},
	registry.PyPI:   {{"pip.conf", "index-url"}, {"pip.ini", "index-url"}, {"uv.toml", "index"}, {"pyproject.toml", "[[tool.uv.index]]"}, {"pyproject.toml", "[[tool.poetry.source]]"}, {"poetry.toml", "repositories"}},
	registry.Crates: {{filepath.Join(".cargo", "config.toml"), "[registries"}, {filepath.Join(".cargo", "config.toml"), "replace-with"}, {filepath.Join(".cargo", "config"), "replace-with"}},
}

// customRegistry: the user installs from a private registry or mirror, so
// a name missing on the public registry is not a sign of a made-up name.
// Project files are searched from cwd up, then the user's config folders.
func customRegistry(eco registry.Eco, cwd string) bool {
	for _, k := range registryEnv[eco] {
		if v := os.Getenv(k); v != "" && !publicRegistry(v) {
			return true
		}
	}
	var dirs []string
	for d := cwd; d != ""; {
		dirs = append(dirs, d)
		up := filepath.Dir(d)
		if up == d {
			break
		}
		d = up
	}
	if h, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, h, filepath.Join(h, ".config", "pip"), filepath.Join(h, ".pip"), filepath.Join(h, ".config", "uv"))
	}
	if runtime.GOOS == "windows" {
		if a := os.Getenv("APPDATA"); a != "" {
			dirs = append(dirs, filepath.Join(a, "pip"), filepath.Join(a, "uv"))
		}
	}
	if ch := os.Getenv("CARGO_HOME"); ch != "" && eco == registry.Crates {
		dirs = append(dirs, filepath.Dir(ch))
	}
	return customRegistryIn(eco, dirs)
}

func customRegistryIn(eco registry.Eco, dirs []string) bool {
	for _, d := range dirs {
		if eco == registry.NPM {
			if b, err := os.ReadFile(filepath.Join(d, ".npmrc")); err == nil && npmrcCustom(b) {
				return true
			}
		}
		for _, f := range registryFiles[eco] {
			if b, err := os.ReadFile(filepath.Join(d, f.name)); err == nil && bytes.Contains(b, []byte(f.marker)) {
				return true
			}
		}
	}
	return false
}

// npmrcCustom: a "registry=" or "@scope:registry=" line points somewhere
// other than the public registry. The "//host/:_authToken=" lines that
// `npm login` writes are not registry settings.
func npmrcCustom(b []byte) bool {
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if k = strings.TrimSpace(k); !ok || strings.HasPrefix(k, "#") || strings.HasPrefix(k, ";") {
			continue
		}
		if (k == "registry" || strings.HasPrefix(k, "@") && strings.HasSuffix(k, ":registry")) && !publicRegistry(v) {
			return true
		}
	}
	return false
}

func publicRegistry(u string) bool {
	u = strings.ToLower(strings.Trim(strings.TrimSpace(u), `"'/`))
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	return u == "registry.npmjs.org" || u == "registry.yarnpkg.com" || u == "pypi.org/simple" || u == "crates.io"
}

// registryBase replaces the public registries' addresses. Only the
// benchmark sets it, to its fake registry; it is never read from the
// environment or a file, so a repository cannot point lookups elsewhere.
var registryBase map[registry.Eco]string
