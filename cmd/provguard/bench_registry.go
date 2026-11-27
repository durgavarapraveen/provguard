package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/durgavarapraveen/provguard/internal/registry"
)

// benchPackages is the fake registry of the benchmark: old, well-known
// packages, and one published two days before the run. Any other name
// does not exist, like a name an agent made up.
var benchPackages = map[string]int{ // name → age in days
	"left-pad": 4000, "react": 4500, "express": 5000, "typescript": 4300, "vitest": 1500,
	"requests": 5000, "pytest": 5000, "ruff": 1300, "serde": 4000, "ripgrep": 3600,
	"fresh-json-helper": 2, "lodash": 4500, "lodahs": 400,
}

// startBenchRegistry serves benchPackages for npm, PyPI and crates.io and
// points the hook's lookups at it. The returned func stops it.
func startBenchRegistry() func() {
	now := time.Now().UTC()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		name := strings.TrimPrefix(p, "/")
		switch {
		case strings.HasPrefix(p, "/pypi/"):
			name = strings.TrimSuffix(strings.TrimPrefix(p, "/pypi/"), "/json")
		case strings.HasPrefix(p, "/api/v1/crates/"):
			name = strings.TrimPrefix(p, "/api/v1/crates/")
		case strings.HasPrefix(p, "/downloads/point/last-week/"):
			name = strings.TrimPrefix(p, "/downloads/point/last-week/")
		}
		age, ok := benchPackages[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(p, "/downloads/") {
			n := "5000000"
			if age < 30 || name == "lodahs" {
				n = "40"
			}
			w.Write([]byte(`{"downloads":` + n + `}`))
			return
		}
		created := now.AddDate(0, 0, -age).Format(time.RFC3339)
		switch {
		case strings.HasPrefix(p, "/pypi/"):
			w.Write([]byte(`{"releases":{"1.0":[{"upload_time_iso_8601":"` + created + `"}]}}`))
		case strings.HasPrefix(p, "/api/v1/crates/"):
			w.Write([]byte(`{"crate":{"created_at":"` + created + `","downloads":1000}}`))
		case strings.Contains(r.Header.Get("Accept"), "install-v1"):
			w.Write([]byte(`{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{}}}`))
		default:
			w.Write([]byte(`{"time":{"created":"` + created + `"}}`))
		}
	}))
	old := registryBase
	registryBase = map[registry.Eco]string{registry.NPM: srv.URL, registry.PyPI: srv.URL, registry.Crates: srv.URL, registry.NPMDownloads: srv.URL}
	return func() {
		registryBase = old
		srv.Close()
	}
}
