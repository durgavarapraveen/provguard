package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	cases := []struct {
		eco        Eco
		spec, want string // want "" = skipped
	}{
		{NPM, "left-pad", "left-pad"},
		{NPM, "left-pad@1.3.0", "left-pad"},
		{NPM, "@types/node@^20", "@types/node"},
		{NPM, "@types/node", "@types/node"},
		{NPM, "'react@latest'", "react"},
		{NPM, "my-alias@npm:real-pkg@2", "real-pkg"},
		{NPM, "user/repo", ""},
		{NPM, "github:user/repo", ""},
		{NPM, "https://x.test/a.tgz", ""},
		{NPM, "./local", ""},
		{NPM, "pkg.tgz", ""},
		{NPM, "--save-dev", ""},
		{NPM, "@/x", ""},
		{NPM, `C:\pkg`, ""},
		{PyPI, "requests", "requests"},
		{PyPI, "Requests==2.31", "requests"},
		{PyPI, "zope.Interface>=5", "zope-interface"},
		{PyPI, "uvicorn[standard]", "uvicorn"},
		{PyPI, "my__pkg; python_version<'3.9'", "my-pkg"},
		{PyPI, "django@^4.2", "django"},
		{PyPI, "pkg@https://x.test/p.whl", ""},
		{PyPI, "pkg @ git+https://x.test/r", ""},
		{PyPI, "git+https://x.test/r", ""},
		{PyPI, "dist/p-1.0-py3-none-any.whl", ""},
		{PyPI, "-r", ""},
		{PyPI, "_bad", ""},
		{Crates, "ripgrep", "ripgrep"},
		{Crates, "Serde@1.0", "serde"},
		{Crates, "1bad", ""},
		{Crates, "https://x.test/r", ""},
	}
	for _, c := range cases {
		p, ok := Parse(c.eco, c.spec)
		if ok != (c.want != "") || p.Name != c.want {
			t.Errorf("Parse(%s, %q) = %q, %v; want %q", c.eco, c.spec, p.Name, ok, c.want)
		}
	}
}

func TestToolEco(t *testing.T) {
	for tool, want := range map[string]Eco{"npx": NPM, "pnpm": NPM, "uv": PyPI, "pip3": PyPI, "cargo": Crates, "go": "", "gem": ""} {
		if got, ok := ToolEco(tool); got != want || ok != (want != "") {
			t.Errorf("ToolEco(%q) = %q, %v", tool, got, ok)
		}
	}
}

// fakeRegistry serves fixed answers for all three registries and counts
// requests.
func fakeRegistry(t *testing.T) (*httptest.Server, *atomic.Int32) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if r.Header.Get("User-Agent") == "" {
			t.Error("request without User-Agent")
		}
		abbr := strings.Contains(r.Header.Get("Accept"), "install-v1")
		switch r.URL.EscapedPath() {
		case "/@scope%2Fnewpkg":
			if abbr {
				w.Write([]byte(`{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"hasInstallScript":true}}}`))
			} else {
				w.Write([]byte(`{"time":{"created":"2026-11-20T10:00:00.000Z"}}`))
			}
		case "/pypi/requests/json":
			w.Write([]byte(`{"releases":{"2.0":[{"upload_time_iso_8601":"2013-09-24T00:00:00.000000Z"}],"0.2":[{"upload_time_iso_8601":"2011-02-14T00:00:00.000000Z"}],"9.9":[]}}`))
		case "/api/v1/crates/serde":
			w.Write([]byte(`{"crate":{"created_at":"2014-12-05T20:20:39.487502+00:00","downloads":500000000}}`))
		case "/downloads/point/last-week/@scope%2Fnewpkg":
			w.Write([]byte(`{"downloads":12,"package":"@scope/newpkg"}`))
		case "/down":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func client(srv *httptest.Server, dir string, now *time.Time) *Client {
	return &Client{
		HTTP: srv.Client(), Dir: dir, Now: func() time.Time { return *now },
		Base: map[Eco]string{NPM: srv.URL, PyPI: srv.URL, Crates: srv.URL, NPMDownloads: srv.URL},
	}
}

func TestLookup(t *testing.T) {
	srv, _ := fakeRegistry(t)
	now := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	c := client(srv, "", &now)
	ctx := context.Background()

	got, err := c.Lookup(ctx, NPM, "@scope/newpkg")
	if err != nil || !got.Found || !got.InstallScripts || !got.Created.Equal(time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)) || got.Downloads != -1 || got.WeeklyDownloads != 12 {
		t.Errorf("npm: %+v, %v", got, err)
	}
	got, err = c.Lookup(ctx, PyPI, "requests")
	if err != nil || !got.Found || got.Created.Year() != 2011 {
		t.Errorf("pypi: %+v, %v", got, err)
	}
	got, err = c.Lookup(ctx, Crates, "serde")
	if err != nil || !got.Found || got.Created.Year() != 2014 || got.Downloads != 500000000 {
		t.Errorf("crates: %+v, %v", got, err)
	}
	for _, eco := range []Eco{NPM, PyPI, Crates} {
		if got, err := c.Lookup(ctx, eco, "made-up-name"); err != nil || got.Found {
			t.Errorf("%s missing: %+v, %v", eco, got, err)
		}
	}
	if _, err := c.Lookup(ctx, "gem", "x"); err != ErrUnknownEco {
		t.Errorf("unknown eco: %v", err)
	}
}

func TestLookupCache(t *testing.T) {
	srv, n := fakeRegistry(t)
	now := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	c := client(srv, t.TempDir(), &now)
	ctx := context.Background()

	c.Lookup(ctx, Crates, "serde")
	c.Lookup(ctx, Crates, "serde")
	if n.Load() != 1 {
		t.Fatalf("fresh cache: %d requests, want 1", n.Load())
	}
	now = now.Add(TTL + time.Minute)
	c.Lookup(ctx, Crates, "serde")
	if n.Load() != 2 {
		t.Fatalf("stale cache: %d requests, want 2", n.Load())
	}

	// A missing name is checked again after NotFoundTTL.
	c.Lookup(ctx, Crates, "nope")
	now = now.Add(NotFoundTTL + time.Minute)
	c.Lookup(ctx, Crates, "nope")
	if n.Load() != 4 {
		t.Fatalf("not-found cache: %d requests, want 4", n.Load())
	}

	// Offline: a stale entry is returned with no error.
	srv.Close()
	now = now.Add(48 * time.Hour)
	got, err := c.Lookup(ctx, Crates, "serde")
	if err != nil || !got.Found {
		t.Errorf("offline with cache: %+v, %v", got, err)
	}
	if _, err := c.Lookup(ctx, Crates, "never-seen"); err == nil {
		t.Error("offline without cache: want error")
	}
}

func TestLookupServerError(t *testing.T) {
	srv, _ := fakeRegistry(t)
	now := time.Now()
	c := client(srv, "", &now)
	c.Base[NPM] = srv.URL + "/down#"
	if _, err := c.Lookup(context.Background(), NPM, "x"); err == nil {
		t.Error("500: want error")
	}
}

func TestLookupTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }))
	defer srv.Close()
	defer close(block)
	now := time.Now()
	c := client(srv, "", &now)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Lookup(ctx, NPM, "x"); err == nil {
		t.Error("timeout: want error")
	}
}
