package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/durgavarapraveen/provguard/internal/registry"
)

func TestCheckPackages(t *testing.T) {
	now := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/crates/serde":
			w.Write([]byte(`{"crate":{"created_at":"2014-12-05T20:20:39Z","downloads":42}}`))
		case "/api/v1/crates/fresh":
			w.Write([]byte(`{"crate":{"created_at":"2026-11-25T00:00:00Z","downloads":3}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := &registry.Client{HTTP: srv.Client(), Now: func() time.Time { return now }, Base: map[registry.Eco]string{registry.Crates: srv.URL}}

	var out, errb bytes.Buffer
	if code := checkPackages(c, registry.Crates, []string{"serde@1", "./local"}, &out, &errb); code != 0 {
		t.Errorf("old crate: exit %d\n%s", code, out.String())
	}
	if s := out.String(); !strings.Contains(s, "first published 2014-12-05") || !strings.Contains(s, "42 downloads") || !strings.Contains(s, "skipped") {
		t.Errorf("output: %s", s)
	}
	out.Reset()
	if code := checkPackages(c, registry.Crates, []string{"fresh", "serde"}, &out, &errb); code != 1 || !strings.Contains(out.String(), "NEW:") {
		t.Errorf("new crate: exit %d\n%s", code, out.String())
	}
	out.Reset()
	if code := checkPackages(c, registry.Crates, []string{"made-up"}, &out, &errb); code != 1 || !strings.Contains(out.String(), "NOT FOUND") {
		t.Errorf("missing crate: exit %d\n%s", code, out.String())
	}
	srv.Close()
	if code := checkPackages(c, registry.Crates, []string{"other"}, &out, &errb); code != 3 {
		t.Errorf("offline: exit %d", code)
	}
	if code := runPkg([]string{"gem", "x"}, &out, &errb); code != 2 {
		t.Errorf("bad eco: exit %d", code)
	}
}
