// Package registry looks up packages on public registries (npm, PyPI,
// crates.io). It answers: does the name exist, when was it first published,
// and does it run install scripts. Results are cached on disk so repeat
// checks are fast and work offline.
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// Eco is a package ecosystem.
type Eco string

const (
	NPM    Eco = "npm"
	PyPI   Eco = "pypi"
	Crates Eco = "crates"
)

// Info is what a registry says about one package.
type Info struct {
	Found bool `json:"found"`
	// Created is the first publish time. Zero means unknown: the record was
	// too large to read, which only happens for old, busy packages.
	Created time.Time `json:"created,omitzero"`
	// InstallScripts: the latest npm version runs preinstall, install or
	// postinstall scripts.
	InstallScripts bool `json:"install_scripts,omitempty"`
	// Downloads is the all-time download count, or -1 when the registry
	// does not give it in the same answer (npm, PyPI).
	Downloads int64     `json:"downloads"`
	Checked   time.Time `json:"checked"`
}

// Default cache lifetimes. A missing name is checked again sooner, so a
// package the user just published is soon allowed.
const (
	TTL         = 24 * time.Hour
	NotFoundTTL = time.Hour
	maxBody     = 16 << 20 // bigger records are old, busy packages
	userAgent   = "provguard (+https://github.com/durgavarapraveen/provguard)"
)

// Client looks up packages. The zero value works with no cache.
type Client struct {
	HTTP *http.Client
	// Dir is the cache folder. "" turns the cache off.
	Dir string
	Now func() time.Time
	// Base overrides a registry's base URL (tests).
	Base map[Eco]string
}

var defaultBase = map[Eco]string{
	NPM:    "https://registry.npmjs.org",
	PyPI:   "https://pypi.org",
	Crates: "https://crates.io",
}

// ErrUnknownEco is returned for an ecosystem this package cannot look up.
var ErrUnknownEco = errors.New("registry: unknown ecosystem")

// Lookup returns what the registry says about name. A fresh cache entry is
// used without a request. When the registry cannot be reached, a stale
// cache entry is returned with a nil error; with no cache entry, the error
// is returned and the caller decides (provguard allows and logs).
func (c *Client) Lookup(ctx context.Context, eco Eco, name string) (Info, error) {
	if _, ok := defaultBase[eco]; !ok {
		return Info{}, ErrUnknownEco
	}
	now := c.now()
	cached, haveCache := c.readCache(eco, name)
	if haveCache && now.Sub(cached.Checked) < ttl(cached) && !cached.Checked.After(now) {
		return cached, nil
	}
	info, err := c.fetch(ctx, eco, name)
	if err != nil {
		if haveCache {
			return cached, nil
		}
		return Info{}, err
	}
	info.Checked = now
	c.writeCache(eco, name, info)
	return info, nil
}

func ttl(i Info) time.Duration {
	if i.Found {
		return TTL
	}
	return NotFoundTTL
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now().UTC()
}

func (c *Client) base(eco Eco) string {
	if b, ok := c.Base[eco]; ok {
		return b
	}
	return defaultBase[eco]
}

func (c *Client) fetch(ctx context.Context, eco Eco, name string) (Info, error) {
	switch eco {
	case NPM:
		return c.npm(ctx, name)
	case PyPI:
		return c.pypi(ctx, name)
	default:
		return c.crates(ctx, name)
	}
}

// get fetches u and decodes JSON into v. found is false on 404.
// truncated is true when the body was larger than maxBody.
func (c *Client) get(ctx context.Context, u, accept string, v any) (found, truncated bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, false, err
	}
	req.Header.Set("User-Agent", userAgent)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return false, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, false, fmt.Errorf("registry: %s: %s", u, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return false, false, err
	}
	if len(body) > maxBody {
		return true, true, nil
	}
	return true, false, json.Unmarshal(body, v)
}

// npm reads the small "abbreviated" record first (versions and install
// scripts). Only a package with few versions needs the full record for its
// first publish time; that keeps busy packages to one small request.
func (c *Client) npm(ctx context.Context, name string) (Info, error) {
	u := c.base(NPM) + "/" + url.PathEscape(name)
	var abbr struct {
		DistTags map[string]string `json:"dist-tags"`
		Versions map[string]struct {
			HasInstallScript bool `json:"hasInstallScript"`
		} `json:"versions"`
	}
	found, trunc, err := c.get(ctx, u, "application/vnd.npm.install-v1+json", &abbr)
	if err != nil || !found {
		return Info{Found: found, Downloads: -1}, err
	}
	info := Info{Found: true, Downloads: -1}
	if trunc {
		return info, nil
	}
	if v, ok := abbr.Versions[abbr.DistTags["latest"]]; ok {
		info.InstallScripts = v.HasInstallScript
	}
	if len(abbr.Versions) > 50 {
		return info, nil // many versions: not a new package
	}
	var full struct {
		Time map[string]string `json:"time"`
	}
	if _, trunc, err = c.get(ctx, u, "application/json", &full); err != nil {
		return Info{}, err
	}
	if !trunc {
		info.Created = parseTime(full.Time["created"])
	}
	return info, nil
}

// pypi takes the earliest file upload as the first publish time.
func (c *Client) pypi(ctx context.Context, name string) (Info, error) {
	var rec struct {
		Releases map[string][]struct {
			Upload string `json:"upload_time_iso_8601"`
		} `json:"releases"`
	}
	found, trunc, err := c.get(ctx, c.base(PyPI)+"/pypi/"+url.PathEscape(name)+"/json", "", &rec)
	if err != nil || !found || trunc {
		return Info{Found: found, Downloads: -1}, err
	}
	info := Info{Found: true, Downloads: -1}
	for _, files := range rec.Releases {
		for _, f := range files {
			if t := parseTime(f.Upload); !t.IsZero() && (info.Created.IsZero() || t.Before(info.Created)) {
				info.Created = t
			}
		}
	}
	return info, nil
}

func (c *Client) crates(ctx context.Context, name string) (Info, error) {
	var rec struct {
		Crate struct {
			Created   string `json:"created_at"`
			Downloads int64  `json:"downloads"`
		} `json:"crate"`
	}
	found, trunc, err := c.get(ctx, c.base(Crates)+"/api/v1/crates/"+url.PathEscape(name), "", &rec)
	if err != nil || !found || trunc {
		return Info{Found: found, Downloads: -1}, err
	}
	return Info{Found: true, Created: parseTime(rec.Crate.Created), Downloads: rec.Crate.Downloads}, nil
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// cachePath hashes the name: npm scoped names hold "/" and "@".
func (c *Client) cachePath(eco Eco, name string) string {
	h := sha256.Sum256([]byte(name))
	return filepath.Join(c.Dir, "registry", string(eco), hex.EncodeToString(h[:16])+".json")
}

func (c *Client) readCache(eco Eco, name string) (Info, bool) {
	if c.Dir == "" {
		return Info{}, false
	}
	b, err := os.ReadFile(c.cachePath(eco, name))
	if err != nil {
		return Info{}, false
	}
	var i Info
	if json.Unmarshal(b, &i) != nil || i.Checked.IsZero() {
		return Info{}, false
	}
	return i, true
}

// writeCache is best effort: a failed write only costs a request later.
func (c *Client) writeCache(eco Eco, name string, i Info) {
	if c.Dir == "" {
		return
	}
	p := c.cachePath(eco, name)
	if os.MkdirAll(filepath.Dir(p), 0o700) != nil {
		return
	}
	b, err := json.Marshal(i)
	if err != nil {
		return
	}
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0o600) != nil {
		return
	}
	if os.Rename(tmp, p) != nil {
		os.Remove(tmp)
	}
}
