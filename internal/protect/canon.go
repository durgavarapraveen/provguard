package protect

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// canonical returns the path that the OS will really open for p.
//
// Windows strips trailing dots and spaces from each
// path segment, ignores the default "::$DATA" stream suffix, accepts
// "\\?\" prefixes and 8.3 short names, and follows symlinks and junctions.
// Any of these let a name-based check be bypassed. canonical removes the
// lexical tricks, then asks the OS for the final path of the deepest part
// that already exists (finalPath: GetFinalPathNameByHandle on Windows,
// EvalSymlinks elsewhere) and appends the rest.
func canonical(p, cwd string) string {
	key := p + "\x00" + cwd
	canonMu.Lock()
	if v, ok := canonCache[key]; ok {
		canonMu.Unlock()
		return v
	}
	canonMu.Unlock()
	v := canonicalUncached(p, cwd)
	canonMu.Lock()
	canonCache[key] = v
	canonMu.Unlock()
	return v
}

// The cache lives for one hook process (one tool call), so it cannot go
// stale across calls. It saves resolving the same home/.claude/cwd paths
// through the OS many times per call (~4 ms).
var (
	canonMu    sync.Mutex
	canonCache = map[string]string{}
	finalCache = map[string]string{}
)

// cachedFinal resolves an existing path once per process. One OS lookup costs
// about 0.4 ms on Windows; writes under the same folder share it.
func cachedFinal(p string) (string, error) {
	canonMu.Lock()
	v, ok := finalCache[p]
	canonMu.Unlock()
	if ok {
		return v, nil
	}
	v, err := finalPath(p)
	if err != nil {
		return "", err
	}
	canonMu.Lock()
	finalCache[p] = v
	canonMu.Unlock()
	return v, nil
}

func canonicalUncached(p, cwd string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	for _, pre := range []string{`\\?\`, `//?/`, `\??\`, `\\.\`} {
		p = strings.TrimPrefix(p, pre)
	}
	p = lexical(p)
	switch {
	case filepath.IsAbs(p):
	case strings.HasPrefix(p, `\`) || strings.HasPrefix(p, "/"):
		// Windows: "\x" is rooted on the current drive, not relative to cwd.
		if a, err := filepath.Abs(p); err == nil {
			p = a
		}
	case cwd != "":
		p = filepath.Join(lexical(cwd), p)
	}
	p = filepath.Clean(p)

	// Resolve the deepest existing ancestor; keep the missing tail as is.
	existing, tail := p, ""
	for i := 0; i < 64; i++ {
		if _, err := os.Lstat(existing); err == nil {
			break
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return p
		}
		tail = filepath.Join(filepath.Base(existing), tail)
		existing = parent
	}
	real, err := cachedFinal(existing)
	if err != nil || real == "" {
		return p
	}
	if tail == "" {
		return real
	}
	return filepath.Join(real, tail)
}

// lexical removes Windows-only spellings segment by segment: a stream
// suffix (":$DATA", ":x") and trailing dots and spaces. A drive "C:" is kept.
func lexical(p string) string {
	sep := func(r rune) bool { return r == '/' || r == '\\' }
	segs := strings.FieldsFunc(p, sep)
	for i, s := range segs {
		if i == 0 && len(s) == 2 && s[1] == ':' {
			continue // drive letter
		}
		if j := strings.IndexByte(s, ':'); j > 0 {
			s = s[:j] // alternate data stream
		}
		if s != "." && s != ".." {
			if t := strings.TrimRight(s, ". "); t != "" {
				s = t
			}
		}
		segs[i] = s
	}
	out := strings.Join(segs, string(filepath.Separator))
	if len(p) > 0 && sep(rune(p[0])) {
		out = string(filepath.Separator) + out
	}
	return out
}
