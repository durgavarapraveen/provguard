package redact

import (
	"encoding/base64"
	"strings"
)

// fakeMarkers: words that test and doc tokens carry and real ones do not.
var fakeMarkers = []string{
	"fake", "test", "example", "dummy", "sample", "placeholder", "changeme",
	"redacted", "notreal", "not_real", "mock", "xxxx", "0000", "1234", "abcd",
	"your", "secret", "token", "foobar", "hunter2",
}

// LooksFake reports whether a found secret value looks made up for a test or
// a doc: it names itself as one, or decodes (base64) to such a name, or is
// too regular to be random (one character repeated, a short alphabet run).
// A real token is random, so it passes none of these.
func LooksFake(v string) bool {
	if hasMarker(v) {
		return true
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		// Decode the token body: the part after a known prefix such as sk-ant-api03-.
		body := v[strings.LastIndexAny(v, "-_")+1:]
		for n := len(body); n >= 8; n-- {
			if b, err := enc.DecodeString(body[:n]); err == nil {
				if hasMarker(string(b)) {
					return true
				}
				break
			}
		}
	}
	return lowVariety(v)
}

func hasMarker(s string) bool {
	l := strings.ToLower(s)
	for _, m := range fakeMarkers {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// lowVariety: a run of 6 or more equal characters, or few distinct
// characters for the length.
func lowVariety(v string) bool {
	run, distinct := 1, map[rune]bool{}
	var prev rune
	for i, r := range v {
		distinct[r] = true
		if i > 0 && r == prev {
			if run++; run >= 6 {
				return true
			}
		} else {
			run = 1
		}
		prev = r
	}
	return len(v) >= 16 && len(distinct)*3 < len(v)
}
