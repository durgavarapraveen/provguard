// Package redact removes secrets from strings and JSON-like values before
// provguard writes them to disk.
package redact

import (
	"math"
	"regexp"
)

type rule struct {
	kind string
	re   *regexp.Regexp
	// group is the submatch index to replace. 0 replaces the whole match.
	group int
}

// Order matters: specific token formats run before generic rules.
var rules = []rule{
	{"private_key", regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`), 0},
	{"aws_access_key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), 0},
	{"github_token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b`), 0},
	{"anthropic_key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`), 0},
	{"openai_key", regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}`), 0},
	{"slack_token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`), 0},
	{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), 0},
	{"stripe_key", regexp.MustCompile(`\b[rs]k_(?:live|test)_[0-9A-Za-z]{16,}\b`), 0},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), 0},
	{"bearer", regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9._~+/-]{16,}=*)`), 1},
	{"url_password", regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:([^@\s/]+)@`), 1},
	{"assignment", regexp.MustCompile(`(?i)\b[A-Za-z0-9_]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)[A-Za-z0-9_]*["']?\s*[:=]\s*["']?([^\s"',;]{6,})`), 1},
}

var candidate = regexp.MustCompile(`[A-Za-z0-9+/_=-]{32,}`)

// minEntropy is above log2(16)=4, so hex strings such as git SHAs stay visible.
const minEntropy = 4.2

// Match is one secret value found in a string.
type Match struct {
	Kind  string
	Value string
}

// Find returns secret values in s. With all=false it uses only token formats
// that rarely give false positives. With all=true it also uses key=value
// assignments and high-entropy strings; use that for known-sensitive content.
func Find(s string, all bool) []Match {
	var out []Match
	for _, r := range rules {
		if r.kind == "assignment" && !all {
			continue
		}
		for _, m := range r.re.FindAllStringSubmatch(s, -1) {
			if v := m[r.group]; v != "" {
				out = append(out, Match{r.kind, v})
			}
		}
	}
	if all {
		for _, m := range candidate.FindAllString(s, -1) {
			if entropy(m) > minEntropy {
				out = append(out, Match{"high_entropy", m})
			}
		}
	}
	return out
}

// String returns s with secrets replaced by [REDACTED:<kind>].
func String(s string) string {
	for _, r := range rules {
		s = replace(s, r)
	}
	return candidate.ReplaceAllStringFunc(s, func(m string) string {
		if entropy(m) > minEntropy {
			return "[REDACTED:high_entropy]"
		}
		return m
	})
}

func replace(s string, r rule) string {
	tag := "[REDACTED:" + r.kind + "]"
	if r.group == 0 {
		return r.re.ReplaceAllString(s, tag)
	}
	idx := r.re.FindAllStringSubmatchIndex(s, -1)
	if idx == nil {
		return s
	}
	out := make([]byte, 0, len(s))
	last := 0
	for _, m := range idx {
		start, end := m[2*r.group], m[2*r.group+1]
		if start < 0 {
			continue
		}
		out = append(out, s[last:start]...)
		out = append(out, tag...)
		last = end
	}
	out = append(out, s[last:]...)
	return string(out)
}

// Value redacts every string inside a decoded JSON value.
// Map keys are kept. Strings longer than max runes are cut after redaction.
func Value(v any, max int) any {
	switch t := v.(type) {
	case string:
		return truncate(String(t), max)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = Value(x, max)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = Value(x, max)
		}
		return out
	default:
		return v
	}
}

func truncate(s string, max int) string {
	if max <= 0 {
		return s
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…[truncated]"
}

func entropy(s string) float64 {
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
