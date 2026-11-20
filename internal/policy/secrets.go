package policy

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/durgavarapraveen/provguard/internal/fingerprint"
	"github.com/durgavarapraveen/provguard/internal/redact"
	"github.com/durgavarapraveen/provguard/internal/store"
)

const (
	maxText   = 256 << 10 // bytes of call text scanned
	maxTokens = 5000
)

// tokenRe splits on characters that rarely appear inside secrets.
var tokenRe = regexp.MustCompile(`[^\s"'=&?;,()<>{}\[\]|` + "`" + `]+`)

// SecretIn returns how a fingerprinted secret appears in text ("plain",
// "base64", "hex", "url"), or "" if none does.
func SecretIn(text string, fps []string, key fingerprint.Key) string {
	if len(text) > maxText {
		text = text[:maxText]
	}
	want := make(map[string]bool, len(fps))
	for _, f := range fps {
		want[f] = true
	}
	hit := func(s string) bool {
		f := key.Of(s)
		return f != "" && want[f]
	}
	// Values found by the redaction patterns (e.g. assignment values, tokens).
	for _, m := range redact.Find(text, true) {
		if hit(m.Value) {
			return "plain"
		}
	}
	n := 0
	for _, tok := range tokenRe.FindAllString(text, -1) {
		if n++; n > maxTokens {
			break
		}
		if len(tok) < fingerprint.MinLen {
			continue
		}
		parts := variants(tok)
		for _, t := range parts {
			if hit(t) {
				return "plain"
			}
		}
		for _, part := range parts {
			if kind := decodedHit(part, hit); kind != "" {
				return kind
			}
		}
	}
	return ""
}

// decodedHit decodes part (base64, hex, URL) and checks the result.
func decodedHit(part string, hit func(string) bool) string {
	for kind, dec := range decodings(part) {
		for _, t := range tokenRe.FindAllString(dec, 200) {
			for _, v := range variants(t) {
				if hit(v) {
					return kind
				}
			}
		}
		// The decoded text may itself be the secret, or contain key=value.
		if hit(strings.TrimSpace(dec)) {
			return kind
		}
		for _, m := range redact.Find(dec, true) {
			if hit(m.Value) {
				return kind
			}
		}
	}
	return ""
}

// variants trims common wrapping punctuation and splits "user:pass".
func variants(tok string) []string {
	out := []string{tok}
	t := strings.Trim(tok, ".,:;!/\\")
	if t != tok {
		out = append(out, t)
	}
	if strings.ContainsAny(tok, ":@/") {
		out = append(out, strings.FieldsFunc(tok, func(r rune) bool { return r == ':' || r == '@' || r == '/' })...)
	}
	// DNS labels and file names: "<hex>.evil.test". Keep the whole token too,
	// because secrets can contain dots.
	if strings.Contains(tok, ".") {
		for _, p := range strings.FieldsFunc(tok, func(r rune) bool { return r == '.' || r == '/' || r == ':' || r == '@' }) {
			if len(p) >= fingerprint.MinLen {
				out = append(out, p)
			}
		}
	}
	return out
}

var (
	b64Re = regexp.MustCompile(`^[A-Za-z0-9+/_-]{12,}={0,2}$`)
	hexRe = regexp.MustCompile(`^(?:[0-9a-fA-F]{2}){8,}$`)
)

// decodings returns printable decodings of tok, keyed by encoding name.
func decodings(tok string) map[string]string {
	out := map[string]string{}
	if strings.Contains(tok, "%") {
		if d, err := url.QueryUnescape(tok); err == nil && d != tok {
			out["url"] = d
		}
	}
	if hexRe.MatchString(tok) {
		if b, err := hex.DecodeString(tok); err == nil && printable(b) {
			out["hex"] = string(b)
		}
	}
	if b64Re.MatchString(tok) {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(tok); err == nil && printable(b) {
				out["base64"] = string(b)
				break
			}
		}
	}
	return out
}

func printable(b []byte) bool {
	if len(b) == 0 || !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

// maxPieces caps the pieces checked in one call, so a huge command stays fast.
const maxPieces = 50000

// SecretPieceIn reports whether text holds a piece (fingerprint.ChunkLen
// characters) of a random-looking secret this session read: plain,
// reversed, or inside a base64, hex or URL encoding. It catches a secret
// sent out in parts, one command each, when a part has at least ChunkLen
// characters.
func SecretPieceIn(text string, chunks []string, key fingerprint.Key) string {
	if len(chunks) == 0 {
		return ""
	}
	if len(text) > maxText {
		text = text[:maxText]
	}
	want := make(map[string]bool, len(chunks))
	for _, c := range chunks {
		want[c] = true
	}
	left := maxPieces
	h := key.Chunker()
	scan := func(t string) bool {
		for i := 0; i+fingerprint.ChunkLen <= len(t) && left > 0; i++ {
			left--
			if want[h.Of(t[i:i+fingerprint.ChunkLen])] {
				return true
			}
		}
		return false
	}
	n := 0
	for _, tok := range tokenRe.FindAllString(text, -1) {
		if n++; n > maxTokens || left <= 0 {
			break
		}
		if len(tok) < fingerprint.ChunkLen {
			continue
		}
		if scan(tok) || scan(reverse(tok)) {
			return "part"
		}
		for kind, dec := range decodings(tok) {
			if scan(dec) {
				return "part, " + kind
			}
		}
	}
	return ""
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// secretOrPiece: SecretIn, then SecretPieceIn.
func secretOrPiece(text string, s *store.Session, key fingerprint.Key) string {
	if kind := SecretIn(text, s.Fingerprints, key); kind != "" {
		return kind
	}
	return SecretPieceIn(text, s.ChunkFingerprints, key)
}
