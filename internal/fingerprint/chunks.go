package fingerprint

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash"

	"github.com/durgavarapraveen/provguard/internal/redact"
)

// ChunkLen is the length of the secret pieces that are fingerprinted, so a
// secret sent out in parts (one command each, or with text between them)
// is still recognized when a part has at least ChunkLen characters.
const ChunkLen = 10

// Chunks returns the fingerprints of every ChunkLen-long piece of v. Only
// random-looking secrets qualify: a piece of a made-up or word-like value
// ("password123") could match ordinary text by chance.
func (k Key) Chunks(v string) []string {
	if len(v) < 2*ChunkLen || redact.LooksFake(v) || distinct(v) < ChunkLen {
		return nil
	}
	h := k.Chunker()
	out := make([]string, 0, len(v)-ChunkLen+1)
	for i := 0; i+ChunkLen <= len(v); i++ {
		out = append(out, h.Of(v[i:i+ChunkLen]))
	}
	return out
}

// Chunker fingerprints many pieces with one HMAC. Not safe for concurrent use.
type Chunker struct {
	mac hash.Hash
	sum []byte
	hex [16]byte
}

func (k Key) Chunker() *Chunker {
	return &Chunker{mac: hmac.New(sha256.New, k), sum: make([]byte, 0, sha256.Size)}
}

// Of returns the fingerprint of one piece. It is shorter than Key.Of's
// (64 bits), because a session keeps thousands of them.
func (c *Chunker) Of(piece string) string {
	c.mac.Reset()
	c.mac.Write([]byte("chunk\x00"))
	c.mac.Write([]byte(piece))
	c.sum = c.mac.Sum(c.sum[:0])
	hex.Encode(c.hex[:], c.sum[:8])
	return string(c.hex[:])
}

func distinct(s string) int {
	seen := map[rune]bool{}
	for _, r := range s {
		seen[r] = true
	}
	return len(seen)
}
