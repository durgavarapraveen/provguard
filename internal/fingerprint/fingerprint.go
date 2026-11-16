// Package fingerprint turns secret values into keyed hashes, so provguard can
// recognize a secret later without storing it.
package fingerprint

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MinLen: shorter values are too easy to match by chance and are ignored.
const MinLen = 8

// Key is the per-install HMAC key.
type Key []byte

// LoadOrCreate reads <home>/key, or creates it with 32 random bytes.
func LoadOrCreate(home string) (Key, error) {
	p := filepath.Join(home, "key")
	b, err := os.ReadFile(p)
	// Another process may have created the file but not written it yet.
	for i := 0; err == nil && len(b) == 0 && i < 40; i++ {
		time.Sleep(5 * time.Millisecond)
		b, err = os.ReadFile(p)
	}
	if err == nil {
		k, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(k) < 32 {
			return nil, errors.New("fingerprint key file is invalid: " + p)
		}
		return k, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return nil, err
	}
	// O_EXCL: if another hook process created the key first, use that one.
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return LoadOrCreate(home)
	}
	if err != nil {
		return nil, err
	}
	if _, err := f.WriteString(hex.EncodeToString(k)); err != nil {
		f.Close()
		return nil, err
	}
	return k, f.Close()
}

// Of returns the fingerprint of v, or "" if v is too short.
func (k Key) Of(v string) string {
	if len(v) < MinLen {
		return ""
	}
	m := hmac.New(sha256.New, k)
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))[:32]
}
