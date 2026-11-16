package fingerprint

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestKeyStableAndPrivate(t *testing.T) {
	home := t.TempDir()
	var wg sync.WaitGroup
	keys := make([]Key, 20)
	for i := range keys {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			k, err := LoadOrCreate(home)
			if err != nil {
				t.Error(err)
			}
			keys[i] = k
		}(i)
	}
	wg.Wait()
	for _, k := range keys[1:] {
		if string(k) != string(keys[0]) {
			t.Fatal("parallel callers got different keys")
		}
	}
	b, _ := os.ReadFile(filepath.Join(home, "key"))
	if len(b) != 64 {
		t.Fatalf("key file length %d", len(b))
	}
}

func TestOf(t *testing.T) {
	k := Key("0123456789abcdef0123456789abcdef")
	if k.Of("short") != "" {
		t.Fatal("short value fingerprinted")
	}
	a, b := k.Of("sup3rS3cret!"), k.Of("sup3rS3cret!")
	if a == "" || a != b || len(a) != 32 {
		t.Fatalf("bad fingerprint %q", a)
	}
	if Key("other-key-other-key-other-key-xx").Of("sup3rS3cret!") == a {
		t.Fatal("fingerprint does not depend on key")
	}
}
