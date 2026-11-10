package aea

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// countingReaderAt counts the bytes a reader pulls from its source.
type countingReaderAt struct {
	r     io.ReaderAt
	bytes atomic.Int64
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	c.bytes.Add(int64(n))
	return n, err
}

// TestDecryptAtMatchesStream checks that seeking AES-CTR gives the same bytes
// as decrypting from the start, including across a counter carry.
func TestDecryptAtMatchesStream(t *testing.T) {
	key := make(dataKey, dataKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	// Force a carry out of the low 64 bits of the counter after two blocks.
	for i := 64 + 8; i < 80; i++ {
		key[i] = 0xff
	}
	key[79] = 0xfe
	src := make([]byte, 4096)
	if _, err := rand.Read(src); err != nil {
		t.Fatal(err)
	}
	want := make([]byte, len(src))
	block, err := aes.NewCipher(key[32:64])
	if err != nil {
		t.Fatal(err)
	}
	cipher.NewCTR(block, key[64:80]).XORKeyStream(want, src)
	for _, off := range []int{0, 1, 15, 16, 17, 31, 32, 33, 100, 1000, 4095} {
		for _, n := range []int{1, 7, 16, 100} {
			if off+n > len(src) {
				continue
			}
			got := make([]byte, n)
			if err := key.decryptAt(got, src[off:off+n], int64(off)); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want[off:off+n]) {
				t.Fatalf("decryptAt(off=%d, n=%d) differs from a linear decrypt", off, n)
			}
		}
	}
}

// TestRandomReaderPartialReads checks that small reads of uncompressed
// segments fetch only their own bytes and still return the right plaintext,
// for an archive mixing incompressible (stored) and compressible segments.
func TestRandomReaderPartialReads(t *testing.T) {
	tool := aeaTool(t)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.bin")
	if err := os.WriteFile(keyFile, []byte("hex:"+hex.EncodeToString(testKey())), 0o600); err != nil {
		t.Fatal(err)
	}
	random := make([]byte, 1<<20)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	plain := append(append(append([]byte{}, random...), make([]byte, 1<<20)...), random[:512<<10]...)
	src := filepath.Join(dir, "plain.bin")
	if err := os.WriteFile(src, plain, 0o644); err != nil {
		t.Fatal(err)
	}
	enc := encrypt(t, tool, dir, keyFile, src, "-a", "lzfse", "-b", "64k")
	f, err := os.Open(enc)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()

	for _, verifyAll := range []bool{false, true} {
		cr := &countingReaderAt{r: f}
		rr, err := NewRandomReader(cr, st.Size(), testKey())
		if err != nil {
			t.Fatal(err)
		}
		rr.SetVerifyAll(verifyAll)
		if rr.Size() != int64(len(plain)) {
			t.Fatalf("size %d, want %d", rr.Size(), len(plain))
		}
		// Warm the cluster headers, then measure one small read in the
		// incompressible region.
		probe := make([]byte, 16)
		if _, err := rr.ReadAt(probe, 0); err != nil {
			t.Fatal(err)
		}
		before := cr.bytes.Load()
		if _, err := rr.ReadAt(probe, 300<<10+5); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(probe, plain[300<<10+5:300<<10+21]) {
			t.Fatal("small read returned the wrong bytes")
		}
		cost := cr.bytes.Load() - before
		// The cost hint agrees: stored segments are cheap, the compressible
		// (zero) region is not, unless every read verifies whole segments.
		if rr.Expensive(300<<10, 16) {
			t.Error("Expensive reports a stored segment as expensive")
		}
		if got := rr.Expensive(1<<20+300<<10, 16); got == verifyAll {
			t.Errorf("verifyAll=%v: Expensive(compressed segment) = %v", verifyAll, got)
		}
		if !verifyAll && cost > 64 {
			t.Errorf("partial read of 16 bytes pulled %d bytes", cost)
		}
		if verifyAll && cost < 64<<10 {
			t.Errorf("verified read pulled only %d bytes; expected a whole segment", cost)
		}

		for i := 0; i < 300; i++ {
			off := randInt(t, len(plain)-1)
			n := 1 + randInt(t, 200000)
			if off+n > len(plain) {
				n = len(plain) - off
			}
			got := make([]byte, n)
			if _, err := rr.ReadAt(got, int64(off)); err != nil {
				t.Fatalf("ReadAt(%d, %d): %v", off, n, err)
			}
			if !bytes.Equal(got, plain[off:off+n]) {
				t.Fatalf("verifyAll=%v: ReadAt(%d, %d) returned the wrong bytes", verifyAll, off, n)
			}
		}
	}
}

func randInt(t *testing.T, n int) int {
	t.Helper()
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		t.Fatal(err)
	}
	return int(v.Int64())
}
