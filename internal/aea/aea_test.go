package aea

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The vectors are produced with Apple's own `aea` tool so the tests assert
// interoperability with the reference implementation rather than with
// themselves. Skipped where the tool is unavailable (e.g. Linux CI).
func aeaTool(t *testing.T) string {
	t.Helper()
	const tool = "/usr/bin/aea"
	if _, err := os.Stat(tool); err != nil {
		t.Skip("Apple's aea tool not available")
	}
	return tool
}

func testKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func encrypt(t *testing.T, tool, dir, keyFile, src string, extra ...string) string {
	t.Helper()
	out := src + ".aea"
	args := append([]string{"encrypt", "-i", src, "-o", out, "-profile", "1", "-key", keyFile}, extra...)
	if b, err := exec.Command(tool, args...).CombinedOutput(); err != nil {
		t.Fatalf("aea encrypt %v: %v: %s", extra, err, b)
	}
	return out
}

func writeRandom(t *testing.T, path string, n int) {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDecryptMatchesAppleTool(t *testing.T) {
	tool := aeaTool(t)
	key := testKey()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.bin")
	if err := os.WriteFile(keyFile, []byte("hex:"+hex.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}

	sizes := map[string]int{"small": 1000, "medium": 1 << 20, "large": 8 << 20, "empty": 0}
	algorithms := []string{"lzfse", "lzma", "zlib", "lz4", "none"}

	for name, size := range sizes {
		src := filepath.Join(dir, name+".bin")
		writeRandom(t, src, size)
		want, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		for _, alg := range algorithms {
			t.Run(name+"/"+alg, func(t *testing.T) {
				enc := encrypt(t, tool, dir, keyFile, src, "-a", alg)
				f, err := os.Open(enc)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				var got bytes.Buffer
				if err := Decrypt(&got, f, key); err != nil {
					t.Fatalf("Decrypt: %v", err)
				}
				if !bytes.Equal(got.Bytes(), want) {
					t.Fatalf("plaintext mismatch: got %d bytes, want %d", got.Len(), len(want))
				}
			})
		}
	}
}

func TestDecryptMultiClusterAndSHA256(t *testing.T) {
	tool := aeaTool(t)
	key := testKey()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.bin")
	os.WriteFile(keyFile, []byte("hex:"+hex.EncodeToString(key)), 0o600)

	src := filepath.Join(dir, "big.bin")
	writeRandom(t, src, 8<<20)
	want, _ := os.ReadFile(src)

	for name, extra := range map[string][]string{
		"block64k": {"-a", "lzfse", "-b", "64k"},
		"sha256":   {"-a", "lzfse", "-checksum", "sha256"},
	} {
		t.Run(name, func(t *testing.T) {
			enc := encrypt(t, tool, dir, keyFile, src, extra...)
			f, err := os.Open(enc)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			var got bytes.Buffer
			if err := Decrypt(&got, f, key); err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(got.Bytes(), want) {
				t.Fatalf("plaintext mismatch")
			}
		})
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	tool := aeaTool(t)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.bin")
	os.WriteFile(keyFile, []byte("hex:"+hex.EncodeToString(testKey())), 0o600)
	src := filepath.Join(dir, "f.bin")
	writeRandom(t, src, 4096)
	enc := encrypt(t, tool, dir, keyFile, src)

	f, err := os.Open(enc)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	bad := make([]byte, 32)
	for i := range bad {
		bad[i] = 0xAA
	}
	var out bytes.Buffer
	if err := Decrypt(&out, f, bad); err == nil {
		t.Fatal("expected failure with a wrong key")
	}
}

func TestHeader(t *testing.T) {
	tool := aeaTool(t)
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.bin")
	os.WriteFile(keyFile, []byte("hex:"+hex.EncodeToString(testKey())), 0o600)
	src := filepath.Join(dir, "f.bin")
	writeRandom(t, src, 512)
	enc := encrypt(t, tool, dir, keyFile, src)

	f, err := os.Open(enc)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h, err := Header(f)
	if err != nil {
		t.Fatalf("Header: %v", err)
	}
	if h.Profile != profileSymmetric {
		t.Errorf("profile = %d, want 1", h.Profile)
	}
}

// TestDecryptAcrossClusters guards the cluster chain: with a 16 KiB segment and
// 256 segments per cluster, every 4 MiB crosses a cluster boundary, and each
// cluster is authenticated by the MAC stored in the previous one.
func TestDecryptAcrossClusters(t *testing.T) {
	tool := aeaTool(t)
	key := testKey()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.bin")
	if err := os.WriteFile(keyFile, []byte("hex:"+hex.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "big.bin")
	writeRandom(t, src, 13<<20)
	want, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	enc := encrypt(t, tool, dir, keyFile, src, "-a", "lzfse", "-b", "16k")

	f, err := os.Open(enc)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var got bytes.Buffer
	if err := Decrypt(&got, f, key); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("plaintext mismatch: got %d bytes, want %d", got.Len(), len(want))
	}
}
