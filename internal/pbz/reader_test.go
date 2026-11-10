package pbz

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildStream makes a real pbz stream with Apple's tool.
func buildStream(t *testing.T, size int) ([]byte, []byte) {
	t.Helper()
	const tool = "/usr/bin/aa"
	if _, err := os.Stat(tool); err != nil {
		t.Skip("Apple's aa tool not available")
	}
	dir := t.TempDir()
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	if err := os.WriteFile(filepath.Join(dir, "f.bin"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "f.aar")
	if msg, err := exec.Command(tool, "archive", "-d", dir, "-o", out, "-a", "lzfse", "-b", "64k").CombinedOutput(); err != nil {
		t.Fatalf("aa archive: %v: %s", err, msg)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return raw, payload
}

func TestReaderRandomAccess(t *testing.T) {
	stream, _ := buildStream(t, 1<<20)
	r, err := NewReader(bytes.NewReader(stream), int64(len(stream)))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if r.Algo() != 'e' {
		t.Errorf("algo = %q, want e", r.Algo())
	}
	// The stream contains the Apple Archive of the tree.
	head := make([]byte, 4)
	if _, err := r.ReadAt(head, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if string(head) != "AA01" {
		t.Errorf("head = %q, want AA01", head)
	}
	size, err := r.Size()
	if err != nil {
		t.Fatal(err)
	}
	if size <= 0 {
		t.Fatalf("size = %d", size)
	}
	blocks, err := r.Blocks()
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) == 0 {
		t.Fatal("no blocks indexed")
	}
	// Blocks must tile the plaintext exactly.
	var plain int64
	for i, b := range blocks {
		if b.PlainOffset != plain {
			t.Errorf("block %d plaintext offset = %d, want %d", i, b.PlainOffset, plain)
		}
		plain += b.PlainSize
	}
	if plain != size {
		t.Errorf("blocks cover %d bytes, size reports %d", plain, size)
	}
}

func TestIndexImportRejectsMismatch(t *testing.T) {
	stream, _ := buildStream(t, 1<<15)
	r, err := NewReader(bytes.NewReader(stream), int64(len(stream)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Size(); err != nil {
		t.Fatal(err)
	}
	idx := r.Export()
	if len(idx.Blocks) == 0 {
		t.Fatal("nothing indexed")
	}

	// A fresh reader accepts the index.
	r2, _ := NewReader(bytes.NewReader(stream), int64(len(stream)))
	if !r2.Import(idx) {
		t.Fatal("a valid index was rejected")
	}
	if got, want := r2.Export().Plain, idx.Plain; got != want {
		t.Errorf("imported plaintext = %d, want %d", got, want)
	}

	// A different algorithm is refused.
	r3, _ := NewReader(bytes.NewReader(stream), int64(len(stream)))
	bad := idx
	bad.Algo = 'z'
	if r3.Import(bad) {
		t.Error("index with a different algorithm was accepted")
	}

	// Blocks that do not line up are refused.
	r4, _ := NewReader(bytes.NewReader(stream), int64(len(stream)))
	bad = idx
	bad.Blocks = append([]Block{}, idx.Blocks...)
	bad.Blocks[0].OuterOffset += 1
	if r4.Import(bad) {
		t.Error("misaligned index was accepted")
	}
}

func TestFileCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cache := FileCache{Dir: dir}
	idx := Index{Algo: 'e', Plain: 1234, Blocks: []Block{{OuterOffset: 12, DataOffset: 28, PlainOffset: 0, PlainSize: 100, CompSize: 50}}}
	if err := cache.Save("k", idx); err != nil {
		t.Fatal(err)
	}
	got, ok := cache.Load("k")
	if !ok {
		t.Fatal("index not found")
	}
	if got.Plain != idx.Plain || len(got.Blocks) != 1 || got.Blocks[0].CompSize != 50 {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if _, ok := cache.Load("missing"); ok {
		t.Error("unexpected hit")
	}
	// Empty caches must not write anything.
	if err := (FileCache{}).Save("k", idx); err != nil {
		t.Error(err)
	}
	if _, ok := (FileCache{}).Load("k"); ok {
		t.Error("empty cache returned a value")
	}
}

var _ = binary.LittleEndian

func TestFileCacheKeyIsURLSafe(t *testing.T) {
	cache := FileCache{Dir: t.TempDir()}
	key := "https://updates.cdn-apple.com/a/b?a=1|8522825728"
	idx := Index{Algo: 'e', Blocks: []Block{{OuterOffset: 12, DataOffset: 28, PlainSize: 10, CompSize: 5}}}
	if err := cache.Save(key, idx); err != nil {
		t.Fatalf("Save with a URL key: %v", err)
	}
	if _, ok := cache.Load(key); !ok {
		t.Fatal("index keyed by a URL was not found")
	}
	entries, err := os.ReadDir(cache.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one cache file, got %d", len(entries))
	}
	if strings.ContainsAny(entries[0].Name(), "/:?") {
		t.Errorf("unsafe cache file name %q", entries[0].Name())
	}
}
