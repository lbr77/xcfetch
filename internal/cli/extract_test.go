package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lbr77/xcfetch/internal/aa"
	"github.com/lbr77/xcfetch/internal/aea"
	"github.com/lbr77/xcfetch/internal/pbz"
	"github.com/lbr77/xcfetch/internal/remote"
)

// rangeServer serves body with Range support and counts what it sends.
type rangeServer struct {
	body     []byte
	bytes    atomic.Int64
	requests atomic.Int64
	server   *httptest.Server
}

func newRangeServer(t *testing.T, body []byte) *rangeServer {
	t.Helper()
	rs := &rangeServer{body: body}
	rs.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.requests.Add(1)
		w.Header().Set("Accept-Ranges", "bytes")
		rangeHeader := r.Header.Get("Range")
		if rangeHeader == "" {
			w.Header().Set("Content-Length", strconv.Itoa(len(rs.body)))
			n, _ := w.Write(rs.body)
			rs.bytes.Add(int64(n))
			return
		}
		spec := strings.TrimPrefix(rangeHeader, "bytes=")
		parts := strings.SplitN(spec, "-", 2)
		start, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			http.Error(w, "bad range", http.StatusBadRequest)
			return
		}
		end := int64(len(rs.body)) - 1
		if len(parts) == 2 && parts[1] != "" {
			if end, err = strconv.ParseInt(parts[1], 10, 64); err != nil {
				http.Error(w, "bad range", http.StatusBadRequest)
				return
			}
		}
		if start >= int64(len(rs.body)) {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		if end >= int64(len(rs.body)) {
			end = int64(len(rs.body)) - 1
		}
		chunk := rs.body[start : end+1]
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(rs.body)))
		w.Header().Set("Content-Length", strconv.Itoa(len(chunk)))
		w.WriteHeader(http.StatusPartialContent)
		n, _ := w.Write(chunk)
		rs.bytes.Add(int64(n))
	}))
	t.Cleanup(rs.server.Close)
	return rs
}

// runtimeFixture builds an archive shaped like a real runtime asset: an outer
// container archive whose payload is a pbz stream wrapping the file tree, all
// encrypted as AEA profile 1.
type runtimeFixture struct {
	encrypted string
	key       []byte
	payload   []byte // the wanted file's contents
	plainSize int64
}

func buildRuntimeFixture(t *testing.T) runtimeFixture {
	t.Helper()
	for _, tool := range []string{"/usr/bin/aa", "/usr/bin/aea"} {
		if _, err := os.Stat(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	key := bytes.Repeat([]byte{0x7c}, 32)
	wanted := bytes.Repeat([]byte("wanted-content\n"), 3000)

	tree := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tree, "AssetData/Restore"), 0o755); err != nil {
		t.Fatal(err)
	}
	// A large, poorly compressible blob that we never want, plus a small file.
	big := make([]byte, 96<<20)
	if _, err := rand.Read(big[:1<<20]); err != nil {
		t.Fatal(err)
	}
	for i := 1 << 20; i < len(big); i += 1 << 20 {
		copy(big[i:], big[:1<<20])
	}
	if err := os.WriteFile(filepath.Join(tree, "AssetData/Restore/big.dmg"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "AssetData/Restore/Restore.plist"), wanted, 0o644); err != nil {
		t.Fatal(err)
	}

	inner := filepath.Join(t.TempDir(), "inner.aar")
	if out, err := exec.Command("/usr/bin/aa", "archive", "-d", tree, "-o", inner, "-a", "lzfse", "-b", "4m").CombinedOutput(); err != nil {
		t.Fatalf("aa archive: %v: %s", err, out)
	}
	innerBytes, err := os.ReadFile(inner)
	if err != nil {
		t.Fatal(err)
	}

	container := encodeContainerPayload(BytesWrapper{innerBytes})
	plain := filepath.Join(t.TempDir(), "payload.aar")
	if err := os.WriteFile(plain, container, 0o644); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "key.txt")
	if err := os.WriteFile(keyFile, []byte("hex:"+hex.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	encrypted := plain + ".aea"
	if out, err := exec.Command("/usr/bin/aea", "encrypt", "-i", plain, "-o", encrypted,
		"-profile", "1", "-key", keyFile, "-a", "lzfse", "-b", "1m").CombinedOutput(); err != nil {
		t.Fatalf("aea encrypt: %v: %s", err, out)
	}
	return runtimeFixture{encrypted: encrypted, key: key, payload: wanted, plainSize: int64(len(container))}
}

// BytesWrapper marks a payload blob.
type BytesWrapper struct{ Data []byte }

// encodeContainerPayload builds a two-item Apple Archive: a metadata item and a
// data item carrying the nested archive.
func encodeContainerPayload(blob BytesWrapper) []byte {
	encode := func(itemType byte, data []byte) []byte {
		var fields bytes.Buffer
		fields.WriteString("TYP1")
		fields.WriteByte(itemType)
		fields.WriteString("YOP1")
		fields.WriteByte('M')
		if data != nil {
			fields.WriteString("DATB")
			var sz [4]byte
			n := uint32(len(data))
			sz[0], sz[1], sz[2], sz[3] = byte(n), byte(n>>8), byte(n>>16), byte(n>>24)
			fields.Write(sz[:])
		}
		size := 6 + fields.Len()
		out := []byte{'A', 'A', '0', '1', byte(size), byte(size >> 8)}
		out = append(out, fields.Bytes()...)
		if data != nil {
			out = append(out, data...)
		}
		return out
	}
	var buf bytes.Buffer
	buf.Write(encode('M', nil))
	buf.Write(encode('M', blob.Data))
	return buf.Bytes()
}

// TestExtractOverRangesAfterLargeBlob covers the expensive regime: the wanted
// file sits behind a 96 MiB blob inside the same compressed stream, so the walk
// must replay that stream's block-header chain. Every skipped block costs one
// AEA segment (1 MiB), which is the cost model the CLI documents.
func TestExtractOverRangesAfterLargeBlob(t *testing.T) {
	fx := buildRuntimeFixture(t)
	body, err := os.ReadFile(fx.encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < 1<<20 {
		t.Fatalf("fixture is only %d bytes", len(body))
	}
	rs := newRangeServer(t, body)

	ctx := context.Background()
	src, err := remote.Open(ctx, rs.server.Client(), rs.server.URL, remote.Options{})
	if err != nil {
		t.Fatalf("remote.Open: %v", err)
	}
	if src.Size() != int64(len(body)) {
		t.Fatalf("size = %d, want %d", src.Size(), len(body))
	}

	plain, err := aea.NewRandomReader(src, src.Size(), fx.key)
	if err != nil {
		t.Fatalf("NewRandomReader: %v", err)
	}
	if plain.Size() != fx.plainSize {
		t.Fatalf("plaintext size = %d, want %d", plain.Size(), fx.plainSize)
	}

	entries, err := aa.IndexStream(plain, plain.Size(), func(p string) bool {
		return strings.Contains(p, "Restore.plist")
	})
	if err != nil {
		t.Fatalf("IndexStream: %v", err)
	}
	var file *aa.Entry
	for i := range entries {
		if strings.HasSuffix(entries[i].Path, "Restore.plist") {
			file = &entries[i]
		}
	}
	if file == nil {
		t.Fatalf("wanted entry not indexed: %+v", entries)
	}
	if file.Size != int64(len(fx.payload)) {
		t.Fatalf("indexed size = %d, want %d", file.Size, len(fx.payload))
	}

	dest := t.TempDir()
	if err := aa.ExtractEntries(dest, entries, nil); err != nil {
		t.Fatalf("ExtractEntries: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "AssetData/Restore/Restore.plist"))
	if err != nil {
		t.Fatalf("extracted file: %v", err)
	}
	if !bytes.Equal(got, fx.payload) {
		t.Fatalf("payload mismatch (%d vs %d bytes)", len(got), len(fx.payload))
	}

	stats := src.Stats()
	ratio := float64(stats.Bytes) / float64(len(body))
	t.Logf("fetched %d bytes of %d (%.1f%%) in %d requests", stats.Bytes, len(body), ratio*100, stats.Requests)
	if ratio > 0.45 {
		t.Errorf("fetched %.1f%% of the object; expected under 45%% for this layout", ratio*100)
	}
	if stats.Bytes <= int64(len(fx.payload)) {
		t.Errorf("fetched %d bytes, less than the wanted payload; something is wrong", stats.Bytes)
	}
}

// TestExtractRandomReads checks that random plaintext reads agree with a full
// linear decrypt, which is the core of the feature.
func TestExtractRandomReads(t *testing.T) {
	fx := buildRuntimeFixture(t)
	f, err := os.Open(fx.encrypted)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()

	rr, err := aea.NewRandomReader(f, st.Size(), fx.key)
	if err != nil {
		t.Fatalf("NewRandomReader: %v", err)
	}
	want := make([]byte, rr.Size())
	if err := aea.Decrypt(&bufWriter{buf: want}, f, fx.key); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	offsets := []int64{0, 1, 1 << 20, rr.Size() / 2, rr.Size() - 100, 1234567}
	for _, off := range offsets {
		buf := make([]byte, 128)
		n, err := rr.ReadAt(buf, off)
		if err != nil && err != io.EOF {
			t.Fatalf("ReadAt(%d): %v", off, err)
		}
		if !bytes.Equal(buf[:n], want[off:off+int64(n)]) {
			t.Fatalf("ReadAt(%d) mismatch", off)
		}
	}
}

// bufWriter appends into a fixed buffer at a growing offset.
type bufWriter struct {
	buf []byte
	off int
}

func (b *bufWriter) Write(p []byte) (int, error) {
	if b.off+len(p) > len(b.buf) {
		return 0, io.ErrShortBuffer
	}
	copy(b.buf[b.off:], p)
	b.off += len(p)
	return len(p), nil
}

// TestExtractBudgetGuard checks that a runaway walk stops with a clear error.
func TestExtractBudgetGuard(t *testing.T) {
	fx := buildRuntimeFixture(t)
	body, err := os.ReadFile(fx.encrypted)
	if err != nil {
		t.Fatal(err)
	}
	rs := newRangeServer(t, body)
	src, err := remote.Open(context.Background(), rs.server.Client(), rs.server.URL, remote.Options{})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := aea.NewRandomReader(src, src.Size(), fx.key)
	if err != nil {
		t.Fatal(err)
	}
	capped := &budget{src: plain, limit: 64 << 10}
	_, err = aa.IndexStreamWith(capped, plain.Size(), func(p string) bool {
		return strings.Contains(p, "Restore.plist")
	}, aa.IndexOptions{})
	if err == nil {
		t.Fatal("expected the budget to stop the walk")
	}
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("err = %v, want ErrBudgetExceeded", err)
	}
}

// TestExtractCheapPayload is the regime that matters in practice: the wanted
// file lives in a small payload, so the large payload is skipped by offset
// arithmetic and never scanned.
func TestExtractCheapPayload(t *testing.T) {
	fx := buildSmallPayloadFixture(t)
	body, err := os.ReadFile(fx.encrypted)
	if err != nil {
		t.Fatal(err)
	}
	rs := newRangeServer(t, body)
	stats := func() (int64, int64) { return rs.bytes.Load(), int64(len(body)) }

	src, err := remote.Open(context.Background(), rs.server.Client(), rs.server.URL, remote.Options{})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := aea.NewRandomReader(src, src.Size(), fx.key)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := aa.IndexStream(plain, plain.Size(), func(p string) bool {
		return strings.HasSuffix(p, "Small.plist")
	})
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := aa.ExtractEntries(dest, entries, nil); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "AssetData/Restore/Small.plist"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, fx.payload) {
		t.Fatal("payload mismatch")
	}
	sent, total := stats()
	t.Logf("fetched %d of %d bytes", sent, total)
	// The floor for any extraction is one AEA segment plus one pbz block
	// (1 MiB + 4 MiB here); what matters is that it does not scale with the
	// object, so assert an absolute bound.
	const floorBudget = 8 << 20
	if sent > floorBudget {
		t.Errorf("fetched %d bytes for a %d byte file; expected at most %d", sent, len(fx.payload), floorBudget)
	}
}

// TestExtractIndexCacheIsReusable checks that a second walk of the same archive
// replays nothing, which is what makes repeated extractions practical.
func TestExtractIndexCacheIsReusable(t *testing.T) {
	fx := buildRuntimeFixture(t)
	body, err := os.ReadFile(fx.encrypted)
	if err != nil {
		t.Fatal(err)
	}
	cache := pbz.FileCache{Dir: t.TempDir()}
	want := func(p string) bool { return strings.HasSuffix(p, "Restore.plist") }

	walk := func() (int64, int) {
		rs := newRangeServer(t, body)
		src, err := remote.Open(context.Background(), rs.server.Client(), rs.server.URL, remote.Options{})
		if err != nil {
			t.Fatal(err)
		}
		plain, err := aea.NewRandomReader(src, src.Size(), fx.key)
		if err != nil {
			t.Fatal(err)
		}
		entries, err := aa.IndexStreamWith(plain, plain.Size(), want, aa.IndexOptions{
			Cache: cache, KeyPrefix: "fixture",
		})
		if err != nil {
			t.Fatal(err)
		}
		return rs.bytes.Load(), len(entries)
	}

	first, n1 := walk()
	second, n2 := walk()
	t.Logf("first walk %d bytes, second walk %d bytes, entries %d/%d", first, second, n1, n2)
	if n1 != n2 || n1 == 0 {
		t.Fatalf("entry counts differ: %d vs %d", n1, n2)
	}
	if second > first/4 {
		t.Errorf("cached walk fetched %d bytes vs %d uncached; the index cache is not being used", second, first)
	}
}

// buildTwoPayloadFixture mirrors the real asset: a large payload and a small
// one, the wanted file living in the small payload.
// buildSmallPayloadFixture has a single small payload: nothing has to be
// scanned, so extraction is dominated by the wanted bytes.
func buildSmallPayloadFixture(t *testing.T) runtimeFixture {
	t.Helper()
	for _, tool := range []string{"/usr/bin/aa", "/usr/bin/aea"} {
		if _, err := os.Stat(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	key := bytes.Repeat([]byte{0x33}, 32)
	wanted := bytes.Repeat([]byte("small-payload\n"), 1000)
	tree := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tree, "AssetData/Restore"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "AssetData/Restore/Small.plist"), wanted, 0o644); err != nil {
		t.Fatal(err)
	}
	return assembleFixture(t, key, wanted, archiveTree(t, tree))
}

// assembleFixture wraps payload archives in a container and encrypts it.
func assembleFixture(t *testing.T, key, wanted []byte, payloads ...[]byte) runtimeFixture {
	t.Helper()
	container := encodeMultiPayload(payloads...)
	plain := filepath.Join(t.TempDir(), "p.aar")
	if err := os.WriteFile(plain, container, 0o644); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "key.txt")
	if err := os.WriteFile(keyFile, []byte("hex:"+hex.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	encrypted := plain + ".aea"
	if msg, err := exec.Command("/usr/bin/aea", "encrypt", "-i", plain, "-o", encrypted,
		"-profile", "1", "-key", keyFile, "-a", "lzfse", "-b", "1m").CombinedOutput(); err != nil {
		t.Fatalf("aea encrypt: %v: %s", err, msg)
	}
	return runtimeFixture{encrypted: encrypted, key: key, payload: wanted, plainSize: int64(len(container))}
}

// archiveTree packs a directory with Apple's tool (a pbz-wrapped archive).
func archiveTree(t *testing.T, dir string) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "a.aar")
	if msg, err := exec.Command("/usr/bin/aa", "archive", "-d", dir, "-o", out, "-a", "lzfse", "-b", "4m").CombinedOutput(); err != nil {
		t.Fatalf("aa archive: %v: %s", err, msg)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func buildTwoPayloadFixture(t *testing.T) runtimeFixture {
	t.Helper()
	for _, tool := range []string{"/usr/bin/aa", "/usr/bin/aea"} {
		if _, err := os.Stat(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	key := bytes.Repeat([]byte{0x33}, 32)
	wanted := bytes.Repeat([]byte("small-payload\n"), 1000)

	bigTree := t.TempDir()
	if err := os.MkdirAll(filepath.Join(bigTree, "AssetData/Restore"), 0o755); err != nil {
		t.Fatal(err)
	}
	big := make([]byte, 96<<20)
	if _, err := rand.Read(big[:1<<20]); err != nil {
		t.Fatal(err)
	}
	for i := 1 << 20; i < len(big); i += 1 << 20 {
		copy(big[i:], big[:1<<20])
	}
	if err := os.WriteFile(filepath.Join(bigTree, "AssetData/Restore/big.dmg"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	smallTree := t.TempDir()
	if err := os.MkdirAll(filepath.Join(smallTree, "AssetData/Restore"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(smallTree, "AssetData/Restore/Small.plist"), wanted, 0o644); err != nil {
		t.Fatal(err)
	}

	return assembleFixture(t, key, wanted, archiveTree(t, bigTree), archiveTree(t, smallTree))
}

// encodeMultiPayload builds a container with two data items.
func encodeMultiPayload(payloads ...[]byte) []byte {
	encode := func(itemType byte, data []byte) []byte {
		var fields bytes.Buffer
		fields.WriteString("TYP1")
		fields.WriteByte(itemType)
		fields.WriteString("YOP1")
		fields.WriteByte('M')
		if data != nil {
			fields.WriteString("DATB")
			n := uint32(len(data))
			fields.Write([]byte{byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)})
		}
		size := 6 + fields.Len()
		out := []byte{'A', 'A', '0', '1', byte(size), byte(size >> 8)}
		out = append(out, fields.Bytes()...)
		return append(out, data...)
	}
	var buf bytes.Buffer
	buf.Write(encode('M', nil)) // metadata item
	for _, p := range payloads {
		buf.Write(encode('M', p))
	}
	return buf.Bytes()
}

// TestRuntimeExtractLocalArchive drives the CLI end to end on a local,
// unencrypted container archive (the `--local` path).
func TestRuntimeExtractLocalArchive(t *testing.T) {
	for _, tool := range []string{"/usr/bin/aa"} {
		if _, err := os.Stat(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	tree := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tree, "AssetData/Restore"), 0o755); err != nil {
		t.Fatal(err)
	}
	wanted := []byte("local-extraction\n")
	if err := os.WriteFile(filepath.Join(tree, "AssetData/Restore/Restore.plist"), wanted, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "AssetData/Restore/other.bin"), bytes.Repeat([]byte("x"), 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	container := encodeMultiPayload(archiveTree(t, tree))
	local := filepath.Join(t.TempDir(), "local.aar")
	if err := os.WriteFile(local, container, 0o644); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(), []string{
		"runtime", "extract", "--local", local, "--match", "Restore.plist", "--out", dest,
	}, &stdout, &stderr); err != nil {
		t.Fatalf("extract: %v\n%s%s", err, stdout.String(), stderr.String())
	}
	got, err := os.ReadFile(filepath.Join(dest, "AssetData/Restore/Restore.plist"))
	if err != nil {
		t.Fatalf("extracted file: %v", err)
	}
	if !bytes.Equal(got, wanted) {
		t.Fatalf("payload = %q", got)
	}
	if _, err := os.Stat(filepath.Join(dest, "AssetData/Restore/other.bin")); !os.IsNotExist(err) {
		t.Error("a non-matching entry was extracted")
	}

	// --list must not write anything.
	listDest := t.TempDir()
	stdout.Reset()
	if err := Run(context.Background(), []string{
		"runtime", "extract", "--local", local, "--match", "Restore.plist", "--list", "--out", listDest,
	}, &stdout, &stderr); err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(stdout.String(), "AssetData/Restore/Restore.plist") {
		t.Errorf("list output = %q", stdout.String())
	}
	if entries, err := os.ReadDir(listDest); err != nil || len(entries) != 0 {
		t.Errorf("--list wrote %d entries", len(entries))
	}
}
