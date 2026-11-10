package remote

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// rangeHandler serves body with Range support and counts requests.
func rangeHandler(t *testing.T, body []byte, requests *atomic.Int64) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		rangeHeader := r.Header.Get("Range")
		if rangeHeader == "" {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.Write(body)
			return
		}
		start, end, ok := parseRange(rangeHeader, len(body))
		if !ok {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(body)))
		w.Header().Set("Content-Length", strconv.Itoa(end-start+1))
		w.WriteHeader(http.StatusPartialContent)
		w.Write(body[start : end+1])
	})
}

func parseRange(header string, size int) (start, end int, ok bool) {
	spec := strings.TrimPrefix(header, "bytes=")
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	start, err := strconv.Atoi(parts[0])
	if err != nil || start < 0 || start >= size {
		return 0, 0, false
	}
	end = size - 1
	if parts[1] != "" {
		if end, err = strconv.Atoi(parts[1]); err != nil {
			return 0, 0, false
		}
	}
	if end >= size {
		end = size - 1
	}
	return start, end, true
}

func testBody(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i%251) ^ 0x5a
	}
	return b
}

func TestOpenAndCachedReads(t *testing.T) {
	body := testBody(1 << 20)
	var requests atomic.Int64
	srv := httptest.NewServer(rangeHandler(t, body, &requests))
	defer srv.Close()

	src, err := Open(context.Background(), srv.Client(), srv.URL, Options{BlockSize: 4 << 10})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if src.Size() != int64(len(body)) {
		t.Fatalf("size = %d, want %d", src.Size(), len(body))
	}

	// Two small reads inside one block must share a request.
	before := requests.Load()
	for _, off := range []int64{100, 200} {
		buf := make([]byte, 32)
		if _, err := src.ReadAt(buf, off); err != nil {
			t.Fatalf("ReadAt(%d): %v", off, err)
		}
		if !bytes.Equal(buf, body[off:off+32]) {
			t.Fatalf("ReadAt(%d) mismatch", off)
		}
	}
	if got := requests.Load() - before; got != 1 {
		t.Errorf("two reads in one block cost %d requests, want 1", got)
	}

	// A read spanning several blocks works and is correct.
	buf := make([]byte, 20000)
	if n, err := src.ReadAt(buf, 4000); err != nil && err != io.EOF {
		t.Fatalf("ReadAt large: %v", err)
	} else if !bytes.Equal(buf[:n], body[4000:4000+n]) {
		t.Fatal("large read mismatch")
	}

	// Reads past the end report EOF.
	short := make([]byte, 16)
	if _, err := src.ReadAt(short, int64(len(body))); err != io.EOF {
		t.Errorf("ReadAt past end = %v, want io.EOF", err)
	}
	stats := src.Stats()
	if stats.Bytes == 0 || stats.Ranges == 0 {
		t.Errorf("stats = %+v, want non-zero transfer", stats)
	}
}

func TestServerWithoutRangeSupport(t *testing.T) {
	body := testBody(64 << 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ignore Range entirely: always the whole object.
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Write(body)
	}))
	defer srv.Close()

	src, err := Open(context.Background(), srv.Client(), srv.URL, Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	buf := make([]byte, 256)
	if _, err := src.ReadAt(buf, 40000); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(buf, body[40000:40256]) {
		t.Fatal("mismatch when the server ignores Range")
	}
}

func TestShortResponseIsRetried(t *testing.T) {
	body := testBody(8 << 10)
	var attempts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			// Truncate the first response mid-range.
			w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", len(body)-1, len(body)))
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusPartialContent)
			w.Write(body[:100])
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			panic(http.ErrAbortHandler)
		}
		start, end, _ := parseRange(r.Header.Get("Range"), len(body))
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(body)))
		w.WriteHeader(http.StatusPartialContent)
		w.Write(body[start : end+1])
	}))
	defer srv.Close()

	src, err := Open(context.Background(), srv.Client(), srv.URL, Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	buf := make([]byte, 1024)
	if _, err := src.ReadAt(buf, 0); err != nil {
		t.Fatalf("ReadAt after a truncated response: %v", err)
	}
	if !bytes.Equal(buf, body[:1024]) {
		t.Fatal("mismatch after retry")
	}
	if attempts.Load() < 2 {
		t.Errorf("attempts = %d, want a retry", attempts.Load())
	}
}

func TestPrefetchFillsCache(t *testing.T) {
	body := testBody(1 << 20)
	var requests atomic.Int64
	srv := httptest.NewServer(rangeHandler(t, body, &requests))
	defer srv.Close()

	src, err := Open(context.Background(), srv.Client(), srv.URL, Options{BlockSize: 4 << 10})
	if err != nil {
		t.Fatal(err)
	}
	offsets := []int64{2048, 8192, 16384, 32768}
	if err := src.Prefetch(context.Background(), offsets, 4); err != nil {
		t.Fatalf("Prefetch: %v", err)
	}
	before := requests.Load()
	for _, off := range offsets {
		if _, err := src.Get(context.Background(), off, 64); err != nil {
			t.Fatalf("Get(%d): %v", off, err)
		}
	}
	if extra := requests.Load() - before; extra != 0 {
		t.Errorf("prefetched reads cost %d extra requests", extra)
	}
}

func TestGetExact(t *testing.T) {
	body := testBody(32 << 10)
	var requests atomic.Int64
	srv := httptest.NewServer(rangeHandler(t, body, &requests))
	defer srv.Close()

	src, err := Open(context.Background(), srv.Client(), srv.URL, Options{BlockSize: 4 << 10})
	if err != nil {
		t.Fatal(err)
	}
	// Larger than the block size: a direct range.
	got, err := src.Get(context.Background(), 5000, 20000)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, body[5000:25000]) {
		t.Fatal("mismatch")
	}
	if _, err := src.Get(context.Background(), int64(len(body)), 1); err == nil {
		t.Error("expected an error reading past the end")
	}
}

func TestParseTotal(t *testing.T) {
	cases := map[string]int64{
		"bytes 0-0/8522825728": 8522825728,
		"bytes 5-9/100":        100,
		"":                     0,
		"garbage":              0,
	}
	for header, want := range cases {
		if got := parseTotal(header); got != want {
			t.Errorf("parseTotal(%q) = %d, want %d", header, got, want)
		}
	}
}
