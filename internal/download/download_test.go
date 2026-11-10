package download

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func testPayload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 31)
	}
	return b
}

func TestFetchResumesPartialFile(t *testing.T) {
	payload := testPayload(3 << 20)
	var rangeRequests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rangeHeader := r.Header.Get("Range")
		if rangeHeader != "" {
			atomic.AddInt32(&rangeRequests, 1)
			start, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(rangeHeader, "bytes="), "-"))
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(payload)-1, len(payload)))
			w.WriteHeader(http.StatusPartialContent)
			w.Write(payload[start:])
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.Write(payload)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "file.bin")
	// Simulate an interrupted download: half the payload already on disk.
	if err := os.WriteFile(dest+".part", payload[:len(payload)/2], 0o644); err != nil {
		t.Fatal(err)
	}

	sum1 := sha1.Sum(payload)
	sum256 := sha256.Sum256(payload)
	if err := Fetch(context.Background(), srv.Client(), srv.URL, dest, Options{
		ExpectedSize: int64(len(payload)),
		SHA1:         sum1[:],
		SHA256:       sum256[:],
	}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch after resume")
	}
	if atomic.LoadInt32(&rangeRequests) == 0 {
		t.Error("expected a ranged request")
	}
	if _, err := os.Stat(dest + ".part"); !os.IsNotExist(err) {
		t.Error("part file should be renamed away")
	}
}

func TestFetchVerifiesChecksum(t *testing.T) {
	payload := testPayload(1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "file.bin")
	bad := make([]byte, 20)
	err := Fetch(context.Background(), srv.Client(), srv.URL, dest, Options{SHA1: bad})
	if !errors.Is(err, ErrChecksum) {
		t.Fatalf("err = %v, want ErrChecksum", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Error("failed download should not be kept")
	}
}

func TestFetchRejectsUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	dest := filepath.Join(t.TempDir(), "file.bin")
	err := Fetch(context.Background(), srv.Client(), srv.URL, dest, Options{})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v, want an authorization error", err)
	}
}

func TestFetchResumesAfterTruncatedResponse(t *testing.T) {
	payload := testPayload(512 << 10)
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&requests, 1)
		start := 0
		if r.Header.Get("Range") != "" {
			start, _ = strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(r.Header.Get("Range"), "bytes="), "-"))
			w.WriteHeader(http.StatusPartialContent)
		} else {
			w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		}
		if n == 1 {
			// Announce the full length, then send only a slice and drop the
			// connection, forcing the client to resume.
			w.Write(payload[:len(payload)/4])
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			panic(http.ErrAbortHandler)
		}
		w.Write(payload[start:])
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "file.bin")
	if err := Fetch(context.Background(), srv.Client(), srv.URL, dest, Options{ExpectedSize: int64(len(payload))}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %d bytes", len(got))
	}
}
