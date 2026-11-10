// Package remote provides an io.ReaderAt over HTTP range requests.
//
// It is the bottom layer of on-demand extraction: parsing an Apple asset needs
// to read small structures (AEA segment headers, pbz block headers, Apple
// Archive item headers) scattered across a multi-gigabyte object, so every read
// becomes a Range request instead of a full download.
package remote

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Stats reports what a Source pulled over the wire.
type Stats struct {
	Requests int64 // number of HTTP requests issued
	Bytes    int64 // response bytes received
	Ranges   int64 // Range requests (as opposed to full-object reads)
}

// Source is a random-access view of one remote object.
type Source struct {
	url string
	hc  *http.Client

	size int64

	// blockSize is the cache granularity: small reads are rounded up to whole
	// blocks so that parsing structures next to each other costs one request.
	blockSize int64
	maxCache  int64

	mu       sync.Mutex
	cache    map[int64][]byte
	cacheLRU []int64
	cached   int64

	requests atomic.Int64
	bytes    atomic.Int64
	ranges   atomic.Int64
}

// Options configures a Source.
type Options struct {
	// BlockSize is the read-ahead granule for small reads (default 8 KiB).
	BlockSize int64
	// MaxCache limits the block cache in bytes (default 32 MiB).
	MaxCache int64
}

// Open resolves the object's size and returns a random-access source.
func Open(ctx context.Context, hc *http.Client, rawURL string, opts Options) (*Source, error) {
	if opts.BlockSize <= 0 {
		opts.BlockSize = 8 << 10
	}
	if opts.MaxCache <= 0 {
		opts.MaxCache = 32 << 20
	}
	s := &Source{
		url:       rawURL,
		hc:        hc,
		blockSize: opts.BlockSize,
		maxCache:  opts.MaxCache,
		cache:     make(map[int64][]byte),
	}

	// A one-byte range request gives us both the total size and a check that
	// ranges are supported.
	data, total, err := s.get(ctx, 0, 1, true)
	if err != nil {
		return nil, err
	}
	if total <= 0 {
		return nil, fmt.Errorf("remote: server did not report a size for %s", rawURL)
	}
	if len(data) != 1 {
		return nil, fmt.Errorf("remote: short probe response (%d bytes)", len(data))
	}
	s.size = total
	return s, nil
}

// Size is the total object size in bytes.
func (s *Source) Size() int64 { return s.size }

// Stats reports cumulative transfer counters.
func (s *Source) Stats() Stats {
	return Stats{Requests: s.requests.Load(), Bytes: s.bytes.Load(), Ranges: s.ranges.Load()}
}

// ReadAt implements io.ReaderAt.
func (s *Source) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= s.size {
		return 0, io.EOF
	}
	if int64(len(p)) > s.size-off {
		p = p[:s.size-off]
	}
	// Large reads bypass the block cache.
	if int64(len(p)) >= s.blockSize {
		data, _, err := s.get(context.Background(), off, int64(len(p)), false)
		if err != nil {
			return 0, err
		}
		n := copy(p, data)
		if n < len(p) {
			return n, io.ErrUnexpectedEOF
		}
		return n, nil
	}
	written := 0
	for written < len(p) {
		pos := off + int64(written)
		blockStart := pos / s.blockSize * s.blockSize
		block, err := s.block(context.Background(), blockStart)
		if err != nil {
			return written, err
		}
		n := copy(p[written:], block[pos-blockStart:])
		written += n
	}
	return written, nil
}

// Get returns exactly size bytes at off, using the cache for small reads.
func (s *Source) Get(ctx context.Context, off, size int64) ([]byte, error) {
	if size <= 0 {
		return nil, nil
	}
	if size <= s.blockSize {
		out := make([]byte, size)
		if _, err := s.ReadAt(out, off); err != nil {
			return nil, err
		}
		return out, nil
	}
	data, _, err := s.get(ctx, off, size, false)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != size {
		return nil, fmt.Errorf("remote: short read at %d: got %d want %d", off, len(data), size)
	}
	return data, nil
}

// Prefetch fetches many small ranges concurrently into the cache. It is used to
// walk structure chains (each link reveals the next offset) that would
// otherwise cost one round trip per link.
func (s *Source) Prefetch(ctx context.Context, offsets []int64, workers int) error {
	if workers <= 0 {
		workers = 16
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var firstErr error
	var mu sync.Mutex
	for _, off := range offsets {
		off := off
		s.mu.Lock()
		if _, ok := s.cache[off/s.blockSize*s.blockSize]; ok {
			s.mu.Unlock()
			continue
		}
		s.mu.Unlock()
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if _, err := s.block(ctx, off/s.blockSize*s.blockSize); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return firstErr
}

// block returns the cached block starting at blockStart, fetching it if needed.
func (s *Source) block(ctx context.Context, blockStart int64) ([]byte, error) {
	s.mu.Lock()
	if data, ok := s.cache[blockStart]; ok {
		s.mu.Unlock()
		return data, nil
	}
	s.mu.Unlock()

	length := s.blockSize
	if blockStart+length > s.size {
		length = s.size - blockStart
	}
	data, _, err := s.get(ctx, blockStart, length, true)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) < length {
		return nil, fmt.Errorf("remote: short block at %d: %d < %d", blockStart, len(data), length)
	}
	data = data[:length]

	s.mu.Lock()
	if prev, ok := s.cache[blockStart]; ok {
		s.mu.Unlock()
		return prev, nil
	}
	s.cache[blockStart] = data
	s.cacheLRU = append(s.cacheLRU, blockStart)
	s.cached += int64(len(data))
	for s.cached > s.maxCache && len(s.cacheLRU) > 1 {
		oldest := s.cacheLRU[0]
		s.cacheLRU = s.cacheLRU[1:]
		s.cached -= int64(len(s.cache[oldest]))
		delete(s.cache, oldest)
	}
	s.mu.Unlock()
	return data, nil
}

// get performs one HTTP request. It returns the body and, when the server
// reports it, the total object size.
func (s *Source) get(ctx context.Context, off, length int64, ranged bool) ([]byte, int64, error) {
	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			case <-time.After(time.Duration(attempt) * 300 * time.Millisecond):
			}
		}
		data, total, retry, err := s.tryGet(ctx, off, length, ranged)
		if err == nil {
			return data, total, nil
		}
		lastErr = err
		if !retry {
			return nil, 0, err
		}
	}
	return nil, 0, lastErr
}

func (s *Source) tryGet(ctx context.Context, off, length int64, ranged bool) (data []byte, total int64, retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, 0, false, err
	}
	req.Header.Set("User-Agent", "xcfetch/1 (+range)")
	req.Header.Set("Accept", "*/*")
	if ranged || length < s.size {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, off+length-1))
	}
	s.requests.Add(1)
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, 0, true, fmt.Errorf("remote: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusPartialContent:
		s.ranges.Add(1)
		total = parseTotal(resp.Header.Get("Content-Range"))
	case http.StatusOK:
		// Server ignored the Range header: read and discard up to off.
		if off > 0 {
			if _, err := io.CopyN(io.Discard, resp.Body, off); err != nil {
				return nil, 0, true, fmt.Errorf("remote: skipping %d bytes: %w", off, err)
			}
		}
		total = resp.ContentLength
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, 0, resp.StatusCode >= 500, fmt.Errorf("remote: HTTP %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	buf := make([]byte, length)
	n, err := io.ReadFull(resp.Body, buf)
	s.bytes.Add(int64(n))
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			// Short body: the CDN dropped the connection mid-range. Retry
			// rather than surfacing a truncated read to the parser.
			return nil, 0, true, fmt.Errorf("remote: short range response at %d: %d of %d bytes", off, n, length)
		}
		return nil, 0, true, fmt.Errorf("remote: reading range: %w", err)
	}
	return buf[:n], total, false, nil
}

// parseTotal extracts the total size from a Content-Range header.
func parseTotal(contentRange string) int64 {
	if contentRange == "" {
		return 0
	}
	// bytes 0-0/12345
	idx := strings.LastIndexByte(contentRange, '/')
	if idx < 0 {
		return 0
	}
	total, err := strconv.ParseInt(contentRange[idx+1:], 10, 64)
	if err != nil {
		return 0
	}
	return total
}

// String renders the URL for logs.
func (s *Source) String() string { return s.url }
