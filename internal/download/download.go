// Package download implements resumable, checksum-verified HTTP downloads.
package download

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Options configures a download.
type Options struct {
	// ExpectedSize is the total byte count; 0 means "unknown, trust the server".
	ExpectedSize int64
	// SHA1 and SHA256 are optional digests verified after the file is complete.
	SHA1, SHA256 []byte
	// Progress receives a human readable progress line; nil disables it.
	Progress func(done, total int64)
	// UserAgent overrides the default.
	UserAgent string
}

// ErrChecksum reports a completed download whose digest does not match.
var ErrChecksum = errors.New("download: checksum mismatch")

// Fetch downloads url into dest, resuming a previous partial file when one is
// present. The partial file is dest+".part"; on success it is renamed to dest.
func Fetch(ctx context.Context, hc *http.Client, rawURL, dest string, opt Options) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	part := dest + ".part"
	var offset int64
	if st, err := os.Stat(part); err == nil {
		offset = st.Size()
	}
	if offset > 0 && opt.ExpectedSize > 0 && offset > opt.ExpectedSize {
		// Stale or truncated; start over.
		if err := os.Remove(part); err != nil {
			return err
		}
		offset = 0
	}

	for attempt := range 3 {
		done, err := fetchOnce(ctx, hc, rawURL, part, offset, opt)
		if err != nil {
			return err
		}
		if done {
			break
		}
		// Server ignored our Range header, or the connection ended early: retry
		// from whatever we now have on disk.
		if st, err := os.Stat(part); err == nil {
			offset = st.Size()
		}
		if attempt == 2 {
			return fmt.Errorf("download: %s: incomplete after %d attempts", rawURL, attempt+1)
		}
	}
	if err := verify(part, opt); err != nil {
		if errors.Is(err, ErrChecksum) {
			_ = os.Remove(part)
		}
		return err
	}
	return os.Rename(part, dest)
}

func fetchOnce(ctx context.Context, hc *http.Client, rawURL, part string, offset int64, opt Options) (complete bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false, err
	}
	ua := opt.UserAgent
	if ua == "" {
		ua = "xcfetch/1"
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	if offset > 0 {
		req.Header.Set("Range", "bytes="+strconv.FormatInt(offset, 10)+"-")
	}

	resp, err := hc.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Full body: restart from zero.
		offset = 0
	case http.StatusPartialContent:
		if offset == 0 {
			return false, fmt.Errorf("download: server sent 206 without a range request")
		}
	case http.StatusRequestedRangeNotSatisfiable:
		// Already complete.
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, fmt.Errorf("download: %s: HTTP %s (session expired or not authorized)", rawURL, resp.Status)
	default:
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return false, fmt.Errorf("download: %s: unexpected redirect to %s", rawURL, resp.Header.Get("Location"))
		}
		return false, fmt.Errorf("download: %s: HTTP %s", rawURL, resp.Status)
	}

	total := opt.ExpectedSize
	if total == 0 && resp.ContentLength > 0 {
		total = offset + resp.ContentLength
	}

	f, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return false, err
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return false, err
	}

	written := offset
	lastReport := time.Now()
	buf := make([]byte, 1<<20)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				return false, werr
			}
			written += int64(n)
			if opt.Progress != nil && time.Since(lastReport) > 200*time.Millisecond {
				opt.Progress(written, total)
				lastReport = time.Now()
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			if opt.Progress != nil {
				opt.Progress(written, total)
			}
			if ctx.Err() != nil {
				return false, rerr
			}
			// Connection dropped mid-stream: keep what we have and let the
			// caller resume with a Range request.
			if err := f.Sync(); err != nil {
				return false, err
			}
			return false, nil
		}
	}
	if err := f.Sync(); err != nil {
		return false, err
	}
	if opt.Progress != nil {
		opt.Progress(written, total)
	}
	if total > 0 && written < total {
		return false, nil // truncated: caller resumes
	}
	return true, nil
}

func verify(path string, opt Options) error {
	if len(opt.SHA1) == 0 && len(opt.SHA256) == 0 {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var h1, h256 hash.Hash
	var w io.Writer = io.Discard
	if len(opt.SHA1) > 0 {
		h1 = sha1.New()
		w = h1
	}
	if len(opt.SHA256) > 0 {
		h256 = sha256.New()
		w = io.MultiWriter(w, h256)
	}
	if _, err := io.Copy(w, f); err != nil {
		return err
	}
	if h1 != nil && !equalBytes(h1.Sum(nil), opt.SHA1) {
		return fmt.Errorf("%w: sha1 got %x want %x", ErrChecksum, h1.Sum(nil), opt.SHA1)
	}
	if h256 != nil && !equalBytes(h256.Sum(nil), opt.SHA256) {
		return fmt.Errorf("%w: sha256 got %x want %x", ErrChecksum, h256.Sum(nil), opt.SHA256)
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ProgressPrinter returns a Progress callback that renders to w with carriage
// returns, or nil when w is not a terminal.
func ProgressPrinter(w io.Writer, isTTY bool) func(done, total int64) {
	if !isTTY {
		return nil
	}
	return func(done, total int64) {
		const width = 24
		pct := 0.0
		bar := ""
		if total > 0 {
			pct = float64(done) / float64(total) * 100
			filled := int(float64(width) * float64(done) / float64(total))
			bar = strings.Repeat("=", filled) + strings.Repeat(" ", width-filled)
		}
		fmt.Fprintf(w, "\r  [%s] %5.1f%% %10s / %-10s", bar, pct, human(done), human(total))
		if done == total && total > 0 {
			fmt.Fprintln(w)
		}
	}
}

func human(n int64) string {
	const unit = 1024
	units := "BKMGTPE"
	value := float64(n)
	exp := 0
	for value >= unit && exp < len(units)-1 {
		value /= unit
		exp++
	}
	if exp == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %ciB", value, units[exp])
}
