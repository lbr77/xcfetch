package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/lbr77/xcfetch/internal/aa"
	"github.com/lbr77/xcfetch/internal/aea"
	"github.com/lbr77/xcfetch/internal/pbz"
	"github.com/lbr77/xcfetch/internal/remote"
	"github.com/lbr77/xcfetch/internal/runtime"
)

// extractUsage documents the on-demand extraction command.
func extractUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  xcfetch runtime extract <version|build> --match SUBSTRING [flags]
  xcfetch runtime extract --local FILE [--key BASE64] --match SUBSTRING [flags]

Extracts selected files from a runtime archive using HTTP range requests: only
the AEA segment headers, pbz block headers and the segments holding the wanted
bytes are fetched, so pulling a 1 KB plist from an 8 GB asset costs megabytes
rather than gigabytes.

Flags:
  --match SUBSTRING   only entries whose path contains this text (repeatable)
  --path PATH         exact entry path (repeatable)
  --list              list the matching entries instead of writing them
  --out DIR           destination (default ~/Downloads/<runtime name>)
  --local FILE        read a local archive instead of the network
  --key BASE64        AEA symmetric key for --local archives
  --payload N         only scan the N-th container payload (skips the rest)
  --max-bytes N       abort the walk after this much transfer (default 4 GiB, 0 = off)
  --no-index-cache    ignore/persist no block indexes
  --verbose           print transfer statistics while working
`)
}

func runRuntimeExtract(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("runtime extract", stderr)
	var matches multiFlag
	var paths multiFlag
	fs.Var(&matches, "match", "substring of the entry path (repeatable)")
	fs.Var(&paths, "path", "exact entry path (repeatable)")
	listOnly := fs.Bool("list", false, "list matching entries without extracting")
	out := fs.String("out", "", "destination directory")
	local := fs.String("local", "", "read a local archive instead of the network")
	keyB64 := fs.String("key", "", "AEA symmetric key (base64) for --local archives")
	verbose := fs.Bool("verbose", false, "print transfer statistics")
	arch := fs.String("arch", "arm64", "architecture variant for downloadable assets")
	maxBytes := fs.Int64("max-bytes", 4<<30, "abort the index walk after this much transfer (0 disables)")
	noCache := fs.Bool("no-index-cache", false, "do not persist or read block indexes")
	payloads := fs.Int("payload", 0, "only descend into this 1-based container payload")

	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(matches) == 0 && len(paths) == 0 {
		return usageErr(stderr, "runtime extract: give at least one --match or --path")
	}
	if *local == "" && len(rest) != 1 {
		return usageErr(stderr, "runtime extract: expected one version, build or identifier (or --local FILE)")
	}

	// Where do the bytes come from?
	var (
		src      io.ReaderAt
		size     int64
		key      []byte
		destName string
		cacheKey string
		stats    func() remote.Stats
	)
	if *local != "" {
		f, err := os.Open(*local)
		if err != nil {
			return err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return err
		}
		src, size = f, st.Size()
		destName = strings.TrimSuffix(filepath.Base(*local), filepath.Ext(*local))
		if *keyB64 != "" {
			key, err = base64.StdEncoding.DecodeString(*keyB64)
			if err != nil {
				return fmt.Errorf("runtime extract: --key: %w", err)
			}
		}
	} else {
		list, err := runtime.Load(ctx, client(nil))
		if err != nil {
			return err
		}
		rt, err := runtime.Find(list, rest[0], "ios", *arch)
		if err != nil {
			return err
		}
		jar, err := openJar()
		if err != nil {
			return err
		}
		hc := client(jar)
		target, err := resolveRuntime(ctx, hc, rt, *arch)
		if err != nil {
			return err
		}
		rs, err := remote.Open(ctx, hc, target.url, remote.Options{})
		if err != nil {
			return err
		}
		cacheKey = fmt.Sprintf("%s|%d", target.url, rs.Size())
		var body io.ReaderAt = rs
		if *maxBytes > 0 {
			body = &budget{src: rs, limit: *maxBytes}
		}
		src, size, key = body, rs.Size(), target.key
		destName = rt.Name
		stats = rs.Stats
		fmt.Fprintf(stdout, "%s %s (%s, %s)\n  %s\n", rt.PlatformName(), rt.DisplayVersion(),
			rt.SimulatorVersion.BuildUpdate, humanBytes(size), target.url)
	}

	// Decrypt on demand when the object is an AEA archive.
	plainSrc, plainSize := src, size
	if len(key) > 0 || isAEA(src) {
		rr, err := aea.NewRandomReader(src, size, key)
		if err != nil {
			return err
		}
		plainSrc, plainSize = rr, rr.Size()
	}

	want := selector(matches, paths)
	opts := aa.IndexOptions{}
	if *payloads > 0 {
		opts.Payloads = []int{*payloads}
	}
	if !*noCache {
		dir, err := indexCacheDir()
		if err == nil && dir != "" {
			opts.Cache = pbz.FileCache{Dir: dir}
			opts.KeyPrefix = cacheKey
		}
	}
	entries, err := aa.IndexStreamWith(plainSrc, plainSize, want, opts)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("runtime extract: no entries matched")
	}

	if *listOnly {
		w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "TYPE\tSIZE\tPATH")
		var total int64
		for _, e := range entries {
			fmt.Fprintf(w, "%s\t%s\t%s\n", e.TypeName(), humanBytes(e.Size), e.Path)
			total += e.Size
		}
		if err := w.Flush(); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%d entries, %s total\n", len(entries), humanBytes(total))
		reportStats(stats, verbose != nil && *verbose, stdout)
		return nil
	}

	dest := *out
	if dest == "" {
		dest = filepath.Join(defaultDownloadDir(), sanitizeFilename(destName))
	}
	start := time.Now()
	if err := aa.ExtractEntries(dest, entries, func(written int64) {
		if *verbose {
			fmt.Fprintf(stderr, "\r  extracted %s", humanBytes(written))
		}
	}); err != nil {
		return err
	}
	if *verbose {
		fmt.Fprintln(stderr)
	}
	for _, e := range entries {
		if e.Type != aa.TypeDirectory {
			fmt.Fprintf(stdout, "  %s\n", filepath.Join(dest, filepath.FromSlash(e.Path)))
		}
	}
	fmt.Fprintf(stdout, "extracted %d entries in %s\n", len(entries), time.Since(start).Round(time.Millisecond))
	reportStats(stats, true, stdout)
	return nil
}

func reportStats(stats func() remote.Stats, show bool, w io.Writer) {
	if stats == nil || !show {
		return
	}
	s := stats()
	fmt.Fprintf(w, "transferred %s in %d requests (%d ranged)\n", humanBytes(s.Bytes), s.Requests, s.Ranges)
}

// selector builds an entry filter from substring and exact-path matchers.
func selector(matches, paths []string) func(string) bool {
	if len(matches) == 0 && len(paths) == 0 {
		return nil
	}
	return func(p string) bool {
		for _, exact := range paths {
			if p == exact {
				return true
			}
		}
		for _, sub := range matches {
			if strings.Contains(p, sub) {
				return true
			}
		}
		return false
	}
}

// isAEA reports whether the object starts with the AEA magic.
func isAEA(src io.ReaderAt) bool {
	head := make([]byte, 4)
	if _, err := src.ReadAt(head, 0); err != nil {
		return false
	}
	return string(head) == "AEA1"
}

// multiFlag collects a repeated string flag.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// ErrBudgetExceeded reports that the index walk hit its transfer budget.
var ErrBudgetExceeded = errors.New("runtime extract: transfer budget exceeded")

// budget caps how much an archive walk may pull from the network.
type budget struct {
	src   io.ReaderAt
	limit int64
	read  int64
}

func (b *budget) ReadAt(p []byte, off int64) (int, error) {
	n, err := b.src.ReadAt(p, off)
	b.read += int64(n)
	if b.read > b.limit {
		return n, fmt.Errorf("%w (%s of %s); raise --max-bytes, narrow --path, "+
			"or rerun to resume from the cached block index", ErrBudgetExceeded,
			humanBytes(b.read), humanBytes(b.limit))
	}
	return n, err
}

// indexCacheDir is where pbz block indexes are persisted.
func indexCacheDir() (string, error) {
	if dir := os.Getenv("XCFETCH_CACHE_DIR"); dir != "" {
		return filepath.Join(dir, "pbz-index"), nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "xcfetch", "pbz-index"), nil
}
