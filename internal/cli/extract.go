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
	"sync/atomic"
	"text/tabwriter"
	"time"

	"github.com/lbr77/xcfetch/internal/aa"
	"github.com/lbr77/xcfetch/internal/aea"
	"github.com/lbr77/xcfetch/internal/pbz"
	"github.com/lbr77/xcfetch/internal/remote"
	"github.com/lbr77/xcfetch/internal/runtime"
	"github.com/lbr77/xcfetch/internal/udif"
)

// headerPrefetch caps the speculative pbz header window for remote assets.
const headerPrefetch = 128

// smallReadGranule is the remote cache granule for small reads.
const smallReadGranule = 1 << 10

// extractUsage documents the on-demand extraction command.
func extractUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  xcfetch runtime extract <version|build> --match SUBSTRING [flags]
  xcfetch runtime extract <version|build> --image PATH [flags]
  xcfetch runtime extract --local FILE [--key BASE64] (--match S | --image PATH) [flags]

Extracts selected files from a runtime archive using HTTP range requests: only
the AEA segment headers, pbz block headers and the segments holding the wanted
bytes are fetched, so pulling a 1 KB plist from an 8 GB asset costs megabytes
rather than gigabytes.

--image reaches into the runtime's disk image (AssetData/Restore/*.dmg): the
UDIF run table, the APFS metadata on the path to each file and the file's own
blocks are read, nothing else. Each path component may be a glob (*, ?, [..])
and {a,b} expands to alternatives. A directory is extracted recursively (or
listed, with --list). On sealed volumes every file is checked against the
volume's own SHA-256 data hashes.

Flags:
  --match SUBSTRING   only archive entries whose path contains this text (repeatable)
  --path PATH         exact archive entry path (repeatable)
  --image PATH        path inside the runtime disk image's volume (repeatable)
  --list              list the matching entries instead of writing them
  --out DIR           destination (default ~/Downloads/<runtime name>)
  --local FILE        read a local archive (or a .dmg, with --image) instead of the network
  --key BASE64        AEA symmetric key for --local archives
  --payload N         only scan the N-th container payload (skips the rest)
  --max-bytes N       abort after this much transfer (default 4 GiB, 0 = off)
  --no-index-cache    ignore/persist no block indexes
  --verify-segments   authenticate whole AEA segments even for small reads, and
                      read every pbz header instead of inferring some
  --verbose           print transfer statistics while working

Example (the tool CoreSimulator uses to build the simulator dyld cache):
  xcfetch runtime extract 26.5 --image \
    'Library/Developer/CoreSimulator/Profiles/Runtimes/*.simruntime/Contents/Resources/{update_dyld_sim_shared_cache,dylib-order.txt,dirty-data-segments-order.txt}'
`)
}

func runRuntimeExtract(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("runtime extract", stderr)
	var matches multiFlag
	var paths multiFlag
	var images multiFlag
	fs.Var(&matches, "match", "substring of the entry path (repeatable)")
	fs.Var(&paths, "path", "exact entry path (repeatable)")
	fs.Var(&images, "image", "path or glob inside the runtime disk image (repeatable)")
	listOnly := fs.Bool("list", false, "list matching entries without extracting")
	out := fs.String("out", "", "destination directory")
	local := fs.String("local", "", "read a local archive instead of the network")
	keyB64 := fs.String("key", "", "AEA symmetric key (base64) for --local archives")
	verbose := fs.Bool("verbose", false, "print transfer statistics")
	arch := fs.String("arch", "arm64", "architecture variant for downloadable assets")
	maxBytes := fs.Int64("max-bytes", 4<<30, "abort the index walk after this much transfer (0 disables)")
	noCache := fs.Bool("no-index-cache", false, "do not persist or read block indexes")
	payloads := fs.Int("payload", 0, "only descend into this 1-based container payload")
	verifyAll := fs.Bool("verify-segments", false, "authenticate whole AEA segments and read every pbz header")

	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(matches) == 0 && len(paths) == 0 && len(images) == 0 {
		return usageErr(stderr, "runtime extract: give at least one --match, --path or --image")
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
		isRemote bool
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
		// Most small reads are 16-byte pbz block headers decrypted in place,
		// so a fine cache granule keeps the walk's transfer close to what it
		// actually needs.
		rs, err := remote.Open(ctx, hc, target.url, remote.Options{BlockSize: smallReadGranule})
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
		isRemote = true
		fmt.Fprintf(stdout, "%s %s (%s, %s)\n  %s\n", rt.PlatformName(), rt.DisplayVersion(),
			rt.SimulatorVersion.BuildUpdate, humanBytes(size), target.url)
	}

	dest := *out
	if dest == "" {
		dest = filepath.Join(defaultDownloadDir(), sanitizeFilename(destName))
	}
	imgOpts := imageOptions{
		patterns: images,
		list:     *listOnly,
		dest:     dest,
		verbose:  *verbose,
		stdout:   stdout,
		stderr:   stderr,
	}

	// A local disk image has no archive layers at all.
	if *local != "" && udif.IsUDIF(src, size) {
		if len(images) == 0 {
			return usageErr(stderr, "runtime extract: %s is a disk image; select files with --image", *local)
		}
		return extractFromImages([]imageSource{{name: filepath.Base(*local), r: src, size: size}}, imgOpts)
	}

	// Decrypt on demand when the object is an AEA archive.
	plainSrc, plainSize := src, size
	if len(key) > 0 || isAEA(src) {
		rr, err := aea.NewRandomReader(src, size, key)
		if err != nil {
			return err
		}
		rr.SetVerifyAll(*verifyAll)
		plainSrc, plainSize = rr, rr.Size()
	}

	sel := selector(matches, paths)
	wantImages := len(images) > 0
	want := func(p string) bool {
		if sel != nil && sel(p) {
			return true
		}
		return wantImages && isDiskImagePath(p)
	}
	opts := aa.IndexOptions{}
	if *payloads > 0 {
		opts.Payloads = []int{*payloads}
	}
	if isRemote {
		opts.Prefetch = headerPrefetch
	}
	if !*noCache {
		dir, err := indexCacheDir()
		if err == nil && dir != "" {
			opts.Cache = pbz.FileCache{Dir: dir}
			opts.KeyPrefix = cacheKey
		}
	}
	start := time.Now()
	entries, err := aa.IndexStreamWith(plainSrc, plainSize, want, opts)
	if err != nil {
		return err
	}

	// Split what the walk found into archive entries the caller selected and
	// disk images to look inside.
	var (
		selected []aa.Entry
		files    int
		disks    []imageSource
	)
	for _, e := range entries {
		if wantImages && e.Type != aa.TypeDirectory && isDiskImagePath(e.Path) && e.Size > 0 {
			disks = append(disks, imageSource{
				name: e.Path,
				r:    io.NewSectionReader(e.Parent(), e.DataOffset(), e.Size),
				size: e.Size,
			})
		}
		if sel == nil {
			continue
		}
		if e.Type == aa.TypeDirectory || sel(e.Path) {
			selected = append(selected, e)
			if e.Type != aa.TypeDirectory {
				files++
			}
		}
	}
	if *verbose {
		fmt.Fprintf(stderr, "  archive walk: %d entries in %s\n", len(entries), time.Since(start).Round(time.Millisecond))
		reportStats(stats, true, stderr)
	}

	if sel != nil {
		if files == 0 {
			for _, p := range paths {
				if strings.Contains(p, "/") && !wantImages {
					return fmt.Errorf("runtime extract: %q is not an archive entry; for files inside the "+
						"runtime disk image use --image %q", p, p)
				}
			}
			if !wantImages {
				return fmt.Errorf("runtime extract: no entries matched")
			}
			fmt.Fprintln(stderr, "runtime extract: no archive entries matched --match/--path")
		} else if err := emitArchiveEntries(selected, *listOnly, dest, *verbose, stdout, stderr); err != nil {
			return err
		}
	}

	if wantImages {
		if len(disks) == 0 {
			return errors.New("runtime extract: the archive contains no disk image to look into")
		}
		if err := extractFromImages(disks, imgOpts); err != nil {
			return err
		}
	}
	reportStats(stats, true, stdout)
	return nil
}

// emitArchiveEntries lists or writes the selected archive entries.
func emitArchiveEntries(entries []aa.Entry, listOnly bool, dest string, verbose bool, stdout, stderr io.Writer) error {
	if listOnly {
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
		return nil
	}
	start := time.Now()
	if err := aa.ExtractEntries(dest, entries, func(written int64) {
		if verbose {
			fmt.Fprintf(stderr, "\r  extracted %s", humanBytes(written))
		}
	}); err != nil {
		return err
	}
	if verbose {
		fmt.Fprintln(stderr)
	}
	for _, e := range entries {
		if e.Type != aa.TypeDirectory {
			fmt.Fprintf(stdout, "  %s\n", filepath.Join(dest, filepath.FromSlash(e.Path)))
		}
	}
	fmt.Fprintf(stdout, "extracted %d entries in %s\n", len(entries), time.Since(start).Round(time.Millisecond))
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

// isDiskImagePath reports whether an archive entry looks like a disk image.
func isDiskImagePath(p string) bool {
	return strings.HasSuffix(strings.ToLower(p), ".dmg")
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

// budget caps how much an archive walk may pull from the network. Reads may
// arrive concurrently (speculative header prefetch).
type budget struct {
	src   io.ReaderAt
	limit int64
	read  atomic.Int64
}

// ReadAt refuses a read that would cross the limit instead of performing it
// and reporting afterwards: callers that got all their bytes treat a trailing
// error as success, so the guard has to fail the read itself.
func (b *budget) ReadAt(p []byte, off int64) (int, error) {
	if total := b.read.Add(int64(len(p))); total > b.limit {
		b.read.Add(-int64(len(p)))
		return 0, fmt.Errorf("%w (%s of %s); raise --max-bytes, narrow --path, "+
			"or rerun to resume from the cached block index", ErrBudgetExceeded,
			humanBytes(total), humanBytes(b.limit))
	}
	n, err := b.src.ReadAt(p, off)
	if n < len(p) {
		b.read.Add(int64(n - len(p)))
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
