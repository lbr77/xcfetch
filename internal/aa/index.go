package aa

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"

	"github.com/lbr77/xcfetch/internal/pbz"
)

// TypeDirectory identifies directory entries, for callers that need to skip them.
const TypeDirectory = typeDirectory

// Entry describes one file in an archive without its data being read.
type Entry struct {
	Path    string
	Type    byte
	Mode    fs.FileMode
	HasMode bool
	Link    string
	Size    int64

	src io.ReaderAt
	off int64
}

// DataOffset is the entry's data position inside its parent view.
func (e Entry) DataOffset() int64 { return e.off }

// Parent returns the reader the entry's data lives in.
func (e Entry) Parent() io.ReaderAt { return e.src }

// Reader returns the entry's contents on demand.
func (e Entry) Reader() io.Reader {
	return io.NewSectionReader(e.src, e.off, e.Size)
}

// TypeName is a human readable entry kind.
func (e Entry) TypeName() string {
	switch e.Type {
	case typeDirectory:
		return "dir"
	case typeRegularFile:
		return "file"
	case typeSymbolicLink:
		return "link"
	case typeBlockSpecial:
		return "block"
	case typeCharacterSpecial:
		return "char"
	case typeFifo:
		return "fifo"
	case typeSocket:
		return "socket"
	case typeMetadata:
		return "meta"
	}
	return fmt.Sprintf("type %q", string(e.Type))
}

// StreamIndexCache persists pbz block indexes so that a repeated walk of the
// same archive does not have to replay the (expensive) block header chain.
type StreamIndexCache interface {
	Load(key string) (pbz.Index, bool)
	Save(key string, idx pbz.Index) error
}

// IndexOptions tunes a remote index walk.
type IndexOptions struct {
	// Cache, when set, stores block indexes keyed by stream identity.
	Cache StreamIndexCache
	// KeyPrefix makes cache keys unique, typically "<url>|<size>".
	KeyPrefix string
	// Payloads, when non-empty, restricts the walk to these 1-based container
	// payload indexes. It lets a caller skip payloads it does not care about
	// instead of paying for their block chains.
	Payloads []int
}

func (o IndexOptions) wantsPayload(index int) bool {
	if len(o.Payloads) == 0 {
		return true
	}
	for _, p := range o.Payloads {
		if p == index {
			return true
		}
	}
	return false
}

// Index walks an Apple Archive and returns its entries, following nested
// payload containers, without reading entry data. Entries are returned in
// archive order.
//
// r must be the *raw* archive (not a pbz stream); use IndexStream when the outer
// layer may be compressed.
func Index(r io.ReaderAt, size int64) ([]Entry, error) {
	return IndexFilter(r, size, nil)
}

// IndexFilter is Index restricted to paths satisfying want (nil accepts all).
// Directories are always included so that callers can create parents.
func IndexFilter(r io.ReaderAt, size int64, want func(string) bool) ([]Entry, error) {
	return IndexStreamWith(r, size, want, IndexOptions{})
}

// IndexStreamWith is IndexStream with caching of nested block indexes.
func IndexStreamWith(r io.ReaderAt, size int64, want func(string) bool, opt IndexOptions) ([]Entry, error) {
	src, sz, err := streamView(r, size)
	if err != nil {
		return nil, err
	}
	var entries []Entry
	if err := indexPath(src, sz, want, &entries, 0, opt); err != nil {
		return nil, err
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

// IndexStream indexes an archive whose outermost layer may be a pbz stream.
func IndexStream(r io.ReaderAt, size int64, want func(string) bool) ([]Entry, error) {
	return IndexStreamWith(r, size, want, IndexOptions{})
}

// maxViewSize is a sentinel size for nested views. Nested streams are indexed
// lazily: a huge bound lets the walk stop at the first read that runs past the
// real end instead of pre-walking a multi-gigabyte block chain.
const maxViewSize int64 = 1 << 62

// streamView unwraps a pbz stream when present.
func streamView(r io.ReaderAt, size int64) (io.ReaderAt, int64, error) {
	head := make([]byte, 4)
	if _, err := r.ReadAt(head, 0); err != nil && err != io.EOF {
		return nil, 0, err
	}
	switch {
	case bytes.HasPrefix(head, []byte("pbz")):
		pr, err := pbz.NewReader(r, size)
		if err != nil {
			return nil, 0, err
		}
		return pr, maxViewSize, nil
	case bytes.Equal(head, []byte("AA01")), bytes.Equal(head, []byte("YAA1")):
		return r, size, nil
	default:
		return nil, 0, fmt.Errorf("aa: not an Apple Archive (magic %q)", head)
	}
}

func indexPath(r io.ReaderAt, size int64, want func(string) bool, out *[]Entry, depth int, opt IndexOptions) error {
	if depth > maxDepth {
		return errors.New("aa: nested archive depth exceeded")
	}
	sr := &seqReader{r: r, size: size}
	for {
		it, err := readHeaderAt(sr)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if it.path == "" {
			// Payload container: recurse into each data blob as a nested view.
			payloadIndex := 0
			for _, blob := range it.blobs {
				if blob.key != "DAT" {
					sr.skip(blob.size)
					continue
				}
				payloadIndex++
				if opt.wantsPayload(payloadIndex) {
					view := io.NewSectionReader(r, sr.off, blob.size)
					if err := indexPayload(view, blob.size, sr.off, want, out, depth+1, opt); err != nil {
						return err
					}
				}
				sr.off += blob.size
			}
			continue
		}

		if it.typ == typeRegularFile || it.typ == typeSymbolicLink || it.typ == typeDirectory {
			entry := Entry{
				Path:    it.path,
				Type:    it.typ,
				Mode:    it.mode,
				HasMode: it.hasMode,
				Link:    it.link,
				src:     r,
				off:     sr.off,
			}
			// Data lives in the DAT blob; other blobs (xattrs, ...) precede or
			// follow it, so the offset is where DAT starts.
			dataOff := sr.off
			hasData := false
			for _, blob := range it.blobs {
				if blob.key == "DAT" {
					entry.Size = blob.size
					entry.off = dataOff
					hasData = true
					break
				}
				dataOff += blob.size
			}
			include := want == nil || want(entry.Path) || it.typ == typeDirectory
			if include && (hasData || it.typ != typeRegularFile) {
				*out = append(*out, entry)
			}
		}
		sr.skip(it.blobBytes)
	}
}

// indexPayload handles one container blob: an archive (possibly pbz wrapped) is
// walked, anything else is skipped.
func indexPayload(view io.ReaderAt, size, offset int64, want func(string) bool, out *[]Entry, depth int, opt IndexOptions) error {
	head := make([]byte, 4)
	if _, err := view.ReadAt(head, 0); err != nil && err != io.EOF {
		return err
	}
	switch {
	case bytes.HasPrefix(head, []byte("pbz")):
		pr, err := pbz.NewReader(view, size)
		if err != nil {
			return err
		}
		key := ""
		if opt.Cache != nil {
			key = fmt.Sprintf("%s|%d|%d", opt.KeyPrefix, offset, size)
			if idx, ok := opt.Cache.Load(key); ok {
				pr.Import(idx)
			}
		}
		if err := indexPath(pr, maxViewSize, want, out, depth, opt); err != nil {
			return err
		}
		if opt.Cache != nil && key != "" {
			// Cache whatever the walk discovered, even a partial index: the next
			// run starts where this one stopped.
			_ = opt.Cache.Save(key, pr.Export())
		}
		return nil
	case bytes.Equal(head, []byte("AA01")), bytes.Equal(head, []byte("YAA1")):
		return indexPath(view, size, want, out, depth, opt)
	default:
		return nil
	}
}

// seqReader tracks a position while reading sequentially from a ReaderAt.
type seqReader struct {
	r    io.ReaderAt
	off  int64
	size int64
}

func (s *seqReader) Read(p []byte) (int, error) {
	if s.off >= s.size {
		return 0, io.EOF
	}
	if int64(len(p)) > s.size-s.off {
		p = p[:s.size-s.off]
	}
	n, err := s.r.ReadAt(p, s.off)
	s.off += int64(n)
	if err == io.EOF && n > 0 {
		err = nil
	}
	return n, err
}

func (s *seqReader) skip(n int64) {
	s.off += n
	if s.off > s.size {
		s.off = s.size
	}
}

// readHeaderAt reads one item header through a seqReader.
func readHeaderAt(sr *seqReader) (item, error) {
	var fixed [itemHeaderSize]byte
	if _, err := io.ReadFull(sr, fixed[:]); err != nil {
		if err == io.EOF {
			return item{}, io.EOF
		}
		if err == io.ErrUnexpectedEOF {
			return item{}, io.EOF
		}
		return item{}, err
	}
	magic := string(fixed[:4])
	if magic != "AA01" && magic != "YAA1" {
		return item{}, fmt.Errorf("%w: item magic %q at %d", errNotArchive, magic, sr.off-itemHeaderSize)
	}
	size := int(binaryLE16(fixed[4:]))
	if size < itemHeaderSize || size > maxHeaderSize {
		return item{}, fmt.Errorf("aa: implausible item header size %d", size)
	}
	buf := make([]byte, size)
	copy(buf, fixed[:])
	if _, err := io.ReadFull(sr, buf[itemHeaderSize:]); err != nil {
		return item{}, fmt.Errorf("aa: reading item header: %w", err)
	}
	return parseItem(buf)
}

func binaryLE16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }

// ExtractEntries copies the selected entries to dest, creating parents and
// applying modes and symlink targets. Files whose data lies outside r are the
// caller's responsibility.
func ExtractEntries(dest string, entries []Entry, progress func(written int64)) error {
	var total int64
	for _, e := range entries {
		if err := writeEntry(dest, e); err != nil {
			return err
		}
		if e.Type == typeRegularFile {
			total += e.Size
			if progress != nil {
				progress(total)
			}
		}
	}
	return nil
}
