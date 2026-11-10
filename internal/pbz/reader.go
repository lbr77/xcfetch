// Package pbz gives random access to Apple's "pbz*" compression streams.
//
// A stream is a 12-byte header (magic + big endian block size) followed by
// blocks of
//
//	uint64 BE plaintext size | uint64 BE compressed size | payload
//
// where a block is stored verbatim when both sizes are equal. Block sizes are
// only discoverable by walking the chain, but each step is a 16-byte read, so an
// index over a multi-gigabyte stream costs a few dozen kilobytes.
package pbz

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/go-compressions/lzfse"
	"github.com/pierrec/lz4/v4"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

// ErrUnsupportedCompression is returned for lzbitmap and unknown algorithms.
var ErrUnsupportedCompression = errors.New("pbz: unsupported stream compression")

const (
	headerSize = 12
	maxBlock   = 1 << 30
)

// Block is one compressed block of the stream.
type Block struct {
	// OuterOffset is the byte offset of the block's 16-byte header in the parent.
	OuterOffset int64
	// DataOffset is the offset of the payload in the parent.
	DataOffset int64
	// PlainOffset is the plaintext offset this block starts at.
	PlainOffset int64
	PlainSize   int64
	CompSize    int64
	// Inferred marks a raw block whose header was not read: its size was
	// deduced from a later header that sits where the guess put it.
	Inferred bool `json:",omitempty"`
}

// CostHint is implemented by parents that know when a small read is
// expensive, i.e. would fetch and decompress a whole unit (an AEA segment)
// to return a few bytes.
type CostHint interface {
	Expensive(off int64, n int) bool
}

// maxInferRun bounds how many consecutive headers may be inferred before one
// is read to confirm them.
const maxInferRun = 64

// Reader is a random-access view of a decompressed pbz stream.
type Reader struct {
	src      io.ReaderAt
	size     int64 // total bytes of the stream in the parent
	algo     byte
	blockMax int64

	mu     sync.Mutex
	blocks []Block
	next   int64 // parent offset of the next block to index
	plain  int64 // plaintext bytes covered by indexed blocks
	done   bool

	// prefetch caps the speculative window of the header walk (0 disables);
	// window is the current size, specEnd where the last window stopped.
	prefetch int
	window   int
	specEnd  int64
	spec     map[int64]bool // header offsets already requested speculatively

	decMu    sync.Mutex
	decCache map[int64]*prefix // decoded compressed blocks, by OuterOffset
	decOrder []int64
}

// decCacheBlocks bounds the decoded-block cache.
const decCacheBlocks = 8

// prefetchWorkers bounds concurrent speculative header reads.
const prefetchWorkers = 32

// minWindow is where the speculative window starts and restarts after a miss.
const minWindow = 8

// SetPrefetch makes the header walk read up to n block headers ahead,
// concurrently, assuming the blocks are stored raw (full size, uncompressed).
// Each header names the next one's offset, so walking an index costs one round
// trip per block; on a remote parent that dominates. Already-compressed data
// (a disk image of LZFSE chunks, say) is stored raw, so the guess holds and the
// sequential walk then hits warm caches. Speculation only runs while the walk
// keeps seeing raw blocks, and the window grows like TCP slow start: it
// doubles (up to n) each time a whole window of guesses held and falls back to
// a few blocks after a miss, so the guesses wasted behind a compressed block
// stay few.
func (r *Reader) SetPrefetch(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prefetch = n
}

// NewReader reads the stream header and prepares an index.
func NewReader(src io.ReaderAt, size int64) (*Reader, error) {
	if size < headerSize {
		return nil, fmt.Errorf("pbz: stream too small (%d bytes)", size)
	}
	hdr := make([]byte, headerSize)
	if _, err := readFullAt(src, hdr, 0); err != nil {
		return nil, fmt.Errorf("pbz: reading header: %w", err)
	}
	if !bytes.HasPrefix(hdr, []byte("pbz")) {
		return nil, fmt.Errorf("pbz: bad magic %q", hdr[:4])
	}
	blockMax := int64(beUint64(hdr[4:12]))
	if blockMax <= 0 || blockMax > maxBlock {
		return nil, fmt.Errorf("pbz: implausible block size %d", blockMax)
	}
	return &Reader{src: src, size: size, algo: hdr[3], blockMax: blockMax, next: headerSize}, nil
}

// Algo is the compression letter from the stream magic.
func (r *Reader) Algo() byte { return r.algo }

// Size is the total plaintext size; indexing walks the whole block chain once.
func (r *Reader) Size() (int64, error) {
	if err := r.indexAll(); err != nil {
		return 0, err
	}
	return r.plain, nil
}

// Blocks returns the block index, indexing the stream first if needed.
func (r *Reader) Blocks() ([]Block, error) {
	if err := r.indexAll(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Block, len(r.blocks))
	copy(out, r.blocks)
	return out, nil
}

// indexAll walks the block chain to the end of the stream.
func (r *Reader) indexAll() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for !r.done {
		if err := r.indexOne(); err != nil {
			return err
		}
	}
	return nil
}

// indexOne appends the next block; it must be called with r.mu held.
func (r *Reader) indexOne() error {
	if r.next >= r.size {
		r.done = true
		return nil
	}
	r.speculate()
	if r.expensive(r.next) {
		ok, err := r.inferRaw()
		if err != nil || ok {
			return err
		}
	}
	hdr := make([]byte, 16)
	n, err := r.src.ReadAt(hdr, r.next)
	if err != nil && !(err == io.EOF && n == len(hdr)) {
		return fmt.Errorf("pbz: reading block header at %d: %w", r.next, err)
	}
	if n < len(hdr) {
		r.done = true
		return nil
	}
	plainSize := int64(beUint64(hdr[0:8]))
	compSize := int64(beUint64(hdr[8:16]))
	if plainSize <= 0 || plainSize > r.blockMax || compSize <= 0 || compSize > plainSize {
		return fmt.Errorf("pbz: implausible block sizes (%d/%d) at %d", plainSize, compSize, r.next)
	}
	if r.next+16+compSize > r.size {
		return fmt.Errorf("pbz: block at %d overruns the stream", r.next)
	}
	r.blocks = append(r.blocks, Block{
		OuterOffset: r.next,
		DataOffset:  r.next + 16,
		PlainOffset: r.plain,
		PlainSize:   plainSize,
		CompSize:    compSize,
	})
	r.plain += plainSize
	r.next += 16 + compSize
	if plainSize < r.blockMax {
		// A short block terminates the stream.
		r.done = true
	}
	return nil
}

// expensive reports whether the parent says a header read at off is costly.
func (r *Reader) expensive(off int64) bool {
	h, ok := r.src.(CostHint)
	return ok && h.Expensive(off, 16)
}

// inferRaw avoids reading a header that sits in an expensive unit. Nearly all
// blocks of an already-compressed payload (a disk image of LZFSE chunks) are
// stored raw at full size, so it assumes that for the block at r.next (and for
// following ones whose headers are expensive too), then reads the first header
// that is cheap to reach and checks it, and the one after it, for plausibility.
// If any assumed block was really compressed, that position lands in payload
// data instead of on a header and the check fails.
//
// Such a run usually ends at the one header that is not raw (a compressed
// block, or the short final block), so on failure the last assumed header is
// probed for real: one expensive read confirms every block before it. Only if
// that fails too does the caller read the header at r.next.
//
// A false acceptance needs payload bytes that spell out a valid header (a
// 64-bit match) or compressed sizes that add up exactly to the raw stride;
// either way later offsets shift, which breaks the consumer's own structure
// checks rather than passing silently. It must be called with r.mu held.
func (r *Reader) inferRaw() (bool, error) {
	stride := 16 + r.blockMax
	pos := r.next
	n := 0 // blocks assumed raw, starting at r.next
	confirmed := false
	for n < maxInferRun {
		pos += stride
		n++
		if pos == r.size {
			confirmed = true // the stream ends right after the assumed blocks
			break
		}
		if pos+16 > r.size {
			break
		}
		if r.expensive(pos) {
			continue
		}
		ok, err := r.plausibleAt(pos, true)
		if err != nil {
			return false, err
		}
		confirmed = ok
		break
	}
	if !confirmed {
		// Probe the last assumed header: if it is real, the blocks before it
		// were raw. Its unit is then cached for the read that follows.
		n--
		if n == 0 {
			return false, nil
		}
		ok, err := r.plausibleAt(r.next+int64(n)*stride, true)
		if err != nil || !ok {
			return false, err
		}
	}
	for i := 0; i < n; i++ {
		r.blocks = append(r.blocks, Block{
			OuterOffset: r.next,
			DataOffset:  r.next + 16,
			PlainOffset: r.plain,
			PlainSize:   r.blockMax,
			CompSize:    r.blockMax,
			Inferred:    true,
		})
		r.plain += r.blockMax
		r.next += stride
	}
	if r.next >= r.size {
		r.done = true
	}
	return true, nil
}

// plausibleAt reports whether a valid block header sits at pos: sizes within
// bounds, a short block only as the last one, and (when follow is set and it
// is cheap to read) a plausible header where this one says the next begins.
func (r *Reader) plausibleAt(pos int64, follow bool) (bool, error) {
	var hdr [16]byte
	n, err := r.src.ReadAt(hdr[:], pos)
	if n < len(hdr) {
		if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil
		}
		return false, err
	}
	plain, comp := int64(beUint64(hdr[0:8])), int64(beUint64(hdr[8:16]))
	if plain <= 0 || plain > r.blockMax || comp <= 0 || comp > plain {
		return false, nil
	}
	end := pos + 16 + comp
	if end > r.size || (plain < r.blockMax && end != r.size) {
		return false, nil
	}
	if follow && end+16 <= r.size && !r.expensive(end) {
		return r.plausibleAt(end, false)
	}
	return true, nil
}

// speculate warms the parent's caches for the next headers, assuming raw
// blocks. It must be called with r.mu held; it reads r.src directly.
func (r *Reader) speculate() {
	if r.prefetch <= 0 || len(r.blocks) == 0 || r.spec[r.next] {
		return
	}
	if last := r.blocks[len(r.blocks)-1]; last.CompSize != last.PlainSize {
		return
	}
	if r.spec == nil {
		r.spec = make(map[int64]bool)
	}
	switch {
	case r.window == 0 || r.next < r.specEnd:
		// First window, or a guess inside the last window missed.
		r.window = min(minWindow, r.prefetch)
	default:
		r.window = min(2*r.window, r.prefetch)
	}
	stride := 16 + r.blockMax
	r.specEnd = r.next + int64(r.window)*stride
	var offs []int64
	for i := 0; i < r.window; i++ {
		off := r.next + int64(i)*stride
		if off+16 > r.size {
			break
		}
		r.spec[off] = true
		if i > 0 && !r.expensive(off) {
			offs = append(offs, off)
		}
	}
	sem := make(chan struct{}, prefetchWorkers)
	var wg sync.WaitGroup
	for _, off := range offs {
		wg.Add(1)
		sem <- struct{}{}
		go func(off int64) {
			defer wg.Done()
			defer func() { <-sem }()
			var hdr [16]byte
			_, _ = r.src.ReadAt(hdr[:], off) // a miss only costs the guess
		}(off)
	}
	wg.Wait()
}

// ensure indexes enough blocks to cover plaintext offset.
func (r *Reader) ensure(off int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for !r.done && r.plain <= off {
		if err := r.indexOne(); err != nil {
			return err
		}
	}
	return nil
}

// ReadAt implements io.ReaderAt over the decompressed stream. Raw blocks are
// read in place, so a small read of a raw block costs only its own bytes.
func (r *Reader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, io.EOF
	}
	read := 0
	for read < len(p) {
		pos := off + int64(read)
		block, ok := r.blockAt(pos)
		if !ok {
			if err := r.ensure(pos); err != nil {
				return read, err
			}
			if block, ok = r.blockAt(pos); !ok {
				return read, io.EOF
			}
		}
		within := pos - block.PlainOffset
		if block.CompSize == block.PlainSize {
			n := int(min(int64(len(p)-read), block.PlainSize-within))
			if _, err := readFullAt(r.src, p[read:read+n], block.DataOffset+within); err != nil {
				return read, fmt.Errorf("pbz: raw block at %d: %w", block.OuterOffset, err)
			}
			read += n
			continue
		}
		data, err := r.decoded(block, within+int64(len(p)-read))
		if err != nil {
			return read, err
		}
		n := copy(p[read:], data[within:])
		if n == 0 {
			return read, io.EOF
		}
		read += n
	}
	return read, nil
}

// blockAt finds the indexed block containing plaintext offset pos.
func (r *Reader) blockAt(pos int64) (Block, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := sort.Search(len(r.blocks), func(i int) bool {
		return r.blocks[i].PlainOffset+r.blocks[i].PlainSize > pos
	})
	if i < len(r.blocks) && pos >= r.blocks[i].PlainOffset {
		return r.blocks[i], true
	}
	return Block{}, false
}

// prefix is the decoded start of a compressed block. Streaming decoders (xz,
// lzma, zlib) stop as soon as the wanted bytes are out, so reading the first
// few hundred bytes of a 4 MiB block costs a prefix of its compressed data,
// not all of it; dec resumes where the last read stopped.
type prefix struct {
	buf []byte
	dec io.Reader // nil once the block is fully decoded
}

// prefixChunk is how much plaintext a streaming decode adds per step, and the
// read size for the compressed data under it.
const prefixChunk = 256 << 10

// decoded returns at least need bytes of a compressed block's plaintext (or
// all of it), from a small cache.
func (r *Reader) decoded(b Block, need int64) ([]byte, error) {
	need = min(need, b.PlainSize)
	r.decMu.Lock()
	defer r.decMu.Unlock()
	pf, ok := r.decCache[b.OuterOffset]
	if !ok {
		dec, err := r.streamDecoder(b)
		if err != nil {
			return nil, err
		}
		pf = &prefix{dec: dec}
		if dec == nil {
			data, err := r.decode(b)
			if err != nil {
				return nil, err
			}
			pf.buf = data
		}
		if r.decCache == nil {
			r.decCache = make(map[int64]*prefix)
		}
		r.decCache[b.OuterOffset] = pf
		r.decOrder = append(r.decOrder, b.OuterOffset)
		for len(r.decOrder) > decCacheBlocks {
			delete(r.decCache, r.decOrder[0])
			r.decOrder = r.decOrder[1:]
		}
	}
	for pf.dec != nil && int64(len(pf.buf)) < need {
		want := min(b.PlainSize, max(need, int64(len(pf.buf))+prefixChunk))
		grown := make([]byte, want)
		copy(grown, pf.buf)
		n, err := io.ReadFull(pf.dec, grown[len(pf.buf):])
		pf.buf = grown[:len(pf.buf)+n]
		if int64(len(pf.buf)) == b.PlainSize {
			pf.dec = nil
			break
		}
		if err != nil {
			delete(r.decCache, b.OuterOffset)
			return nil, fmt.Errorf("pbz: block at %d: decompressing: %w", b.OuterOffset, err)
		}
	}
	if int64(len(pf.buf)) < need {
		return nil, fmt.Errorf("pbz: block at %d: decoded %d of %d bytes", b.OuterOffset, len(pf.buf), need)
	}
	return pf.buf, nil
}

// streamDecoder returns an incremental decoder for the block, or nil when the
// algorithm only decodes whole blocks (lzfse, lz4).
func (r *Reader) streamDecoder(b Block) (io.Reader, error) {
	comp := bufio.NewReaderSize(io.NewSectionReader(r.src, b.DataOffset, b.CompSize), prefixChunk)
	switch r.algo {
	case 'x':
		head, err := comp.Peek(6)
		if err != nil {
			return nil, fmt.Errorf("pbz: block at %d: %w", b.OuterOffset, err)
		}
		if bytes.Equal(head, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}) {
			xr, err := xz.NewReader(comp)
			if err != nil {
				return nil, fmt.Errorf("pbz: xz block at %d: %w", b.OuterOffset, err)
			}
			return xr, nil
		}
		lr, err := lzma.NewReader(comp)
		if err != nil {
			return nil, fmt.Errorf("pbz: lzma block at %d: %w", b.OuterOffset, err)
		}
		return lr, nil
	case 'z':
		zr, err := zlib.NewReader(comp)
		if err != nil {
			return nil, fmt.Errorf("pbz: zlib block at %d: %w", b.OuterOffset, err)
		}
		return zr, nil
	}
	return nil, nil
}

// decode fetches and expands one block.
func (r *Reader) decode(b Block) ([]byte, error) {
	payload := make([]byte, b.CompSize)
	if _, err := readFullAt(r.src, payload, b.DataOffset); err != nil {
		return nil, fmt.Errorf("pbz: block at %d: reading payload: %w", b.OuterOffset, err)
	}
	if b.CompSize == b.PlainSize {
		return payload, nil
	}
	switch r.algo {
	case 'e':
		out, err := lzfse.DecompressLimit(payload, int(b.PlainSize))
		if err != nil {
			return nil, fmt.Errorf("pbz: lzfse block at %d: %w", b.OuterOffset, err)
		}
		return out, nil
	case 'x':
		var rd io.Reader
		if bytes.HasPrefix(payload, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}) {
			xr, err := xz.NewReader(bytes.NewReader(payload))
			if err != nil {
				return nil, fmt.Errorf("pbz: xz block at %d: %w", b.OuterOffset, err)
			}
			rd = xr
		} else {
			lr, err := lzma.NewReader(bytes.NewReader(payload))
			if err != nil {
				return nil, fmt.Errorf("pbz: lzma block at %d: %w", b.OuterOffset, err)
			}
			rd = lr
		}
		out := make([]byte, b.PlainSize)
		if _, err := io.ReadFull(rd, out); err != nil {
			return nil, fmt.Errorf("pbz: block at %d: decompressing: %w", b.OuterOffset, err)
		}
		return out, nil
	case 'z':
		zr, err := zlib.NewReader(bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("pbz: zlib block at %d: %w", b.OuterOffset, err)
		}
		defer zr.Close()
		out := make([]byte, b.PlainSize)
		if _, err := io.ReadFull(zr, out); err != nil {
			return nil, fmt.Errorf("pbz: block at %d: decompressing: %w", b.OuterOffset, err)
		}
		return out, nil
	case '4':
		out := make([]byte, b.PlainSize)
		n, err := lz4.UncompressBlock(payload, out)
		if err != nil {
			return nil, fmt.Errorf("pbz: lz4 block at %d: %w", b.OuterOffset, err)
		}
		return out[:n], nil
	case 'b':
		return nil, fmt.Errorf("%w: lzbitmap", ErrUnsupportedCompression)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedCompression, r.algo)
	}
}

func beUint64(b []byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}

func readFullAt(r io.ReaderAt, buf []byte, off int64) (int, error) {
	n, err := r.ReadAt(buf, off)
	if n == len(buf) {
		return n, nil
	}
	if err == nil {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}
