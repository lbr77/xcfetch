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
}

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

	// prefetch is the speculative window of the header walk (0 disables).
	prefetch int
	spec     map[int64]bool // header offsets already requested speculatively

	decMu    sync.Mutex
	decCache map[int64][]byte // decoded compressed blocks, by OuterOffset
	decOrder []int64
}

// decCacheBlocks bounds the decoded-block cache.
const decCacheBlocks = 8

// prefetchWorkers bounds concurrent speculative header reads.
const prefetchWorkers = 16

// SetPrefetch makes the header walk read up to n block headers ahead,
// concurrently, assuming the blocks are stored raw (full size, uncompressed).
// Each header names the next one's offset, so walking an index costs one round
// trip per block; on a remote parent that dominates. Already-compressed data
// (a disk image of LZFSE chunks, say) is stored raw, so the guess holds and the
// sequential walk then hits warm caches. Speculation only runs while the walk
// keeps seeing raw blocks, so compressible streams do not pay for misses.
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
	stride := 16 + r.blockMax
	var offs []int64
	for i := 0; i < r.prefetch; i++ {
		off := r.next + int64(i)*stride
		if off+16 > r.size {
			break
		}
		r.spec[off] = true
		if i > 0 {
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
		data, err := r.decoded(block)
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

// decoded returns a compressed block's plaintext, from a small cache.
func (r *Reader) decoded(b Block) ([]byte, error) {
	r.decMu.Lock()
	if data, ok := r.decCache[b.OuterOffset]; ok {
		r.decMu.Unlock()
		return data, nil
	}
	r.decMu.Unlock()
	data, err := r.decode(b)
	if err != nil {
		return nil, err
	}
	r.decMu.Lock()
	defer r.decMu.Unlock()
	if r.decCache == nil {
		r.decCache = make(map[int64][]byte)
	}
	if _, ok := r.decCache[b.OuterOffset]; !ok {
		r.decCache[b.OuterOffset] = data
		r.decOrder = append(r.decOrder, b.OuterOffset)
		for len(r.decOrder) > decCacheBlocks {
			delete(r.decCache, r.decOrder[0])
			r.decOrder = r.decOrder[1:]
		}
	}
	return data, nil
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
