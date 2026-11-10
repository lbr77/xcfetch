package pbz

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"
	"testing"
)

// countingReaderAt records the bytes and the offsets a reader pulls.
type countingReaderAt struct {
	r     io.ReaderAt
	mu    sync.Mutex
	bytes int64
	offs  map[int64]bool
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	c.mu.Lock()
	c.bytes += int64(n)
	if c.offs == nil {
		c.offs = make(map[int64]bool)
	}
	c.offs[off] = true
	c.mu.Unlock()
	return n, err
}

// synthStream builds a pbzz stream of blockSize blocks: stored raw where the
// data is incompressible, zlib-compressed where it is not.
func synthStream(t *testing.T, plain []byte, blockSize int) []byte {
	t.Helper()
	var out bytes.Buffer
	out.WriteString("pbzz")
	binary.Write(&out, binary.BigEndian, uint64(blockSize))
	for off := 0; off < len(plain); off += blockSize {
		chunk := plain[off:min(off+blockSize, len(plain))]
		var z bytes.Buffer
		zw := zlib.NewWriter(&z)
		zw.Write(chunk)
		zw.Close()
		payload := z.Bytes()
		if len(payload) >= len(chunk) {
			payload = chunk
		}
		binary.Write(&out, binary.BigEndian, uint64(len(chunk)))
		binary.Write(&out, binary.BigEndian, uint64(len(payload)))
		out.Write(payload)
	}
	return out.Bytes()
}

func TestRawBlocksReadInPlace(t *testing.T) {
	const blockSize = 64 << 10
	plain := make([]byte, 40*blockSize+1234)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	// Two compressible blocks in the middle.
	clear(plain[10*blockSize : 12*blockSize])
	stream := synthStream(t, plain, blockSize)

	for _, prefetch := range []int{0, 8} {
		src := &countingReaderAt{r: bytes.NewReader(stream)}
		r, err := NewReader(src, int64(len(stream)))
		if err != nil {
			t.Fatal(err)
		}
		r.SetPrefetch(prefetch)
		if _, err := r.Size(); err != nil {
			t.Fatal(err)
		}
		indexCost := src.bytes

		// A small read from a raw block costs only its own bytes.
		got := make([]byte, 100)
		off := int64(30*blockSize + 77)
		if _, err := r.ReadAt(got, off); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, plain[off:off+100]) {
			t.Fatal("raw read returned the wrong bytes")
		}
		if cost := src.bytes - indexCost; cost != 100 {
			t.Errorf("prefetch=%d: 100-byte read of a raw block pulled %d bytes", prefetch, cost)
		}

		// Reads spanning raw and compressed blocks stay correct.
		for _, span := range [][2]int64{
			{9*blockSize + 10, 3 * blockSize},
			{0, int64(len(plain))},
			{int64(len(plain)) - 2000, 2000},
		} {
			buf := make([]byte, span[1])
			if _, err := r.ReadAt(buf, span[0]); err != nil {
				t.Fatalf("ReadAt(%d, %d): %v", span[0], span[1], err)
			}
			if !bytes.Equal(buf, plain[span[0]:span[0]+span[1]]) {
				t.Fatalf("ReadAt(%d, %d) returned the wrong bytes", span[0], span[1])
			}
		}
		// Past the compressed blocks the raw-stride guess is wrong, so a read
		// at the guessed position of header 13 can only come from speculation
		// (the real header 13 sits earlier).
		stride := int64(16 + blockSize)
		if speculated := src.offs[12+13*stride]; speculated != (prefetch > 0) {
			t.Errorf("prefetch=%d: speculative read at the raw-stride guess = %v", prefetch, speculated)
		}
	}
}

// hintedReader marks chosen offsets as expensive, as an AEA reader does for
// headers inside compressed segments.
type hintedReader struct {
	*countingReaderAt
	expensive map[int64]bool
}

func (h *hintedReader) Expensive(off int64, n int) bool { return h.expensive[off] }

// trueHeaders walks a stream the slow way and returns its header offsets.
func trueHeaders(t *testing.T, stream []byte) []int64 {
	t.Helper()
	var offs []int64
	for pos := int64(12); pos < int64(len(stream)); {
		offs = append(offs, pos)
		pos += 16 + int64(binary.BigEndian.Uint64(stream[pos+8:]))
	}
	return offs
}

func TestInferredHeaders(t *testing.T) {
	const blockSize = 64 << 10
	plain := make([]byte, 30*blockSize-5000) // 29 full blocks + a short one
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	for _, b := range []int{10, 11, 20} { // compressible blocks
		clear(plain[b*blockSize : (b+1)*blockSize])
	}
	stream := synthStream(t, plain, blockSize)
	headers := trueHeaders(t, stream)
	if len(headers) != 30 {
		t.Fatalf("fixture has %d blocks", len(headers))
	}
	// Expensive: a run of raw headers (3-5), a compressed block's header (10,
	// must be read), raw blocks after compressed ones (12, 21), and the short
	// final block (29, must be read).
	expensive := map[int64]bool{}
	for _, b := range []int{3, 4, 5, 10, 12, 21, 29} {
		expensive[headers[b]] = true
	}
	mustRead := map[int64]bool{headers[10]: true, headers[29]: true}

	src := &hintedReader{countingReaderAt: &countingReaderAt{r: bytes.NewReader(stream)}, expensive: expensive}
	r, err := NewReader(src, int64(len(stream)))
	if err != nil {
		t.Fatal(err)
	}
	r.SetPrefetch(8)
	blocks, err := r.Blocks()
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != len(headers) {
		t.Fatalf("indexed %d blocks, want %d", len(blocks), len(headers))
	}
	inferred := 0
	for i, b := range blocks {
		if b.OuterOffset != headers[i] {
			t.Fatalf("block %d at %d, want %d", i, b.OuterOffset, headers[i])
		}
		if b.Inferred {
			inferred++
			if !expensive[b.OuterOffset] {
				t.Errorf("block %d inferred although its header was cheap", i)
			}
		}
	}
	if inferred != 5 {
		t.Errorf("inferred %d headers, want 5 (blocks 3, 4, 5, 12 and 21)", inferred)
	}
	for off := range expensive {
		if src.offs[off] != mustRead[off] {
			t.Errorf("header at %d read=%v, want %v", off, src.offs[off], mustRead[off])
		}
	}
	got := make([]byte, len(plain))
	if _, err := r.ReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("plaintext differs after an inferred index")
	}
	// The inferred index survives a cache round trip.
	r2, _ := NewReader(bytes.NewReader(stream), int64(len(stream)))
	if !r2.Import(r.Export()) {
		t.Fatal("Import rejected an inferred index")
	}
	if b2, _ := r2.Blocks(); len(b2) != len(blocks) {
		t.Fatalf("reimported index has %d blocks", len(b2))
	}
}

// TestCompressedPrefixDecode checks that reading the start of a compressed
// block decodes (and fetches) only a prefix of it, and that later reads extend
// the same decode.
func TestCompressedPrefixDecode(t *testing.T) {
	const blockSize = 4 << 20
	plain := make([]byte, blockSize)
	// Compressible but not trivially: random words from a small alphabet.
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	for i := range plain {
		plain[i] = 'a' + plain[i]%16
	}
	stream := synthStream(t, plain, blockSize)
	if comp := binary.BigEndian.Uint64(stream[12+8:]); comp >= blockSize {
		t.Fatalf("fixture block is not compressed (%d bytes)", comp)
	}
	src := &countingReaderAt{r: bytes.NewReader(stream)}
	r, err := NewReader(src, int64(len(stream)))
	if err != nil {
		t.Fatal(err)
	}
	head := make([]byte, 100)
	if _, err := r.ReadAt(head, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(head, plain[:100]) {
		t.Fatal("prefix read returned the wrong bytes")
	}
	compSize := int64(len(stream) - 28)
	if src.bytes > compSize/2 {
		t.Errorf("reading 100 bytes pulled %d of %d compressed bytes", src.bytes, compSize)
	}
	tail := make([]byte, 1000)
	if _, err := r.ReadAt(tail, blockSize-1000); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tail, plain[blockSize-1000:]) {
		t.Fatal("tail read returned the wrong bytes")
	}
	mid := make([]byte, 5000)
	if _, err := r.ReadAt(mid, 1<<20); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mid, plain[1<<20:1<<20+5000]) {
		t.Fatal("middle read returned the wrong bytes")
	}
}

// TestInferredRunEndingInCompressedBlock covers runs of expensive raw headers
// that end at a compressed block or at the short final block: one probe of the
// last header confirms the run, the others are never read.
func TestInferredRunEndingInCompressedBlock(t *testing.T) {
	const blockSize = 64 << 10
	plain := make([]byte, 20*blockSize-7000)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	clear(plain[8*blockSize : 9*blockSize]) // block 8 compresses
	stream := synthStream(t, plain, blockSize)
	headers := trueHeaders(t, stream)
	expensive := map[int64]bool{}
	for _, b := range []int{4, 5, 6, 7, 8, 16, 17, 18, 19} {
		expensive[headers[b]] = true
	}
	src := &hintedReader{countingReaderAt: &countingReaderAt{r: bytes.NewReader(stream)}, expensive: expensive}
	r, err := NewReader(src, int64(len(stream)))
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := r.Blocks()
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range blocks {
		if b.OuterOffset != headers[i] {
			t.Fatalf("block %d at %d, want %d", i, b.OuterOffset, headers[i])
		}
	}
	// Only the run ends (compressed block 8, final block 19) are read.
	for _, b := range []int{4, 5, 6, 7, 16, 17, 18} {
		if src.offs[headers[b]] {
			t.Errorf("expensive header %d was read", b)
		}
	}
	for _, b := range []int{8, 19} {
		if !src.offs[headers[b]] {
			t.Errorf("run end %d was not probed", b)
		}
	}
	got := make([]byte, len(plain))
	if _, err := r.ReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("plaintext differs")
	}
}
