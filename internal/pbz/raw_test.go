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
