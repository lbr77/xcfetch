package aa

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"

	"github.com/go-compressions/lzfse"
	"github.com/pierrec/lz4/v4"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

// Apple wraps archives in a "pbz*" stream: a 12 byte header (magic + big
// endian block size) followed by blocks of
//
//	uint64 BE uncompressed size | uint64 BE compressed size | payload
//
// where a block is stored verbatim when both sizes are equal. The algorithm
// letter is the fourth magic byte: e=lzfse, x=lzma, z=zlib, 4=lz4, b=lzbitmap.
// A raw archive has no wrapper at all and starts straight with "AA01".
const (
	streamHeaderSize = 12
	blockHeaderSize  = 16
	maxBlockSize     = 1 << 30
)

var errUnsupportedCompression = errors.New("aa: unsupported stream compression")

// sniff returns the first bytes of r without consuming them.
func sniff(br *bufio.Reader) ([]byte, error) {
	if _, err := br.Peek(4); err != nil {
		return nil, err
	}
	return br.Peek(4)
}

// ArchiveReader returns an io.Reader yielding the raw (uncompressed) archive,
// transparently unwrapping the pbz* stream when present.
func ArchiveReader(r io.Reader) (io.Reader, error) {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReaderSize(r, 64<<10)
	}
	head, err := sniff(br)
	if err != nil {
		return nil, fmt.Errorf("aa: reading archive magic: %w", err)
	}
	if bytes.HasPrefix(head, []byte("AA01")) || bytes.HasPrefix(head, []byte("YAA1")) {
		return br, nil
	}
	if !bytes.HasPrefix(head, []byte("pbz")) {
		return nil, fmt.Errorf("aa: not an Apple Archive (magic %q)", head)
	}
	return newStreamReader(br)
}

type streamReader struct {
	br     *bufio.Reader
	algo   byte
	block  []byte // compressed block payload
	plain  []byte // decompressed block
	remain []byte // unconsumed decompressed bytes
	err    error
}

func newStreamReader(br *bufio.Reader) (io.Reader, error) {
	var hdr [streamHeaderSize]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, fmt.Errorf("aa: reading stream header: %w", err)
	}
	if !bytes.HasPrefix(hdr[:], []byte("pbz")) {
		return nil, fmt.Errorf("aa: bad stream magic %q", hdr[:4])
	}
	blockSize := beUint64(hdr[4:12])
	if blockSize == 0 || blockSize > maxBlockSize {
		return nil, fmt.Errorf("aa: implausible stream block size %d", blockSize)
	}
	return &streamReader{br: br, algo: hdr[3]}, nil
}

// Read implements io.Reader over the decompressed stream.
func (s *streamReader) Read(p []byte) (int, error) {
	for len(s.remain) == 0 {
		if s.err != nil {
			return 0, s.err
		}
		if err := s.nextBlock(); err != nil {
			s.err = err
			if err == io.EOF {
				return 0, io.EOF
			}
			return 0, err
		}
	}
	n := copy(p, s.remain)
	s.remain = s.remain[n:]
	return n, nil
}

func (s *streamReader) nextBlock() error {
	var hdr [blockHeaderSize]byte
	if _, err := io.ReadFull(s.br, hdr[:]); err != nil {
		if err == io.EOF {
			return io.EOF
		}
		return fmt.Errorf("aa: reading block header: %w", err)
	}
	plainSize := beUint64(hdr[0:8])
	compSize := beUint64(hdr[8:16])
	if plainSize > maxBlockSize || compSize > maxBlockSize {
		return fmt.Errorf("aa: implausible block sizes (%d/%d)", plainSize, compSize)
	}
	if compSize > plainSize {
		return fmt.Errorf("aa: compressed block larger than plaintext (%d > %d)", compSize, plainSize)
	}
	s.block = grow(s.block, int(compSize))
	if _, err := io.ReadFull(s.br, s.block); err != nil {
		return fmt.Errorf("aa: reading block payload: %w", err)
	}
	if compSize == plainSize {
		s.remain = s.block
		return nil
	}
	out, err := s.inflate(int(plainSize))
	if err != nil {
		return err
	}
	s.plain = out
	s.remain = out
	return nil
}

func (s *streamReader) inflate(plainSize int) ([]byte, error) {
	switch s.algo {
	case 'e': // LZFSE / LZVN block stream
		out, err := lzfse.DecompressLimit(s.block, plainSize)
		if err != nil {
			return nil, fmt.Errorf("aa: lzfse: %w", err)
		}
		return out, nil
	case 'x': // LZMA alone or XZ, depending on what Apple wrote
		lr, err := lzmaReader(s.block)
		if err != nil {
			return nil, err
		}
		out := make([]byte, plainSize)
		if _, err := io.ReadFull(lr, out); err != nil {
			return nil, fmt.Errorf("aa: lzma: %w", err)
		}
		return out, nil
	case 'z': // zlib
		zr, err := zlib.NewReader(bytes.NewReader(s.block))
		if err != nil {
			return nil, fmt.Errorf("aa: zlib: %w", err)
		}
		defer zr.Close()
		out := make([]byte, plainSize)
		if _, err := io.ReadFull(zr, out); err != nil {
			return nil, fmt.Errorf("aa: zlib: %w", err)
		}
		return out, nil
	case '4': // raw lz4 block
		out := make([]byte, plainSize)
		n, err := lz4.UncompressBlock(s.block, out)
		if err != nil {
			return nil, fmt.Errorf("aa: lz4: %w", err)
		}
		return out[:n], nil
	case 'b':
		return nil, fmt.Errorf("%w: lzbitmap", errUnsupportedCompression)
	default:
		return nil, fmt.Errorf("%w: %q", errUnsupportedCompression, s.algo)
	}
}

// lzmaReader returns a reader for an LZMA-alone or an XZ stream. Apple uses
// both: `compression_tool` emits LZMA-alone, current MobileAsset payloads use
// the XZ container (magic FD 37 7A 58 5A 00).
func lzmaReader(b []byte) (io.Reader, error) {
	if bytes.HasPrefix(b, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}) {
		r, err := xz.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("aa: xz: %w", err)
		}
		return r, nil
	}
	r, err := lzma.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("aa: lzma: %w", err)
	}
	return r, nil
}

func beUint64(b []byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}

func grow(b []byte, n int) []byte {
	if cap(b) >= n {
		return b[:n]
	}
	return make([]byte, n)
}
