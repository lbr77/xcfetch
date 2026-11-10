package aea

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/go-compressions/lzfse"
	"github.com/pierrec/lz4/v4"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

// decompress expands one segment payload using the compression algorithm
// recorded in the root header. origSize is the announced size of the plaintext
// and is used both as the output size and to bound the decompressor.
func (d *decryptor) decompress(src []byte, origSize int, cluster uint32, seg int) ([]byte, error) {
	fail := func(err error) ([]byte, error) {
		return nil, fmt.Errorf("aea: cluster %d segment %d: decompressing (%q): %w",
			cluster, seg, string(d.root.compression), err)
	}
	switch d.root.compression {
	case 'e': // LZFSE
		out, err := lzfse.DecompressLimit(src, origSize)
		if err != nil {
			return fail(err)
		}
		if len(out) != origSize {
			return fail(fmt.Errorf("expected %d bytes, got %d", origSize, len(out)))
		}
		return out, nil
	case 'z': // ZLIB
		out := grow(nil, origSize)
		if err := inflateZlib(src, out); err != nil {
			return fail(err)
		}
		return out, nil
	case 'x': // LZMA
		out := grow(nil, origSize)
		if err := inflateLZMA(src, out); err != nil {
			return fail(err)
		}
		return out, nil
	case '4': // LZ4 raw block
		out := grow(nil, origSize)
		n, err := lz4.UncompressBlock(src, out)
		if err != nil {
			return fail(err)
		}
		if n != origSize {
			return fail(fmt.Errorf("expected %d bytes, got %d", origSize, n))
		}
		return out, nil
	}
	// '-' is handled by the caller (compressed size equals original size).
	return fail(fmt.Errorf("unsupported compression id"))
}

// inflateZlib inflates a zlib stream into dst, which must be exactly the size
// of the uncompressed data.
func inflateZlib(src, dst []byte) error {
	zr, err := zlib.NewReader(bytes.NewReader(src))
	if err != nil {
		return err
	}
	if _, err := io.ReadFull(zr, dst); err != nil {
		zr.Close()
		return err
	}
	// A trailing byte means the segment declares a size that is too small.
	var extra [1]byte
	if n, _ := zr.Read(extra[:]); n != 0 {
		zr.Close()
		return fmt.Errorf("decompressed data exceeds %d bytes", len(dst))
	}
	return zr.Close()
}

// inflateLZMA inflates an LZMA stream into dst. Apple and the reference
// implementations emit the .xz container; a bare LZMA stream is accepted too.
func inflateLZMA(src, dst []byte) error {
	var (
		rd  io.Reader
		err error
	)
	if bytes.HasPrefix(src, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}) {
		rd, err = xz.NewReader(bytes.NewReader(src))
	} else {
		rd, err = lzma.NewReader(bytes.NewReader(src))
	}
	if err != nil {
		return err
	}
	if _, err := io.ReadFull(rd, dst); err != nil {
		return err
	}
	var extra [1]byte
	if n, _ := rd.Read(extra[:]); n != 0 {
		return fmt.Errorf("decompressed data exceeds %d bytes", len(dst))
	}
	return nil
}

// verifyChecksum checks the segment checksum stored in the segment header
// against the plaintext.
func (d *decryptor) verifyChecksum(data, want []byte) error {
	switch d.root.checksum {
	case 0:
		return nil
	case 2:
		got := sha256.Sum256(data)
		if !bytes.Equal(got[:], want) {
			return fmt.Errorf("checksum mismatch (sha256)")
		}
	case 1:
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], murmur64a(data, 0xE2236FDC26A5F6D2))
		if !bytes.Equal(b[:], want) {
			return fmt.Errorf("checksum mismatch (murmur64)")
		}
	}
	return nil
}

// murmur64a implements MurmurHash64A with the AEA seed.
func murmur64a(data []byte, seed uint64) uint64 {
	const (
		m = 0xc6a4a7935bd1e995
		r = 47
	)
	h := seed ^ uint64(len(data))*m
	n := len(data) &^ 7
	for i := 0; i < n; i += 8 {
		k := binary.LittleEndian.Uint64(data[i:])
		k *= m
		k ^= k >> r
		k *= m
		h ^= k
		h *= m
	}
	tail := data[n:]
	switch len(tail) {
	case 7:
		h ^= uint64(tail[6]) << 48
		fallthrough
	case 6:
		h ^= uint64(tail[5]) << 40
		fallthrough
	case 5:
		h ^= uint64(tail[4]) << 32
		fallthrough
	case 4:
		h ^= uint64(tail[3]) << 24
		fallthrough
	case 3:
		h ^= uint64(tail[2]) << 16
		fallthrough
	case 2:
		h ^= uint64(tail[1]) << 8
		fallthrough
	case 1:
		h ^= uint64(tail[0])
		h *= m
	}
	h ^= h >> r
	h *= m
	h ^= h >> r
	return h
}
