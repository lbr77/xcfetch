// Package udif reads Apple UDIF disk images (.dmg) as a random-access disk.
//
// A UDIF image is a data fork of independently compressed chunks followed by a
// "koly" trailer. The trailer points at an XML property list whose "blkx"
// entries each describe one partition as a run table ("mish" block): every run
// maps a range of logical 512-byte sectors to a compressed byte range of the
// data fork. That table is all that is needed to translate any logical offset
// into one chunk read and one decompression, so an image can be read in place
// (or over HTTP ranges) without ever being converted to a raw disk.
package udif

import (
	"bytes"
	"compress/bzip2"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/go-compressions/lzfse"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
	"howett.net/plist"
)

// SectorSize is the logical sector size UDIF run tables are expressed in.
const SectorSize = 512

const (
	trailerSize = 512
	// maxPlistSize bounds the XML block map read into memory.
	maxPlistSize = 256 << 20
	// maxRunBytes bounds one decoded run; real images use 1 MiB or smaller.
	maxRunBytes = 64 << 20
	// defaultCacheBytes bounds the decoded-run cache.
	defaultCacheBytes = 64 << 20
)

// Run types from the mish block.
const (
	runZeroFill   uint32 = 0x00000000
	runRaw        uint32 = 0x00000001
	runIgnore     uint32 = 0x00000002
	runADC        uint32 = 0x80000004
	runZlib       uint32 = 0x80000005
	runBzip2      uint32 = 0x80000006
	runLZFSE      uint32 = 0x80000007
	runLZMA       uint32 = 0x80000008
	runComment    uint32 = 0x7ffffffe
	runTerminator uint32 = 0xffffffff
)

// ErrNotUDIF is returned when the object does not end with a koly trailer.
var ErrNotUDIF = errors.New("udif: no koly trailer (not a UDIF disk image)")

// Partition is one blkx entry: a named range of the logical disk.
type Partition struct {
	Name   string
	Offset int64 // logical byte offset
	Length int64 // logical bytes
}

// Stats counts what reads cost at the image layer.
type Stats struct {
	RunsDecoded int64 // compressed runs decompressed
	BytesIn     int64 // compressed bytes read from the data fork
}

// run maps a logical byte range to a data fork range.
type run struct {
	kind   uint32
	lstart int64
	llen   int64
	pstart int64
	plen   int64
}

// Image is a random-access view of the logical disk inside a UDIF image.
type Image struct {
	src   io.ReaderAt
	size  int64
	runs  []run
	parts []Partition

	mu       sync.Mutex
	cache    map[int][]byte
	order    []int
	cached   int64
	maxCache int64
	stats    Stats
}

// IsUDIF reports whether the object of the given size ends with a koly trailer.
func IsUDIF(src io.ReaderAt, size int64) bool {
	if size < trailerSize {
		return false
	}
	magic := make([]byte, 4)
	if _, err := src.ReadAt(magic, size-trailerSize); err != nil && err != io.EOF {
		return false
	}
	return string(magic) == "koly"
}

// Open parses the trailer and the block map. Nothing else is read until the
// image is accessed.
func Open(src io.ReaderAt, size int64) (*Image, error) {
	if size < trailerSize {
		return nil, ErrNotUDIF
	}
	tr := make([]byte, trailerSize)
	if _, err := readFullAt(src, tr, size-trailerSize); err != nil {
		return nil, fmt.Errorf("udif: reading trailer: %w", err)
	}
	if string(tr[:4]) != "koly" {
		return nil, ErrNotUDIF
	}
	be := binary.BigEndian
	dataForkOffset := int64(be.Uint64(tr[24:]))
	xmlOffset := int64(be.Uint64(tr[216:]))
	xmlLength := int64(be.Uint64(tr[224:]))
	sectorCount := int64(be.Uint64(tr[492:]))
	if xmlLength <= 0 {
		return nil, errors.New("udif: image has no XML block map (resource-fork-only images are not supported)")
	}
	if xmlLength > maxPlistSize || xmlOffset < 0 || xmlOffset+xmlLength > size {
		return nil, fmt.Errorf("udif: implausible block map at %d (+%d)", xmlOffset, xmlLength)
	}
	xmlData := make([]byte, xmlLength)
	if _, err := readFullAt(src, xmlData, xmlOffset); err != nil {
		return nil, fmt.Errorf("udif: reading block map: %w", err)
	}
	var doc struct {
		ResourceFork struct {
			Blkx []struct {
				Name   string `plist:"Name"`
				CFName string `plist:"CFName"`
				Data   []byte `plist:"Data"`
			} `plist:"blkx"`
		} `plist:"resource-fork"`
	}
	if _, err := plist.Unmarshal(xmlData, &doc); err != nil {
		return nil, fmt.Errorf("udif: decoding block map: %w", err)
	}
	if len(doc.ResourceFork.Blkx) == 0 {
		return nil, errors.New("udif: block map has no blkx entries")
	}

	im := &Image{
		src:      src,
		size:     sectorCount * SectorSize,
		cache:    make(map[int][]byte),
		maxCache: defaultCacheBytes,
	}
	for i, b := range doc.ResourceFork.Blkx {
		name := b.Name
		if name == "" {
			name = b.CFName
		}
		part, runs, err := parseMish(b.Data, dataForkOffset, size)
		if err != nil {
			return nil, fmt.Errorf("udif: blkx %d (%s): %w", i, name, err)
		}
		part.Name = name
		im.parts = append(im.parts, part)
		im.runs = append(im.runs, runs...)
	}
	sort.Slice(im.runs, func(i, j int) bool { return im.runs[i].lstart < im.runs[j].lstart })
	for i := 1; i < len(im.runs); i++ {
		prev := im.runs[i-1]
		if im.runs[i].lstart < prev.lstart+prev.llen {
			return nil, fmt.Errorf("udif: runs overlap at logical offset %d", im.runs[i].lstart)
		}
	}
	if n := len(im.runs); n > 0 {
		if end := im.runs[n-1].lstart + im.runs[n-1].llen; end > im.size {
			im.size = end
		}
	}
	return im, nil
}

// parseMish decodes one blkx run table.
func parseMish(b []byte, dataForkOffset, fileSize int64) (Partition, []run, error) {
	const headerLen, chunkLen = 204, 40
	if len(b) < headerLen || string(b[:4]) != "mish" {
		return Partition{}, nil, errors.New("not a mish block")
	}
	be := binary.BigEndian
	firstSector := int64(be.Uint64(b[8:]))
	sectorCount := int64(be.Uint64(b[16:]))
	dataOffset := int64(be.Uint64(b[24:]))
	n := int(be.Uint32(b[200:]))
	if n < 0 || headerLen+n*chunkLen > len(b) {
		return Partition{}, nil, fmt.Errorf("%d chunks do not fit in %d bytes", n, len(b))
	}
	part := Partition{Offset: firstSector * SectorSize, Length: sectorCount * SectorSize}
	runs := make([]run, 0, n)
	for i := 0; i < n; i++ {
		c := b[headerLen+i*chunkLen:]
		kind := be.Uint32(c[0:])
		if kind == runTerminator {
			break
		}
		if kind == runComment {
			continue
		}
		r := run{
			kind:   kind,
			lstart: (firstSector + int64(be.Uint64(c[8:]))) * SectorSize,
			llen:   int64(be.Uint64(c[16:])) * SectorSize,
			pstart: dataForkOffset + dataOffset + int64(be.Uint64(c[24:])),
			plen:   int64(be.Uint64(c[32:])),
		}
		if r.llen == 0 {
			continue
		}
		if r.llen < 0 {
			return Partition{}, nil, fmt.Errorf("run %d: negative length", i)
		}
		// Only compressed runs are buffered whole; zero and raw runs can be
		// arbitrarily long.
		if r.kind != runZeroFill && r.kind != runIgnore && r.kind != runRaw && r.llen > maxRunBytes {
			return Partition{}, nil, fmt.Errorf("run %d: implausible length %d", i, r.llen)
		}
		if r.kind != runZeroFill && r.kind != runIgnore {
			if r.plen < 0 || r.pstart < 0 || r.pstart+r.plen > fileSize {
				return Partition{}, nil, fmt.Errorf("run %d: data %d+%d outside the image", i, r.pstart, r.plen)
			}
		}
		runs = append(runs, r)
	}
	return part, runs, nil
}

// Size is the logical disk size in bytes.
func (im *Image) Size() int64 { return im.size }

// Partitions lists the blkx entries in table order.
func (im *Image) Partitions() []Partition {
	out := make([]Partition, len(im.parts))
	copy(out, im.parts)
	return out
}

// RunCount is the number of data runs in the image.
func (im *Image) RunCount() int { return len(im.runs) }

// Stats reports decode activity so far.
func (im *Image) Stats() Stats {
	im.mu.Lock()
	defer im.mu.Unlock()
	return im.stats
}

// ReadAt implements io.ReaderAt over the logical disk. Sectors no run covers
// read as zeros.
func (im *Image) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("udif: negative offset %d", off)
	}
	if off >= im.size {
		return 0, io.EOF
	}
	var short bool
	if int64(len(p)) > im.size-off {
		p = p[:im.size-off]
		short = true
	}
	done := 0
	for done < len(p) {
		pos := off + int64(done)
		// Last run starting at or before pos.
		i := sort.Search(len(im.runs), func(i int) bool { return im.runs[i].lstart > pos }) - 1
		if i < 0 || pos >= im.runs[i].lstart+im.runs[i].llen {
			// A gap: zeros up to the next run.
			next := im.size
			if i+1 < len(im.runs) {
				next = im.runs[i+1].lstart
			}
			n := int(min(int64(len(p)-done), next-pos))
			clear(p[done : done+n])
			done += n
			continue
		}
		r := im.runs[i]
		within := pos - r.lstart
		n := int(min(int64(len(p)-done), r.llen-within))
		dst := p[done : done+n]
		switch r.kind {
		case runZeroFill, runIgnore:
			clear(dst)
		case runRaw:
			if within+int64(n) > r.plen {
				return done, fmt.Errorf("udif: raw run at %d is shorter than its sectors", r.lstart)
			}
			if _, err := readFullAt(im.src, dst, r.pstart+within); err != nil {
				return done, fmt.Errorf("udif: raw run at %d: %w", r.lstart, err)
			}
		default:
			data, err := im.decoded(i)
			if err != nil {
				return done, err
			}
			copy(dst, data[within:])
		}
		done += n
	}
	if short {
		return done, io.EOF
	}
	return done, nil
}

// decoded returns the decompressed contents of run i, from cache if possible.
func (im *Image) decoded(i int) ([]byte, error) {
	im.mu.Lock()
	if data, ok := im.cache[i]; ok {
		im.mu.Unlock()
		return data, nil
	}
	im.mu.Unlock()

	r := im.runs[i]
	comp := make([]byte, r.plen)
	if _, err := readFullAt(im.src, comp, r.pstart); err != nil {
		return nil, fmt.Errorf("udif: run at logical %d: reading %d bytes at %d: %w", r.lstart, r.plen, r.pstart, err)
	}
	data, err := decodeRun(r.kind, comp, int(r.llen))
	if err != nil {
		return nil, fmt.Errorf("udif: run at logical %d: %w", r.lstart, err)
	}
	if int64(len(data)) < r.llen {
		// Short output: the tail of the run reads as zeros.
		full := make([]byte, r.llen)
		copy(full, data)
		data = full
	}

	im.mu.Lock()
	defer im.mu.Unlock()
	im.stats.RunsDecoded++
	im.stats.BytesIn += r.plen
	if prev, ok := im.cache[i]; ok {
		return prev, nil
	}
	im.cache[i] = data
	im.order = append(im.order, i)
	im.cached += int64(len(data))
	for im.cached > im.maxCache && len(im.order) > 1 {
		oldest := im.order[0]
		im.order = im.order[1:]
		im.cached -= int64(len(im.cache[oldest]))
		delete(im.cache, oldest)
	}
	return data, nil
}

// decodeRun expands one compressed run.
func decodeRun(kind uint32, comp []byte, size int) ([]byte, error) {
	switch kind {
	case runLZFSE:
		out, err := lzfse.DecompressLimit(comp, size)
		if err != nil {
			return nil, fmt.Errorf("lzfse: %w", err)
		}
		return out, nil
	case runZlib:
		zr, err := zlib.NewReader(bytes.NewReader(comp))
		if err != nil {
			return nil, fmt.Errorf("zlib: %w", err)
		}
		defer zr.Close()
		return readUpTo(zr, size, "zlib")
	case runBzip2:
		return readUpTo(bzip2.NewReader(bytes.NewReader(comp)), size, "bzip2")
	case runLZMA:
		if bytes.HasPrefix(comp, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}) {
			xr, err := xz.NewReader(bytes.NewReader(comp))
			if err != nil {
				return nil, fmt.Errorf("xz: %w", err)
			}
			return readUpTo(xr, size, "xz")
		}
		lr, err := lzma.NewReader(bytes.NewReader(comp))
		if err != nil {
			return nil, fmt.Errorf("lzma: %w", err)
		}
		return readUpTo(lr, size, "lzma")
	case runADC:
		return decodeADC(comp, size)
	}
	return nil, fmt.Errorf("unsupported run type %#08x", kind)
}

func readUpTo(r io.Reader, size int, name string) ([]byte, error) {
	out := make([]byte, size)
	n, err := io.ReadFull(r, out)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return out[:n], nil
}

// decodeADC expands Apple Data Compression, the LZ77 variant of old UDCO
// images: a literal run (high bit set), a 2-byte match (bit 6 set) or a 3-byte
// match.
func decodeADC(in []byte, size int) ([]byte, error) {
	out := make([]byte, 0, size)
	for i := 0; i < len(in) && len(out) < size; {
		c := in[i]
		var length, dist int
		switch {
		case c&0x80 != 0:
			length = int(c&0x7f) + 1
			if i+1+length > len(in) {
				return nil, errors.New("adc: literal overruns input")
			}
			out = append(out, in[i+1:i+1+length]...)
			i += 1 + length
			continue
		case c&0x40 != 0:
			if i+3 > len(in) {
				return nil, errors.New("adc: truncated match")
			}
			length = int(c&0x3f) + 4
			dist = int(in[i+1])<<8 | int(in[i+2])
			i += 3
		default:
			if i+2 > len(in) {
				return nil, errors.New("adc: truncated match")
			}
			length = int(c>>2) + 3
			dist = (int(c&3)<<8 | int(in[i+1]))
			i += 2
		}
		start := len(out) - dist - 1
		if start < 0 {
			return nil, errors.New("adc: match before start of output")
		}
		for k := 0; k < length; k++ {
			out = append(out, out[start+k])
		}
	}
	if len(out) > size {
		out = out[:size]
	}
	return out, nil
}

func readFullAt(r io.ReaderAt, buf []byte, off int64) (int, error) {
	n, err := r.ReadAt(buf, off)
	if n == len(buf) {
		return n, nil
	}
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}
