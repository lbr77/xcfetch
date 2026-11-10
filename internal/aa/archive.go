package aa

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
)

// An Apple Archive is a flat sequence of items. Each item is a header plus the
// concatenated blobs its header declares:
//
//	"AA01" | uint16 LE header size | field records | blob bytes
//
// A field record is a 4 byte key (three ASCII bytes plus a one byte type
// selector) followed by its value. Selectors: '*' flag, '1'/'2'/'4'/'8' uints,
// 'P' length-prefixed string, 'S'/'T' timespecs, 'F'..'J' hashes and
// 'A'/'B'/'C' blob sizes (u16/u32/u64 byte counts). Blob payloads are not part
// of the header; they follow it in field order and their exact byte counts are
// the values of the 'A'/'B'/'C' fields, which is why a file's data length can be
// known before any bytes are read.
const (
	itemMagicSize  = 4
	itemHeaderSize = 6 // magic + uint16 size
	maxHeaderSize  = 1 << 16
)

// entry type selectors.
const (
	typeBlockSpecial     = 'B'
	typeCharacterSpecial = 'C'
	typeDirectory        = 'D'
	typeRegularFile      = 'F'
	typeSymbolicLink     = 'L'
	typeMetadata         = 'M'
	typeFifo             = 'P'
	typeSocket           = 'S'
)

var errNotArchive = errors.New("aa: not an Apple Archive")

// item is the parsed header of one archive entry.
type item struct {
	typ       byte
	path      string
	link      string
	mode      fs.FileMode
	hasMode   bool
	blobs     []blobField // in field order
	blobBytes int64       // sum of blob sizes
}

// blobField is a header field whose payload lives after the header.
type blobField struct {
	key  string
	size int64
}

// parseItem decodes one item header from buf (which holds exactly the header).
func parseItem(buf []byte) (item, error) {
	if len(buf) < itemHeaderSize {
		return item{}, fmt.Errorf("aa: short item header (%d bytes)", len(buf))
	}
	switch string(buf[:4]) {
	case "AA01", "YAA1":
	default:
		return item{}, fmt.Errorf("%w: magic %q", errNotArchive, buf[:4])
	}
	it := item{}
	pos := itemHeaderSize
	for pos < len(buf) {
		if len(buf)-pos < 4 {
			return item{}, fmt.Errorf("aa: truncated field key at offset %d", pos)
		}
		key := string(buf[pos : pos+3])
		sub := buf[pos+3]
		pos += 4
		switch sub {
		case '*':
			// flag: no value
		case '1', '2', '4', '8':
			width := int(sub - '0')
			val, next, err := readUint(buf, pos, width)
			if err != nil {
				return item{}, fieldErr(key, err)
			}
			pos = next
			switch key {
			case "TYP":
				it.typ = byte(val)
			case "MOD":
				it.mode = fs.FileMode(val)
				it.hasMode = true
			}
		case 'A', 'B', 'C':
			width := map[byte]int{'A': 2, 'B': 4, 'C': 8}[sub]
			val, next, err := readUint(buf, pos, width)
			if err != nil {
				return item{}, fieldErr(key, err)
			}
			pos = next
			it.blobs = append(it.blobs, blobField{key: key, size: int64(val)})
			it.blobBytes += int64(val)
		case 'P':
			if len(buf)-pos < 2 {
				return item{}, fmt.Errorf("aa: truncated string length for %s", key)
			}
			n := int(binary.LittleEndian.Uint16(buf[pos:]))
			pos += 2
			if len(buf)-pos < n {
				return item{}, fmt.Errorf("aa: truncated string value for %s", key)
			}
			val := string(buf[pos : pos+n])
			pos += n
			switch key {
			case "PAT":
				it.path = val
			case "LNK":
				it.link = val
			}
		case 'S', 'T':
			width := 8
			if sub == 'T' {
				width = 12
			}
			if len(buf)-pos < width {
				return item{}, fmt.Errorf("aa: truncated %s field", key)
			}
			pos += width
		case 'F', 'G', 'H', 'I', 'J':
			width := map[byte]int{'F': 4, 'G': 20, 'H': 32, 'I': 48, 'J': 64}[sub]
			if len(buf)-pos < width {
				return item{}, fmt.Errorf("aa: truncated %s field", key)
			}
			pos += width
		default:
			return item{}, fmt.Errorf("aa: unknown field selector %q for %s", sub, key)
		}
	}
	return it, nil
}

func fieldErr(key string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("aa: field %s: %w", key, err)
}

func readUint(buf []byte, pos, width int) (uint64, int, error) {
	if len(buf)-pos < width {
		return 0, pos, errors.New("truncated numeric value")
	}
	var v uint64
	for i := 0; i < width; i++ {
		v |= uint64(buf[pos+i]) << (8 * i)
	}
	return v, pos + width, nil
}

// readHeader reads the next item header from r, returning io.EOF at the end of
// the archive.
func readHeader(r io.Reader) (item, error) {
	var fixed [itemHeaderSize]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		if err == io.EOF {
			return item{}, io.EOF
		}
		if err == io.ErrUnexpectedEOF {
			// Trailing padding is tolerated by Apple's tools.
			return item{}, io.EOF
		}
		return item{}, err
	}
	magic := string(fixed[:4])
	if magic != "AA01" && magic != "YAA1" {
		return item{}, fmt.Errorf("%w: item magic %q", errNotArchive, magic)
	}
	size := int(binary.LittleEndian.Uint16(fixed[4:]))
	if size < itemHeaderSize || size > maxHeaderSize {
		return item{}, fmt.Errorf("aa: implausible item header size %d", size)
	}
	buf := make([]byte, size)
	copy(buf, fixed[:])
	if _, err := io.ReadFull(r, buf[itemHeaderSize:]); err != nil {
		return item{}, fmt.Errorf("aa: reading item header: %w", err)
	}
	return parseItem(buf)
}
