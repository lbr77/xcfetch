package apfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// apfsPartitionType is GUID 7C3457EF-0000-11AA-AA11-00306543ECAC in GPT's
// mixed-endian encoding.
var apfsPartitionType = []byte{0xef, 0x57, 0x34, 0x7c, 0x00, 0x00, 0xaa, 0x11, 0xaa, 0x11, 0x00, 0x30, 0x65, 0x43, 0xec, 0xac}

// FindContainer locates the APFS container on a disk: either the disk itself or
// the first APFS partition of a GUID partition table. It returns the
// container's byte range.
func FindContainer(r io.ReaderAt, size int64) (off, length int64, err error) {
	head := make([]byte, 4096)
	if _, err := readFullAt(r, head, 0); err != nil {
		return 0, 0, fmt.Errorf("apfs: reading disk header: %w", err)
	}
	if string(head[32:36]) == "NXSB" {
		return 0, size, nil
	}
	for _, sector := range []int64{512, 4096} {
		hdr := make([]byte, 92)
		if _, err := readFullAt(r, hdr, sector); err != nil {
			continue
		}
		if string(hdr[:8]) != "EFI PART" {
			continue
		}
		le := binary.LittleEndian
		entriesLBA := int64(le.Uint64(hdr[72:]))
		count := int64(le.Uint32(hdr[80:]))
		entrySize := int64(le.Uint32(hdr[84:]))
		if count <= 0 || count > 1024 || entrySize < 56 || entrySize > 4096 {
			return 0, 0, fmt.Errorf("apfs: implausible GPT (%d entries of %d bytes)", count, entrySize)
		}
		table := make([]byte, count*entrySize)
		if _, err := readFullAt(r, table, entriesLBA*sector); err != nil {
			return 0, 0, fmt.Errorf("apfs: reading GPT entries: %w", err)
		}
		for i := int64(0); i < count; i++ {
			e := table[i*entrySize:]
			if !bytes.Equal(e[:16], apfsPartitionType) {
				continue
			}
			first, last := int64(le.Uint64(e[32:])), int64(le.Uint64(e[40:]))
			if first <= 0 || last < first || (last+1)*sector > size {
				return 0, 0, fmt.Errorf("apfs: APFS partition %d has implausible bounds %d-%d", i, first, last)
			}
			return first * sector, (last - first + 1) * sector, nil
		}
		return 0, 0, errors.New("apfs: GUID partition table has no APFS partition")
	}
	return 0, 0, ErrNotAPFS
}

// OpenDisk finds the container on a disk and opens it.
func OpenDisk(r io.ReaderAt, size int64) (*Container, error) {
	off, length, err := FindContainer(r, size)
	if err != nil {
		return nil, err
	}
	return Open(io.NewSectionReader(r, off, length), length)
}
