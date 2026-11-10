// Package apfs is a read-only APFS reader built for random access: it reads
// only the blocks on the path to what it is asked for, so it can sit on top of
// a disk image that is itself fetched on demand.
//
// It covers what Apple's simulator runtime images need: checkpoint selection,
// object maps, file-system B-trees with hashed directory keys, sealed volumes
// (header-less hashed nodes and the separate file-extent tree), symlinks and
// per-extent data hashes. Encrypted volumes, snapshots and decmpfs-compressed
// files are rejected with explicit errors.
package apfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Object types and storage flags (obj_phys_t.o_type).
const (
	objTypeMask       = 0x0000ffff
	objStorageMask    = 0xc0000000
	objPhysical       = 0x40000000
	objTypeNXSB       = 0x00000001
	objTypeBtree      = 0x00000002
	objTypeBtreeNode  = 0x00000003
	objTypeOmap       = 0x0000000b
	objTypeFS         = 0x0000000d
	objTypeIntegrity  = 0x0000001e
	omapValDeleted    = 0x1
	omapValEncrypted  = 0x4
	maxCheckpointScan = 4096
	defaultBlockCache = 4096 // blocks
	nxMaxFileSystems  = 100
	nxFSOidOffset     = 184
)

// ErrNotAPFS is returned when no container superblock is found.
var ErrNotAPFS = errors.New("apfs: no container superblock (not an APFS container)")

// Container is an opened APFS container.
type Container struct {
	r          io.ReaderAt
	size       int64
	BlockSize  int64
	BlockCount uint64
	XID        uint64

	sb   []byte
	omap *omap

	mu     sync.Mutex
	blocks map[uint64][]byte
	order  []uint64
	reads  int64
}

// Open finds the newest valid checkpoint of the container in r.
func Open(r io.ReaderAt, size int64) (*Container, error) {
	head := make([]byte, 4096)
	if _, err := readFullAt(r, head, 0); err != nil {
		return nil, fmt.Errorf("apfs: reading block 0: %w", err)
	}
	if string(head[32:36]) != "NXSB" {
		return nil, ErrNotAPFS
	}
	bs := int64(le32(head[36:]))
	if bs < 4096 || bs > 65536 || bs&(bs-1) != 0 {
		return nil, fmt.Errorf("apfs: implausible block size %d", bs)
	}
	c := &Container{r: r, size: size, BlockSize: bs, blocks: make(map[uint64][]byte)}

	blk0, err := c.block(0)
	if err != nil {
		return nil, err
	}
	best := blk0
	if !verifyChecksum(blk0) {
		best = nil
	}
	// The checkpoint descriptor area holds every recent superblock; the valid
	// one with the highest transaction id is the current state. Block 0 is only
	// a copy written at some earlier point.
	descBlocks := le32(blk0[104:])
	descBase := le64(blk0[112:])
	if descBlocks&0x80000000 == 0 && descBlocks <= maxCheckpointScan {
		for i := uint64(0); i < uint64(descBlocks); i++ {
			b, err := c.block(descBase + i)
			if err != nil {
				return nil, err
			}
			if le32(b[24:])&objTypeMask != objTypeNXSB || string(b[32:36]) != "NXSB" || !verifyChecksum(b) {
				continue
			}
			if best == nil || le64(b[16:]) > le64(best[16:]) {
				best = b
			}
		}
	}
	if best == nil {
		return nil, errors.New("apfs: no container superblock with a valid checksum")
	}
	c.sb = best
	c.XID = le64(best[16:])
	c.BlockCount = le64(best[40:])
	if c.size > 0 && int64(c.BlockCount)*bs > c.size {
		return nil, fmt.Errorf("apfs: container claims %d blocks of %d bytes, but only %d bytes are present",
			c.BlockCount, bs, c.size)
	}
	if c.omap, err = c.openOmap(le64(best[160:])); err != nil {
		return nil, fmt.Errorf("apfs: container object map: %w", err)
	}
	return c, nil
}

// BlocksRead is the number of distinct metadata blocks fetched so far.
func (c *Container) BlocksRead() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

// block returns one block, cached.
func (c *Container) block(addr uint64) ([]byte, error) {
	if c.BlockCount > 0 && addr >= c.BlockCount {
		return nil, fmt.Errorf("apfs: block %#x beyond the container (%d blocks)", addr, c.BlockCount)
	}
	c.mu.Lock()
	if b, ok := c.blocks[addr]; ok {
		c.mu.Unlock()
		return b, nil
	}
	c.mu.Unlock()
	b := make([]byte, c.BlockSize)
	if _, err := readFullAt(c.r, b, int64(addr)*c.BlockSize); err != nil {
		return nil, fmt.Errorf("apfs: reading block %#x: %w", addr, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	c.blocks[addr] = b
	c.order = append(c.order, addr)
	for len(c.order) > defaultBlockCache {
		delete(c.blocks, c.order[0])
		c.order = c.order[1:]
	}
	return b, nil
}

// object reads a block that must carry a valid object header of type typ.
func (c *Container) object(addr uint64, typ uint32) ([]byte, error) {
	b, err := c.block(addr)
	if err != nil {
		return nil, err
	}
	if !verifyChecksum(b) {
		return nil, fmt.Errorf("apfs: object at block %#x fails its checksum", addr)
	}
	if got := le32(b[24:]) & objTypeMask; got != typ {
		return nil, fmt.Errorf("apfs: block %#x is object type %#x, want %#x", addr, got, typ)
	}
	return b, nil
}

// readAt reads file data straight from the container, bypassing the block
// cache (data is read once; only metadata is worth keeping).
func (c *Container) readAt(p []byte, off int64) error {
	_, err := readFullAt(c.r, p, off)
	return err
}

// omap is an object map: virtual oid -> physical address, versioned by xid.
type omap struct {
	t   *tree
	xid uint64

	mu    sync.Mutex
	cache map[uint64]uint64
}

func (c *Container) openOmap(addr uint64) (*omap, error) {
	b, err := c.object(addr, objTypeOmap)
	if err != nil {
		return nil, err
	}
	treeType := le32(b[40:])
	if treeType&objStorageMask != objPhysical {
		return nil, fmt.Errorf("apfs: object map tree is not physical (type %#x)", treeType)
	}
	t, err := c.openTree("omap", le64(b[48:]), true, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	return &omap{t: t, xid: c.XID, cache: make(map[uint64]uint64)}, nil
}

// lookup returns the physical address of the newest version of oid that is not
// newer than the checkpoint.
func (o *omap) lookup(oid uint64) (uint64, error) {
	o.mu.Lock()
	if addr, ok := o.cache[oid]; ok {
		o.mu.Unlock()
		return addr, nil
	}
	o.mu.Unlock()

	var (
		found   bool
		bestXID uint64
		val     []byte
	)
	err := o.t.scan(func(k []byte) int { return cmpU64(le64(k), oid) }, func(k, v []byte) (bool, error) {
		xid := le64(k[8:])
		if xid <= o.xid && (!found || xid >= bestXID) && len(v) >= 16 {
			found, bestXID, val = true, xid, v
		}
		return false, nil
	})
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, fmt.Errorf("apfs: object %#x is not in the object map", oid)
	}
	flags := le32(val[0:])
	if flags&omapValDeleted != 0 {
		return 0, fmt.Errorf("apfs: object %#x is deleted", oid)
	}
	if flags&omapValEncrypted != 0 {
		return 0, fmt.Errorf("apfs: object %#x is encrypted (encrypted volumes are not supported)", oid)
	}
	addr := le64(val[8:])
	o.mu.Lock()
	o.cache[oid] = addr
	o.mu.Unlock()
	return addr, nil
}

// verifyChecksum checks an object's Fletcher-64 checksum: summing the whole
// block with the stored checksum moved to the end must give zero.
func verifyChecksum(b []byte) bool {
	if len(b) < 32 || len(b)%4 != 0 {
		return false
	}
	if bytes.Equal(b[:8], make([]byte, 8)) && le64(b[8:]) == 0 {
		return false // all-zero header
	}
	const mod = 0xffffffff
	var sum1, sum2 uint64
	add := func(w uint32) {
		sum1 = (sum1 + uint64(w)) % mod
		sum2 = (sum2 + sum1) % mod
	}
	for i := 8; i < len(b); i += 4 {
		add(binary.LittleEndian.Uint32(b[i:]))
	}
	add(binary.LittleEndian.Uint32(b[0:]))
	add(binary.LittleEndian.Uint32(b[4:]))
	return sum1 == 0 && sum2 == 0
}

func cmpU64(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
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
