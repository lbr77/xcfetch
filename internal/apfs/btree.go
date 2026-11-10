package apfs

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
)

// B-tree flags (btree_info_fixed_t.bt_flags).
const (
	btreePhysical = 0x00000010
	btreeHashed   = 0x00000080
	btreeNoHeader = 0x00000100
)

// B-tree node flags (btree_node_phys_t.btn_flags).
const (
	btnodeRoot     = 0x0001
	btnodeLeaf     = 0x0002
	btnodeFixed    = 0x0004
	btnodeHashed   = 0x0008
	btnodeNoHeader = 0x0010
)

const (
	nodeHeaderSize = 56 // obj_phys_t + btree node fields before btn_data
	btreeInfoSize  = 40
	maxTreeDepth   = 16
	hashedValSize  = 8 + 32 // child oid + SHA-256 sized child hash
)

// btreeInfo is btree_info_fixed_t from the root node's tail.
type btreeInfo struct {
	flags    uint32
	nodeSize uint32
	keySize  uint32
	valSize  uint32
}

// node is one parsed B-tree node.
type node struct {
	b     []byte
	flags uint16
	level uint16
	nkeys int
	toc   int // offset of the table of contents
	keys  int // offset of the key area
	vend  int // end of the value area
}

func parseNode(b []byte) (*node, error) {
	if len(b) < nodeHeaderSize {
		return nil, errors.New("apfs: node smaller than its header")
	}
	n := &node{
		b:     b,
		flags: le16(b[32:]),
		level: le16(b[34:]),
		nkeys: int(le32(b[36:])),
	}
	tocOff, tocLen := int(le16(b[40:])), int(le16(b[42:]))
	n.toc = nodeHeaderSize + tocOff
	n.keys = n.toc + tocLen
	n.vend = len(b)
	if n.flags&btnodeRoot != 0 {
		n.vend -= btreeInfoSize
	}
	entry := 8
	if n.flags&btnodeFixed != 0 {
		entry = 4
	}
	if n.nkeys < 0 || n.toc+n.nkeys*entry > n.keys || n.keys > n.vend {
		return nil, fmt.Errorf("apfs: node table of contents is inconsistent (%d keys)", n.nkeys)
	}
	return n, nil
}

func (n *node) leaf() bool { return n.flags&btnodeLeaf != 0 }

// kv returns the key and value of entry i. A nil value marks a ghost entry.
func (n *node) kv(i int, info btreeInfo) (k, v []byte, err error) {
	var ko, kl, vo, vl int
	if n.flags&btnodeFixed != 0 {
		e := n.toc + i*4
		ko, vo = int(le16(n.b[e:])), int(le16(n.b[e+2:]))
		kl, vl = int(info.keySize), int(info.valSize)
		if !n.leaf() {
			vl = 8
			if info.flags&btreeHashed != 0 {
				vl = hashedValSize
			}
		}
	} else {
		e := n.toc + i*8
		ko, kl = int(le16(n.b[e:])), int(le16(n.b[e+2:]))
		vo, vl = int(le16(n.b[e+4:])), int(le16(n.b[e+6:]))
	}
	if k, err = span(n.b, n.keys+ko, kl, n.vend); err != nil {
		return nil, nil, fmt.Errorf("apfs: key %d: %w", i, err)
	}
	if vo == 0xffff {
		return k, nil, nil
	}
	if v, err = span(n.b, n.vend-vo, vl, n.vend); err != nil {
		return nil, nil, fmt.Errorf("apfs: value %d: %w", i, err)
	}
	return k, v, nil
}

func span(b []byte, off, n, limit int) ([]byte, error) {
	if off < 0 || n < 0 || off+n > limit {
		return nil, fmt.Errorf("range %d+%d outside node", off, n)
	}
	return b[off : off+n], nil
}

// tree is a B-tree rooted at one node. Child references are physical block
// addresses or virtual oids resolved through an object map.
type tree struct {
	c        *Container
	name     string
	root     uint64
	rootPhys bool
	info     btreeInfo
	om       *omap // resolves virtual child oids
	// hashSum computes a child node hash for hashed trees; nil skips checks.
	hashSum func([]byte) []byte
}

// openTree loads the root node and its btree_info. On sealed volumes hashSum
// checks every node against the hash its parent recorded, and rootHash (when
// known) anchors the root itself.
func (c *Container) openTree(name string, oid uint64, rootPhysical bool, om *omap, hashSum func([]byte) []byte, rootHash []byte) (*tree, error) {
	t := &tree{c: c, name: name, root: oid, rootPhys: rootPhysical, om: om, hashSum: hashSum}
	n, err := t.load(oid, rootPhysical, rootHash)
	if err != nil {
		return nil, fmt.Errorf("apfs: %s tree root: %w", name, err)
	}
	if n.flags&btnodeRoot == 0 {
		return nil, fmt.Errorf("apfs: %s tree: node %#x is not a root node", name, oid)
	}
	tail := n.b[len(n.b)-btreeInfoSize:]
	t.info = btreeInfo{
		flags:    le32(tail[0:]),
		nodeSize: le32(tail[4:]),
		keySize:  le32(tail[8:]),
		valSize:  le32(tail[12:]),
	}
	if t.info.nodeSize != 0 && int64(t.info.nodeSize) != c.BlockSize {
		return nil, fmt.Errorf("apfs: %s tree: node size %d differs from block size %d", name, t.info.nodeSize, c.BlockSize)
	}
	return t, nil
}

// childPhysical reports whether child references in this tree are physical.
func (t *tree) childPhysical() bool {
	return t.info.flags&btreePhysical != 0 || t.om == nil
}

// load reads and validates one node. wantHash, when set, is the hash the
// parent recorded for it.
func (t *tree) load(oid uint64, physical bool, wantHash []byte) (*node, error) {
	addr := oid
	if !physical {
		if t.om == nil {
			return nil, fmt.Errorf("apfs: %s tree: virtual node %#x without an object map", t.name, oid)
		}
		var err error
		if addr, err = t.om.lookup(oid); err != nil {
			return nil, fmt.Errorf("apfs: %s tree: %w", t.name, err)
		}
	}
	b, err := t.c.block(addr)
	if err != nil {
		return nil, err
	}
	flags := le16(b[32:])
	if flags&btnodeNoHeader == 0 {
		// Nodes with an object header carry a Fletcher-64 checksum.
		if !verifyChecksum(b) {
			return nil, fmt.Errorf("apfs: %s tree: node at block %#x fails its checksum", t.name, addr)
		}
		if typ := le32(b[24:]) & objTypeMask; typ != objTypeBtree && typ != objTypeBtreeNode {
			return nil, fmt.Errorf("apfs: %s tree: block %#x is object type %#x, not a B-tree node", t.name, addr, typ)
		}
	}
	if wantHash != nil && t.hashSum != nil {
		if got := t.hashSum(b); len(wantHash) < len(got) || !bytes.Equal(got, wantHash[:len(got)]) {
			return nil, fmt.Errorf("apfs: %s tree: node at block %#x does not match the hash its parent recorded", t.name, addr)
		}
	}
	return parseNode(b)
}

// cmpFunc places a key relative to the wanted range: negative before it, zero
// inside it, positive after it. It must be monotone in the tree's key order.
type cmpFunc func(k []byte) int

// scan calls fn for every live record whose key is inside the range, in key
// order, until fn returns true.
func (t *tree) scan(cmp cmpFunc, fn func(k, v []byte) (bool, error)) error {
	root, err := t.load(t.root, t.rootPhys, nil)
	if err != nil {
		return err
	}
	_, err = t.scanNode(root, cmp, fn, 0)
	return err
}

func (t *tree) scanNode(n *node, cmp cmpFunc, fn func(k, v []byte) (bool, error), depth int) (bool, error) {
	if depth > maxTreeDepth {
		return false, fmt.Errorf("apfs: %s tree deeper than %d levels", t.name, maxTreeDepth)
	}
	if n.leaf() {
		for i := 0; i < n.nkeys; i++ {
			k, v, err := n.kv(i, t.info)
			if err != nil {
				return false, err
			}
			c := cmp(k)
			if c < 0 {
				continue
			}
			if c > 0 {
				return true, nil
			}
			if v == nil {
				continue
			}
			if stop, err := fn(k, v); stop || err != nil {
				return true, err
			}
		}
		return false, nil
	}
	physical := t.childPhysical()
	hashed := t.info.flags&btreeHashed != 0 || n.flags&btnodeHashed != 0
	for i := 0; i < n.nkeys; i++ {
		k, v, err := n.kv(i, t.info)
		if err != nil {
			return false, err
		}
		if cmp(k) > 0 {
			return true, nil
		}
		if i+1 < n.nkeys {
			next, _, err := n.kv(i+1, t.info)
			if err != nil {
				return false, err
			}
			if cmp(next) < 0 {
				continue // the whole child sorts before the range
			}
		}
		if len(v) < 8 {
			return false, fmt.Errorf("apfs: %s tree: index value of %d bytes", t.name, len(v))
		}
		var want []byte
		if hashed && len(v) >= hashedValSize {
			want = v[8:]
		}
		childOID := le64(v)
		if hashed && !physical {
			// A sealed volume's hashed, virtual file-system tree stores child
			// oids relative to the root's oid (observed on Apple's simulator
			// runtime images; not in the published reference). The child hash
			// check below confirms every resolved node.
			childOID += t.root
		}
		child, err := t.load(childOID, physical, want)
		if err != nil {
			return false, err
		}
		if int(child.level) >= int(n.level) {
			return false, fmt.Errorf("apfs: %s tree: child level %d under level %d", t.name, child.level, n.level)
		}
		if stop, err := t.scanNode(child, cmp, fn, depth+1); stop || err != nil {
			return stop, err
		}
	}
	return false, nil
}

// Hash types (integrity_meta_phys_t.im_hash_type).
const (
	hashSHA256    = 1
	hashSHA512256 = 2
	hashSHA384    = 3
	hashSHA512    = 4
)

// hashFunc returns the digest function for an integrity hash type.
func hashFunc(typ uint32) func([]byte) []byte {
	switch typ {
	case hashSHA256:
		return func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
	case hashSHA512256:
		return func(b []byte) []byte { s := sha512.Sum512_256(b); return s[:] }
	case hashSHA384:
		return func(b []byte) []byte { s := sha512.Sum384(b); return s[:] }
	case hashSHA512:
		return func(b []byte) []byte { s := sha512.Sum512(b); return s[:] }
	}
	return nil
}

func le16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func le64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }
