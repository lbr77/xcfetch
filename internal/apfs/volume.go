package apfs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"
)

// File-system record types (j_key_t, high 4 bits).
const (
	typeInode    = 3
	typeXattr    = 4
	typeExtent   = 8
	typeDirRec   = 9
	typeFileInfo = 13

	objIDMask       = 0x0fffffffffffffff
	objTypeShift    = 60
	extentLenMask   = 0x00ffffffffffffff
	fileInfoLBAMask = 0x00ffffffffffffff
	fileInfoHash    = 1
	rootDirID       = 2

	incompatCaseInsensitive = 0x1
	incompatNormInsensitive = 0x8
	incompatSealed          = 0x20

	xattrDataStream   = 0x1
	xattrDataEmbedded = 0x2
	inoExtTypeDstream = 8
	ufCompressed      = 0x20
	maxSymlinks       = 40
	symlinkXattr      = "com.apple.fs.symlink"
)

// Directory entry types (DT_*), from j_drec_val_t.flags.
const (
	DTDir  = 4
	DTReg  = 8
	DTLink = 10
)

// ErrCompressed is returned for decmpfs-compressed files.
var ErrCompressed = errors.New("apfs: file is decmpfs-compressed (not supported)")

// Volume is one file system in a container.
type Volume struct {
	c        *Container
	Name     string
	Role     uint16
	Sealed   bool
	caseFold bool
	hashed   bool

	om   *omap
	fs   *tree
	fext *tree
	hash func([]byte) []byte
}

// Volumes opens every file system in the container.
func (c *Container) Volumes() ([]*Volume, error) {
	var out []*Volume
	for i := 0; i < nxMaxFileSystems; i++ {
		oid := le64(c.sb[nxFSOidOffset+8*i:])
		if oid == 0 {
			continue
		}
		addr, err := c.omap.lookup(oid)
		if err != nil {
			return nil, fmt.Errorf("apfs: volume %d: %w", i, err)
		}
		v, err := c.openVolume(addr)
		if err != nil {
			return nil, fmt.Errorf("apfs: volume %d: %w", i, err)
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, errors.New("apfs: container has no volumes")
	}
	return out, nil
}

func (c *Container) openVolume(addr uint64) (*Volume, error) {
	b, err := c.object(addr, objTypeFS)
	if err != nil {
		return nil, err
	}
	if string(b[32:36]) != "APSB" {
		return nil, errors.New("apfs: volume superblock has a bad magic")
	}
	incompat := le64(b[56:])
	name := b[704:960]
	if i := strings.IndexByte(string(name), 0); i >= 0 {
		name = name[:i]
	}
	v := &Volume{
		c:        c,
		Name:     string(name),
		Role:     le16(b[964:]),
		Sealed:   incompat&incompatSealed != 0,
		caseFold: incompat&incompatCaseInsensitive != 0,
		hashed:   incompat&(incompatCaseInsensitive|incompatNormInsensitive) != 0,
	}
	// Encrypted metadata is refused by the object map (OMAP_VAL_ENCRYPTED).
	if v.om, err = c.openOmap(le64(b[128:])); err != nil {
		return nil, fmt.Errorf("apfs: volume %q object map: %w", v.Name, err)
	}
	var rootHash []byte
	if v.Sealed {
		if v.hash, rootHash, err = v.integrity(le64(b[1024:])); err != nil {
			return nil, fmt.Errorf("apfs: volume %q: %w", v.Name, err)
		}
	}
	rootType := le32(b[116:])
	v.fs, err = c.openTree("fs", le64(b[136:]), rootType&objStorageMask == objPhysical, v.om, v.hash, rootHash)
	if err != nil {
		return nil, fmt.Errorf("apfs: volume %q: %w", v.Name, err)
	}
	if fextOID := le64(b[1032:]); v.Sealed && fextOID != 0 {
		fextType := le32(b[1040:])
		v.fext, err = c.openTree("fext", fextOID, fextType&objStorageMask == objPhysical, v.om, v.hash, nil)
		if err != nil {
			return nil, fmt.Errorf("apfs: volume %q: %w", v.Name, err)
		}
	}
	return v, nil
}

// integrity reads the sealed volume's hash algorithm and the hash of the
// file-system tree's root node.
func (v *Volume) integrity(oid uint64) (func([]byte) []byte, []byte, error) {
	if oid == 0 {
		return nil, nil, errors.New("sealed volume without integrity metadata")
	}
	addr := oid
	if a, err := v.om.lookup(oid); err == nil {
		addr = a
	}
	b, err := v.c.object(addr, objTypeIntegrity)
	if err != nil {
		return nil, nil, fmt.Errorf("integrity metadata: %w", err)
	}
	h := hashFunc(le32(b[40:]))
	if h == nil {
		return nil, nil, fmt.Errorf("integrity metadata: unknown hash type %d", le32(b[40:]))
	}
	size := len(h(nil))
	off := int(le32(b[44:]))
	if off < 56 || off+size > len(b) {
		return nil, nil, fmt.Errorf("integrity metadata: root hash at %d is out of range", off)
	}
	return h, append([]byte(nil), b[off:off+size]...), nil
}

// jcmp ranges over the records of one object id and record type.
func jcmp(id uint64, typ uint8) cmpFunc {
	return func(k []byte) int {
		if len(k) < 8 {
			return -1
		}
		h := le64(k)
		if c := cmpU64(h&objIDMask, id); c != 0 {
			return c
		}
		return cmpU64(h>>objTypeShift, uint64(typ))
	}
}

// Inode is the subset of j_inode_val_t extraction needs.
type Inode struct {
	ID        uint64
	ParentID  uint64
	PrivateID uint64
	ModTime   time.Time
	BSDFlags  uint32
	UID, GID  uint32
	Mode      uint16
	Size      int64
}

// IsDir reports whether the inode is a directory.
func (i Inode) IsDir() bool { return i.Mode&0o170000 == 0o040000 }

// IsSymlink reports whether the inode is a symbolic link.
func (i Inode) IsSymlink() bool { return i.Mode&0o170000 == 0o120000 }

// IsRegular reports whether the inode is a regular file.
func (i Inode) IsRegular() bool { return i.Mode&0o170000 == 0o100000 }

// Perm is the permission part of the mode.
func (i Inode) Perm() fs.FileMode { return fs.FileMode(i.Mode & 0o777) }

// Compressed reports whether the data lives in a decmpfs xattr/resource fork.
func (i Inode) Compressed() bool { return i.BSDFlags&ufCompressed != 0 }

// Inode reads the inode record for id.
func (v *Volume) Inode(id uint64) (Inode, error) {
	var (
		ino   Inode
		found bool
	)
	err := v.fs.scan(jcmp(id, typeInode), func(_, val []byte) (bool, error) {
		if len(val) < 92 {
			return true, fmt.Errorf("apfs: inode %d record is %d bytes", id, len(val))
		}
		ino = Inode{
			ID:        id,
			ParentID:  le64(val[0:]),
			PrivateID: le64(val[8:]),
			ModTime:   time.Unix(0, int64(le64(val[24:]))),
			BSDFlags:  le32(val[68:]),
			UID:       le32(val[72:]),
			GID:       le32(val[76:]),
			Mode:      le16(val[80:]),
		}
		if ds, ok := xfield(val[92:], inoExtTypeDstream); ok && len(ds) >= 8 {
			ino.Size = int64(le64(ds))
		}
		found = true
		return true, nil
	})
	if err != nil {
		return Inode{}, err
	}
	if !found {
		return Inode{}, fmt.Errorf("apfs: inode %d not found", id)
	}
	return ino, nil
}

// xfield returns the data of the extended field of type typ in an xf_blob_t.
func xfield(blob []byte, typ uint8) ([]byte, bool) {
	if len(blob) < 4 {
		return nil, false
	}
	n := int(le16(blob))
	hdr := 4
	data := hdr + 4*n
	if data > len(blob) {
		return nil, false
	}
	for i := 0; i < n; i++ {
		h := blob[hdr+4*i:]
		size := int(le16(h[2:]))
		if data+size > len(blob) {
			return nil, false
		}
		if h[0] == typ {
			return blob[data : data+size], true
		}
		data += (size + 7) &^ 7
	}
	return nil, false
}

// DirEntry is one directory record.
type DirEntry struct {
	Name string
	ID   uint64
	Type uint8 // DT_*
}

// readDir lists the records of directory id.
func (v *Volume) readDir(id uint64) ([]DirEntry, error) {
	var out []DirEntry
	err := v.fs.scan(jcmp(id, typeDirRec), func(k, val []byte) (bool, error) {
		name, ok := v.drecName(k)
		if !ok {
			return true, fmt.Errorf("apfs: malformed directory record under %d", id)
		}
		if len(val) < 18 {
			return true, fmt.Errorf("apfs: short directory record %q", name)
		}
		out = append(out, DirEntry{Name: name, ID: le64(val[0:]), Type: uint8(le16(val[16:]) & 0xf)})
		return false, nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

// drecName decodes the name from a hashed or plain directory record key,
// trusting whichever layout is self-consistent.
func (v *Volume) drecName(k []byte) (string, bool) {
	hashed := func() (string, bool) {
		if len(k) < 12 {
			return "", false
		}
		n := int(le32(k[8:]) & 0x3ff)
		if 12+n != len(k) || n == 0 {
			return "", false
		}
		return strings.TrimRight(string(k[12:12+n]), "\x00"), true
	}
	plain := func() (string, bool) {
		if len(k) < 10 {
			return "", false
		}
		n := int(le16(k[8:]))
		if 10+n != len(k) || n == 0 {
			return "", false
		}
		return strings.TrimRight(string(k[10:10+n]), "\x00"), true
	}
	if v.hashed {
		if s, ok := hashed(); ok {
			return s, true
		}
		return plain()
	}
	if s, ok := plain(); ok {
		return s, true
	}
	return hashed()
}

// xattr returns the value of the named extended attribute of id.
func (v *Volume) xattr(id uint64, name string) ([]byte, bool, error) {
	var (
		out   []byte
		found bool
		ierr  error
	)
	err := v.fs.scan(jcmp(id, typeXattr), func(k, val []byte) (bool, error) {
		if len(k) < 10 {
			return false, nil
		}
		n := int(le16(k[8:]))
		if 10+n > len(k) || strings.TrimRight(string(k[10:10+n]), "\x00") != name {
			return false, nil
		}
		if len(val) < 4 {
			return true, fmt.Errorf("apfs: short xattr %q", name)
		}
		flags, dlen := le16(val[0:]), int(le16(val[2:]))
		found = true
		switch {
		case flags&xattrDataEmbedded != 0:
			if 4+dlen > len(val) {
				return true, fmt.Errorf("apfs: xattr %q overruns its record", name)
			}
			out = append([]byte(nil), val[4:4+dlen]...)
		case flags&xattrDataStream != 0:
			if len(val) < 4+16 {
				return true, fmt.Errorf("apfs: short xattr stream %q", name)
			}
			streamID, size := le64(val[4:]), int64(le64(val[12:]))
			out, ierr = v.readStream(streamID, size)
		default:
			return true, fmt.Errorf("apfs: xattr %q has unknown flags %#x", name, flags)
		}
		return true, nil
	})
	if err == nil {
		err = ierr
	}
	return out, found, err
}

// readStream reads a whole (small) data stream.
func (v *Volume) readStream(id uint64, size int64) ([]byte, error) {
	if size < 0 || size > 64<<20 {
		return nil, fmt.Errorf("apfs: stream %d of %d bytes is too large to buffer", id, size)
	}
	ext, err := v.extents(id)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, size)
	r := &extentReader{v: v, ext: ext, size: size}
	if _, err := r.ReadAt(buf, 0); err != nil && err != io.EOF {
		return nil, err
	}
	return buf, nil
}

// extent is one run of a file's data.
type extent struct {
	logical int64
	length  int64
	phys    uint64 // block number, 0 for a hole
}

// extents lists the data runs of a data stream, in logical order.
func (v *Volume) extents(privateID uint64) ([]extent, error) {
	var out []extent
	if v.fext != nil {
		err := v.fext.scan(func(k []byte) int { return cmpU64(le64(k), privateID) }, func(k, val []byte) (bool, error) {
			if len(k) < 16 || len(val) < 16 {
				return true, errors.New("apfs: short file-extent tree record")
			}
			out = append(out, extent{
				logical: int64(le64(k[8:])),
				length:  int64(le64(val[0:]) & extentLenMask),
				phys:    le64(val[8:]),
			})
			return false, nil
		})
		if err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		err := v.fs.scan(jcmp(privateID, typeExtent), func(k, val []byte) (bool, error) {
			if len(k) < 16 || len(val) < 16 {
				return true, errors.New("apfs: short file extent record")
			}
			out = append(out, extent{
				logical: int64(le64(k[8:])),
				length:  int64(le64(val[0:]) & extentLenMask),
				phys:    le64(val[8:]),
			})
			return false, nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].logical < out[j].logical })
	return out, nil
}

// extentReader is an io.ReaderAt over a data stream.
type extentReader struct {
	v    *Volume
	ext  []extent
	size int64
}

func (r *extentReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= r.size {
		return 0, io.EOF
	}
	var short bool
	if int64(len(p)) > r.size-off {
		p, short = p[:r.size-off], true
	}
	bs := r.v.c.BlockSize
	done := 0
	for done < len(p) {
		pos := off + int64(done)
		i := sort.Search(len(r.ext), func(i int) bool { return r.ext[i].logical > pos }) - 1
		if i < 0 || pos >= r.ext[i].logical+r.ext[i].length {
			next := r.size
			if i+1 < len(r.ext) {
				next = r.ext[i+1].logical
			}
			n := int(min(int64(len(p)-done), next-pos))
			clear(p[done : done+n])
			done += n
			continue
		}
		e := r.ext[i]
		within := pos - e.logical
		n := int(min(int64(len(p)-done), e.length-within))
		if e.phys == 0 {
			clear(p[done : done+n])
		} else if err := r.v.c.readAt(p[done:done+n], int64(e.phys)*bs+within); err != nil {
			return done, fmt.Errorf("apfs: reading data at block %#x: %w", e.phys, err)
		}
		done += n
	}
	if short {
		return done, io.EOF
	}
	return done, nil
}

// Node is a resolved path.
type Node struct {
	Path string // volume-relative, with on-disk spelling
	Inode
	Link string // symlink target, for symlinks
}

// Stat resolves p (relative to the volume root) without following a symlink
// in the last component.
func (v *Volume) Stat(p string) (Node, error) { return v.resolve(p, false) }

// StatFollow resolves p following every symlink.
func (v *Volume) StatFollow(p string) (Node, error) { return v.resolve(p, true) }

type step struct {
	name string
	id   uint64
}

func (v *Volume) resolve(p string, followLast bool) (Node, error) {
	comps := splitPath(p)
	stack := []step{{"", rootDirID}}
	links := 0
	for len(comps) > 0 {
		name := comps[0]
		comps = comps[1:]
		switch name {
		case ".":
			continue
		case "..":
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		parent := stack[len(stack)-1]
		ent, err := v.child(parent.id, name)
		if err != nil {
			return Node{}, fmt.Errorf("%s: %w", joinSteps(append(stack, step{name: name})), err)
		}
		if ent.Type == DTLink && (len(comps) > 0 || followLast) {
			links++
			if links > maxSymlinks {
				return Node{}, fmt.Errorf("apfs: %s: too many symlinks", p)
			}
			target, err := v.readlink(ent.ID)
			if err != nil {
				return Node{}, err
			}
			if strings.HasPrefix(target, "/") {
				stack = stack[:1]
			}
			comps = append(splitPath(target), comps...)
			continue
		}
		stack = append(stack, step{ent.Name, ent.ID})
	}
	last := stack[len(stack)-1]
	ino, err := v.Inode(last.id)
	if err != nil {
		return Node{}, err
	}
	n := Node{Path: joinSteps(stack), Inode: ino}
	if ino.IsSymlink() {
		if n.Link, err = v.readlink(last.id); err != nil {
			return Node{}, err
		}
	}
	return n, nil
}

// ErrNotExist marks a missing path component.
var ErrNotExist = fs.ErrNotExist

// child finds name in directory dir, exactly or (on case-insensitive volumes)
// by case folding.
func (v *Volume) child(dir uint64, name string) (DirEntry, error) {
	entries, err := v.readDir(dir)
	if err != nil {
		return DirEntry{}, err
	}
	for _, e := range entries {
		if e.Name == name {
			return e, nil
		}
	}
	if v.caseFold {
		for _, e := range entries {
			if strings.EqualFold(e.Name, name) {
				return e, nil
			}
		}
	}
	return DirEntry{}, ErrNotExist
}

func (v *Volume) readlink(id uint64) (string, error) {
	data, ok, err := v.xattr(id, symlinkXattr)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("apfs: symlink %d has no target", id)
	}
	return strings.TrimRight(string(data), "\x00"), nil
}

// ReadDir lists the directory at p (following symlinks).
func (v *Volume) ReadDir(p string) ([]Node, error) {
	dir, err := v.StatFollow(p)
	if err != nil {
		return nil, err
	}
	return v.Children(dir)
}

// Children lists the entries of a directory node.
func (v *Volume) Children(dir Node) ([]Node, error) {
	if !dir.IsDir() {
		return nil, fmt.Errorf("apfs: %s is not a directory", dir.Path)
	}
	entries, err := v.readDir(dir.ID)
	if err != nil {
		return nil, err
	}
	out := make([]Node, 0, len(entries))
	for _, e := range entries {
		ino, err := v.Inode(e.ID)
		if err != nil {
			return nil, err
		}
		n := Node{Path: path.Join(dir.Path, e.Name), Inode: ino}
		if ino.IsSymlink() {
			if n.Link, err = v.readlink(e.ID); err != nil {
				return nil, err
			}
		}
		out = append(out, n)
	}
	return out, nil
}

// Glob expands a pattern whose components use path.Match syntax. Components
// without metacharacters are looked up directly.
func (v *Volume) Glob(pattern string) ([]string, error) {
	paths := []string{""}
	comps := splitPath(pattern)
	for i, comp := range comps {
		var next []string
		for _, base := range paths {
			if !hasMeta(comp) {
				next = append(next, path.Join(base, comp))
				continue
			}
			dir, err := v.StatFollow(base)
			if err != nil || !dir.IsDir() {
				continue
			}
			entries, err := v.readDir(dir.ID)
			if err != nil {
				return nil, err
			}
			for _, e := range entries {
				ok, err := path.Match(comp, e.Name)
				if err != nil {
					return nil, fmt.Errorf("apfs: pattern %q: %w", pattern, err)
				}
				if !ok && v.caseFold {
					ok, _ = path.Match(strings.ToLower(comp), strings.ToLower(e.Name))
				}
				if ok {
					next = append(next, path.Join(dir.Path, e.Name))
				}
			}
		}
		paths = next
		if len(paths) == 0 {
			return nil, fmt.Errorf("apfs: %s: %w", path.Join(comps[:i+1]...), ErrNotExist)
		}
	}
	return paths, nil
}

// Open returns the contents of a regular file.
func (v *Volume) Open(n Node) (io.ReaderAt, error) {
	if !n.IsRegular() {
		return nil, fmt.Errorf("apfs: %s is not a regular file", n.Path)
	}
	if n.Compressed() {
		return nil, fmt.Errorf("%s: %w", n.Path, ErrCompressed)
	}
	ext, err := v.extents(n.PrivateID)
	if err != nil {
		return nil, err
	}
	return &extentReader{v: v, ext: ext, size: n.Size}, nil
}

// Verify checks the file against the sealed volume's per-extent data hashes.
// It returns the number of bytes covered by a hash; zero means the volume
// recorded none for this file.
func (v *Volume) Verify(n Node, data io.ReaderAt) (int64, error) {
	if !v.Sealed || v.hash == nil || !n.IsRegular() || n.Size == 0 {
		return 0, nil
	}
	type info struct {
		lba    int64
		blocks int64
		hash   []byte
	}
	var infos []info
	collect := func(k, val []byte) (bool, error) {
		if len(k) < 16 || len(val) < 3 {
			return true, errors.New("apfs: short file-info record")
		}
		ia := le64(k[8:])
		if ia>>56 != fileInfoHash {
			return false, nil
		}
		size := int(val[2])
		if 3+size > len(val) {
			return true, errors.New("apfs: file-info hash overruns its record")
		}
		infos = append(infos, info{
			lba:    int64(ia & fileInfoLBAMask),
			blocks: int64(le16(val[0:])),
			hash:   append([]byte(nil), val[3:3+size]...),
		})
		return false, nil
	}
	err := v.fs.scan(jcmp(n.PrivateID, typeFileInfo), collect)
	if err == nil && len(infos) == 0 && n.ID != n.PrivateID {
		err = v.fs.scan(jcmp(n.ID, typeFileInfo), collect)
	}
	if err != nil || len(infos) == 0 {
		return 0, err
	}
	bs := v.c.BlockSize
	var covered int64
	for _, in := range infos {
		if in.blocks <= 0 || in.blocks > 1<<20 {
			return covered, fmt.Errorf("apfs: %s: implausible hashed length of %d blocks", n.Path, in.blocks)
		}
		// The record's address is a byte offset into the file; the length
		// is in blocks.
		buf := make([]byte, in.blocks*bs)
		got, err := data.ReadAt(buf, in.lba)
		if err != nil && err != io.EOF {
			return covered, err
		}
		// Past end of file the hashed blocks read as zeros.
		clear(buf[got:])
		if sum := v.hash(buf); !equalPrefix(sum, in.hash) {
			return covered, fmt.Errorf("apfs: %s: data at offset %d does not match the sealed volume's hash", n.Path, in.lba)
		}
		covered += int64(got)
	}
	return covered, nil
}

func equalPrefix(a, b []byte) bool {
	if len(a) == 0 || len(b) < len(a) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hasMeta(s string) bool { return strings.ContainsAny(s, `*?[\`) }

func splitPath(p string) []string {
	var out []string
	for _, c := range strings.Split(p, "/") {
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

func joinSteps(s []step) string {
	parts := make([]string, 0, len(s))
	for _, st := range s[1:] {
		parts = append(parts, st.name)
	}
	return strings.Join(parts, "/")
}
