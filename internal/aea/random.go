package aea

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// RandomReader decrypts arbitrary plaintext ranges of an AEA archive without
// reading the whole archive.
//
// The format allows this: every cluster carries its own encrypted segment
// headers and every segment has its own key, so the plaintext is addressed as
//
//	cluster = off / (segmentsPerCluster * segmentSize)
//	segment = (off % clusterSpan) / segmentSize
//
// A caller that knows an offset therefore needs one cluster header block (a few
// kilobytes) and one segment (segmentSize). Only the cluster chain has to be
// walked in order, and each link costs one small read because the previous
// cluster records the byte length of the next payload.
type RandomReader struct {
	src     io.ReaderAt
	size    int64
	keyLen  int
	profile uint32
	mainKey []byte
	root    rootHeader
	hdrLen  int

	firstClusterOff int64
	clusterSpan     int64
	headerBytes     int64
	macBytes        int64

	// partial lets reads of segments stored without compression fetch and
	// decrypt only the requested bytes (AES-CTR is seekable). The segment MAC
	// covers the whole segment, so such reads are not authenticated; callers
	// that need every byte authenticated turn this off.
	partial bool

	discoverMu sync.Mutex // serialises cluster chain discovery
	mu         sync.Mutex // guards clusters, the segment cache and keys
	clusters   []clusterInfo
	segCache   map[uint64][]byte
	segOrder   []uint64
	cached     int64
	segKeys    map[uint64]dataKey
}

// clusterInfo is the parsed header block of one cluster.
type clusterInfo struct {
	headerOff   int64
	payloadOff  int64
	payloadSize int64
	hdrs        []byte  // decrypted segment headers
	macs        []byte  // next-cluster MAC followed by per-segment MACs
	segOffs     []int64 // absolute offset of each segment's payload
}

const (
	// segCacheBytes bounds the decrypted-segment cache.
	segCacheBytes = 8 << 20
	// maxClusterHeaders bounds memory spent on one cluster header block.
	maxClusterHeaders = 1 << 26
)

// NewRandomReader parses the archive prologue and returns an on-demand reader.
// key is the symmetric key for profile 1 (nil for profile 0).
func NewRandomReader(r io.ReaderAt, size int64, key []byte) (*RandomReader, error) {
	if size < fileHeaderSize {
		return nil, fmt.Errorf("aea: file too small (%d bytes)", size)
	}
	prologue := make([]byte, fileHeaderSize)
	if _, err := readFullAt(r, prologue, 0); err != nil {
		return nil, fmt.Errorf("aea: reading header: %w", err)
	}
	if string(prologue[:4]) != "AEA1" {
		return nil, fmt.Errorf("aea: not an AEA archive: bad magic %q", string(prologue[:4]))
	}
	fh := fileHeader{
		profile:  uint32(prologue[4]) | uint32(prologue[5])<<8 | uint32(prologue[6])<<16,
		scrypt:   prologue[7],
		authSize: binary.LittleEndian.Uint32(prologue[8:]),
	}
	if err := fh.validate(); err != nil {
		return nil, err
	}

	off := int64(fileHeaderSize)
	authData := make([]byte, fh.authSize)
	if _, err := readFullAt(r, authData, off); err != nil {
		return nil, fmt.Errorf("aea: reading auth data: %w", err)
	}
	off += int64(fh.authSize)
	off += int64(signatureSize(fh.profile))
	pub := make([]byte, publicKeySize(fh.profile))
	if _, err := readFullAt(r, pub, off); err != nil {
		return nil, fmt.Errorf("aea: reading public key section: %w", err)
	}
	off += int64(len(pub))

	var mainSalt [32]byte
	var rootMAC [32]byte
	var encRoot [rootHeaderSize]byte
	var firstMAC [32]byte
	for _, step := range []struct {
		name string
		buf  []byte
	}{
		{"main salt", mainSalt[:]},
		{"root header MAC", rootMAC[:]},
		{"root header", encRoot[:]},
		{"first cluster MAC", firstMAC[:]},
	} {
		if _, err := readFullAt(r, step.buf, off); err != nil {
			return nil, fmt.Errorf("aea: reading %s: %w", step.name, err)
		}
		off += int64(len(step.buf))
	}

	mainKey, err := deriveMainKey(fh, pub, mainSalt[:], key)
	if err != nil {
		return nil, err
	}
	ks := keySize(fh.profile)
	rootKey := dataKey(deriveKey(ks, mainKey, nil, []byte("AEA_RHEK")))
	if !rootKey.verify(rootMAC[:], encRoot[:], append(firstMAC[:], authData...)) {
		return nil, fmt.Errorf("aea: root header MAC mismatch (wrong key or corrupted archive)")
	}
	var plain [rootHeaderSize]byte
	if err := rootKey.decryptInto(plain[:], encRoot[:]); err != nil {
		return nil, fmt.Errorf("aea: decrypting root header: %w", err)
	}
	rh, err := parseRootHeader(plain[:])
	if err != nil {
		return nil, err
	}

	spc := int64(rh.segmentsPerCluster)
	hdrLen := int64(8 + rh.checksumSize())
	a := &RandomReader{
		src:             r,
		size:            size,
		keyLen:          ks,
		profile:         fh.profile,
		mainKey:         mainKey,
		root:            rh,
		hdrLen:          int(hdrLen),
		firstClusterOff: off,
		clusterSpan:     spc * int64(rh.segmentSize),
		headerBytes:     spc * hdrLen,
		macBytes:        32 + 32*spc,
		clusters:        make([]clusterInfo, 0, 16),
		segCache:        make(map[uint64][]byte),
		segKeys:         make(map[uint64]dataKey),
		partial:         true,
	}
	if a.clusterSpan <= 0 {
		return nil, fmt.Errorf("aea: implausible cluster span %d", a.clusterSpan)
	}
	if a.headerBytes+a.macBytes > maxClusterHeaders {
		return nil, fmt.Errorf("aea: cluster header block of %d bytes is too large", a.headerBytes+a.macBytes)
	}
	return a, nil
}

// SetVerifyAll makes every read decrypt and authenticate whole segments, even
// when only a few bytes of an uncompressed segment are wanted.
func (a *RandomReader) SetVerifyAll(v bool) { a.partial = !v }

// Size is the plaintext size announced by the root header.
func (a *RandomReader) Size() int64 { return int64(a.root.originalSize) }

// Profile is the AEA profile id.
func (a *RandomReader) Profile() uint32 { return a.profile }

// ReadAt implements io.ReaderAt over the decrypted plaintext.
func (a *RandomReader) ReadAt(p []byte, off int64) (int, error) {
	total := a.Size()
	if off < 0 || off >= total {
		return 0, io.EOF
	}
	if int64(len(p)) > total-off {
		p = p[:total-off]
	}
	read := 0
	for read < len(p) {
		pos := off + int64(read)
		cluster := pos / a.clusterSpan
		within := pos % a.clusterSpan
		seg := int(within / int64(a.root.segmentSize))
		segOff := within % int64(a.root.segmentSize)

		if a.partial {
			n, ok, err := a.readStored(cluster, seg, segOff, p[read:])
			if err != nil {
				return read, err
			}
			if ok {
				read += n
				continue
			}
		}
		data, err := a.segment(cluster, seg)
		if err != nil {
			if err == io.EOF {
				return read, io.EOF
			}
			return read, err
		}
		if segOff >= int64(len(data)) {
			return read, io.EOF
		}
		n := copy(p[read:], data[segOff:])
		if n == 0 {
			return read, io.EOF
		}
		read += n
	}
	return read, nil
}

// readStored serves a read from a segment stored without compression by
// fetching and decrypting just the requested bytes. ok is false when the
// segment is compressed, already cached, or wanted whole (then the verified
// path costs nothing extra).
func (a *RandomReader) readStored(cluster int64, seg int, segOff int64, p []byte) (int, bool, error) {
	if seg < 0 || seg >= int(a.root.segmentsPerCluster) {
		return 0, false, nil
	}
	key := uint64(cluster)<<32 | uint64(seg)
	a.mu.Lock()
	_, cached := a.segCache[key]
	a.mu.Unlock()
	if cached {
		return 0, false, nil
	}
	info, err := a.clusterInfo(cluster)
	if err != nil {
		return 0, false, err
	}
	hdr := info.hdrs[seg*a.hdrLen:]
	origSize := int64(binary.LittleEndian.Uint32(hdr[0:]))
	compSize := int64(binary.LittleEndian.Uint32(hdr[4:]))
	if origSize == 0 || compSize != origSize || segOff >= origSize {
		return 0, false, nil
	}
	n := min(int64(len(p)), origSize-segOff)
	if segOff == 0 && n == origSize {
		return 0, false, nil
	}
	buf := p[:n]
	if _, err := readFullAt(a.src, buf, info.segOffs[seg]+segOff); err != nil {
		return 0, false, fmt.Errorf("aea: cluster %d segment %d: reading data: %w", cluster, seg, err)
	}
	if err := a.segmentKey(cluster, seg).decryptAt(buf, buf, segOff); err != nil {
		return 0, false, fmt.Errorf("aea: cluster %d segment %d: decrypting: %w", cluster, seg, err)
	}
	return int(n), true, nil
}

// segmentKey derives (and memoises) the data key of one segment.
func (a *RandomReader) segmentKey(cluster int64, seg int) dataKey {
	id := uint64(cluster)<<32 | uint64(seg)
	a.mu.Lock()
	k, ok := a.segKeys[id]
	a.mu.Unlock()
	if ok {
		return k
	}
	clusterKey := deriveKey(macKeySize, a.mainKey, nil, indexedInfo("AEA_CK", uint32(cluster)))
	k = dataKey(deriveKey(a.keyLen, clusterKey, nil, indexedInfo("AEA_SK", uint32(seg))))
	a.mu.Lock()
	a.segKeys[id] = k
	a.mu.Unlock()
	return k
}

// segment returns the decrypted, checksum-verified plaintext of one segment.
func (a *RandomReader) segment(cluster int64, seg int) ([]byte, error) {
	if seg < 0 || seg >= int(a.root.segmentsPerCluster) {
		return nil, io.EOF
	}
	key := uint64(cluster)<<32 | uint64(seg)
	a.mu.Lock()
	if data, ok := a.segCache[key]; ok {
		a.mu.Unlock()
		return data, nil
	}
	a.mu.Unlock()

	info, err := a.clusterInfo(cluster)
	if err != nil {
		return nil, err
	}
	hdr := info.hdrs[seg*a.hdrLen:]
	origSize := int(binary.LittleEndian.Uint32(hdr[0:]))
	compSize := int(binary.LittleEndian.Uint32(hdr[4:]))
	checksum := hdr[8:a.hdrLen]
	if compSize == 0 || origSize == 0 {
		return nil, io.EOF
	}

	cipher := make([]byte, compSize)
	if _, err := readFullAt(a.src, cipher, info.segOffs[seg]); err != nil {
		return nil, fmt.Errorf("aea: cluster %d segment %d: reading data: %w", cluster, seg, err)
	}

	segKey := a.segmentKey(cluster, seg)
	segMAC := info.macs[32+32*seg : 32+32*seg+32]
	if !segKey.verify(segMAC, cipher, nil) {
		return nil, fmt.Errorf("aea: cluster %d segment %d: MAC mismatch (corrupted archive)", cluster, seg)
	}
	plain := make([]byte, compSize)
	if err := segKey.decryptInto(plain, cipher); err != nil {
		return nil, fmt.Errorf("aea: cluster %d segment %d: decrypting: %w", cluster, seg, err)
	}
	out := plain
	if origSize > compSize {
		out, err = decompressSegment(a.root.compression, plain, origSize)
		if err != nil {
			return nil, fmt.Errorf("aea: cluster %d segment %d: %w", cluster, seg, err)
		}
	}
	if err := verifySegmentChecksum(a.root.checksum, out, checksum); err != nil {
		return nil, fmt.Errorf("aea: cluster %d segment %d: %w", cluster, seg, err)
	}

	a.mu.Lock()
	if prev, ok := a.segCache[key]; ok {
		a.mu.Unlock()
		return prev, nil
	}
	a.segCache[key] = out
	a.segOrder = append(a.segOrder, key)
	a.cached += int64(len(out))
	for a.cached > segCacheBytes && len(a.segOrder) > 1 {
		oldest := a.segOrder[0]
		a.segOrder = a.segOrder[1:]
		a.cached -= int64(len(a.segCache[oldest]))
		delete(a.segCache, oldest)
	}
	a.mu.Unlock()
	return out, nil
}

// clusterInfo walks the chain up to cluster and returns its parsed header block.
func (a *RandomReader) clusterInfo(cluster int64) (clusterInfo, error) {
	a.discoverMu.Lock()
	defer a.discoverMu.Unlock()

	for {
		a.mu.Lock()
		n := len(a.clusters)
		if int64(n) > cluster {
			info := a.clusters[cluster]
			a.mu.Unlock()
			return info, nil
		}
		var off int64
		if n == 0 {
			off = a.firstClusterOff
		} else {
			prev := a.clusters[n-1]
			off = prev.payloadOff + prev.payloadSize
		}
		var prevHeaderOff int64 = -1
		if n > 0 {
			prevHeaderOff = a.clusters[n-1].headerOff
		}
		a.mu.Unlock()

		info, err := a.readCluster(int64(n), off, prevHeaderOff)
		if err != nil {
			return clusterInfo{}, err
		}
		a.mu.Lock()
		a.clusters = append(a.clusters, info)
		a.mu.Unlock()
	}
}

// readCluster reads, authenticates and decrypts one cluster header block.
func (a *RandomReader) readCluster(index, off, prevHeaderOff int64) (clusterInfo, error) {
	enc := make([]byte, a.headerBytes)
	if _, err := readFullAt(a.src, enc, off); err != nil {
		return clusterInfo{}, fmt.Errorf("aea: cluster %d: reading segment headers: %w", index, err)
	}
	macs := make([]byte, a.macBytes)
	if _, err := readFullAt(a.src, macs, off+a.headerBytes); err != nil {
		return clusterInfo{}, fmt.Errorf("aea: cluster %d: reading header MACs: %w", index, err)
	}

	clusterKey := deriveKey(macKeySize, a.mainKey, nil, indexedInfo("AEA_CK", uint32(index)))
	chekKey := dataKey(deriveKey(a.keyLen, clusterKey, nil, []byte("AEA_CHEK")))
	if prevHeaderOff >= 0 {
		prevMAC := make([]byte, 32)
		if _, err := readFullAt(a.src, prevMAC, prevHeaderOff+a.headerBytes); err != nil {
			return clusterInfo{}, fmt.Errorf("aea: cluster %d: reading chain MAC: %w", index-1, err)
		}
		if !chekKey.verify(prevMAC, enc, macs) {
			return clusterInfo{}, fmt.Errorf("aea: cluster %d: header MAC mismatch (corrupted archive)", index)
		}
	}

	hdrs := make([]byte, a.headerBytes)
	if err := chekKey.decryptInto(hdrs, enc); err != nil {
		return clusterInfo{}, fmt.Errorf("aea: cluster %d: decrypting segment headers: %w", index, err)
	}
	payloadOff := off + a.headerBytes + a.macBytes
	segOffs := make([]int64, a.root.segmentsPerCluster)
	var payloadSize int64
	for i := 0; i < int(a.root.segmentsPerCluster); i++ {
		segOffs[i] = payloadOff + payloadSize
		payloadSize += int64(binary.LittleEndian.Uint32(hdrs[i*a.hdrLen+4:]))
	}
	return clusterInfo{
		headerOff:   off,
		payloadOff:  payloadOff,
		payloadSize: payloadSize,
		hdrs:        hdrs,
		macs:        macs,
		segOffs:     segOffs,
	}, nil
}

func readFullAt(r io.ReaderAt, buf []byte, off int64) (int, error) {
	n, err := r.ReadAt(buf, off)
	if n == len(buf) {
		return n, nil
	}
	if err == nil {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}
