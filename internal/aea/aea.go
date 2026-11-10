// Package aea decrypts Apple Encrypted Archives (AEA1).
//
// It is a pure Go implementation of the AEA container format described in
// https://github.com/kinnay/AEA/blob/main/FORMAT.md: HKDF-SHA256 key
// derivation, HMAC-SHA256 authentication and AES-CTR encryption, with the
// payload decompressed per segment (none, LZFSE, LZMA, ZLIB, LZ4).
//
// Decryption is streaming: the archive is consumed block by block and the
// plaintext is handed to the caller's io.Writer as soon as a segment has been
// verified, so memory use is bounded by the segment size of the archive and
// not by its total size.
package aea

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Header describes the prologue of an AEA archive.
//
// The type is called HeaderInfo rather than Header because this package also
// exposes a Header function; Go does not allow a type and a function to share
// a name.
type HeaderInfo struct {
	Profile    uint32            // 24-bit profile id
	ScryptBits uint8             // scrypt strength selector (profile 5)
	AuthData   []byte            // raw auth data blob
	Sizes      map[string]string // parsed "key\0value" auth data pairs, nil if not well formed
}

// Archive profiles.
const (
	profileNone         uint32 = 0 // signed, no encryption
	profileSymmetric    uint32 = 1 // symmetric encryption
	profileSymmetricSig uint32 = 2 // symmetric encryption, signed
	profileECDHE        uint32 = 3 // asymmetric encryption
	profileECDHESig     uint32 = 4 // asymmetric encryption, signed
	profilePassword     uint32 = 5 // password based encryption
)

const (
	fileHeaderSize  = 12
	rootHeaderSize  = 0x30
	dataKeySize     = 80 // HMAC key, AES-CTR key, AES-CTR IV
	macKeySize      = 32
	maxAuthDataSize = 64 << 20 // sanity bound, keeps hostile headers from exhausting memory
)

// profileName returns the name used by Apple's aea tool.
func profileName(p uint32) string {
	switch p {
	case profileNone:
		return "hkdf_sha256_hmac__none__ecdsa_p256"
	case profileSymmetric:
		return "hkdf_sha256_aesctr_hmac__symmetric__none"
	case profileSymmetricSig:
		return "hkdf_sha256_aesctr_hmac__symmetric__ecdsa_p256"
	case profileECDHE:
		return "hkdf_sha256_aesctr_hmac__ecdhe_p256__none"
	case profileECDHESig:
		return "hkdf_sha256_aesctr_hmac__ecdhe_p256__ecdsa_p256"
	case profilePassword:
		return "hkdf_sha256_aesctr_hmac__scrypt__none"
	}
	return fmt.Sprintf("unknown profile %d", p)
}

// signatureSize is the size of the signature section for a profile.
func signatureSize(p uint32) int {
	switch p {
	case profileNone:
		return 128
	case profileSymmetricSig, profileECDHESig:
		return 160 // 128 byte ECDSA signature + 32 byte MAC
	}
	return 0
}

// publicKeySize is the size of the public key section for a profile.
func publicKeySize(p uint32) int {
	switch p {
	case profileNone:
		return 32 // main key seed
	case profileECDHE, profileECDHESig:
		return 65 // X9.62 uncompressed sender public key
	}
	return 0
}

// keySize is the size of the derived data keys for a profile.
func keySize(p uint32) int {
	if p == profileNone {
		return macKeySize
	}
	return dataKeySize
}

func isEncrypted(p uint32) bool { return p != profileNone }

// fileHeader is the fixed 12 byte prologue of an AEA file.
type fileHeader struct {
	profile  uint32
	scrypt   uint8
	authSize uint32
}

func readFileHeader(r io.Reader) (fileHeader, error) {
	var b [fileHeaderSize]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return fileHeader{}, fmt.Errorf("aea: reading file header: %w", err)
	}
	if string(b[:4]) != "AEA1" {
		return fileHeader{}, fmt.Errorf("aea: not an AEA archive: bad magic %q", string(b[:4]))
	}
	return fileHeader{
		profile:  uint32(b[4]) | uint32(b[5])<<8 | uint32(b[6])<<16,
		scrypt:   b[7],
		authSize: binary.LittleEndian.Uint32(b[8:]),
	}, nil
}

func (h fileHeader) validate() error {
	if h.profile > profilePassword {
		return fmt.Errorf("aea: %s", profileName(h.profile))
	}
	if h.scrypt > 3 {
		return fmt.Errorf("aea: invalid scrypt strength %d", h.scrypt)
	}
	if h.authSize > maxAuthDataSize {
		return fmt.Errorf("aea: auth data size %d exceeds limit %d", h.authSize, maxAuthDataSize)
	}
	return nil
}

// Header parses the file header and auth data of the archive in r. Nothing
// beyond the auth data is consumed from r.
func Header(r io.Reader) (HeaderInfo, error) {
	fh, err := readFileHeader(r)
	if err != nil {
		return HeaderInfo{}, err
	}
	if err := fh.validate(); err != nil {
		return HeaderInfo{}, err
	}
	h := HeaderInfo{Profile: fh.profile, ScryptBits: fh.scrypt}
	if fh.authSize > 0 {
		h.AuthData = make([]byte, fh.authSize)
		if _, err := io.ReadFull(r, h.AuthData); err != nil {
			return HeaderInfo{}, fmt.Errorf("aea: reading auth data: %w", err)
		}
		h.Sizes = parseAuthPairs(h.AuthData)
	}
	return h, nil
}

// parseAuthPairs decodes the auth data as a sequence of
// uint32 length prefixed "key\0value" pairs. It returns nil when the blob is
// not a well formed sequence of pairs (a raw auth data blob is legal too).
func parseAuthPairs(b []byte) map[string]string {
	if len(b) < 4 {
		return nil
	}
	pairs := make(map[string]string)
	for len(b) > 0 {
		if len(b) < 4 {
			return nil
		}
		n := uint64(binary.LittleEndian.Uint32(b))
		b = b[4:]
		if n > uint64(len(b)) {
			return nil
		}
		pair := b[:n]
		b = b[n:]
		i := bytes.IndexByte(pair, 0)
		if i < 0 {
			return nil
		}
		key := string(pair[:i])
		if _, dup := pairs[key]; dup {
			return nil
		}
		pairs[key] = string(pair[i+1:])
	}
	if len(pairs) == 0 {
		return nil
	}
	return pairs
}

// macKey is the first 32 bytes of a data key: the HMAC-SHA256 key.
// dataKey holds a full 32 (MAC only) or 80 byte (MAC + AES-CTR) key.
type dataKey []byte

// mac computes the AEA MAC: HMAC-SHA256 over salt || data || le64(len(salt)).
func macOf(key, data, salt []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(salt)
	m.Write(data)
	var l [8]byte
	binary.LittleEndian.PutUint64(l[:], uint64(len(salt)))
	m.Write(l[:])
	return m.Sum(nil)
}

// verify reports whether got is the MAC of data with the given salt.
func (k dataKey) verify(got, data, salt []byte) bool {
	return hmac.Equal(got, macOf(k[:macKeySize], data, salt))
}

// decryptInto decrypts src into dst (which must be the same length) with
// AES-CTR. For MAC-only keys (profile 0) the data is stored in the clear.
func (k dataKey) decryptInto(dst, src []byte) error {
	if len(k) == macKeySize {
		copy(dst, src)
		return nil
	}
	block, err := aes.NewCipher(k[32:64])
	if err != nil {
		return fmt.Errorf("aes: %w", err)
	}
	cipher.NewCTR(block, k[64:80]).XORKeyStream(dst, src)
	return nil
}

// deriveKey runs HKDF-SHA256 with the given salt and info.
func deriveKey(n int, ikm, salt, info []byte) []byte {
	out := make([]byte, n)
	k := hkdf.New(sha256.New, ikm, salt, info)
	if _, err := io.ReadFull(k, out); err != nil {
		// hkdf only fails if out exceeds 255*32 bytes, which cannot happen.
		panic("aea: hkdf: " + err.Error())
	}
	return out
}

// indexedInfo returns info || le32(index) for the key derivation infos that
// carry a cluster or segment index.
func indexedInfo(info string, index uint32) []byte {
	b := make([]byte, len(info)+4)
	copy(b, info)
	binary.LittleEndian.PutUint32(b[len(info):], index)
	return b
}

// mainKeyInfo builds the info for the main key: "AEA_AMK", the 24-bit profile
// and scrypt strength from the file header, then any public keys the profile
// mixes into the derivation.
func mainKeyInfo(profile uint32, scrypt uint8, keys ...[]byte) []byte {
	b := make([]byte, 0, 11+65*3)
	b = append(b, "AEA_AMK"...)
	b = append(b, byte(profile), byte(profile>>8), byte(profile>>16), scrypt)
	for _, k := range keys {
		b = append(b, k...)
	}
	return b
}

// rootHeader is the decrypted 48 byte root header.
type rootHeader struct {
	originalSize       uint64
	archiveSize        uint64
	segmentSize        uint32
	segmentsPerCluster uint32
	compression        byte
	checksum           byte
}

func parseRootHeader(b []byte) (rootHeader, error) {
	if len(b) < rootHeaderSize {
		return rootHeader{}, fmt.Errorf("aea: root header truncated: %d bytes", len(b))
	}
	rh := rootHeader{
		originalSize:       binary.LittleEndian.Uint64(b[0:]),
		archiveSize:        binary.LittleEndian.Uint64(b[8:]),
		segmentSize:        binary.LittleEndian.Uint32(b[16:]),
		segmentsPerCluster: binary.LittleEndian.Uint32(b[20:]),
		compression:        b[24],
		checksum:           b[25],
	}
	if rh.segmentSize == 0 {
		return rootHeader{}, fmt.Errorf("aea: root header: zero segment size")
	}
	if rh.segmentsPerCluster == 0 || rh.segmentsPerCluster > 1<<24 {
		return rootHeader{}, fmt.Errorf("aea: root header: invalid segments per cluster %d", rh.segmentsPerCluster)
	}
	switch rh.compression {
	case '-', '4', 'e', 'x', 'z':
	case 'b', 'f', 'm':
		return rootHeader{}, fmt.Errorf("aea: root header: unsupported compression id %q", rh.compression)
	default:
		return rootHeader{}, fmt.Errorf("aea: root header: unknown compression id %q", rh.compression)
	}
	switch rh.checksum {
	case 0, 1, 2:
	default:
		return rootHeader{}, fmt.Errorf("aea: root header: unknown checksum algorithm %d", rh.checksum)
	}
	return rh, nil
}

func (rh rootHeader) checksumSize() int {
	switch rh.checksum {
	case 0:
		return 0
	case 1:
		return 8
	default:
		return 32
	}
}

// Decrypt streams the plaintext of the AEA archive in r to w.
//
// key is the 32-byte symmetric key for profiles 1 and 2, the passphrase for
// profile 5, and must be nil for profile 0 (signed, unencrypted).
//
// Every header, segment and checksum is verified; a failure is reported with
// the stage that failed. The plaintext is written incrementally, so w may be a
// file or network connection without buffering the plaintext.
func Decrypt(w io.Writer, r io.Reader, key []byte) error {
	br := bufio.NewReaderSize(r, 64<<10)
	fh, err := readFileHeader(br)
	if err != nil {
		return err
	}
	if err := fh.validate(); err != nil {
		return err
	}

	// Auth data.
	authData := make([]byte, fh.authSize)
	if _, err := io.ReadFull(br, authData); err != nil {
		return fmt.Errorf("aea: reading auth data: %w", err)
	}

	// Signature. Verification requires the signer's public key, which this API
	// does not take; the section is skipped but still advances the stream so
	// profiles 0, 2 and 4 parse correctly.
	if n := int64(signatureSize(fh.profile)); n > 0 {
		if _, err := io.CopyN(io.Discard, br, n); err != nil {
			return fmt.Errorf("aea: reading signature section: %w", err)
		}
	}

	// Public key section.
	pub := make([]byte, publicKeySize(fh.profile))
	if _, err := io.ReadFull(br, pub); err != nil {
		return fmt.Errorf("aea: reading public key section: %w", err)
	}

	var mainSalt [32]byte
	var rootMAC [32]byte
	var encRoot [rootHeaderSize]byte
	var clusterMAC [32]byte
	if _, err := io.ReadFull(br, mainSalt[:32]); err != nil {
		return fmt.Errorf("aea: reading main salt: %w", err)
	}
	if _, err := io.ReadFull(br, rootMAC[:]); err != nil {
		return fmt.Errorf("aea: reading root header MAC: %w", err)
	}
	if _, err := io.ReadFull(br, encRoot[:]); err != nil {
		return fmt.Errorf("aea: reading root header: %w", err)
	}
	if _, err := io.ReadFull(br, clusterMAC[:]); err != nil {
		return fmt.Errorf("aea: reading first cluster header MAC: %w", err)
	}

	mainKey, err := deriveMainKey(fh, pub, mainSalt[:], key)
	if err != nil {
		return err
	}
	ks := keySize(fh.profile)

	// Root header: MAC then decrypt (or plain copy for profile 0).
	rootKey := dataKey(deriveKey(ks, mainKey, nil, []byte("AEA_RHEK")))
	if !rootKey.verify(rootMAC[:], encRoot[:], append(clusterMAC[:], authData...)) {
		return fmt.Errorf("aea: root header MAC mismatch (wrong key or corrupted archive)")
	}
	var rootPlain [rootHeaderSize]byte
	if err := rootKey.decryptInto(rootPlain[:], encRoot[:]); err != nil {
		return fmt.Errorf("aea: decrypting root header: %w", err)
	}
	rh, err := parseRootHeader(rootPlain[:])
	if err != nil {
		return err
	}
	if rh.originalSize == 0 {
		return nil
	}

	d := &decryptor{
		keySize:   ks,
		mainKey:   mainKey,
		root:      rh,
		segHdrLen: 8 + rh.checksumSize(),
	}
	return d.run(w, br, clusterMAC[:])
}

// deriveMainKey derives the 32 byte main key from the profile specific key
// material.
func deriveMainKey(fh fileHeader, pub, mainSalt, key []byte) ([]byte, error) {
	var (
		ikm  []byte
		salt = mainSalt
		info []byte
	)
	switch fh.profile {
	case profileNone:
		// The main key seed is stored in the public key section.
		ikm = pub
		// Profile 0 is signed and mixes the signer's public key into the info,
		// but the seed and MAC alone are enough to verify the archive.
		info = mainKeyInfo(fh.profile, fh.scrypt)
	case profileSymmetric:
		if len(key) != macKeySize {
			return nil, fmt.Errorf("aea: profile 1 requires a %d-byte symmetric key, got %d bytes", macKeySize, len(key))
		}
		ikm = key
		info = mainKeyInfo(fh.profile, fh.scrypt)
	case profileSymmetricSig:
		return nil, fmt.Errorf("aea: profile 2 requires the ECDSA signing public key for key derivation, which is not supported")
	case profileECDHE, profileECDHESig:
		return nil, fmt.Errorf("aea: profile %d is ECDHE encrypted and requires the recipient private key, which is not supported", fh.profile)
	case profilePassword:
		if len(key) == 0 {
			return nil, errors.New("aea: profile 5 requires a password")
		}
		var err error
		ikm, salt, err = passwordKeyMaterial(string(key), fh.scrypt, mainSalt)
		if err != nil {
			return nil, err
		}
		info = mainKeyInfo(fh.profile, fh.scrypt)
	}
	return deriveKey(macKeySize, ikm, salt, info), nil
}

// decryptor walks the clusters of an archive.
type decryptor struct {
	keySize   int
	mainKey   []byte
	root      rootHeader
	segHdrLen int // 8 + checksum size

	segHdrs    []byte // encrypted segment headers of the current cluster
	segHdrsRaw []byte // decrypted segment headers
	macs       []byte // next cluster MAC followed by the per segment MACs
	cipherBuf  []byte // encrypted segment payload
	plainBuf   []byte // decrypted segment payload
	plainTail  []byte // decompressed segment payload, when it does not fit plainBuf
}

// run decodes every cluster of the archive, writing verified plaintext to w.
func (d *decryptor) run(w io.Writer, r io.Reader, firstClusterMAC []byte) error {
	spc := int(d.root.segmentsPerCluster)
	hdrBlock := d.segHdrLen * spc
	if hdrBlock <= 0 || hdrBlock > maxAuthDataSize {
		return fmt.Errorf("aea: root header: segment header block of %d bytes is out of range", hdrBlock)
	}
	d.segHdrs = make([]byte, hdrBlock)
	d.segHdrsRaw = make([]byte, hdrBlock)
	d.macs = make([]byte, 32+(32*spc))

	// expectMAC must be its own buffer: d.macs is reused for every cluster, so
	// aliasing it here would compare each cluster against its own MAC.
	var expectMAC [32]byte
	copy(expectMAC[:], firstClusterMAC)
	var written uint64

	for cluster := uint32(0); ; cluster++ {
		clusterKey := deriveKey(macKeySize, d.mainKey, nil, indexedInfo("AEA_CK", cluster))
		headerKey := dataKey(deriveKey(d.keySize, clusterKey, nil, []byte("AEA_CHEK")))

		if _, err := io.ReadFull(r, d.segHdrs); err != nil {
			return fmt.Errorf("aea: cluster %d: reading segment headers: %w", cluster, err)
		}
		if _, err := io.ReadFull(r, d.macs); err != nil {
			return fmt.Errorf("aea: cluster %d: reading header MACs: %w", cluster, err)
		}
		if !headerKey.verify(expectMAC[:], d.segHdrs, d.macs) {
			return fmt.Errorf("aea: cluster %d: header MAC mismatch (corrupted archive)", cluster)
		}
		if err := headerKey.decryptInto(d.segHdrsRaw, d.segHdrs); err != nil {
			return fmt.Errorf("aea: cluster %d: decrypting segment headers: %w", cluster, err)
		}

		for seg := 0; seg < spc; seg++ {
			hdr := d.segHdrsRaw[seg*d.segHdrLen:]
			origSize := int(binary.LittleEndian.Uint32(hdr[0:]))
			compSize := int(binary.LittleEndian.Uint32(hdr[4:]))
			checksum := hdr[8:d.segHdrLen]

			if compSize == 0 || origSize == 0 {
				return fmt.Errorf("aea: cluster %d segment %d: empty segment before end of data", cluster, seg)
			}
			if compSize > origSize || uint64(origSize) > uint64(d.root.segmentSize) {
				return fmt.Errorf("aea: cluster %d segment %d: invalid sizes (original %d, compressed %d, segment size %d)",
					cluster, seg, origSize, compSize, d.root.segmentSize)
			}

			d.cipherBuf = grow(d.cipherBuf, compSize)
			payload := d.cipherBuf[:compSize]
			if _, err := io.ReadFull(r, payload); err != nil {
				return fmt.Errorf("aea: cluster %d segment %d: reading data: %w", cluster, seg, err)
			}

			segKey := dataKey(deriveKey(d.keySize, clusterKey, nil, indexedInfo("AEA_SK", uint32(seg))))
			segMAC := d.macs[32+32*seg : 32+32*seg+32]
			if !segKey.verify(segMAC, payload, nil) {
				return fmt.Errorf("aea: cluster %d segment %d: MAC mismatch (corrupted archive)", cluster, seg)
			}
			d.plainBuf = grow(d.plainBuf, compSize)
			plain := d.plainBuf[:compSize]
			if err := segKey.decryptInto(plain, payload); err != nil {
				return fmt.Errorf("aea: cluster %d segment %d: decrypting data: %w", cluster, seg, err)
			}

			out := plain
			if origSize > compSize {
				var derr error
				out, derr = d.decompress(plain, origSize, cluster, seg)
				if derr != nil {
					return derr
				}
			}
			if err := d.verifyChecksum(out, checksum); err != nil {
				return fmt.Errorf("aea: cluster %d segment %d: %w", cluster, seg, err)
			}
			if _, err := w.Write(out); err != nil {
				return fmt.Errorf("aea: cluster %d segment %d: writing plaintext: %w", cluster, seg, err)
			}

			written += uint64(origSize)
			if written > d.root.originalSize {
				return fmt.Errorf("aea: cluster %d segment %d: plaintext exceeds announced size %d",
					cluster, seg, d.root.originalSize)
			}
			if written == d.root.originalSize {
				return nil
			}
		}

		copy(expectMAC[:], d.macs[:32])
	}
}

// grow resizes b to n bytes, reusing its capacity when possible.
func grow(b []byte, n int) []byte {
	if cap(b) >= n {
		return b[:n]
	}
	return make([]byte, n)
}
