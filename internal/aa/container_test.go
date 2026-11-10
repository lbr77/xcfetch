package aa

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// aaItem builds one raw archive item: "AA01" | uint16 size | fields | blobs.
type aaItem struct {
	fields []byte
	blobs  [][]byte
}

func (it *aaItem) field(key string, sub byte, value []byte) {
	it.fields = append(it.fields, []byte(key)...)
	it.fields = append(it.fields, sub)
	it.fields = append(it.fields, value...)
}

func (it *aaItem) uinteger(key string, v uint64, width int) {
	buf := make([]byte, width)
	switch width {
	case 1:
		buf[0] = byte(v)
	case 2:
		binary.LittleEndian.PutUint16(buf, uint16(v))
	case 4:
		binary.LittleEndian.PutUint32(buf, uint32(v))
	case 8:
		binary.LittleEndian.PutUint64(buf, v)
	}
	it.field(key, byte('0'+width), buf)
}

func (it *aaItem) str(key, value string) {
	buf := make([]byte, 2+len(value))
	binary.LittleEndian.PutUint16(buf, uint16(len(value)))
	copy(buf[2:], value)
	it.field(key, 'P', buf)
}

func (it *aaItem) blob(key string, data []byte) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(len(data)))
	it.field(key, 'B', buf)
	it.blobs = append(it.blobs, data)
}

func (it *aaItem) encode() []byte {
	size := itemHeaderSize + len(it.fields)
	blobLen := 0
	for _, b := range it.blobs {
		blobLen += len(b)
	}
	out := make([]byte, 6, size+blobLen)
	copy(out, "AA01")
	binary.LittleEndian.PutUint16(out[4:], uint16(size))
	out = append(out, it.fields...)
	for _, b := range it.blobs {
		out = append(out, b...)
	}
	return out
}

// TestExtractNestedContainer mirrors the real simulator runtime asset: an outer
// archive of pathless payload blobs, each a compressed Apple Archive tree, plus
// a manifest archive whose entries carry no data.
func TestExtractNestedContainer(t *testing.T) {
	tool := aaTool(t)

	// Inner tree, produced by Apple's tool (so it exercises pbz framing too).
	tree := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tree, "AssetData/Restore"), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("dmg bytes\n"), 1000)
	if err := os.WriteFile(filepath.Join(tree, "AssetData/Restore/094-00001-001.dmg"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "AssetData/Restore/BuildManifest.plist"), []byte("<plist/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(t.TempDir(), "inner.aar")
	if out, err := exec.Command(tool, "archive", "-d", tree, "-o", inner, "-a", "lzfse").CombinedOutput(); err != nil {
		t.Fatalf("aa archive: %v: %s", err, out)
	}
	innerBytes, err := os.ReadFile(inner)
	if err != nil {
		t.Fatal(err)
	}

	// Manifest archive: same paths, no data blobs.
	manifest := &aaItem{}
	manifest.field("TYP", '1', []byte("D"))
	manifest.str("PAT", "")
	manifest.uinteger("MOD", 0o755, 2)
	manifestFile := &aaItem{}
	manifestFile.field("TYP", '1', []byte("F"))
	manifestFile.str("PAT", "AssetData/Restore/094-00001-001.dmg")
	manifestFile.uinteger("MOD", 0o644, 2)

	// Container: metadata item, payload blob, manifest archive.
	meta := &aaItem{}
	meta.field("TYP", '1', []byte("M"))
	meta.field("YOP", '1', []byte("M"))
	meta.blob("DAT", []byte("manifest text"))

	blobItem := &aaItem{}
	blobItem.field("TYP", '1', []byte("M"))
	blobItem.blob("DAT", innerBytes)

	manifestItem := &aaItem{}
	manifestItem.field("TYP", '1', []byte("M"))
	manifestItem.blob("DAT", append(manifest.encode(), manifestFile.encode()...))

	var container bytes.Buffer
	for _, it := range []*aaItem{meta, blobItem, manifestItem} {
		container.Write(it.encode())
	}

	dest := t.TempDir()
	if err := Extract(dest, bytes.NewReader(container.Bytes())); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "AssetData/Restore/094-00001-001.dmg"))
	if err != nil {
		t.Fatalf("payload file missing: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: %d vs %d bytes", len(got), len(payload))
	}
	// The manifest item must not clobber the real file with an empty one.
	if len(got) == 0 {
		t.Fatal("manifest entry overwrote the payload")
	}
	if got, err := os.ReadFile(filepath.Join(dest, "payload-1.bin")); err != nil || string(got) != "manifest text" {
		t.Errorf("metadata payload = %q, %v", got, err)
	}
}

func TestExtractContainerRejectsDeepNesting(t *testing.T) {
	// Build a self-similar chain of containers deeper than maxDepth.
	nested := []byte("AA01\x16\x00TYP1MYOP1MDATB\x00\x00\x00\x00")
	_ = nested // a zero-length payload is not enough to recurse; use empty archive
	inner := []byte("AA01\x0a\x00TYP1M")
	cur := inner
	for i := 0; i < maxDepth+2; i++ {
		it := &aaItem{}
		it.field("TYP", '1', []byte("M"))
		it.blob("DAT", cur)
		cur = it.encode()
	}
	err := Extract(t.TempDir(), bytes.NewReader(cur))
	if err == nil {
		t.Fatal("expected a depth error")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("depth")) {
		t.Errorf("err = %v, want a depth error", err)
	}
}
