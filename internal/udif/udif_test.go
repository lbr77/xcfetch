package udif

import (
	"bytes"
	"crypto/rand"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// fixtureTree writes files mixing incompressible and compressible data.
func fixtureTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	random := make([]byte, 3<<20)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "random.bin"), random, 0o644); err != nil {
		t.Fatal(err)
	}
	text := bytes.Repeat([]byte("simulator runtime payload\n"), 100000)
	if err := os.WriteFile(filepath.Join(dir, "text.txt"), text, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// hdiutilImages builds one image per UDIF format plus a raw conversion.
func hdiutilImages(t *testing.T) (raw []byte, images map[string]string) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("hdiutil is macOS only")
	}
	if _, err := exec.LookPath("hdiutil"); err != nil {
		t.Skip("hdiutil not available")
	}
	dir := t.TempDir()
	base := filepath.Join(dir, "base.dmg")
	if out, err := exec.Command("hdiutil", "create", "-quiet", "-fs", "APFS", "-volname", "Fixture",
		"-format", "UDRW", "-srcfolder", fixtureTree(t), base).CombinedOutput(); err != nil {
		t.Skipf("hdiutil create failed (%v): %s", err, out)
	}
	convert := func(format, out string) {
		if msg, err := exec.Command("hdiutil", "convert", "-quiet", base, "-format", format, "-o", out).CombinedOutput(); err != nil {
			t.Fatalf("hdiutil convert %s: %v: %s", format, err, msg)
		}
	}
	convert("UDTO", filepath.Join(dir, "raw"))
	raw, err := os.ReadFile(filepath.Join(dir, "raw.cdr"))
	if err != nil {
		t.Fatal(err)
	}
	// UDRW (the read/write source) has no koly trailer; UDRO is the
	// read-only format with raw runs.
	images = map[string]string{}
	for _, f := range []string{"UDRO", "ULFO", "UDZO", "UDBZ", "ULMO"} {
		out := filepath.Join(dir, f+".dmg")
		convert(f, out)
		images[f] = out
	}
	return raw, images
}

func TestImagesMatchRawConversion(t *testing.T) {
	raw, images := hdiutilImages(t)
	for format, path := range images {
		t.Run(format, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !IsUDIF(bytes.NewReader(data), int64(len(data))) {
				t.Fatal("IsUDIF = false")
			}
			im, err := Open(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if im.Size() != int64(len(raw)) {
				t.Fatalf("logical size %d, raw conversion is %d", im.Size(), len(raw))
			}
			got := make([]byte, len(raw))
			if _, err := im.ReadAt(got, 0); err != nil && err != io.EOF {
				t.Fatalf("ReadAt: %v", err)
			}
			if !bytes.Equal(got, raw) {
				t.Fatal("logical disk differs from hdiutil's raw conversion")
			}
			for i := 0; i < 200; i++ {
				off := randN(t, len(raw))
				n := 1 + randN(t, 300000)
				if off+n > len(raw) {
					n = len(raw) - off
				}
				buf := make([]byte, n)
				if _, err := im.ReadAt(buf, int64(off)); err != nil && err != io.EOF {
					t.Fatalf("ReadAt(%d, %d): %v", off, n, err)
				}
				if !bytes.Equal(buf, raw[off:off+n]) {
					t.Fatalf("ReadAt(%d, %d) differs from the raw conversion", off, n)
				}
			}
			if len(im.Partitions()) == 0 {
				t.Error("no partitions reported")
			}
		})
	}
}

func TestNotUDIF(t *testing.T) {
	junk := bytes.Repeat([]byte{1}, 4096)
	if IsUDIF(bytes.NewReader(junk), int64(len(junk))) {
		t.Fatal("IsUDIF accepted junk")
	}
	if _, err := Open(bytes.NewReader(junk), int64(len(junk))); err != ErrNotUDIF {
		t.Fatalf("Open(junk) = %v, want ErrNotUDIF", err)
	}
}

func TestADC(t *testing.T) {
	// literal "abc", then a 2-byte match copying 3 bytes from distance 3.
	in := []byte{0x82, 'a', 'b', 'c', 0x00, 0x02}
	got, err := decodeADC(in, 6)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abcabc" {
		t.Fatalf("decodeADC = %q", got)
	}
}

func randN(t *testing.T, n int) int {
	t.Helper()
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		t.Fatal(err)
	}
	return int(v.Int64())
}
