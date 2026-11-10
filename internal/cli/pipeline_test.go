package cli

import (
	"bytes"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestUnpackAppleArchiveAEA exercises the production path for simulator
// runtimes: Apple Encrypted Archive -> streaming decrypt -> Apple Archive
// extraction, with fixtures produced by Apple's own aea/aa tools.
func TestUnpackAppleArchiveAEA(t *testing.T) {
	for _, tool := range []string{"/usr/bin/aa", "/usr/bin/aea"} {
		if _, err := os.Stat(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	key := bytes.Repeat([]byte{0x42}, 32)
	payload := make([]byte, 3<<20)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "AssetData/Restore"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "AssetData/Restore/fake.dmg"), payload, 0o644); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(t.TempDir(), "t.aar")
	if out, err := exec.Command("/usr/bin/aa", "archive", "-d", src, "-o", archive, "-a", "lzfse").CombinedOutput(); err != nil {
		t.Fatalf("aa archive: %v: %s", err, out)
	}
	keyFile := filepath.Join(t.TempDir(), "key.txt")
	if err := os.WriteFile(keyFile, []byte("hex:"+hexEncode(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	encrypted := filepath.Join(t.TempDir(), "t.aar.aea")
	if out, err := exec.Command("/usr/bin/aea", "encrypt", "-i", archive, "-o", encrypted,
		"-profile", "1", "-key", keyFile, "-a", "lzfse").CombinedOutput(); err != nil {
		t.Fatalf("aea encrypt: %v: %s", err, out)
	}

	dest := t.TempDir()
	if err := unpackAppleArchive(encrypted, dest, key); err != nil {
		t.Fatalf("unpackAppleArchive: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "AssetData/Restore/fake.dmg"))
	if err != nil {
		t.Fatalf("extracted file: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch (%d vs %d bytes)", len(got), len(payload))
	}
}

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
