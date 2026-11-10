package dmg

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestExtractHdiutil builds a real APFS disk image with hdiutil and checks the
// extraction and the .simruntime discovery.
func TestExtractHdiutil(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("hdiutil is macOS only")
	}
	if _, err := exec.LookPath("hdiutil"); err != nil {
		t.Skip("hdiutil not available")
	}
	payload := bytes.Repeat([]byte("runtime payload\n"), 4096)

	src := t.TempDir()
	bundle := filepath.Join(src, "Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 26.5.simruntime/Contents/Resources")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "RuntimeRoot.txt"), payload, 0o644); err != nil {
		t.Fatal(err)
	}

	img := filepath.Join(t.TempDir(), "runtime.dmg")
	if out, err := exec.Command("hdiutil", "create", "-quiet", "-fs", "APFS", "-volname", "iOS 26.5 Simulator",
		"-srcfolder", src, img).CombinedOutput(); err != nil {
		t.Skipf("hdiutil create failed (%v): %s", err, out)
	}

	dest := t.TempDir()
	images, err := Extract(context.Background(), img, dest, ToolHdiutil)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(images) != 1 {
		t.Fatalf("found %d simruntime bundles, want 1: %v", len(images), images)
	}
	got, err := os.ReadFile(filepath.Join(images[0], "Contents/Resources/RuntimeRoot.txt"))
	if err != nil {
		t.Fatalf("reading extracted file: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
}

func TestResolveTool(t *testing.T) {
	if got := resolve(ToolHdiutil); got != ToolHdiutil {
		t.Errorf("explicit tool overridden: %v", got)
	}
	if _, err := exec.LookPath("hdiutil"); err == nil && runtime.GOOS == "darwin" {
		if got := resolve(ToolAuto); got == ToolAuto && true {
			// Either 7z or hdiutil may win depending on PATH; both are fine.
			if got != Tool7z && got != ToolHdiutil {
				t.Errorf("resolve(auto) = %v", got)
			}
		}
	}
}

func TestFindFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "a/b"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "a/b/x.dmg"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(root, "a/y.dmg"), []byte("y"), 0o644)
	got, err := findFiles(root, ".dmg")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("found %d files, want 2: %v", len(got), got)
	}
}
