package apfs_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/lbr77/xcfetch/internal/apfs"
	"github.com/lbr77/xcfetch/internal/udif"
)

// openImage opens the first volume of a UDIF image file.
func openImage(t *testing.T, path string) *apfs.Volume {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	im, err := udif.Open(f, st.Size())
	if err != nil {
		t.Fatalf("udif.Open: %v", err)
	}
	c, err := apfs.OpenDisk(im, im.Size())
	if err != nil {
		t.Fatalf("apfs.OpenDisk: %v", err)
	}
	vols, err := c.Volumes()
	if err != nil {
		t.Fatalf("Volumes: %v", err)
	}
	return vols[0]
}

func readNode(t *testing.T, v *apfs.Volume, n apfs.Node) []byte {
	t.Helper()
	r, err := v.Open(n)
	if err != nil {
		t.Fatalf("Open(%s): %v", n.Path, err)
	}
	buf := make([]byte, n.Size)
	if _, err := r.ReadAt(buf, 0); err != nil && err != io.EOF {
		t.Fatalf("ReadAt(%s): %v", n.Path, err)
	}
	return buf
}

// TestHdiutilVolume reads files, directories and symlinks from an ordinary
// (unsealed) APFS volume built by hdiutil.
func TestHdiutilVolume(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("hdiutil is macOS only")
	}
	if _, err := exec.LookPath("hdiutil"); err != nil {
		t.Skip("hdiutil not available")
	}
	src := t.TempDir()
	res := filepath.Join(src, "Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 26.5.simruntime/Contents/Resources")
	if err := os.MkdirAll(filepath.Join(res, "RuntimeRoot/usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	tool := make([]byte, 1796880)
	if _, err := rand.Read(tool); err != nil {
		t.Fatal(err)
	}
	order := bytes.Repeat([]byte("/usr/lib/libSystem.B.dylib\n"), 3000)
	files := map[string][]byte{
		"update_dyld_sim_shared_cache":   tool,
		"dylib-order.txt":                order,
		"dirty-data-segments-order.txt":  order[:5000],
		"RuntimeRoot/usr/lib/libA.dylib": []byte("A"),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(res, name), data, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("libA.dylib", filepath.Join(res, "RuntimeRoot/usr/lib/libB.dylib")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../..", filepath.Join(res, "RuntimeRoot/usr/lib/up")); err != nil {
		t.Fatal(err)
	}
	// Many entries in one directory spread the records over several leaves.
	many := filepath.Join(src, "many")
	if err := os.MkdirAll(many, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 600; i++ {
		name := filepath.Join(many, strings.Repeat("x", 40)+string(rune('a'+i%26))+strings.Repeat("y", i%7)+"-"+itoa(i))
		if err := os.WriteFile(name, []byte(itoa(i)), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	img := filepath.Join(t.TempDir(), "rt.dmg")
	if out, err := exec.Command("hdiutil", "create", "-quiet", "-fs", "APFS", "-volname", "iOS 26.5 Simulator",
		"-format", "ULFO", "-srcfolder", src, img).CombinedOutput(); err != nil {
		t.Skipf("hdiutil create failed (%v): %s", err, out)
	}
	v := openImage(t, img)
	if v.Name != "iOS 26.5 Simulator" {
		t.Errorf("volume name %q", v.Name)
	}

	base := "Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 26.5.simruntime/Contents/Resources/"
	for name, want := range files {
		n, err := v.Stat(base + name)
		if err != nil {
			t.Fatalf("Stat(%s): %v", name, err)
		}
		if n.Size != int64(len(want)) || !n.IsRegular() {
			t.Fatalf("%s: size %d regular=%v", name, n.Size, n.IsRegular())
		}
		if got := readNode(t, v, n); !bytes.Equal(got, want) {
			t.Fatalf("%s: contents differ", name)
		}
		if n.Perm() != 0o755 {
			t.Errorf("%s: mode %o", name, n.Perm())
		}
	}

	// Globs and brace-free alternatives resolve to on-disk spellings.
	got, err := v.Glob("Library/Developer/CoreSimulator/Profiles/Runtimes/*.simruntime/Contents/Resources/update_dyld_sim_shared_cache")
	if err != nil || len(got) != 1 || got[0] != base+"update_dyld_sim_shared_cache" {
		t.Fatalf("Glob = %v, %v", got, err)
	}
	// Case-insensitive lookup on a case-insensitive volume.
	if n, err := v.Stat(strings.ToLower(base) + "UPDATE_dyld_sim_shared_cache"); err != nil {
		t.Errorf("case-insensitive Stat: %v", err)
	} else if n.Path != base+"update_dyld_sim_shared_cache" {
		t.Errorf("case-insensitive Stat path %q", n.Path)
	}

	// Symlinks: the last component is not followed by Stat, intermediate ones are.
	link, err := v.Stat(base + "RuntimeRoot/usr/lib/libB.dylib")
	if err != nil || !link.IsSymlink() || link.Link != "libA.dylib" {
		t.Fatalf("Stat(libB) = %+v, %v", link, err)
	}
	through, err := v.StatFollow(base + "RuntimeRoot/usr/lib/libB.dylib")
	if err != nil || through.Size != 1 {
		t.Fatalf("StatFollow(libB) = %+v, %v", through, err)
	}
	up, err := v.Stat(base + "RuntimeRoot/usr/lib/up/dylib-order.txt")
	if err != nil || up.Path != base+"dylib-order.txt" {
		t.Fatalf("Stat through a relative dir symlink = %+v, %v", up, err)
	}

	entries, err := v.ReadDir("many")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 600 {
		t.Fatalf("ReadDir(many) = %d entries, want 600", len(entries))
	}
	if _, err := v.Stat(base + "missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat(missing) = %v, want ErrNotExist", err)
	}
}

// TestRuntimeImage checks the reader against a real, sealed simulator runtime
// image and its mounted copy. Set XCFETCH_TEST_RUNTIME_DMG to the image (for
// example /System/Library/AssetsV2/com_apple_MobileAsset_iOSSimulatorRuntime/
// <hash>.asset/AssetData/Restore/<build>.dmg) and XCFETCH_TEST_RUNTIME_MOUNT
// to where CoreSimulator mounted it (/Library/Developer/CoreSimulator/Volumes/
// iOS_<build>).
func TestRuntimeImage(t *testing.T) {
	dmg, mount := os.Getenv("XCFETCH_TEST_RUNTIME_DMG"), os.Getenv("XCFETCH_TEST_RUNTIME_MOUNT")
	if dmg == "" || mount == "" {
		t.Skip("set XCFETCH_TEST_RUNTIME_DMG and XCFETCH_TEST_RUNTIME_MOUNT")
	}
	v := openImage(t, dmg)
	if !v.Sealed {
		t.Fatalf("volume %q is not sealed", v.Name)
	}
	pattern := "Library/Developer/CoreSimulator/Profiles/Runtimes/*.simruntime/Contents/Resources/"
	for _, name := range []string{"update_dyld_sim_shared_cache", "dylib-order.txt", "dirty-data-segments-order.txt", "profile.plist"} {
		paths, err := v.Glob(pattern + name)
		if err != nil || len(paths) != 1 {
			t.Fatalf("Glob(%s) = %v, %v", name, paths, err)
		}
		n, err := v.Stat(paths[0])
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(filepath.Join(mount, paths[0]))
		if err != nil {
			t.Fatal(err)
		}
		got := readNode(t, v, n)
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: %d bytes differ from the mounted copy (%d bytes)", paths[0], len(got), len(want))
		}
		covered, err := v.Verify(n, bytes.NewReader(got))
		if err != nil {
			t.Fatalf("Verify(%s): %v", name, err)
		}
		if covered != n.Size {
			t.Errorf("%s: seal hashes cover %d of %d bytes", name, covered, n.Size)
		}
		// A flipped byte must be caught.
		bad := append([]byte(nil), got...)
		bad[len(bad)/2] ^= 1
		if _, err := v.Verify(n, bytes.NewReader(bad)); err == nil {
			t.Errorf("%s: Verify accepted corrupted data", name)
		}
	}
	// A symlink inside RuntimeRoot.
	link := "Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 26.5.simruntime/Contents/Resources/RuntimeRoot/usr/lib/libsqlite3.0.dylib"
	if want, err := os.Readlink(filepath.Join(mount, link)); err == nil {
		n, err := v.Stat(link)
		if err != nil || !n.IsSymlink() || n.Link != want {
			t.Errorf("Stat(%s) = %+v, %v; want link to %q", link, n, err, want)
		}
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}
