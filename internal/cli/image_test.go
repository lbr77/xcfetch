package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestExpandBraces(t *testing.T) {
	got := expandBraces("a/{x,y}/b{1,2}")
	want := []string{"a/x/b1", "a/x/b2", "a/y/b1", "a/y/b2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expandBraces = %v, want %v", got, want)
	}
	if got := expandBraces("plain"); !reflect.DeepEqual(got, []string{"plain"}) {
		t.Fatalf("expandBraces(plain) = %v", got)
	}
}

func TestSafeImagePath(t *testing.T) {
	for p, ok := range map[string]bool{
		"Library/x":   true,
		"../x":        false,
		"/abs":        false,
		"a/./b":       false,
		"":            false,
		"a//b":        false,
		"a/b..c/file": true,
	} {
		if got := safeImagePath(p); got != ok {
			t.Errorf("safeImagePath(%q) = %v", p, got)
		}
	}
}

// TestRuntimeExtractLocalImage pulls files out of a local disk image by glob.
func TestRuntimeExtractLocalImage(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("hdiutil is macOS only")
	}
	if _, err := exec.LookPath("hdiutil"); err != nil {
		t.Skip("hdiutil not available")
	}
	src := t.TempDir()
	res := filepath.Join(src, "Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 26.5.simruntime/Contents/Resources")
	if err := os.MkdirAll(res, 0o755); err != nil {
		t.Fatal(err)
	}
	want := map[string][]byte{
		"update_dyld_sim_shared_cache":  bytes.Repeat([]byte{0xcf, 0xfa, 0xed, 0xfe}, 50000),
		"dylib-order.txt":               []byte("/usr/lib/libobjc.A.dylib\n"),
		"dirty-data-segments-order.txt": []byte("/usr/lib/libc++.1.dylib\n"),
		"profile.plist":                 []byte("<plist/>"),
	}
	for name, data := range want {
		if err := os.WriteFile(filepath.Join(res, name), data, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	img := filepath.Join(t.TempDir(), "rt.dmg")
	if out, err := exec.Command("hdiutil", "create", "-quiet", "-fs", "APFS", "-volname", "iOS 26.5 Simulator",
		"-format", "ULFO", "-srcfolder", src, img).CombinedOutput(); err != nil {
		t.Skipf("hdiutil create failed (%v): %s", err, out)
	}

	dest := t.TempDir()
	var stdout, stderr bytes.Buffer
	pattern := "Library/Developer/CoreSimulator/Profiles/Runtimes/*.simruntime/Contents/Resources/" +
		"{update_dyld_sim_shared_cache,dylib-order.txt,dirty-data-segments-order.txt}"
	err := Run(context.Background(), []string{"runtime", "extract", "--local", img, "--image", pattern, "--out", dest}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("extract: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	for name, data := range want {
		path := filepath.Join(dest, "Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 26.5.simruntime/Contents/Resources", name)
		got, err := os.ReadFile(path)
		if name == "profile.plist" {
			if err == nil {
				t.Errorf("%s was extracted but not asked for", name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v\n%s", name, err, stdout.String())
		}
		if !bytes.Equal(got, data) {
			t.Errorf("%s: contents differ", name)
		}
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o755 {
			t.Errorf("%s: mode %v", name, st.Mode())
		}
	}
	if !strings.Contains(stdout.String(), "extracted 3 files") {
		t.Errorf("summary missing: %s", stdout.String())
	}

	// A path that is not there is an error naming it.
	stdout.Reset()
	err = Run(context.Background(), []string{"runtime", "extract", "--local", img, "--image", "nope/missing", "--out", dest}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "nope/missing") {
		t.Fatalf("missing path: err = %v", err)
	}

	// --list on a directory shows its children.
	stdout.Reset()
	err = Run(context.Background(), []string{"runtime", "extract", "--local", img, "--list", "--image",
		"Library/Developer/CoreSimulator/Profiles/Runtimes/*.simruntime/Contents/Resources"}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "update_dyld_sim_shared_cache") {
		t.Errorf("listing lacks the tool: %s", stdout.String())
	}
}
