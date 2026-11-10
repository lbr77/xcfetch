package aa

import (
	"bytes"
	"crypto/rand"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func aaTool(t *testing.T) string {
	t.Helper()
	const tool = "/usr/bin/aa"
	if _, err := os.Stat(tool); err != nil {
		t.Skip("Apple's aa tool not available")
	}
	return tool
}

// tree builds a fixture with every entry kind we claim to support.
func tree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "AssetData/Restore"), 0o755))
	must(os.MkdirAll(filepath.Join(root, "sub/deep"), 0o755))
	must(os.MkdirAll(filepath.Join(root, "dir with space"), 0o755))
	must(os.WriteFile(filepath.Join(root, "a.txt"), []byte("hello\n"), 0o644))
	must(os.WriteFile(filepath.Join(root, "empty"), nil, 0o600))
	must(os.WriteFile(filepath.Join(root, "sub/deep/y.bin"), bytes.Repeat([]byte{0xAB}, 4096), 0o755))
	must(os.WriteFile(filepath.Join(root, "dir with space/ünïcode.txt"), []byte("unicode\n"), 0o644))
	big := make([]byte, 3<<20)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	must(os.WriteFile(filepath.Join(root, "AssetData/Restore/big.dmg"), big, 0o644))
	must(os.Symlink("a.txt", filepath.Join(root, "link")))
	return root
}

func archive(t *testing.T, tool, src, algo string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "t.aar")
	args := []string{"archive", "-d", src, "-o", out}
	if algo != "" {
		args = append(args, "-a", algo)
	}
	if b, err := exec.Command(tool, args...).CombinedOutput(); err != nil {
		t.Fatalf("aa archive %v: %v: %s", args, err, b)
	}
	return out
}

// snapshot describes a tree as name -> content/mode/symlink target.
func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			out[rel] = "dir " + info.Mode().Perm().String()
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			out[rel] = "link -> " + link
		default:
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			out[rel] = "file " + info.Mode().Perm().String() + " " + string(data)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestExtractMatchesAppleTool(t *testing.T) {
	tool := aaTool(t)
	src := tree(t)
	want := snapshot(t, src)

	for _, algo := range []string{"raw", "lzfse", "zlib", "lzma", "lz4"} {
		t.Run(algo, func(t *testing.T) {
			ar := archive(t, tool, src, algo)
			f, err := os.Open(ar)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			dest := t.TempDir()
			if err := Extract(dest, f); err != nil {
				t.Fatalf("Extract: %v", err)
			}
			got := snapshot(t, dest)
			if !equalTrees(want, got) {
				t.Fatalf("tree mismatch\nwant: %s\ngot:  %s", dump(want), dump(got))
			}
		})
	}
}

func TestExtractMultiBlockStream(t *testing.T) {
	tool := aaTool(t)
	// A 12 MiB file forces several 4 MiB stream blocks.
	src := t.TempDir()
	big := make([]byte, 12<<20)
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "big.bin"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	ar := archive(t, tool, src, "lzfse")
	f, err := os.Open(ar)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dest := t.TempDir()
	if err := Extract(dest, f); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "big.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, big) {
		t.Fatalf("payload mismatch: %d vs %d bytes", len(got), len(big))
	}
}

func TestExtractFilter(t *testing.T) {
	tool := aaTool(t)
	src := tree(t)
	ar := archive(t, tool, src, "lzfse")
	f, err := os.Open(ar)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dest := t.TempDir()
	if err := ExtractFilter(dest, f, func(p string) bool {
		return strings.HasSuffix(p, "f") || strings.HasSuffix(p, ".txt")
	}); err != nil {
		t.Fatalf("ExtractFilter: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "AssetData/Restore/big.dmg")); !os.IsNotExist(err) {
		t.Error("filter should have skipped big.dmg")
	}
	if _, err := os.Stat(filepath.Join(dest, "a.txt")); err != nil {
		t.Errorf("a.txt missing: %v", err)
	}
}

func TestArchiveReaderRejectsGarbage(t *testing.T) {
	if err := Extract(t.TempDir(), bytes.NewReader([]byte("not an archive"))); err == nil {
		t.Fatal("expected an error")
	}
	var nilReader io.Reader = bytes.NewReader(nil)
	if _, err := ArchiveReader(nilReader); err == nil {
		t.Fatal("expected an error for an empty stream")
	}
}

func equalTrees(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func dump(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		v := m[k]
		if len(v) > 60 {
			v = v[:60] + "…"
		}
		sb.WriteString("\n  " + k + " = " + v)
	}
	return sb.String()
}
