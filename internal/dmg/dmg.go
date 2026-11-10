// Package dmg extracts Apple disk images without macOS.
//
// Simulator runtimes shipped inside the MobileAsset archive are UDIF disk
// images containing an APFS or HFS+ volume. Extracting them is done by an
// external tool because both filesystems are large, independently evolving
// parsers:
//
//   - 7-Zip >= 22 can read APFS and HFS+ inside .dmg (Linux: p7zip / 7zip).
//   - On macOS, hdiutil mounts the image read-only and the tree is copied.
//
// Extraction is recursive: iOS 18 runtime images contain a further .dmg.
package dmg

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Tool is the extracted strategy used to read a dmg.
type Tool string

const (
	ToolAuto    Tool = "auto"
	Tool7z      Tool = "7z"
	ToolHdiutil Tool = "hdiutil"
)

// ErrNoTool means neither 7-Zip nor hdiutil is available.
var ErrNoTool = errors.New("dmg: neither 7z/7zz nor hdiutil found in PATH")

// Extract unpacks dmgPath into destDir, then recursively extracts any .dmg it
// finds (up to two levels deep, which covers the iOS 18 nested layout). It
// returns the paths of extracted *.simruntime bundles.
func Extract(ctx context.Context, dmgPath, destDir string, tool Tool) ([]string, error) {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, err
	}
	if err := extractOne(ctx, dmgPath, destDir, tool); err != nil {
		return nil, err
	}
	// Nested images (iOS 18: AssetData/Restore/092-*.dmg).
	inner, err := findFiles(destDir, ".dmg")
	if err != nil {
		return nil, err
	}
	for _, nested := range inner {
		sub := strings.TrimSuffix(nested, filepath.Ext(nested)) + ".contents"
		if err := extractOne(ctx, nested, sub, tool); err != nil {
			return nil, fmt.Errorf("dmg: nested %s: %w", nested, err)
		}
		if err := os.Remove(nested); err != nil {
			return nil, err
		}
	}
	return findBundles(destDir)
}

func extractOne(ctx context.Context, dmgPath, destDir string, tool Tool) error {
	switch resolve(tool) {
	case Tool7z:
		bin, err := look7z()
		if err != nil {
			return err
		}
		cmd := exec.CommandContext(ctx, bin, "x", "-bd", "-y", "-o"+destDir, dmgPath)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("dmg: %s x: %w: %s", bin, err, tail(string(out)))
		}
		return nil
	case ToolHdiutil:
		return extractHdiutil(ctx, dmgPath, destDir)
	default:
		return ErrNoTool
	}
}

func resolve(tool Tool) Tool {
	if tool != ToolAuto {
		return tool
	}
	if _, err := look7z(); err == nil {
		return Tool7z
	}
	if runtime.GOOS == "darwin" {
		if _, err := exec.LookPath("hdiutil"); err == nil {
			return ToolHdiutil
		}
	}
	return ToolAuto
}

func look7z() (string, error) {
	for _, name := range []string{"7zz", "7z", "7za"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", ErrNoTool
}

func extractHdiutil(ctx context.Context, dmgPath, destDir string) error {
	mnt, err := os.MkdirTemp("", "xcfetch-mnt-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(mnt)
	if out, err := exec.CommandContext(ctx, "hdiutil", "attach", "-nobrowse", "-readonly", "-mountpoint", mnt, dmgPath).CombinedOutput(); err != nil {
		return fmt.Errorf("dmg: hdiutil attach: %w: %s", err, tail(string(out)))
	}
	defer exec.Command("hdiutil", "detach", mnt).Run()

	// Copy the mounted tree (including the hidden volume root entries that matter).
	out, err := exec.CommandContext(ctx, "ditto", mnt, destDir).CombinedOutput()
	if err != nil {
		return fmt.Errorf("dmg: ditto: %w: %s", err, tail(string(out)))
	}
	return nil
}

func findFiles(root, suffix string) ([]string, error) {
	var found []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), suffix) {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return found, nil
}

// findBundles returns every *.simruntime bundle directory below root.
func findBundles(root string) ([]string, error) {
	var found []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && strings.HasSuffix(d.Name(), ".simruntime") {
			found = append(found, path)
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return found, nil
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	const max = 400
	if len(s) <= max {
		return s
	}
	return "…" + s[len(s)-max:]
}

// ExtractTree extracts every .dmg found below root (each into a sibling
// directory named after the image) and returns all *.simruntime bundles in the
// tree. Already-extracted images are skipped, so it is safe to re-run.
func ExtractTree(ctx context.Context, root string, tool Tool) ([]string, error) {
	images, err := findFiles(root, ".dmg")
	if err != nil {
		return nil, err
	}
	for _, img := range images {
		dest := strings.TrimSuffix(img, filepath.Ext(img)) + ".contents"
		if st, err := os.Stat(dest); err == nil && st.IsDir() {
			continue
		}
		if err := extractOne(ctx, img, dest, tool); err != nil {
			return nil, fmt.Errorf("dmg: %s: %w", img, err)
		}
		// iOS 18 nests a second image inside the first.
		inner, err := findFiles(dest, ".dmg")
		if err != nil {
			return nil, err
		}
		for _, nested := range inner {
			sub := strings.TrimSuffix(nested, filepath.Ext(nested)) + ".contents"
			if err := extractOne(ctx, nested, sub, tool); err != nil {
				return nil, fmt.Errorf("dmg: nested %s: %w", nested, err)
			}
		}
	}
	return findBundles(root)
}
