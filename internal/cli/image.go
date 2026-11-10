package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/lbr77/xcfetch/internal/apfs"
	"github.com/lbr77/xcfetch/internal/udif"
)

// imageSource is one disk image, local or inside an archive.
type imageSource struct {
	name string
	r    io.ReaderAt
	size int64
}

// imageOptions controls listing/extraction from disk images.
type imageOptions struct {
	patterns []string
	list     bool
	dest     string
	verbose  bool
	stdout   io.Writer
	stderr   io.Writer
}

// imageReport accumulates what an extraction wrote.
type imageReport struct {
	files    int
	links    int
	bytes    int64
	verified int64
}

// extractFromImages resolves every pattern in the APFS volumes of the given
// disk images and lists or writes the matches. A pattern must match in at least
// one volume.
func extractFromImages(images []imageSource, opt imageOptions) error {
	var patterns []string
	for _, p := range opt.patterns {
		patterns = append(patterns, expandBraces(strings.TrimPrefix(p, "/"))...)
	}
	found := make(map[string]bool)
	start := time.Now()
	var rep imageReport
	for _, src := range images {
		im, err := udif.Open(src.r, src.size)
		if err != nil {
			return fmt.Errorf("%s: %w", src.name, err)
		}
		c, err := apfs.OpenDisk(im, im.Size())
		if err != nil {
			return fmt.Errorf("%s: %w", src.name, err)
		}
		vols, err := c.Volumes()
		if err != nil {
			return fmt.Errorf("%s: %w", src.name, err)
		}
		for _, v := range vols {
			sealed := ""
			if v.Sealed {
				sealed = ", sealed"
			}
			fmt.Fprintf(opt.stdout, "%s: APFS volume %q (%d-byte blocks%s)\n", src.name, v.Name, c.BlockSize, sealed)
			for _, pat := range patterns {
				if found[pat] {
					continue
				}
				matches, err := v.Glob(pat)
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}
				if err != nil {
					return err
				}
				var nodes []apfs.Node
				for _, p := range matches {
					n, err := v.Stat(p)
					if errors.Is(err, fs.ErrNotExist) {
						continue
					}
					if err != nil {
						return err
					}
					nodes = append(nodes, n)
				}
				if len(nodes) > 0 {
					found[pat] = true
				}
				for _, n := range nodes {
					if opt.list {
						if err := listImageNode(v, n, opt.stdout); err != nil {
							return err
						}
						continue
					}
					if err := writeImageNode(v, n, opt, &rep); err != nil {
						return err
					}
				}
			}
		}
		if opt.verbose {
			st := im.Stats()
			fmt.Fprintf(opt.stderr, "  %s: %d of %d image runs decoded (%s compressed), %d APFS metadata blocks\n",
				src.name, st.RunsDecoded, im.RunCount(), humanBytes(st.BytesIn), c.BlocksRead())
		}
	}
	var missing []string
	for _, p := range patterns {
		if !found[p] {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("runtime extract: not found in the disk image: %s", strings.Join(missing, ", "))
	}
	if !opt.list {
		verified := ""
		if rep.verified > 0 {
			verified = fmt.Sprintf(", %s checked against the volume's seal hashes", humanBytes(rep.verified))
		}
		fmt.Fprintf(opt.stdout, "extracted %d files, %d links (%s) in %s%s\n", rep.files, rep.links,
			humanBytes(rep.bytes), time.Since(start).Round(time.Millisecond), verified)
	}
	return nil
}

// listImageNode prints a node, or a directory's children.
func listImageNode(v *apfs.Volume, n apfs.Node, w io.Writer) error {
	nodes := []apfs.Node{n}
	if n.IsDir() {
		children, err := v.Children(n)
		if err != nil {
			return err
		}
		nodes = children
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TYPE\tMODE\tSIZE\tPATH")
	for _, c := range nodes {
		kind, size, name := "file", humanBytes(c.Size), c.Path
		switch {
		case c.IsDir():
			kind, size = "dir", "-"
		case c.IsSymlink():
			kind, size, name = "link", "-", c.Path+" -> "+c.Link
		case !c.IsRegular():
			kind = "other"
		}
		fmt.Fprintf(tw, "%s\t%04o\t%s\t%s\n", kind, c.Perm(), size, name)
	}
	return tw.Flush()
}

// writeImageNode materialises a node (recursively for directories) below dest.
func writeImageNode(v *apfs.Volume, n apfs.Node, opt imageOptions, rep *imageReport) error {
	if !safeImagePath(n.Path) {
		return fmt.Errorf("runtime extract: refusing unsafe image path %q", n.Path)
	}
	full := filepath.Join(opt.dest, filepath.FromSlash(n.Path))
	switch {
	case n.IsDir():
		if err := os.MkdirAll(full, 0o755); err != nil {
			return err
		}
		children, err := v.Children(n)
		if err != nil {
			return err
		}
		for _, c := range children {
			if err := writeImageNode(v, c, opt, rep); err != nil {
				return err
			}
		}
		return nil
	case n.IsSymlink():
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		_ = os.Remove(full)
		if err := os.Symlink(n.Link, full); err != nil {
			return fmt.Errorf("runtime extract: symlink %q: %w", n.Path, err)
		}
		rep.links++
		fmt.Fprintf(opt.stdout, "  %s -> %s\n", full, n.Link)
		return nil
	case n.IsRegular():
		return writeImageFile(v, n, full, opt, rep)
	default:
		fmt.Fprintf(opt.stderr, "  skipping %s (not a file, directory or symlink)\n", n.Path)
		return nil
	}
}

func writeImageFile(v *apfs.Volume, n apfs.Node, full string, opt imageOptions, rep *imageReport) error {
	data, err := v.Open(n)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(full, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, io.NewSectionReader(data, 0, n.Size))
	var covered int64
	if err == nil {
		// Check the bytes as written against the seal: this also catches a
		// corrupted transfer, since partial AEA reads are not authenticated.
		covered, err = v.Verify(n, f)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(full)
		return fmt.Errorf("runtime extract: %s: %w", n.Path, err)
	}
	if err := os.Chmod(full, n.Perm()); err != nil {
		return err
	}
	_ = os.Chtimes(full, n.ModTime, n.ModTime)
	rep.files++
	rep.bytes += n.Size
	rep.verified += covered
	note := ""
	if covered > 0 {
		note = ", verified"
	}
	fmt.Fprintf(opt.stdout, "  %s (%s%s)\n", full, humanBytes(n.Size), note)
	return nil
}

// safeImagePath rejects paths that could escape the destination.
func safeImagePath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") {
		return false
	}
	for _, c := range strings.Split(p, "/") {
		if c == "" || c == "." || c == ".." {
			return false
		}
	}
	return true
}

// expandBraces expands {a,b} alternatives (not nested) into separate patterns.
func expandBraces(p string) []string {
	i := strings.IndexByte(p, '{')
	if i < 0 {
		return []string{p}
	}
	j := strings.IndexByte(p[i:], '}')
	if j < 0 {
		return []string{p}
	}
	j += i
	var out []string
	for _, alt := range strings.Split(p[i+1:j], ",") {
		out = append(out, expandBraces(p[:i]+alt+p[j+1:])...)
	}
	return out
}
