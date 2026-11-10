package aa

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxDepth bounds nested container payloads. Apple's simulator runtime assets
// nest two levels (container -> payload -> tree) plus a manifest.
const maxDepth = 3

// Extract writes every entry of the archive in r below dest.
//
// r may be a raw Apple Archive or a pbz* compressed stream. Directories, regular
// files, symbolic links and unix modes are preserved; xattrs, device nodes and
// sockets are skipped.
//
// Modern Apple assets are containers rather than trees: the archive holds
// pathless payload blobs, each of which is itself a pbz* stream wrapping another
// Apple Archive. Extract follows those payloads, so a runtime asset yields its
// AssetData/... tree. Manifest archives (entries with no data blob) are ignored
// rather than materialised as empty files.
//
// Memory use is bounded: entries are streamed in 1 MiB chunks.
func Extract(dest string, r io.Reader) error {
	return ExtractFilter(dest, r, nil)
}

// ExtractFilter is Extract restricted to entries whose archive path satisfies
// want (nil accepts everything). Directories are always created because they
// are needed as parents.
func ExtractFilter(dest string, r io.Reader, want func(path string) bool) error {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	return extractArchive(dest, r, want, 0)
}

func extractArchive(dest string, r io.Reader, want func(string) bool, depth int) error {
	if depth > maxDepth {
		return errors.New("aa: nested archive depth exceeded")
	}
	archive, err := ArchiveReader(r)
	if err != nil {
		return err
	}
	buf := make([]byte, 1<<20)
	payloadIndex := 0
	for {
		it, err := readHeader(archive)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if it.path == "" {
			// Payload container: recurse into its blobs.
			for _, blob := range it.blobs {
				if blob.key != "DAT" {
					if err := discardN(archive, blob.size); err != nil {
						return fmt.Errorf("aa: discarding %s blob: %w", blob.key, err)
					}
					continue
				}
				payloadIndex++
				lr := io.LimitReader(archive, blob.size)
				if err := extractPayload(dest, lr, want, depth+1, payloadIndex); err != nil {
					return err
				}
				if err := discardN(lr, -1); err != nil {
					return fmt.Errorf("aa: draining payload %d: %w", payloadIndex, err)
				}
			}
			continue
		}
		if err := extractEntry(dest, archive, it, want, buf); err != nil {
			return err
		}
	}
}

// extractPayload decodes one container payload: an Apple Archive (optionally
// wrapped in a pbz* stream) is extracted in place, anything else is written as
// an opaque file.
func extractPayload(dest string, r io.Reader, want func(string) bool, depth, index int) error {
	br := bufio.NewReaderSize(r, 64<<10)
	head, err := br.Peek(4)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && err != io.EOF {
		return fmt.Errorf("aa: payload %d: %w", index, err)
	}
	switch {
	case bytes.Equal(head, []byte("AA01")), bytes.Equal(head, []byte("YAA1")):
		return extractArchive(dest, br, want, depth)
	case bytes.HasPrefix(head, []byte("pbz")):
		sr, err := newStreamReader(br)
		if err != nil {
			return fmt.Errorf("aa: payload %d: %w", index, err)
		}
		return extractArchive(dest, sr, want, depth)
	default:
		name := fmt.Sprintf("payload-%d.bin", index)
		path := filepath.Join(dest, name)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		_, cerr := io.Copy(f, br)
		if err := f.Close(); cerr == nil {
			cerr = err
		}
		if cerr != nil {
			return fmt.Errorf("aa: writing payload %d: %w", index, cerr)
		}
		return nil
	}
}

func extractEntry(dest string, archive io.Reader, it item, want func(string) bool, buf []byte) error {
	if !safePath(it.path) {
		return discardN(archive, it.blobBytes)
	}
	full := filepath.Join(dest, filepath.FromSlash(it.path))
	selected := want == nil || want(it.path)

	switch it.typ {
	case typeDirectory:
		if err := os.MkdirAll(full, 0o755); err != nil {
			return err
		}
		if err := applyMode(full, it); err != nil {
			return err
		}
		return drainBlobs(archive, it, nil, full, buf)

	case typeRegularFile:
		if !hasData(it) {
			// Manifest entry: metadata only, no content.
			return drainBlobs(archive, it, nil, full, buf)
		}
		if !selected {
			return drainBlobs(archive, it, nil, full, buf)
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if it.hasMode {
			mode = it.mode & 0o7777
		}
		f, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			return err
		}
		err = drainBlobs(archive, it, f, full, buf)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		return applyMode(full, it)

	case typeSymbolicLink:
		if it.link == "" || !selected {
			return drainBlobs(archive, it, nil, full, buf)
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		_ = os.Remove(full)
		if err := os.Symlink(it.link, full); err != nil {
			return fmt.Errorf("aa: symlink %q: %w", it.path, err)
		}
		return drainBlobs(archive, it, nil, full, buf)

	case typeBlockSpecial, typeCharacterSpecial, typeFifo, typeSocket, typeMetadata:
		return discardN(archive, it.blobBytes)

	default:
		if err := discardN(archive, it.blobBytes); err != nil {
			return err
		}
		return fmt.Errorf("aa: unsupported entry type %q for %q", string(it.typ), it.path)
	}
}

// hasData reports whether the entry carries a data blob (manifest entries do
// not, empty files carry one of size zero).
func hasData(it item) bool {
	for _, b := range it.blobs {
		if b.key == "DAT" {
			return true
		}
	}
	return false
}

// drainBlobs walks the blobs of an item in field order, writing DAT payloads to
// out and discarding the rest.
func drainBlobs(archive io.Reader, it item, out io.Writer, path string, buf []byte) error {
	for _, blob := range it.blobs {
		dst := io.Discard
		if blob.key == "DAT" && out != nil {
			dst = out
		}
		if err := copyN(archive, dst, blob.size, buf); err != nil {
			return fmt.Errorf("aa: %s blob in %q: %w", blob.key, path, err)
		}
	}
	return nil
}

func copyN(src io.Reader, dst io.Writer, n int64, buf []byte) error {
	for n > 0 {
		chunk := int64(len(buf))
		if n < chunk {
			chunk = n
		}
		if _, err := io.ReadFull(src, buf[:chunk]); err != nil {
			return err
		}
		if _, err := dst.Write(buf[:chunk]); err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}

// discardN drops n bytes; a negative n drains until EOF.
func discardN(r io.Reader, n int64) error {
	if n == 0 {
		return nil
	}
	if n < 0 {
		_, err := io.Copy(io.Discard, r)
		return err
	}
	_, err := io.CopyN(io.Discard, r, n)
	return err
}

func applyMode(path string, it item) error {
	if !it.hasMode {
		return nil
	}
	if err := os.Chmod(path, it.mode&0o7777); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// safePath rejects absolute paths and any traversal component.
func safePath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".." || part == "." {
			return false
		}
	}
	return true
}
