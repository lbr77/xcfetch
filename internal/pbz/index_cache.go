package pbz

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

// Index is a serialisable block index for one stream: everything needed to skip
// the header chain on a later run.
type Index struct {
	Algo   byte    `json:"algo"`
	Blocks []Block `json:"blocks"`
	Plain  int64   `json:"plain"`
}

// Export returns the currently indexed blocks.
func (r *Reader) Export() Index {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := Index{Algo: r.algo, Plain: r.plain, Blocks: make([]Block, len(r.blocks))}
	copy(out.Blocks, r.blocks)
	return out
}

// Import seeds the reader with a previously exported index. Entries that do not
// fit this stream are ignored, so a stale cache cannot corrupt a read: the walk
// simply continues from the last consistent block.
func (r *Reader) Import(idx Index) bool {
	if idx.Algo != r.algo || len(idx.Blocks) == 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var (
		next  int64 = headerSize
		plain int64
	)
	accepted := make([]Block, 0, len(idx.Blocks))
	for _, b := range idx.Blocks {
		if b.OuterOffset != next || b.PlainOffset != plain {
			break
		}
		if b.PlainSize <= 0 || b.CompSize <= 0 || b.CompSize > b.PlainSize {
			break
		}
		if next+16+b.CompSize > r.size {
			break
		}
		accepted = append(accepted, b)
		next += 16 + b.CompSize
		plain += b.PlainSize
	}
	if len(accepted) == 0 {
		return false
	}
	r.blocks = append(r.blocks, accepted...)
	r.next = next
	r.plain = plain
	if plain < idx.Plain || len(accepted) == len(idx.Blocks) {
		// Either fully seeded, or the cache simply stops early (keep walking).
	}
	return true
}

// FileCache stores block indexes as JSON files in one directory.
type FileCache struct {
	Dir string
}

// path maps an arbitrary key (which typically contains a URL) to a file name.
func (c FileCache) path(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(c.Dir, hex.EncodeToString(sum[:12])+".json")
}

// Load reads the index stored under key, if any.
func (c FileCache) Load(key string) (Index, bool) {
	if c.Dir == "" || key == "" {
		return Index{}, false
	}
	data, err := os.ReadFile(c.path(key))
	if err != nil {
		return Index{}, false
	}
	var idx Index
	if err := json.Unmarshal(data, &idx); err != nil {
		return Index{}, false
	}
	return idx, true
}

// Save writes the index for key.
func (c FileCache) Save(key string, idx Index) error {
	if c.Dir == "" || key == "" || len(idx.Blocks) == 0 {
		return nil
	}
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(idx)
	if err != nil {
		return err
	}
	tmp := c.path(key) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path(key))
}
