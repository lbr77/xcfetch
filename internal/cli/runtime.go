package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/libr/xcfetch/internal/aa"
	"github.com/libr/xcfetch/internal/aea"
	"github.com/libr/xcfetch/internal/dmg"
	"github.com/libr/xcfetch/internal/download"
	"github.com/libr/xcfetch/internal/pallas"
	"github.com/libr/xcfetch/internal/runtime"
)

func runtimeUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  xcfetch runtime list [--platform ios] [--beta] [--arch arm64]
  xcfetch runtime fetch <version|build> [flags]
  xcfetch runtime extract <version|build> --match TEXT [flags]

Flags for fetch:
  --platform ios|watchos|tvos|visionos   platform filter (default ios)
  --arch arm64|x86_64|universal          architecture variant (default arm64)
  --out DIR                              where to write (default ~/Downloads)
  --no-extract                           only download the archive
  --keep-archive                         keep the .aar/.dmg after unpacking
  --dmg-tool auto|7z|hdiutil             disk image extractor (default auto)
  --only SUBSTRING                       extract only matching archive entries
`)
}

func runRuntime(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		runtimeUsage(stderr)
		return ErrUsage
	}
	switch args[0] {
	case "list":
		return runtimeList(ctx, args[1:], stdout, stderr)
	case "fetch", "download":
		return runtimeFetch(ctx, args[1:], stdout, stderr)
	case "extract":
		return runRuntimeExtract(ctx, args[1:], stdout, stderr)
	case "help", "-h", "--help":
		runtimeUsage(stdout)
		return nil
	default:
		fmt.Fprintf(stderr, "xcfetch runtime: unknown subcommand %q\n", args[0])
		return ErrUsage
	}
}

func runtimeList(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("runtime list", stderr)
	platform := fs.String("platform", "ios", "ios, watchos, tvos, visionos or all")
	beta := fs.Bool("beta", false, "include beta and release-candidate runtimes")
	arch := fs.String("arch", "", "only runtimes supporting this architecture")
	if err := fs.Parse(args); err != nil {
		return ErrUsage
	}
	if fs.NArg() > 0 {
		return usageErr(stderr, "runtime list: unexpected argument %q", fs.Arg(0))
	}

	list, err := runtime.Load(ctx, client(nil))
	if err != nil {
		return err
	}
	plat := *platform
	if strings.EqualFold(plat, "all") {
		plat = ""
	}
	w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PLATFORM\tVERSION\tBUILD\tARCH\tTYPE\tSIZE\tSOURCE")
	shown := 0
	for _, r := range list {
		if plat != "" && !strings.EqualFold(r.PlatformName(), plat) {
			continue
		}
		if !*beta && r.Prerelease() {
			continue
		}
		if *arch != "" && len(r.Architectures) > 0 && !hasArch(r.Architectures, *arch) {
			continue
		}
		source := "pallas"
		if r.HasDirectSource() {
			source = "direct"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.PlatformName(), r.DisplayVersion(), r.SimulatorVersion.BuildUpdate,
			strings.Join(r.Architectures, ","), r.ContentType,
			humanBytes(r.FileSize), source)
		shown++
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if shown == 0 {
		fmt.Fprintln(stderr, "xcfetch: no runtimes matched (try --beta or --platform all)")
	}
	return nil
}

func runtimeFetch(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("runtime fetch", stderr)
	platform := fs.String("platform", "ios", "ios, watchos, tvos or visionos")
	arch := fs.String("arch", "arm64", "arm64, x86_64 or universal")
	out := fs.String("out", defaultDownloadDir(), "output directory")
	noExtract := fs.Bool("no-extract", false, "only download the archive")
	keepArchive := fs.Bool("keep-archive", false, "keep the archive after unpacking")
	dmgTool := fs.String("dmg-tool", "auto", "auto, 7z or hdiutil")
	only := fs.String("only", "", "extract only entries whose path contains this substring")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return usageErr(stderr, "runtime fetch: expected exactly one version, build or identifier")
	}

	list, err := runtime.Load(ctx, client(nil))
	if err != nil {
		return err
	}
	rt, err := runtime.Find(list, rest[0], *platform, *arch)
	if err != nil {
		return err
	}

	jar, err := openJar()
	if err != nil {
		return err
	}
	hc := client(jar)

	target, err := resolveRuntime(ctx, hc, rt, *arch)
	if err != nil {
		return err
	}

	dest := filepath.Join(*out, target.filename)
	fmt.Fprintf(stdout, "%s %s (%s, %s)\n", rt.PlatformName(), rt.DisplayVersion(), rt.SimulatorVersion.BuildUpdate, humanBytes(target.size))
	fmt.Fprintf(stdout, "  %s\n", target.url)

	if reuseArchive(dest, target.size) {
		fmt.Fprintf(stdout, "  reusing %s\n", dest)
	} else if err := download.Fetch(ctx, hc, target.url, dest, download.Options{
		ExpectedSize: target.size,
		SHA1:         target.sha1,
		SHA256:       target.sha256,
		Progress:     download.ProgressPrinter(stderr, isTTY(os.Stderr)),
	}); err != nil {
		return err
	} else {
		fmt.Fprintf(stdout, "  saved %s\n", dest)
	}

	if *noExtract {
		return nil
	}

	destDir := strings.TrimSuffix(dest, filepath.Ext(dest))
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	tool := dmg.Tool(*dmgTool)
	var images []string
	switch strings.ToLower(filepath.Ext(dest)) {
	case ".aar", ".aea":
		var filter func(string) bool
		if *only != "" {
			filter = func(p string) bool { return strings.Contains(p, *only) }
		}
		if err := unpackAppleArchiveFiltered(dest, destDir, target.key, filter); err != nil {
			return err
		}
		if filter != nil {
			fmt.Fprintf(stdout, "  extracted matching entries into %s\n", destDir)
			if !*keepArchive {
				if err := os.Remove(dest); err != nil {
					return err
				}
			}
			return nil
		}
		images, err = dmg.ExtractTree(ctx, destDir, tool)
		if err != nil {
			return err
		}
	case ".dmg":
		images, err = dmg.Extract(ctx, dest, destDir, tool)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("runtime fetch: don't know how to unpack %s", dest)
	}

	if len(images) == 0 {
		fmt.Fprintf(stdout, "  unpacked into %s\n", destDir)
	}
	for _, img := range images {
		fmt.Fprintf(stdout, "  %s\n", img)
	}
	if !*keepArchive {
		if err := os.Remove(dest); err != nil {
			return err
		}
	}
	return nil
}

type runtimeTarget struct {
	url      string
	filename string
	size     int64
	sha1     []byte
	sha256   []byte
	key      []byte
}

func resolveRuntime(ctx context.Context, hc *http.Client, rt runtime.Runtime, arch string) (runtimeTarget, error) {
	if rt.HasDirectSource() {
		name := path.Base(rt.SourceURL)
		if i := strings.IndexByte(name, '?'); i >= 0 {
			name = name[:i]
		}
		return runtimeTarget{
			url:      rt.SourceURL,
			filename: name,
			size:     rt.FileSize,
		}, nil
	}

	build := rt.SimulatorVersion.BuildUpdate
	if build == "" {
		return runtimeTarget{}, fmt.Errorf("runtime %s has no build number; cannot query MobileAsset", rt.Identifier)
	}
	assets, err := pallas.Query(ctx, hc, pallas.AssetTypeIOSRuntime, pallas.AudienceMacOSGeneric, build)
	if err != nil {
		return runtimeTarget{}, err
	}
	asset, err := pallas.Pick(assets, arch)
	if err != nil {
		return runtimeTarget{}, err
	}
	key, err := asset.Key()
	if err != nil {
		return runtimeTarget{}, err
	}
	sha1, err := asset.Sum()
	if err != nil {
		return runtimeTarget{}, err
	}
	sha256, err := asset.Sum256()
	if err != nil {
		return runtimeTarget{}, err
	}
	name := rt.Name + path.Ext(asset.RelativePath)
	if name == "" || name == path.Ext(asset.RelativePath) {
		name = path.Base(asset.RelativePath)
	}
	return runtimeTarget{
		url:      asset.FullURL(),
		filename: sanitizeFilename(name),
		size:     asset.Size,
		sha1:     sha1,
		sha256:   sha256,
		key:      key,
	}, nil
}

// unpackAppleArchive decrypts (when key is set) and extracts an Apple Archive,
// streaming between the two stages so the plaintext never hits disk.
func unpackAppleArchive(archivePath, destDir string, key []byte) error {
	return unpackAppleArchiveFiltered(archivePath, destDir, key, nil)
}

// unpackAppleArchiveFiltered decrypts (when key is set) and extracts an Apple
// Archive, streaming between the two stages so the plaintext never hits disk.
func unpackAppleArchiveFiltered(archivePath, destDir string, key []byte, want func(string) bool) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	if len(key) == 0 {
		return aa.ExtractFilter(destDir, f, want)
	}
	pr, pw := io.Pipe()
	errc := make(chan error, 1)
	go func() {
		err := aea.Decrypt(pw, f, key)
		_ = pw.CloseWithError(err)
		errc <- err
	}()
	extractErr := aa.ExtractFilter(destDir, pr, want)
	_ = pr.CloseWithError(extractErr)
	decryptErr := <-errc
	if extractErr != nil {
		return extractErr
	}
	return decryptErr
}

func sanitizeFilename(name string) string {
	repl := strings.NewReplacer("/", "-", ":", "-")
	return repl.Replace(name)
}

func hasArch(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

func defaultDownloadDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, "Downloads")
}

func usageErr(w io.Writer, format string, args ...any) error {
	fmt.Fprintf(w, "xcfetch: "+format+"\n", args...)
	return ErrUsage
}

func humanBytes(n int64) string {
	if n < 0 {
		return "-"
	}
	return humanFloat(float64(n))
}

// humanFloat renders a byte count with a binary unit suffix.
func humanFloat(n float64) string {
	const unit = 1024
	switch {
	case n < unit:
		return fmt.Sprintf("%.0f B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	exp := -1
	for n >= unit && exp < len(units)-1 {
		n /= unit
		exp++
	}
	return fmt.Sprintf("%.1f %s", n, units[exp])
}

// reuseArchive reports whether dest already holds the complete archive.
func reuseArchive(dest string, size int64) bool {
	if size <= 0 {
		return false
	}
	st, err := os.Stat(dest)
	return err == nil && st.Size() == size
}
