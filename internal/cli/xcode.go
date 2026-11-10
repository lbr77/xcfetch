package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/libr/xcfetch/internal/adc"
	"github.com/libr/xcfetch/internal/appleid"
	"github.com/libr/xcfetch/internal/download"
	"github.com/libr/xcfetch/internal/session"
)

func xcodeUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  xcfetch xcode login [--apple-id ID] [--force]
  xcfetch xcode logout
  xcfetch xcode status
  xcfetch xcode list [--query TEXT] [--all]
  xcfetch xcode download <name|version> [flags]

Flags for download:
  --out DIR            where to write (default ~/Downloads)
  --kind xip|dmg       archive type to fetch (default xip)
  --no-download        print the resolved CDN URL and stop
`)
}

func runXcode(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		xcodeUsage(stderr)
		return ErrUsage
	}
	switch args[0] {
	case "login":
		return xcodeLogin(ctx, args[1:], stdout, stderr)
	case "logout":
		return xcodeLogout(stdout)
	case "status":
		return xcodeStatus(ctx, stdout, stderr)
	case "list":
		return xcodeList(ctx, args[1:], stdout, stderr)
	case "download", "fetch":
		return xcodeDownload(ctx, args[1:], stdout, stderr)
	case "help", "-h", "--help":
		xcodeUsage(stdout)
		return nil
	default:
		fmt.Fprintf(stderr, "xcfetch xcode: unknown subcommand %q\n", args[0])
		return ErrUsage
	}
}

func xcodeLogin(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("xcode login", stderr)
	appleID := fs.String("apple-id", "", "Apple ID (default $"+AppleIDEnv+")")
	force := fs.Bool("force", false, "sign in even if a valid session exists")
	if err := fs.Parse(args); err != nil {
		return ErrUsage
	}

	jar, err := openJar()
	if err != nil {
		return err
	}
	hc := client(jar)

	if !*force && !jar.Empty() {
		sess := &appleid.Session{Client: hc, Jar: jar}
		if err := sess.Validate(ctx); err == nil {
			fmt.Fprintln(stdout, "Already signed in; session is valid. Use --force to sign in again.")
			return nil
		}
	}

	id := envOr(AppleIDEnv, *appleID)
	p := newPrompter(stdout)
	if id == "" {
		fmt.Fprint(stdout, "Apple ID: ")
		line, err := p.readLine()
		if err != nil {
			return err
		}
		id = strings.TrimSpace(line)
	}
	password := os.Getenv(PasswordEnv)
	if password == "" {
		password, err = p.PromptPassword("Password: ")
		if err != nil {
			return err
		}
	}

	sess, err := appleid.Login(ctx, appleid.Credentials{AppleID: id, Password: password}, p, appleid.Options{Jar: jar, HTTP: hc})
	if err != nil {
		return err
	}
	if err := sess.Validate(ctx); err != nil {
		fmt.Fprintf(stderr, "xcfetch: signed in but the developer session check failed: %v\n", err)
	}
	if err := jar.Save(); err != nil {
		return err
	}
	path, _ := session.DefaultPath()
	fmt.Fprintf(stdout, "Signed in as %s. Session saved to %s\n", id, path)
	return nil
}

func xcodeLogout(stdout io.Writer) error {
	jar, err := openJar()
	if err != nil {
		return err
	}
	if err := jar.Clear(); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Signed out; saved session removed.")
	return nil
}

func xcodeStatus(ctx context.Context, stdout, stderr io.Writer) error {
	jar, err := openJar()
	if err != nil {
		return err
	}
	if jar.Empty() {
		fmt.Fprintln(stdout, "Not signed in.")
		return nil
	}
	sess := &appleid.Session{Client: client(jar), Jar: jar}
	if err := sess.Validate(ctx); err != nil {
		fmt.Fprintf(stdout, "Session present but not valid: %v\n", err)
		return nil
	}
	fmt.Fprintln(stdout, "Session is valid.")
	return nil
}

func xcodeList(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("xcode list", stderr)
	query := fs.String("query", "", "only entries whose name contains this text")
	all := fs.Bool("all", false, "list every download, not just Xcode")
	if err := fs.Parse(args); err != nil {
		return ErrUsage
	}

	jar, err := openJar()
	if err != nil {
		return err
	}
	hc := client(jar)
	if jar.Empty() {
		return adc.ErrUnauthorized
	}
	list, err := adc.ListDownloads(ctx, hc)
	if err != nil {
		return err
	}
	if !*all {
		list = adc.XcodeArchives(list)
	}
	w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tMODIFIED\tSIZE\tFILE")
	shown := 0
	for _, d := range list {
		if *query != "" && !strings.Contains(strings.ToLower(d.Name), strings.ToLower(*query)) {
			continue
		}
		for _, f := range d.Files {
			lower := strings.ToLower(f.RemotePath)
			if !strings.HasSuffix(lower, ".xip") && !strings.HasSuffix(lower, ".dmg") {
				continue
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", d.Name, d.Modified().Format("2006-01-02"), humanBytes(f.FileSize), filepath.Base(f.RemotePath))
			shown++
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if shown == 0 {
		fmt.Fprintln(stderr, "xcfetch: no Xcode archives matched")
	}
	return nil
}

func xcodeDownload(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("xcode download", stderr)
	out := fs.String("out", defaultDownloadDir(), "output directory")
	kind := fs.String("kind", "xip", "xip or dmg")
	noDownload := fs.Bool("no-download", false, "resolve the URL only")
	rest, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return usageErr(stderr, "xcode download: expected one name or version, e.g. \"Xcode 16.2\"")
	}

	jar, err := openJar()
	if err != nil {
		return err
	}
	hc := client(jar)
	if jar.Empty() {
		return adc.ErrUnauthorized
	}
	list, err := adc.ListDownloads(ctx, hc)
	if err != nil {
		return err
	}
	dl, file, err := adc.Find(list, rest[0], "."+*kind)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(dl.Name, "Xcode") {
		fmt.Fprintf(stderr, "xcfetch: warning: %q is not an Xcode entry\n", dl.Name)
	}

	cdnURL, err := adc.Authorize(ctx, hc, file.RemotePath)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s (%s)\n  %s\n", dl.Name, humanBytes(file.FileSize), cdnURL)
	if *noDownload {
		return nil
	}

	dest := filepath.Join(*out, filepath.Base(file.RemotePath))
	start := time.Now()
	if err := download.Fetch(ctx, hc, cdnURL, dest, download.Options{
		ExpectedSize: file.FileSize,
		Progress:     download.ProgressPrinter(stderr, isTTY(os.Stderr)),
	}); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "  saved %s in %s\n", dest, time.Since(start).Round(time.Second))
	if strings.HasSuffix(strings.ToLower(dest), ".xip") {
		fmt.Fprintln(stdout, "  next: unxip the archive (https://github.com/saagarjha/unxip) or point xtool at it: xtool sdk build --xip "+dest)
	}
	return nil
}
