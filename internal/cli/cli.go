package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lbr77/xcfetch/internal/session"
)

// ErrUsage marks command-line mistakes (exit status 2).
var ErrUsage = errors.New("usage")

const (
	version = "0.1.0"

	// AppleIDEnv is the environment variable holding the Apple ID.
	AppleIDEnv = "XCFETCH_APPLE_ID"
	// PasswordEnv is the environment variable holding the Apple ID password.
	PasswordEnv = "XCFETCH_APPLE_PASSWORD"
	// ConfigEnv overrides the config directory.
	ConfigEnv = "XCFETCH_CONFIG_DIR"
)

const usage = `xcfetch - fetch Apple simulator runtimes and Xcode archives off-platform

Usage:
  xcfetch runtime list [flags]            List downloadable simulator runtimes
  xcfetch runtime fetch <version> [flags] Download (and unpack) one simulator runtime
  xcfetch runtime extract <version>       Extract selected files over HTTP ranges
  xcfetch xcode login [flags]             Sign in with an Apple ID
  xcfetch xcode logout                    Forget the saved session
  xcfetch xcode status                    Show whether the saved session is valid
  xcfetch xcode list [flags]              List downloadable Xcode archives
  xcfetch xcode download <name> [flags]   Download an Xcode archive (.xip)
  xcfetch version                         Print the version

Environment:
  XCFETCH_APPLE_ID           Apple ID used by "xcode login"
  XCFETCH_APPLE_PASSWORD     Password (otherwise prompted)
  XCFETCH_CONFIG_DIR         Config directory (default: ~/.config/xcfetch)

Notes:
  * Simulator runtimes from iOS 18 on need no Apple ID: they come from Apple's
    public MobileAsset (Pallas) service.
  * Xcode archives require a developer-account session, i.e. "xcode login".
  * Run "xcfetch <command> -h" for the flags of one command.
`

// Run dispatches a command line.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stdout, usage)
		return nil
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	case "version", "-v", "--version":
		fmt.Fprintf(stdout, "xcfetch %s\n", version)
		return nil
	case "runtime":
		return runRuntime(ctx, args[1:], stdout, stderr)
	case "xcode":
		return runXcode(ctx, args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "xcfetch: unknown command %q\n\n%s", args[0], usage)
		return ErrUsage
	}
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// client builds an HTTP client bound to jar with sane timeouts.
func client(jar http.CookieJar) *http.Client {
	return &http.Client{
		Timeout: 0, // large downloads; per-request deadlines come from ctx
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConns:          8,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   20 * time.Second,
			ExpectContinueTimeout: 5 * time.Second,
			ForceAttemptHTTP2:     true,
		},
		Jar: jar,
	}
}

func isTTY(f *os.File) bool {
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

func openJar() (*session.Jar, error) {
	path, err := session.DefaultPath()
	if err != nil {
		return nil, err
	}
	return session.New(path)
}

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

// parse reorders args so flags may follow positional arguments, which the
// standard flag package does not allow, and parses them. It returns the
// positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[0] != '-' {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if strings.ContainsRune(name, '=') {
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			continue
		}
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	if err := fs.Parse(append(flags, positional...)); err != nil {
		return nil, ErrUsage
	}
	return fs.Args(), nil
}
