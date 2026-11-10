package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestParseAllowsFlagsAfterPositionals(t *testing.T) {
	fs := newFlagSet("t", io.Discard)
	platform := fs.String("platform", "ios", "")
	beta := fs.Bool("beta", false, "")
	noExtract := fs.Bool("no-extract", false, "")
	out := fs.String("out", "", "")

	rest, err := parse(fs, []string{"26.5", "--platform", "tvos", "--beta", "--no-extract", "--out", "/tmp/x"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rest) != 1 || rest[0] != "26.5" {
		t.Fatalf("positionals = %v", rest)
	}
	if *platform != "tvos" || !*beta || !*noExtract || *out != "/tmp/x" {
		t.Fatalf("flags not applied: %v %v %v %v", *platform, *beta, *noExtract, *out)
	}
}

func TestParseWithEqualsForm(t *testing.T) {
	fs := newFlagSet("t", io.Discard)
	out := fs.String("out", "", "")
	rest, err := parse(fs, []string{"--out=/var/tmp", "26.5"})
	if err != nil {
		t.Fatal(err)
	}
	if *out != "/var/tmp" || len(rest) != 1 {
		t.Fatalf("out=%q rest=%v", *out, rest)
	}
}

func TestRunDispatch(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := Run(context.Background(), []string{"version"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stdout.String(), "xcfetch ") {
		t.Errorf("version output = %q", stdout.String())
	}

	stdout.Reset()
	if err := Run(context.Background(), nil, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Error("bare invocation should print usage")
	}

	stderr.Reset()
	if err := Run(context.Background(), []string{"nope"}, io.Discard, &stderr); err != ErrUsage {
		t.Fatalf("err = %v, want ErrUsage", err)
	}
}

func TestRuntimeFetchRequiresOneArgument(t *testing.T) {
	var stderr bytes.Buffer
	err := Run(context.Background(), []string{"runtime", "fetch"}, io.Discard, &stderr)
	if err != ErrUsage {
		t.Fatalf("err = %v, want ErrUsage", err)
	}
	if !strings.Contains(stderr.String(), "expected exactly one") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestXcodeCommandsRequireSession(t *testing.T) {
	t.Setenv("XCFETCH_CONFIG_DIR", t.TempDir())
	err := Run(context.Background(), []string{"xcode", "list"}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("err = %v, want an authorization error", err)
	}

	var stdout bytes.Buffer
	if err := Run(context.Background(), []string{"xcode", "status"}, &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "Not signed in") {
		t.Errorf("status output = %q", stdout.String())
	}
	if err := Run(context.Background(), []string{"xcode", "logout"}, &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestClientHasNoResponseTimeout(t *testing.T) {
	hc := client(nil)
	if hc.Timeout != 0 {
		t.Errorf("client timeout = %v, large downloads would be cut off", hc.Timeout)
	}
	if hc.Transport == nil {
		t.Error("client should carry a tuned transport")
	}
	var _ = http.DefaultTransport
}
