package pallas

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAppleRootsEmbedded(t *testing.T) {
	roots, err := AppleRoots()
	if err != nil {
		t.Fatal(err)
	}
	// Apple Root CA, the root gdmf.apple.com chains to, pinned by fingerprint.
	const appleRootCA = "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"
	found := false
	for _, c := range roots {
		// Apple Root CA (2006) is self-signed with SHA-1, which Go refuses to
		// check; a trust anchor's own signature is never verified anyway.
		if !c.IsCA || !bytes.Equal(c.RawIssuer, c.RawSubject) {
			t.Errorf("%s is not a self-issued CA", c.Subject)
		}
		if time.Now().After(c.NotAfter) {
			t.Errorf("%s expired on %s", c.Subject, c.NotAfter)
		}
		sum := sha256.Sum256(c.Raw)
		if hex.EncodeToString(sum[:]) == appleRootCA {
			found = true
		}
	}
	if !found {
		t.Fatal("Apple Root CA is not embedded")
	}
	if len(roots) != 5 {
		t.Errorf("%d embedded roots, want 5", len(roots))
	}
}

// TestWithAppleRootsKeepsExistingRoots: a client that already trusts a
// server (here a test server) keeps doing so; the Apple roots are added.
func TestWithAppleRootsKeepsExistingRoots(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	hc := WithAppleRoots(srv.Client())
	resp, err := hc.Get(srv.URL)
	if err != nil {
		t.Fatalf("wrapped client lost the caller's roots: %v", err)
	}
	resp.Body.Close()
	if hc.Transport.(*http.Transport).TLSClientConfig.RootCAs.Equal(srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs) {
		t.Error("root pool unchanged; Apple roots were not added")
	}
	// The caller's own transport is not modified.
	if srv.Client().Transport == hc.Transport {
		t.Error("WithAppleRoots modified the caller's transport in place")
	}
}

func TestWithAppleRootsDefaultClient(t *testing.T) {
	hc := WithAppleRoots(nil)
	tr, ok := hc.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("default client did not get a root pool")
	}
	if tr == http.DefaultTransport {
		t.Fatal("DefaultTransport was modified")
	}
}
