package pallas

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
)

// appleRootsPEM holds Apple's root certificates. gdmf.apple.com presents a
// chain that ends at Apple Root CA, which macOS trusts but Linux CA bundles do
// not, so a plain client on Linux fails with "certificate signed by unknown
// authority".
//
//go:embed apple_roots.pem
var appleRootsPEM []byte

// AppleRoots returns the embedded Apple root certificates.
func AppleRoots() ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for rest := appleRootsPEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pallas: embedded Apple root: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("pallas: no embedded Apple roots")
	}
	return out, nil
}

// WithAppleRoots returns a client like hc whose TLS also trusts Apple's roots,
// on top of whatever it trusted before (the system pool, or the roots a caller
// configured). Clients with a transport other than *http.Transport are
// returned unchanged.
func WithAppleRoots(hc *http.Client) *http.Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	rt := hc.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	base, ok := rt.(*http.Transport)
	if !ok {
		return hc
	}
	t := base.Clone()
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{}
	}
	var pool *x509.CertPool
	if t.TLSClientConfig.RootCAs != nil {
		pool = t.TLSClientConfig.RootCAs.Clone()
	} else if sys, err := x509.SystemCertPool(); err == nil {
		pool = sys
	} else {
		pool = x509.NewCertPool()
	}
	pool.AppendCertsFromPEM(appleRootsPEM)
	t.TLSClientConfig.RootCAs = pool
	out := *hc
	out.Transport = t
	return &out
}
