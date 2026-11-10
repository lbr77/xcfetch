package appleid

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// endpoints holds Apple's identity-service URLs. It is a variable so tests can
// point the client at a fake server; every field is the production endpoint.
var endpoints = struct {
	logout         string
	olympusKey     string
	olympusSession string
	federate       string
	srpInit        string
	srpComplete    string
	authOptions    string
	requestCode    string
	trust          string
	verifyDevice   string
	verifySMS      string
}{
	logout:         "https://appstoreconnect.apple.com/logout",
	olympusKey:     "https://appstoreconnect.apple.com/olympus/v1/app/config?hostname=itunesconnect.apple.com",
	olympusSession: "https://appstoreconnect.apple.com/olympus/v1/session",
	federate:       "https://idmsa.apple.com/appleauth/auth/federate",
	srpInit:        "https://idmsa.apple.com/appleauth/auth/signin/init",
	srpComplete:    "https://idmsa.apple.com/appleauth/auth/signin/complete?isRememberMeEnabled=false",
	authOptions:    "https://idmsa.apple.com/appleauth/auth",
	requestCode:    "https://idmsa.apple.com/appleauth/auth/verify/phone",
	trust:          "https://idmsa.apple.com/appleauth/auth/2sv/trust",
	verifyDevice:   "https://idmsa.apple.com/appleauth/auth/verify/trusteddevice/securitycode",
	verifySMS:      "https://idmsa.apple.com/appleauth/auth/verify/phone/securitycode",
}

// serviceKeyCache memoises Apple's public sign-in widget key for the process.
var serviceKeyCache struct {
	sync.Mutex
	key string
}

// serviceKey resolves Apple's sign-in widget key, first from App Store Connect's
// sign-out redirect and then from the legacy Olympus endpoint.
func serviceKey(ctx context.Context, hc *http.Client) (string, error) {
	serviceKeyCache.Lock()
	cached := serviceKeyCache.key
	serviceKeyCache.Unlock()
	if cached != "" {
		return cached, nil
	}

	key, err := serviceKeyFromSignOut(ctx, hc)
	if err != nil || key == "" {
		key, err = serviceKeyFromOlympus(ctx, hc)
		if err != nil {
			return "", fmt.Errorf("appleid: resolving service key: %w", err)
		}
	}
	if key == "" {
		return "", fmt.Errorf("appleid: Apple returned an empty service key")
	}
	serviceKeyCache.Lock()
	serviceKeyCache.key = key
	serviceKeyCache.Unlock()
	return key, nil
}

func serviceKeyFromSignOut(ctx context.Context, hc *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoints.logout, nil)
	if err != nil {
		return "", err
	}
	noFollow := *hc
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noFollow.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return "", fmt.Errorf("sign-out returned HTTP %s", resp.Status)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", fmt.Errorf("sign-out redirect has no Location")
	}
	u, err := url.Parse(loc)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(u.Query().Get("widgetKey")), nil
}

func serviceKeyFromOlympus(ctx context.Context, hc *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoints.olympusKey, nil)
	if err != nil {
		return "", err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("olympus app config returned HTTP %s", resp.Status)
	}
	var doc struct {
		AuthServiceKey string `json:"authServiceKey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", err
	}
	return strings.TrimSpace(doc.AuthServiceKey), nil
}
