package appleid

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeApple emulates the subset of idmsa/olympus behaviour the login flow uses.
type fakeApple struct {
	t *testing.T

	mu          sync.Mutex
	federated   bool
	complete    int  // status for /signin/complete
	has2FA      bool // complete returns 409
	validate    int  // status for /olympus/v1/session
	gotHashcash string
	gotM1       string
	gotCode     string
	gotTrust    bool
	gotSMS      bool
	steps       []string
	server      *httptest.Server
}

func newFakeApple(t *testing.T) *fakeApple {
	f := &fakeApple{t: t, complete: http.StatusOK, validate: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://appstoreconnect.apple.com/login?widgetKey=KEY-FROM-LOGOUT&x=1")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/federate", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.steps = append(f.steps, "federate:"+r.Method)
		f.mu.Unlock()
		switch r.Method {
		case http.MethodPost:
			json.NewEncoder(w).Encode(map[string]bool{"federated": f.federated})
		case http.MethodGet:
			w.Header().Set("X-Apple-HC-Bits", "4")
			w.Header().Set("X-Apple-HC-Challenge", "challenge-token")
			w.WriteHeader(http.StatusOK)
		}
	})
	mux.HandleFunc("/signin/init", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			A           string   `json:"a"`
			AccountName string   `json:"accountName"`
			Protocols   []string `json:"protocols"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.AccountName != "dev@example.com" || req.Protocols[0] != "s2k" || req.A == "" {
			f.t.Errorf("bad SRP init request: %+v", req)
		}
		f.mu.Lock()
		f.steps = append(f.steps, "srp-init")
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{
			"b":         base64.StdEncoding.EncodeToString(vectorServerPublic()),
			"salt":      "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g",
			"iteration": 20000,
			"protocol":  "s2k",
			"c":         "server-challenge",
		})
	})
	mux.HandleFunc("/signin/complete", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			AccountName string `json:"accountName"`
			C           string `json:"c"`
			M1          string `json:"m1"`
			M2          string `json:"m2"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.gotHashcash = r.Header.Get(headerHashcash)
		f.gotM1 = req.M1
		f.steps = append(f.steps, "srp-complete")
		f.mu.Unlock()
		if req.C != "server-challenge" || req.M1 == "" || req.M2 == "" {
			f.t.Errorf("bad SRP complete request: %+v", req)
		}
		if f.has2FA {
			w.Header().Set(headerSessionID, "session-123")
			w.Header().Set(headerSCNT, "scnt-456")
			w.WriteHeader(http.StatusConflict)
			io.WriteString(w, `{"authType":"hsa2"}`)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "myacinfo", Value: "token", Path: "/"})
		w.WriteHeader(f.complete)
		if f.complete != http.StatusOK {
			io.WriteString(w, `{"service_errors":[{"code":"-20209","description":"-20209: Your account is locked"}]}`)
		}
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerSessionID) != "session-123" || r.Header.Get(headerSCNT) != "scnt-456" || r.Header.Get(headerWidgetKey) == "" {
			f.t.Errorf("2FA options request missing session headers")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"trustedPhoneNumbers": []map[string]any{{"id": 7, "numberWithDialCode": "+1 ••••1234"}},
			"securityCode":        map[string]int{"length": 6},
			"noTrustedDevices":    false,
		})
	})
	mux.HandleFunc("/verify/phone", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			f.t.Errorf("SMS request should be PUT, got %s", r.Method)
		}
		f.mu.Lock()
		f.gotSMS = true
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/verify/phone/securitycode", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			SecurityCode struct {
				Code string `json:"code"`
			} `json:"securityCode"`
			PhoneNumber struct {
				ID int `json:"id"`
			} `json:"phoneNumber"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.gotCode = req.SecurityCode.Code
		f.mu.Unlock()
		if req.PhoneNumber.ID != 7 {
			f.t.Errorf("wrong phone id %d", req.PhoneNumber.ID)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/2sv/trust", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.gotTrust = true
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/olympus/v1/session", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"user": map[string]string{"emailAddress": "dev@example.com"}})
	})
	mux.HandleFunc("/olympus-app-config", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"authServiceKey": "KEY-FROM-OLYMPUS"})
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	pointEndpointsAt(f.server.URL)
	return f
}

// pointEndpointsAt rewrites the package endpoints to a test server and returns
// a restore function the test must defer.
func pointEndpointsAt(base string) {
	restore := endpoints
	endpoints.logout = base + "/logout"
	endpoints.olympusKey = base + "/olympus-app-config"
	endpoints.olympusSession = base + "/olympus/v1/session"
	endpoints.federate = base + "/federate"
	endpoints.srpInit = base + "/signin/init"
	endpoints.srpComplete = base + "/signin/complete"
	endpoints.authOptions = base + "/auth"
	endpoints.requestCode = base + "/verify/phone"
	endpoints.verifySMS = base + "/verify/phone/securitycode"
	endpoints.trust = base + "/2sv/trust"
	serviceKeyCache.Lock()
	serviceKeyCache.key = ""
	serviceKeyCache.Unlock()
	pendingRestore = func() {
		endpoints = restore
		serviceKeyCache.Lock()
		serviceKeyCache.key = ""
		serviceKeyCache.Unlock()
	}
}

var pendingRestore func()

func TestLoginWithoutSecondFactor(t *testing.T) {
	t.Cleanup(func() { pendingRestore() })
	f := newFakeApple(t)

	p := &scriptedPrompter{}
	sess, err := Login(context.Background(), Credentials{AppleID: "dev@example.com", Password: "pw"}, p,
		Options{Now: timeFixture})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if err := sess.Validate(context.Background()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if f.gotHashcash == "" || !strings.HasPrefix(f.gotHashcash, "1:4:250101000000:challenge-token:") {
		t.Errorf("unexpected hashcash %q", f.gotHashcash)
	}
	if f.gotM1 == "" {
		t.Error("no M1 sent")
	}
	if header := sess.CookieHeader(f.server.URL + "/"); !strings.Contains(header, "myacinfo=token") {
		t.Errorf("session cookie missing from CookieHeader: %q", header)
	}
	want := []string{"federate:POST", "federate:GET", "srp-init", "srp-complete"}
	if strings.Join(f.steps, ",") != strings.Join(want, ",") {
		t.Errorf("steps = %v, want %v", f.steps, want)
	}
}

func TestLoginWithSMSSecondFactor(t *testing.T) {
	t.Cleanup(func() { pendingRestore() })
	f := newFakeApple(t)
	f.has2FA = true

	p := &scriptedPrompter{codes: []string{"123456"}}
	if _, err := Login(context.Background(), Credentials{AppleID: "dev@example.com", Password: "pw"}, p,
		Options{Now: timeFixture}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !f.gotSMS {
		t.Error("SMS code was not requested")
	}
	if f.gotCode != "123456" {
		t.Errorf("code = %q", f.gotCode)
	}
	if !f.gotTrust {
		t.Error("session was not trusted")
	}
	if !strings.Contains(strings.Join(p.notified, " "), "+1 ••••1234") {
		t.Errorf("user was not told where the code went: %v", p.notified)
	}
}

func TestLoginErrors(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*fakeApple)
		wantErr  error
		contains string
	}{
		{"federated", func(f *fakeApple) { f.federated = true }, ErrFederated, ""},
		{"bad password", func(f *fakeApple) { f.complete = http.StatusUnauthorized }, ErrInvalidCredentials, ""},
		{"locked", func(f *fakeApple) { f.complete = http.StatusForbidden }, ErrAccountLocked, "locked"},
		{"terms", func(f *fakeApple) { f.complete = http.StatusPreconditionFailed }, ErrPrivacyAcknowledgement, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(func() { pendingRestore() })
			f := newFakeApple(t)
			tc.setup(f)
			_, err := Login(context.Background(), Credentials{AppleID: "dev@example.com", Password: "pw"},
				&scriptedPrompter{}, Options{Now: timeFixture})
			if err == nil || !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if tc.contains != "" && !strings.Contains(err.Error(), tc.contains) {
				t.Errorf("err = %v, want it to mention %q", err, tc.contains)
			}
		})
	}
}

func TestValidateRejectsBadSession(t *testing.T) {
	t.Cleanup(func() { pendingRestore() })
	newFakeApple(t)
	hc := &http.Client{}
	sess := &Session{Client: hc, Jar: nil}
	// Point the client at a 401 endpoint.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	endpoints.olympusSession = srv.URL
	if err := sess.Validate(context.Background()); err == nil {
		t.Fatal("expected an error for a rejected session")
	}
}

func TestServiceKeyFallsBackToOlympus(t *testing.T) {
	t.Cleanup(func() { pendingRestore() })
	newFakeApple(t)
	hc := &http.Client{}
	endpoints.logout = "https://127.0.0.1:1/logout" // unreachable
	key, err := serviceKey(context.Background(), hc)
	if err != nil {
		t.Fatalf("serviceKey: %v", err)
	}
	if key != "KEY-FROM-OLYMPUS" {
		t.Errorf("key = %q", key)
	}
}

// scriptedPrompter feeds canned answers.
type scriptedPrompter struct {
	mu       sync.Mutex
	codes    []string
	notified []string
}

func (p *scriptedPrompter) PromptPassword(string) (string, error) { return "pw", nil }

func (p *scriptedPrompter) PromptCode(string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.codes) == 0 {
		return "", errors.New("no code available")
	}
	code := p.codes[0]
	p.codes = p.codes[1:]
	return code, nil
}

func (p *scriptedPrompter) PromptChoice(string, []string) (int, error) { return 0, nil }

func (p *scriptedPrompter) Notify(msg string) {
	p.mu.Lock()
	p.notified = append(p.notified, msg)
	p.mu.Unlock()
}
