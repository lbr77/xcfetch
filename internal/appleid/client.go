package appleid

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

const (
	headerSessionID = "X-Apple-ID-Session-Id"
	headerWidgetKey = "X-Apple-Widget-Key"
	headerSCNT      = "scnt"
	headerHashcash  = "X-Apple-HC"
	userAgentChrome = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
	defaultTimeout  = 60
)

// Options configures Login.
type Options struct {
	// Jar persists cookies across calls; nil creates an in-memory jar.
	Jar http.CookieJar
	// HTTP is the client used for all requests; nil creates a default one.
	HTTP *http.Client
	// Now overrides the clock for hashcash timestamps (tests).
	Now func() time.Time
}

// Session is an authenticated Apple session.
type Session struct {
	Client *http.Client
	Jar    http.CookieJar
}

// errors returned by Login.
var (
	// ErrFederated reports an Apple ID managed by an identity provider.
	ErrFederated = errors.New("appleid: this Apple ID uses federated (SSO) sign-in; use a personal Apple ID")
	// ErrInvalidCredentials reports a rejected Apple ID or password.
	ErrInvalidCredentials = errors.New("appleid: invalid Apple ID or password")
	// ErrAccountLocked reports an account Apple has locked.
	ErrAccountLocked = errors.New("appleid: account is locked")
	// ErrPrivacyAcknowledgement reports that the account must accept new terms.
	ErrPrivacyAcknowledgement = errors.New("appleid: Apple ID terms acceptance required; sign in at appleid.apple.com once")
	// ErrSecurityKey reports a hardware-security-key protected account.
	ErrSecurityKey = errors.New("appleid: this account requires a hardware security key, which is not supported")
	// ErrTwoStepAuth reports the legacy two-step (not two-factor) scheme.
	ErrTwoStepAuth = errors.New("appleid: this account uses legacy two-step verification, which is not supported")
	// ErrIncorrectCode reports a rejected verification code.
	ErrIncorrectCode = errors.New("appleid: incorrect verification code")
)

// sessionData carries the headers Apple expects while a 2FA challenge is open.
type sessionData struct {
	serviceKey string
	sessionID  string
	scnt       string
}

// authOptions is Apple's second-factor challenge description.
type authOptions struct {
	TrustedPhoneNumbers []struct {
		ID                 int    `json:"id"`
		NumberWithDialCode string `json:"numberWithDialCode"`
	} `json:"trustedPhoneNumbers"`
	TrustedDevices []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"trustedDevices"`
	NoTrustedDevices bool      `json:"noTrustedDevices"`
	FSAChallenge     *struct{} `json:"fsaChallenge"`
	SecurityCode     struct {
		Length int `json:"length"`
	} `json:"securityCode"`
}

// Login performs the full Apple ID sign-in: SRP, then second-factor
// verification when Apple asks for it, then session validation.
func Login(ctx context.Context, creds Credentials, p Prompter, opts Options) (*Session, error) {
	hc, jar, err := clientAndJar(opts)
	if err != nil {
		return nil, err
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	key, err := serviceKey(ctx, hc)
	if err != nil {
		return nil, err
	}

	federated, err := checkFederation(ctx, hc, key, creds.AppleID)
	if err != nil {
		return nil, err
	}
	if federated {
		return nil, ErrFederated
	}

	state, err := srpSignIn(ctx, hc, key, creds.AppleID, creds.Password, now)
	if err != nil {
		return nil, err
	}

	sess := &Session{Client: hc, Jar: jar}
	if state == nil {
		return sess, sess.Validate(ctx)
	}
	if err := completeSecondFactor(ctx, hc, p, *state); err != nil {
		return nil, err
	}
	return sess, sess.Validate(ctx)
}

// Validate confirms the cookies are accepted by App Store Connect.
func (s *Session) Validate(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoints.olympusSession, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	switch {
	case resp.StatusCode == http.StatusOK:
		var doc struct {
			Provider struct {
				ProviderID any `json:"providerId"`
			} `json:"provider"`
		}
		_ = json.Unmarshal(body, &doc)
		return nil
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("appleid: session rejected (HTTP %s)", resp.Status)
	default:
		return fmt.Errorf("appleid: session check failed (HTTP %s): %s", resp.Status, truncate(body, 200))
	}
}

// CookieHeader renders the jar's cookies for host.
func (s *Session) CookieHeader(host string) string {
	u, err := url.Parse(host)
	if err != nil || s.Jar == nil {
		return ""
	}
	var parts []string
	for _, c := range s.Jar.Cookies(u) {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// Logout deletes every apple.com cookie from the jar.
func (s *Session) Logout() {
	if s.Jar == nil {
		return
	}
	for _, host := range []string{"https://idmsa.apple.com/", "https://appstoreconnect.apple.com/", "https://developer.apple.com/"} {
		if u, err := url.Parse(host); err == nil {
			for _, c := range s.Jar.Cookies(u) {
				c.MaxAge = -1
				s.Jar.SetCookies(u, []*http.Cookie{c})
			}
		}
	}
}

func clientAndJar(opts Options) (*http.Client, http.CookieJar, error) {
	jar := opts.Jar
	if jar == nil {
		j, err := cookiejar.New(nil)
		if err != nil {
			return nil, nil, err
		}
		jar = j
	}
	if opts.HTTP != nil {
		hc := *opts.HTTP
		hc.Jar = jar
		return &hc, jar, nil
	}
	return &http.Client{Jar: jar, Timeout: defaultTimeout * time.Second}, jar, nil
}

// checkFederation reports whether the account is managed by an identity provider.
func checkFederation(ctx context.Context, hc *http.Client, key, appleID string) (bool, error) {
	body, _ := json.Marshal(map[string]any{"accountName": appleID, "rememberMe": true})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoints.federate, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set(headerWidgetKey, key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgentChrome)

	resp, err := hc.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("appleid: federation check: HTTP %s: %s", resp.Status, truncate(raw, 200))
	}
	var doc struct {
		Federated bool `json:"federated"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return false, fmt.Errorf("appleid: federation check: %w", err)
	}
	return doc.Federated, nil
}

// srpSignIn runs SRP and returns nil when the session is already complete, or
// the open second-factor challenge.
func srpSignIn(ctx context.Context, hc *http.Client, key, appleID, password string, now func() time.Time) (*sessionData, error) {
	client, err := newSRPClient()
	if err != nil {
		return nil, err
	}

	// Hashcash must be minted before the SRP exchange, using the challenge Apple
	// returns from the federate endpoint.
	hashcash, err := mintHashcashForAccount(ctx, hc, key, appleID, now)
	if err != nil {
		return nil, err
	}

	initBody, _ := json.Marshal(map[string]any{
		"a":           base64.StdEncoding.EncodeToString(client.publicKey()),
		"accountName": appleID,
		"protocols":   []string{"s2k", "s2k_fo"},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoints.srpInit, bytes.NewReader(initBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set(headerWidgetKey, key)
	req.Header.Set("User-Agent", userAgentChrome)

	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("appleid: SRP init: HTTP %s: %s", resp.Status, truncate(raw, 200))
	}
	var initResp struct {
		B         string `json:"b"`
		Salt      string `json:"salt"`
		Iteration int    `json:"iteration"`
		Protocol  string `json:"protocol"`
		C         string `json:"c"`
	}
	if err := json.Unmarshal(raw, &initResp); err != nil {
		return nil, fmt.Errorf("appleid: SRP init: %w", err)
	}
	serverPublic, err := base64.StdEncoding.DecodeString(initResp.B)
	if err != nil {
		return nil, fmt.Errorf("appleid: SRP init: bad server public key: %w", err)
	}
	salt, err := base64.StdEncoding.DecodeString(initResp.Salt)
	if err != nil {
		return nil, fmt.Errorf("appleid: SRP init: bad salt: %w", err)
	}
	if initResp.Iteration <= 0 {
		return nil, fmt.Errorf("appleid: SRP init: implausible iteration count %d", initResp.Iteration)
	}

	stretched := pbkdfPassword(password, salt, initResp.Iteration, initResp.Protocol)
	_, sessionKeyHash, err := client.sharedSecret(appleID, stretched, salt, serverPublic)
	if err != nil {
		return nil, err
	}
	m1 := client.clientProof(appleID, salt, serverPublic, sessionKeyHash)
	m2 := client.serverProof(m1, sessionKeyHash)

	completeBody, _ := json.Marshal(map[string]any{
		"accountName": appleID,
		"c":           initResp.C,
		"m1":          base64.StdEncoding.EncodeToString(m1),
		"m2":          base64.StdEncoding.EncodeToString(m2),
		"rememberMe":  false,
	})
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, endpoints.srpComplete, bytes.NewReader(completeBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set(headerWidgetKey, key)
	req.Header.Set(headerHashcash, hashcash)
	req.Header.Set("User-Agent", userAgentChrome)

	resp, err = hc.Do(req)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil, nil
	case http.StatusUnauthorized:
		return nil, ErrInvalidCredentials
	case http.StatusForbidden:
		return nil, fmt.Errorf("%w: %s", ErrAccountLocked, serviceErrorText(body))
	case http.StatusConflict:
		sessionID := resp.Header.Get(headerSessionID)
		scnt := resp.Header.Get(headerSCNT)
		if sessionID == "" || scnt == "" {
			return nil, fmt.Errorf("appleid: 2FA required but Apple did not send session headers")
		}
		return &sessionData{serviceKey: key, sessionID: sessionID, scnt: scnt}, nil
	case http.StatusPreconditionFailed:
		return nil, ErrPrivacyAcknowledgement
	default:
		return nil, fmt.Errorf("appleid: sign-in failed: HTTP %s: %s", resp.Status, serviceErrorText(body))
	}
}

// mintHashcashForAccount asks Apple for a hashcash challenge and mints a value.
func mintHashcashForAccount(ctx context.Context, hc *http.Client, key, appleID string, now func() time.Time) (string, error) {
	u := endpoints.federate + "?widgetKey=" + url.QueryEscape(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgentChrome)

	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("appleid: hashcash challenge: HTTP %s", resp.Status)
	}
	bitsStr := resp.Header.Get("X-Apple-HC-Bits")
	challenge := resp.Header.Get("X-Apple-HC-Challenge")
	if bitsStr == "" || challenge == "" {
		return "", fmt.Errorf("appleid: hashcash challenge missing headers")
	}
	var bits uint
	if _, err := fmt.Sscanf(bitsStr, "%d", &bits); err != nil || bits == 0 || bits > 32 {
		return "", fmt.Errorf("appleid: bad hashcash difficulty %q", bitsStr)
	}
	return mintHashcash(challenge, bits, now()), nil
}

// completeSecondFactor walks Apple's second-factor flow with the user.
func completeSecondFactor(ctx context.Context, hc *http.Client, p Prompter, sd sessionData) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoints.authOptions, nil)
	if err != nil {
		return err
	}
	req.Header.Set(headerSessionID, sd.sessionID)
	req.Header.Set(headerWidgetKey, sd.serviceKey)
	req.Header.Set(headerSCNT, sd.scnt)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgentChrome)

	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("appleid: second-factor options: HTTP %s: %s", resp.Status, truncate(raw, 200))
	}
	var opts authOptions
	if err := json.Unmarshal(raw, &opts); err != nil {
		return fmt.Errorf("appleid: second-factor options: %w", err)
	}
	switch {
	case len(opts.TrustedDevices) > 0:
		return ErrTwoStepAuth
	case opts.FSAChallenge != nil:
		return ErrSecurityKey
	case len(opts.TrustedPhoneNumbers) == 0:
		return fmt.Errorf("appleid: no trusted phone numbers on this account; add one at appleid.apple.com")
	}

	phone := opts.TrustedPhoneNumbers[0]
	if len(opts.TrustedPhoneNumbers) > 1 {
		choices := make([]string, 0, len(opts.TrustedPhoneNumbers))
		for _, ph := range opts.TrustedPhoneNumbers {
			choices = append(choices, ph.NumberWithDialCode)
		}
		idx, err := p.PromptChoice("Choose a phone number for the verification code:", choices)
		if err != nil {
			return err
		}
		phone = opts.TrustedPhoneNumbers[idx]
	}

	if !opts.NoTrustedDevices || len(opts.TrustedPhoneNumbers) > 1 {
		// Only send an SMS explicitly when Apple is not doing it for us.
		if err := requestSMS(ctx, hc, sd, phone.ID); err != nil {
			return err
		}
	}
	p.Notify(fmt.Sprintf("Sending a verification code by SMS to %s", phone.NumberWithDialCode))

	code, err := p.PromptCode("Verification code: ")
	if err != nil {
		return err
	}
	if err := submitCode(ctx, hc, sd, strings.TrimSpace(code), phone.ID); err != nil {
		return err
	}
	if err := trustSession(ctx, hc, sd); err != nil {
		return err
	}
	return nil
}

func requestSMS(ctx context.Context, hc *http.Client, sd sessionData, phoneID int) error {
	body, _ := json.Marshal(map[string]any{
		"phoneNumber": map[string]int{"id": phoneID},
		"mode":        "sms",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoints.requestCode, bytes.NewReader(body))
	if err != nil {
		return err
	}
	applySessionHeaders(req, sd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgentChrome)

	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("appleid: requesting SMS code: HTTP %s", resp.Status)
	}
	return nil
}

func submitCode(ctx context.Context, hc *http.Client, sd sessionData, code string, phoneID int) error {
	body, _ := json.Marshal(map[string]any{
		"securityCode": map[string]string{"code": code},
		"phoneNumber":  map[string]int{"id": phoneID},
		"mode":         "sms",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoints.verifySMS, bytes.NewReader(body))
	if err != nil {
		return err
	}
	applySessionHeaders(req, sd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgentChrome)

	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusAccepted:
		return nil
	case http.StatusBadRequest, http.StatusUnauthorized:
		return ErrIncorrectCode
	case http.StatusPreconditionFailed:
		return ErrPrivacyAcknowledgement
	default:
		return fmt.Errorf("appleid: submitting verification code: HTTP %s", resp.Status)
	}
}

func trustSession(ctx context.Context, hc *http.Client, sd sessionData) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoints.trust, nil)
	if err != nil {
		return err
	}
	applySessionHeaders(req, sd)
	req.Header.Set("User-Agent", userAgentChrome)

	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("appleid: trusting the session: HTTP %s", resp.Status)
	}
	return nil
}

func applySessionHeaders(req *http.Request, sd sessionData) {
	req.Header.Set(headerSessionID, sd.sessionID)
	req.Header.Set(headerWidgetKey, sd.serviceKey)
	req.Header.Set(headerSCNT, sd.scnt)
	req.Header.Set("Accept", "application/json")
}

// serviceErrorText extracts Apple's human readable error from a sign-in body.
func serviceErrorText(body []byte) string {
	var doc struct {
		ServiceErrors []struct {
			Code        string `json:"code"`
			Message     string `json:"message"`
			Description string `json:"description"`
		} `json:"service_errors"`
	}
	if err := json.Unmarshal(body, &doc); err == nil && len(doc.ServiceErrors) > 0 {
		e := doc.ServiceErrors[0]
		text := e.Description
		if text == "" {
			text = e.Message
		}
		return strings.TrimSpace(strings.TrimPrefix(text, "-20209: "))
	}
	return truncate(body, 200)
}

func truncate(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
