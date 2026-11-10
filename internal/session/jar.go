// Package session persists the Apple session cookies between runs.
//
// The cookie jar is snapshotted for the handful of hosts involved in a
// developer session, so that `xcfetch xcode login` only has to run once.
package session

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// hosts whose cookies make up a developer session.
var snapshotHosts = []string{
	"https://idmsa.apple.com/",
	"https://appstoreconnect.apple.com/",
	"https://developer.apple.com/",
	"https://developerservices2.apple.com/",
	"https://download.developer.apple.com/",
}

// ConfigDir is $XDG_CONFIG_HOME/xcfetch (or ~/.config/xcfetch).
func ConfigDir() (string, error) {
	if dir := os.Getenv("XCFETCH_CONFIG_DIR"); dir != "" {
		return dir, nil
	}
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "xcfetch"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "xcfetch"), nil
}

// DefaultPath is the default cookie file location.
func DefaultPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "cookies.json"), nil
}

type storedCookie struct {
	Host    string    `json:"host"`
	Name    string    `json:"name"`
	Value   string    `json:"value"`
	Path    string    `json:"path,omitempty"`
	Expires time.Time `json:"expires,omitempty"`
	Secure  bool      `json:"secure,omitempty"`
}

// Jar is an in-memory cookie jar with JSON persistence.
type Jar struct {
	jar  *cookiejar.Jar
	path string
}

// New opens (or creates) the jar stored at path. An empty path keeps the jar
// in memory only.
func New(path string) (*Jar, error) {
	cj, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	j := &Jar{jar: cj, path: path}
	if path != "" {
		if err := j.load(); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	return j, nil
}

func (j *Jar) Cookies(u *url.URL) []*http.Cookie { return j.jar.Cookies(u) }

func (j *Jar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.jar.SetCookies(u, cookies)
}

// Save writes the snapshot to disk with 0600 permissions.
func (j *Jar) Save() error {
	if j.path == "" {
		return nil
	}
	var stored []storedCookie
	for _, host := range snapshotHosts {
		u, err := url.Parse(host)
		if err != nil {
			continue
		}
		for _, c := range j.jar.Cookies(u) {
			stored = append(stored, storedCookie{
				Host: host, Name: c.Name, Value: c.Value,
				Path: c.Path, Expires: c.Expires, Secure: c.Secure,
			})
		}
	}
	if err := os.MkdirAll(filepath.Dir(j.path), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(struct {
		Cookies []storedCookie `json:"cookies"`
	}{stored}, "", "  ")
	if err != nil {
		return err
	}
	tmp := j.path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, j.path)
}

func (j *Jar) load() error {
	body, err := os.ReadFile(j.path)
	if err != nil {
		return err
	}
	var doc struct {
		Cookies []storedCookie `json:"cookies"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("session: %s: %w", j.path, err)
	}
	for _, sc := range doc.Cookies {
		u, err := url.Parse(sc.Host)
		if err != nil {
			continue
		}
		if !sc.Expires.IsZero() && sc.Expires.Before(time.Now()) {
			continue
		}
		j.jar.SetCookies(u, []*http.Cookie{{
			Name: sc.Name, Value: sc.Value, Path: sc.Path,
			Expires: sc.Expires, Secure: sc.Secure,
		}})
	}
	return nil
}

// Clear deletes the persisted cookies.
func (j *Jar) Clear() error {
	cj, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	j.jar = cj
	if j.path == "" {
		return nil
	}
	if err := os.Remove(j.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Empty reports whether the jar holds no cookies at all.
func (j *Jar) Empty() bool {
	for _, host := range snapshotHosts {
		u, err := url.Parse(host)
		if err != nil {
			continue
		}
		if len(j.jar.Cookies(u)) > 0 {
			return false
		}
	}
	return true
}

// CookieHeader renders the cookies matching host as a Cookie header value.
func (j *Jar) CookieHeader(host string) string {
	u, err := url.Parse(host)
	if err != nil {
		return ""
	}
	parts := ""
	for _, c := range j.jar.Cookies(u) {
		if parts != "" {
			parts += "; "
		}
		parts += c.Name + "=" + c.Value
	}
	return parts
}
