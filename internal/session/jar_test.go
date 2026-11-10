package session

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJarRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cookies.json")
	jar, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if !jar.Empty() {
		t.Fatal("new jar should be empty")
	}
	u, _ := url.Parse("https://developer.apple.com/")
	jar.SetCookies(u, []*http.Cookie{
		{Name: "myacinfo", Value: "abc", Path: "/", Secure: true, Expires: time.Now().Add(time.Hour)},
		{Name: "stale", Value: "x", Path: "/", Expires: time.Now().Add(-time.Hour)},
	})
	if jar.Empty() {
		t.Fatal("jar should hold cookies")
	}
	if err := jar.Save(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("cookie file mode = %o, want 600", perm)
	}

	reloaded, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	header := reloaded.CookieHeader("https://developer.apple.com/")
	if header != "myacinfo=abc" {
		t.Errorf("CookieHeader = %q, want myacinfo=abc", header)
	}
	// Expired cookies are dropped on load.
	if got := reloaded.CookieHeader("https://developer.apple.com/"); got == "" || containsCookie(got, "stale") {
		t.Errorf("expired cookie survived: %q", got)
	}

	if err := reloaded.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("Clear should delete the file")
	}
	if !reloaded.Empty() {
		t.Error("jar should be empty after Clear")
	}
}

func TestJarUnrelatedHostsIgnored(t *testing.T) {
	jar, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("https://example.com/")
	jar.SetCookies(u, []*http.Cookie{{Name: "x", Value: "1", Path: "/"}})
	if !jar.Empty() {
		t.Error("cookies for unrelated hosts must not count as a session")
	}
}

func containsCookie(header, name string) bool {
	return len(header) > 0 && (header == name || len(header) > len(name) &&
		(header[:len(name)+1] == name+"=" || containsSub(header, "; "+name+"=")))
}

func containsSub(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
