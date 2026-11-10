package adc

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
)

const fixture = `{
  "resultCode": 0,
  "resultsString": "ok",
  "downloads": [
    {"name": "Xcode 16.2", "files": [{"remotePath": "/Developer_Tools/Xcode_16.2/Xcode_16.2.xip", "fileSize": 3000000000}], "dateModified": 757382400.0},
    {"name": "Xcode 26.4", "files": [{"remotePath": "/Developer_Tools/Xcode_26.4/Xcode_26.4.xip", "fileSize": 4000000000}], "dateModified": 790000000.0},
    {"name": "Command Line Tools for Xcode 16.2", "files": [{"remotePath": "/Developer_Tools/cli.dmg", "fileSize": 100}], "dateModified": 757382400.0}
  ]
}`

func TestListDownloadsAndDateDecoding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if got := r.Header.Get("X-Requested-With"); got != "XMLHttpRequest" {
			t.Errorf("missing XHR header, got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fixture))
	}))
	defer srv.Close()

	saved := ListURL
	defer func() { setListURL(saved) }()
	setListURL(srv.URL)

	list, err := ListDownloads(context.Background(), srv.Client())
	if err != nil {
		t.Fatalf("ListDownloads: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("got %d downloads", len(list))
	}
	// Newest first.
	if list[0].Name != "Xcode 26.4" {
		t.Errorf("ordering wrong, first = %q", list[0].Name)
	}
	// dateModified is an NSDate reference interval (seconds since 2001).
	if got, want := list[1].Modified().Year(), 2025; got != want {
		t.Errorf("year = %d, want %d (%s)", got, want, list[1].Modified())
	}
}

func TestXcodeArchivesFilter(t *testing.T) {
	list, err := ListDownloads(context.Background(), staticClient(fixture))
	if err != nil {
		t.Fatal(err)
	}
	xcodes := XcodeArchives(list)
	if len(xcodes) != 2 {
		t.Fatalf("got %d Xcode entries, want 2", len(xcodes))
	}
}

func TestFindPicksNewest(t *testing.T) {
	list, err := ListDownloads(context.Background(), staticClient(fixture))
	if err != nil {
		t.Fatal(err)
	}
	dl, file, err := Find(list, "xcode", ".xip")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if dl.Name != "Xcode 26.4" {
		t.Errorf("picked %q, want Xcode 26.4", dl.Name)
	}
	if file.RemotePath != "/Developer_Tools/Xcode_26.4/Xcode_26.4.xip" {
		t.Errorf("wrong file %q", file.RemotePath)
	}
	if _, _, err := Find(list, "xcode", ".pkg"); err == nil {
		t.Error("expected an error when no file matches the extension")
	}
}

func TestFindRejectsUnknown(t *testing.T) {
	list, _ := ListDownloads(context.Background(), staticClient(fixture))
	if _, _, err := Find(list, "nope", ".xip"); err == nil {
		t.Fatal("expected an error")
	}
}

func TestListDownloadsUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	saved := ListURL
	defer func() { setListURL(saved) }()
	setListURL(srv.URL)
	_, err := ListDownloads(context.Background(), srv.Client())
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func TestAuthorizeReturnsRedirectAndKeepsCookie(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("path"); got != "/Developer_Tools/x/Xcode.xip" {
			t.Errorf("path = %q", got)
		}
		http.SetCookie(w, &http.Cookie{Name: "ADCDownloadAuth", Value: "tok", Path: "/"})
		w.Header().Set("Location", "https://download.developer.apple.com/Developer_Tools/x/Xcode.xip")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	saved := AuthURL
	defer func() { setAuthURL(saved) }()
	setAuthURL(srv.URL)

	hc := &http.Client{Jar: jar}
	got, err := Authorize(context.Background(), hc, "/Developer_Tools/x/Xcode.xip")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if got != "https://download.developer.apple.com/Developer_Tools/x/Xcode.xip" {
		t.Errorf("url = %q", got)
	}
	if len(jar.Cookies(mustURL(t, srv.URL))) == 0 {
		t.Error("ADCDownloadAuth cookie was not stored")
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestAuthorizeUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	saved := AuthURL
	defer func() { setAuthURL(saved) }()
	setAuthURL(srv.URL)
	if _, err := Authorize(context.Background(), srv.Client(), "/x.xip"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
}

func staticClient(body string) *http.Client {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	saved := ListURL
	setListURL(srv.URL)
	// The server is intentionally leaked for the duration of the test binary.
	_ = srv
	_ = saved
	return srv.Client()
}
