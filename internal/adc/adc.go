// Package adc talks to Apple's authenticated Developer Downloads service.
//
// Two endpoints matter:
//
//	POST https://developer.apple.com/services-account/QH65B2/downloadws/listDownloads.action
//	     -> JSON listing every Xcode archive the account can download
//	GET  https://developerservices2.apple.com/services/download?path=<remotePath>
//	     -> 302 to download.developer.apple.com carrying the ADCDownloadAuth cookie
//
// Both are plain HTTPS; no macOS service or private framework is involved.
package adc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const cdnPrefix = "https://download.developer.apple.com/"

// Endpoints are variables so tests can point them at a fake server.
var (
	ListURL = "https://developer.apple.com/services-account/QH65B2/downloadws/listDownloads.action"
	AuthURL = "https://developerservices2.apple.com/services/download"
)

func setListURL(u string) { ListURL = u }
func setAuthURL(u string) { AuthURL = u }

// Download is one entry of the downloads listing.
type Download struct {
	Name         string    `json:"name"`
	Files        []File    `json:"files"`
	DateModified AppleDate `json:"dateModified"`
}

// AppleDate decodes Apple's two date encodings: an NSDate reference interval
// (seconds since 2001-01-01, what the service currently returns) and the older
// ISO-8601 / "Jan 2, 2006" strings.
type AppleDate struct{ time.Time }

func (d *AppleDate) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] != '"' {
		var secs float64
		if err := json.Unmarshal(b, &secs); err != nil {
			return err
		}
		d.Time = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC).Add(
			time.Duration(secs * float64(time.Second)))
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "Jan 2, 2006", "2006/01/02"} {
		if t, err := time.Parse(layout, s); err == nil {
			d.Time = t
			return nil
		}
	}
	return fmt.Errorf("adc: unrecognized date %q", s)
}

// File is one archive inside a Download.
type File struct {
	RemotePath string `json:"remotePath"`
	FileSize   int64  `json:"fileSize"`
}

// Modified returns the modification time, if Apple supplied one.
func (d Download) Modified() time.Time { return d.DateModified.Time }

// ErrUnauthorized means the session cookies were rejected.
var ErrUnauthorized = fmt.Errorf("adc: not authorized (run `xcfetch xcode login`)")

// ListDownloads returns everything Apple offers to the current session.
func ListDownloads(ctx context.Context, hc *http.Client) ([]Download, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ListURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/javascript")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, ErrUnauthorized
	default:
		return nil, fmt.Errorf("adc: listDownloads: HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var doc struct {
		ResultCode    int        `json:"resultCode"`
		ResultsString string     `json:"resultsString"`
		Downloads     []Download `json:"downloads"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("adc: listDownloads: decode: %w", err)
	}
	if doc.ResultCode != 0 {
		return nil, fmt.Errorf("adc: listDownloads: result %d: %s", doc.ResultCode, doc.ResultsString)
	}
	if len(doc.Downloads) == 0 {
		return nil, fmt.Errorf("adc: listDownloads returned no entries: %s", doc.ResultsString)
	}
	sort.SliceStable(doc.Downloads, func(i, j int) bool {
		return doc.Downloads[i].Modified().After(doc.Downloads[j].Modified())
	})
	return doc.Downloads, nil
}

// Authorize resolves remotePath to the final CDN URL. The 302 response sets the
// ADCDownloadAuth cookie on the shared jar; the caller must reuse the same jar
// for the actual download.
func Authorize(ctx context.Context, hc *http.Client, remotePath string) (string, error) {
	u := AuthURL + "?path=" + url.QueryEscape(remotePath)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "*/*")

	// Do not follow the redirect: we only need its Location, and following it
	// would transfer the whole archive.
	noFollow := *hc
	noFollow.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := noFollow.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		loc := resp.Header.Get("Location")
		if loc == "" {
			return "", fmt.Errorf("adc: authorize: redirect without Location")
		}
		return loc, nil
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return "", ErrUnauthorized
	case resp.StatusCode == http.StatusOK:
		// Some accounts get the archive inline; the CDN path is derivable.
		return cdnPrefix + strings.TrimPrefix(remotePath, "/"), nil
	default:
		return "", fmt.Errorf("adc: authorize: HTTP %s", resp.Status)
	}
}

// Find returns the newest download whose name contains query (case
// insensitive) and its first archive matching ext (".xip", ".dmg", ...).
func Find(dls []Download, query, ext string) (Download, File, error) {
	q := strings.ToLower(strings.TrimSpace(query))
	var matches []Download
	for _, d := range dls {
		if strings.Contains(strings.ToLower(d.Name), q) {
			matches = append(matches, d)
		}
	}
	if len(matches) == 0 {
		return Download{}, File{}, fmt.Errorf("adc: no download matching %q", query)
	}
	sort.SliceStable(matches, func(i, j int) bool {
		return versionKey(matches[i].Name) > versionKey(matches[j].Name)
	})
	for _, d := range matches {
		for _, f := range d.Files {
			if ext == "" || strings.HasSuffix(strings.ToLower(f.RemotePath), strings.ToLower(ext)) {
				return d, f, nil
			}
		}
	}
	return Download{}, File{}, fmt.Errorf("adc: no %s file in %q", ext, matches[0].Name)
}

// versionKey extracts a sortable key from an Xcode name ("Xcode 16.2 beta 2").
func versionKey(name string) string {
	var sb strings.Builder
	for _, r := range name {
		switch {
		case r >= '0' && r <= '9':
			sb.WriteRune(r)
		case r == '.':
			sb.WriteRune('.')
		case r == ' ':
			sb.WriteRune(' ')
		}
	}
	fields := strings.Fields(sb.String())
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		if isNumeric(f) {
			if n, err := strconv.Atoi(f); err == nil {
				parts = append(parts, fmt.Sprintf("%04d", n))
				continue
			}
		}
		parts = append(parts, f)
	}
	return strings.Join(parts, ".")
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// XcodeArchives filters a listing down to Xcode entries with a .xip or .dmg.
func XcodeArchives(dls []Download) []Download {
	out := make([]Download, 0, len(dls))
	for _, d := range dls {
		if !strings.HasPrefix(d.Name, "Xcode") {
			continue
		}
		hasArchive := false
		for _, f := range d.Files {
			lower := strings.ToLower(f.RemotePath)
			if strings.HasSuffix(lower, ".xip") || strings.HasSuffix(lower, ".dmg") {
				hasArchive = true
				break
			}
		}
		if hasArchive {
			out = append(out, d)
		}
	}
	return out
}
