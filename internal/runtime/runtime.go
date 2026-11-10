// Package runtime reads Apple's downloadable simulator runtime index.
//
// The index is a binary plist published at
// https://devimages-cdn.apple.com/downloads/xcode/simulators/index2.dvtdownloadableindex
// and needs no authentication to read.
package runtime

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"howett.net/plist"
)

const IndexURL = "https://devimages-cdn.apple.com/downloads/xcode/simulators/index2.dvtdownloadableindex"

// Runtime is one downloadable simulator runtime.
type Runtime struct {
	Category         string   `plist:"category"`
	Platform         string   `plist:"platform"`
	Identifier       string   `plist:"identifier"`
	Version          string   `plist:"version"`
	Name             string   `plist:"name"`
	ContentType      string   `plist:"contentType"`
	DownloadMethod   string   `plist:"downloadMethod"`
	Authentication   string   `plist:"authentication"`
	Architectures    []string `plist:"architectures"`
	FileSize         int64    `plist:"fileSize"`
	SourceURL        string   `plist:"source"`
	SimulatorVersion Version  `plist:"simulatorVersion"`
	HostRequirements HostReqs `plist:"hostRequirements"`
	TrainName        string   `plist:"trainName"`
}

// Version is Apple's per-runtime version tuple.
type Version struct {
	Version     string `plist:"version"`
	BuildUpdate string `plist:"buildUpdate"`
}

// HostReqs mirrors the index's host requirements block.
type HostReqs struct {
	MinHostVersion    string   `plist:"minHostVersion"`
	MaxHostVersion    string   `plist:"maxHostVersion"`
	MinXcodeVersion   string   `plist:"minXcodeVersion"`
	ExcludedHostArchs []string `plist:"excludedHostArchitectures"`
}

// HasDirectSource reports whether Apple publishes a direct download URL
// (runtimes up to iOS 17.5). Newer runtimes are delivered through MobileAsset.
func (r Runtime) HasDirectSource() bool { return r.SourceURL != "" }

// MobileAsset reports whether the runtime must be resolved through Pallas.
func (r Runtime) MobileAsset() bool {
	return r.DownloadMethod == "mobileAsset" || r.SourceURL == ""
}

// PlatformName shortens "com.apple.platform.iphoneos" to "iOS".
func (r Runtime) PlatformName() string {
	switch r.Platform {
	case "com.apple.platform.iphoneos":
		return "iOS"
	case "com.apple.platform.watchos":
		return "watchOS"
	case "com.apple.platform.appletvos":
		return "tvOS"
	case "com.apple.platform.xros":
		return "visionOS"
	case "com.apple.platform.macosx":
		return "macOS"
	}
	return strings.TrimPrefix(r.Platform, "com.apple.platform.")
}

// DisplayVersion is the human version, including beta seed when Apple encodes
// one in the identifier (e.g. com.apple.dmg.iPhoneSimulatorSDK17_4_b3).
func (r Runtime) DisplayVersion() string {
	v := r.SimulatorVersion.Version
	if v == "" {
		v = r.Version
	}
	if seed := seedSuffix(r.Identifier); seed != "" {
		v += "-" + seed
	}
	return v
}

// Prerelease reports whether the runtime is a beta, RC or seed build.
func (r Runtime) Prerelease() bool {
	if seedSuffix(r.Identifier) != "" {
		return true
	}
	haystack := strings.ToLower(r.Name + " " + r.SimulatorVersion.Version + " " + r.TrainName)
	for _, marker := range []string{"beta", " rc", "seed", "rru"} {
		if strings.Contains(haystack, marker) {
			return true
		}
	}
	return false
}

func seedSuffix(identifier string) string {
	// _b3 / _beta / _rc / _rru suffixes carry the release channel.
	i := strings.LastIndex(identifier, "_")
	if i < 0 {
		return ""
	}
	tail := identifier[i+1:]
	switch {
	case tail == "rc", tail == "rru", tail == "beta":
		return tail
	case strings.HasPrefix(tail, "b") && len(tail) > 1 && isDigits(tail[1:]):
		return "beta" + tail[1:]
	}
	return ""
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

// Load fetches and decodes the runtime index.
func Load(ctx context.Context, hc *http.Client) ([]Runtime, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, IndexURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("runtime index: HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Version       string    `plist:"version"`
		Downloadables []Runtime `plist:"downloadables"`
	}
	if _, err := plist.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("runtime index: decode: %w", err)
	}
	out := make([]Runtime, 0, len(doc.Downloadables))
	for _, r := range doc.Downloadables {
		if r.Category != "simulator" {
			continue
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Platform != out[j].Platform {
			return out[i].Platform < out[j].Platform
		}
		return compareVersions(out[j].SimulatorVersion.Version, out[i].SimulatorVersion.Version) < 0
	})
	return out, nil
}

// Find selects the newest runtime matching query, which may be a version
// ("26.5"), a version with seed ("26.5-beta2"), a build ("23F77"), or an
// identifier. platform filters by PlatformName ("" means iOS).
func Find(runtimes []Runtime, query, platform string, arch string) (Runtime, error) {
	var candidates []Runtime
	q := strings.ToLower(strings.TrimSpace(query))
	for _, r := range runtimes {
		if platform != "" && !strings.EqualFold(r.PlatformName(), platform) {
			continue
		}
		if arch != "" && len(r.Architectures) > 0 && !containsFold(r.Architectures, arch) {
			continue
		}
		switch {
		case strings.EqualFold(r.Identifier, q),
			strings.EqualFold(r.SimulatorVersion.BuildUpdate, q),
			strings.EqualFold(r.DisplayVersion(), q),
			strings.EqualFold(r.SimulatorVersion.Version, q),
			strings.EqualFold(strings.TrimSpace(r.Name), q):
			candidates = append(candidates, r)
		}
	}
	if len(candidates) == 0 {
		return Runtime{}, fmt.Errorf("no runtime matches %q (platform %q, arch %q)", query, platform, arch)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.Prerelease() != b.Prerelease() {
			return b.Prerelease() // releases first
		}
		if c := compareVersions(a.DisplayVersion(), b.DisplayVersion()); c != 0 {
			return c > 0
		}
		return a.SimulatorVersion.BuildUpdate > b.SimulatorVersion.BuildUpdate
	})
	return candidates[0], nil
}

func containsFold(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

// compareVersions compares dotted numeric versions (suffixes after '-' compare
// lexically against the shorter/absent one being smaller).
func compareVersions(a, b string) int {
	as, bs := strings.SplitN(a, "-", 2), strings.SplitN(b, "-", 2)
	an, bn := strings.Split(as[0], "."), strings.Split(bs[0], ".")
	for i := 0; i < len(an) || i < len(bn); i++ {
		var x, y int
		if i < len(an) {
			fmt.Sscanf(an[i], "%d", &x)
		}
		if i < len(bn) {
			fmt.Sscanf(bn[i], "%d", &y)
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	var asuf, bsuf string
	if len(as) > 1 {
		asuf = as[1]
	}
	if len(bs) > 1 {
		bsuf = bs[1]
	}
	switch {
	case asuf == bsuf:
		return 0
	case asuf == "":
		return 1 // release outranks prerelease
	case bsuf == "":
		return -1
	case asuf < bsuf:
		return -1
	}
	return 1
}
