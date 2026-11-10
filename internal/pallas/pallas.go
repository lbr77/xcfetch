// Package pallas resolves Apple MobileAsset downloads through the public Pallas
// service at gdmf.apple.com.
//
// Simulator runtimes from iOS 18 onward are no longer published as plain URLs.
// The device asks Pallas for an asset by build number and receives a signed JWT
// whose payload lists the CDN location, size, checksums and the symmetric key
// needed to open the Apple Encrypted Archive.
package pallas

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Endpoint is Apple's asset query endpoint.
const Endpoint = "https://gdmf.apple.com/v2/assets"

// AudienceMacOSGeneric is the AssetAudience Apple publishes simulator runtime
// assets for. It is a capability-free constant used by every Mac.
const AudienceMacOSGeneric = "02d8e57e-dd1c-4090-aa50-b4ed2aef0062"

// AssetTypeIOSRuntime is the iOS simulator runtime asset type.
const AssetTypeIOSRuntime = "com.apple.MobileAsset.iOSSimulatorRuntime"

// Asset is one downloadable archive returned by Pallas.
type Asset struct {
	URL            string   `json:"__BaseURL"`
	RelativePath   string   `json:"__RelativePath"`
	Size           int64    `json:"_DownloadSize"`
	UnarchivedSize int64    `json:"_UnarchivedSize"`
	Compression    string   `json:"_CompressionAlgorithm"`
	Format         string   `json:"AssetFormat"`
	SHA1           string   `json:"_Measurement"`
	SHA256         string   `json:"_Measurement-SHA256"`
	DecryptionKey  string   `json:"ArchiveDecryptionKey"`
	Build          string   `json:"Build"`
	SimulatorVer   string   `json:"SimulatorVersion"`
	Architectures  []string `json:"Architectures"`
	AssetType      string   `json:"AssetType"`
	TrainName      string   `json:"TrainName"`
	IsAutoAsset    bool     `json:"_IsMAAutoAsset"`
}

// FullURL joins Apple's base URL with the relative path.
func (a Asset) FullURL() string {
	base := strings.TrimSuffix(a.URL, "/")
	rel := strings.TrimPrefix(a.RelativePath, "/")
	if base == "" {
		return rel
	}
	return base + "/" + rel
}

// Key decodes ArchiveDecryptionKey into the 32-byte AEA symmetric key.
func (a Asset) Key() ([]byte, error) {
	if a.DecryptionKey == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(a.DecryptionKey)
	if err != nil {
		return nil, fmt.Errorf("pallas: decode ArchiveDecryptionKey: %w", err)
	}
	return raw, nil
}

// Sum returns the decoded SHA-1 measurement, if present.
func (a Asset) Sum() ([]byte, error) { return decodeSum(a.SHA1) }

// Sum256 returns the decoded SHA-256 measurement, if present.
func (a Asset) Sum256() ([]byte, error) { return decodeSum(a.SHA256) }

func decodeSum(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("pallas: decode measurement: %w", err)
	}
	return raw, nil
}

// Query asks Pallas for every asset of assetType matching build.
func Query(ctx context.Context, hc *http.Client, assetType, audience, build string) ([]Asset, error) {
	body := map[string]any{
		"ClientVersion":  2,
		"AssetType":      assetType,
		"AssetAudience":  audience,
		"RequestedBuild": build,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, Endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "xcfetch/1 (+mobileasset)")
	// gdmf.apple.com chains to Apple's own root, absent from Linux CA bundles.
	resp, err := WithAppleRoots(hc).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pallas: HTTP %s", resp.Status)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, err
	}
	return parseResponse(buf.Bytes())
}

// parseResponse decodes the JWT (its payload is the JSON document we need; the
// JWS signature is not verified because the transport is TLS to gdmf.apple.com).
func parseResponse(raw []byte) ([]Asset, error) {
	token := strings.TrimSpace(string(raw))
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("pallas: response is not a JWT (got %d segments)", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Tolerate padded base64url.
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("pallas: decode JWT payload: %w", err)
		}
	}
	var doc struct {
		Assets []Asset `json:"Assets"`
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("pallas: decode JWT payload JSON: %w", err)
	}
	return doc.Assets, nil
}

// Pick chooses the asset for arch ("arm64", "x86_64", or "" for universal-first
// then any). Universal assets list more than one architecture.
func Pick(assets []Asset, arch string) (Asset, error) {
	if len(assets) == 0 {
		return Asset{}, fmt.Errorf("pallas: no assets returned")
	}
	pick := func(match func(Asset) bool) (Asset, bool) {
		for _, a := range assets {
			if match(a) {
				return a, true
			}
		}
		return Asset{}, false
	}
	switch arch {
	case "":
		if a, ok := pick(func(a Asset) bool { return len(a.Architectures) > 1 }); ok {
			return a, nil
		}
		return assets[0], nil
	case "universal":
		if a, ok := pick(func(a Asset) bool { return len(a.Architectures) > 1 }); ok {
			return a, nil
		}
		return Asset{}, fmt.Errorf("pallas: no universal asset (have %v)", architectures(assets))
	default:
		if a, ok := pick(func(a Asset) bool {
			return len(a.Architectures) == 1 && strings.EqualFold(a.Architectures[0], arch)
		}); ok {
			return a, nil
		}
		if a, ok := pick(func(a Asset) bool {
			for _, x := range a.Architectures {
				if strings.EqualFold(x, arch) {
					return true
				}
			}
			return false
		}); ok {
			return a, nil
		}
		return Asset{}, fmt.Errorf("pallas: no asset for arch %q (have %v)", arch, architectures(assets))
	}
}

func architectures(assets []Asset) [][]string {
	out := make([][]string, 0, len(assets))
	for _, a := range assets {
		out = append(out, a.Architectures)
	}
	return out
}
