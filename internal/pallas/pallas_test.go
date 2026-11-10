package pallas

import (
	"context"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// A trimmed but verbatim Pallas payload (JWT middle segment) for iOS 26.5.
const fixturePayload = `{"Nonce":"x","PostingDate":"2026-11-10T00:00:00Z","Assets":[` +
	`{"_Measurement":"a1qNHW354vEtYlfMYS6LN2KkH84=","_MeasurementAlgorithm":"SHA-1",` +
	`"_UnarchivedSize":8494321664,"__RelativePath":"com_apple_MobileAsset_iOSSimulatorRuntime/A108B06B.aar",` +
	`"Build":"23F77","_CompressionAlgorithm":"AppleArchive","ArchiveDecryptionKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",` +
	`"__BaseURL":"https://updates.cdn-apple.com/2026MobileAssets/mobileassets/141-17392/0A72/",` +
	`"_DownloadSize":8522825728,"Architectures":["arm64"],"SimulatorVersion":"26.5"},` +
	`{"_Measurement":"AAAA","__RelativePath":"com_apple_MobileAsset_iOSSimulatorRuntime/431E.aar",` +
	`"Build":"23F77","_CompressionAlgorithm":"AppleArchive","ArchiveDecryptionKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",` +
	`"__BaseURL":"https://updates.cdn-apple.com/2026MobileAssets/mobileassets/141-17391/861A/",` +
	`"_DownloadSize":10603200512,"Architectures":["arm64","x86_64"],"SimulatorVersion":"26.5"}]}`

func jwt(payload string) []byte {
	enc := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return []byte("eyJhbGciOiJFUzI1NiJ9." + enc + ".c2ln")
}

func TestParseResponse(t *testing.T) {
	assets, err := parseResponse(jwt(fixturePayload))
	if err != nil {
		t.Fatalf("parseResponse: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("got %d assets, want 2", len(assets))
	}
	first := assets[0]
	if got, want := first.FullURL(), "https://updates.cdn-apple.com/2026MobileAssets/mobileassets/141-17392/0A72/com_apple_MobileAsset_iOSSimulatorRuntime/A108B06B.aar"; got != want {
		t.Errorf("FullURL() = %q, want %q", got, want)
	}
	if first.Size != 8522825728 || first.UnarchivedSize != 8494321664 {
		t.Errorf("sizes = %d/%d", first.Size, first.UnarchivedSize)
	}
	key, err := first.Key()
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}
	sum, err := first.Sum()
	if err != nil {
		t.Fatalf("Sum: %v", err)
	}
	if len(sum) != 20 {
		t.Errorf("sha1 length = %d, want 20", len(sum))
	}
}

func TestParseResponseRejectsNonJWT(t *testing.T) {
	if _, err := parseResponse([]byte(`{"Assets":[]}`)); err == nil {
		t.Fatal("expected an error for a non-JWT body")
	}
}

func TestPickArchitecture(t *testing.T) {
	assets := []Asset{
		{Architectures: []string{"arm64"}, URL: "a"},
		{Architectures: []string{"arm64", "x86_64"}, URL: "universal"},
	}
	if got, _ := Pick(assets, ""); got.URL != "universal" {
		t.Errorf("default pick = %q, want universal", got.URL)
	}
	if got, _ := Pick(assets, "arm64"); got.URL != "a" {
		t.Errorf("arm64 pick = %q, want a", got.URL)
	}
	if got, _ := Pick(assets, "x86_64"); got.URL != "universal" {
		t.Errorf("x86_64 pick = %q, want universal", got.URL)
	}
	if _, err := Pick(assets, "ppc"); err == nil {
		t.Error("expected an error for an unknown architecture")
	}
}

// TestLiveQuery hits Apple. Opt in with XCFETCH_NET_TESTS=1.
func TestLiveQuery(t *testing.T) {
	if os.Getenv("XCFETCH_NET_TESTS") != "1" {
		t.Skip("set XCFETCH_NET_TESTS=1 to query gdmf.apple.com")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	assets, err := Query(ctx, http.DefaultClient, AssetTypeIOSRuntime, AudienceMacOSGeneric, "23F77")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(assets) == 0 {
		t.Fatal("no assets returned")
	}
	for _, a := range assets {
		if !strings.HasPrefix(a.FullURL(), "https://updates.cdn-apple.com/") {
			t.Errorf("unexpected base URL %q", a.FullURL())
		}
		if a.Size < 1<<30 {
			t.Errorf("implausible runtime size %d", a.Size)
		}
		key, err := a.Key()
		if err != nil || len(key) != 32 {
			t.Errorf("key: %v (%d bytes)", err, len(key))
		}
	}
}
