package runtime

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"26.5", "26.4", 1},
		{"26.5", "26.5", 0},
		{"26.10", "26.9", 1},
		{"18.0", "26.0", -1},
		{"26.5-beta2", "26.5", -1},
		{"26.5-rc", "26.5-beta4", 1},
	}
	for _, c := range cases {
		got := compareVersions(c.a, c.b)
		if got != c.want {
			t.Errorf("compareVersions(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func sample() []Runtime {
	return []Runtime{
		{Identifier: "com.apple.dmg.iPhoneSimulatorSDK26_5", Platform: "com.apple.platform.iphoneos",
			Name: "iOS 26.5 Simulator Runtime", ContentType: "cryptexDiskImage", DownloadMethod: "mobileAsset",
			Architectures: []string{"arm64", "x86_64"}, SimulatorVersion: Version{Version: "26.5", BuildUpdate: "23F77"}},
		{Identifier: "com.apple.dmg.iPhoneSimulatorSDK26_5_arm64", Platform: "com.apple.platform.iphoneos",
			Name: "iOS 26.5 Simulator Runtime", ContentType: "cryptexDiskImage", DownloadMethod: "mobileAsset",
			Architectures: []string{"arm64"}, SimulatorVersion: Version{Version: "26.5", BuildUpdate: "23F77"}},
		{Identifier: "com.apple.dmg.iPhoneSimulatorSDK17_5", Platform: "com.apple.platform.iphoneos",
			Name: "iOS 17.5 Simulator Runtime", ContentType: "diskImage", SourceURL: "https://download.developer.apple.com/x/iOS_17.5.dmg",
			Authentication: "virtual", Architectures: []string{"arm64", "x86_64"},
			SimulatorVersion: Version{Version: "17.5", BuildUpdate: "21F79"}},
		{Identifier: "com.apple.dmg.iPhoneSimulatorSDK17_4_b3", Platform: "com.apple.platform.iphoneos",
			Name: "iOS 17.4 beta 3 Simulator Runtime", ContentType: "diskImage",
			SimulatorVersion: Version{Version: "17.4", BuildUpdate: "21E5200d"}},
	}
}

func TestFind(t *testing.T) {
	list := sample()
	tests := []struct {
		query, platform, arch string
		wantBuild             string
		wantErr               bool
	}{
		{"26.5", "ios", "arm64", "23F77", false},
		{"23F77", "", "", "23F77", false},
		{"17.5", "ios", "", "21F79", false},
		{"17.4-beta3", "ios", "", "21E5200d", false},
		{"26.5", "ios", "x86_64", "23F77", false}, // arm64-only variant filtered out, universal kept
		{"26.5", "ios", "ppc", "", true},          // no variant has this arch
		{"99.9", "ios", "", "", true},
		{"26.5", "watchos", "", "", true},
	}
	for _, tc := range tests {
		got, err := Find(list, tc.query, tc.platform, tc.arch)
		if tc.wantErr {
			if err == nil {
				t.Errorf("Find(%q,%q,%q) unexpectedly succeeded", tc.query, tc.platform, tc.arch)
			}
			continue
		}
		if err != nil {
			t.Errorf("Find(%q,%q,%q): %v", tc.query, tc.platform, tc.arch, err)
			continue
		}
		if got.SimulatorVersion.BuildUpdate != tc.wantBuild {
			t.Errorf("Find(%q) build = %q, want %q", tc.query, got.SimulatorVersion.BuildUpdate, tc.wantBuild)
		}
	}
}

func TestPrereleaseDetection(t *testing.T) {
	cases := []struct {
		r    Runtime
		want bool
	}{
		{Runtime{Name: "iOS 26.5 Simulator Runtime", Identifier: "com.apple.dmg.iPhoneSimulatorSDK26_5", SimulatorVersion: Version{Version: "26.5"}}, false},
		{Runtime{Name: "iOS 26.5 Simulator Runtime", Identifier: "com.apple.dmg.iPhoneSimulatorSDK26_5_b1", SimulatorVersion: Version{Version: "26.5"}}, true},
		{Runtime{Name: "iOS 17.4 beta 3 Simulator Runtime", Identifier: "com.apple.dmg.iPhoneSimulatorSDK17_4_b3"}, true},
		{Runtime{Name: "iOS 26.5 Simulator Runtime", Identifier: "7b7b40f5", TrainName: "RaveCSeed"}, true},
		{Runtime{Name: "iOS 27.0 Simulator Runtime", Identifier: "com.apple.dmg.iPhoneSimulatorSDK27_0_rc"}, true},
	}
	for _, c := range cases {
		if got := c.r.Prerelease(); got != c.want {
			t.Errorf("Prerelease(%q, %q) = %v, want %v", c.r.Name, c.r.Identifier, got, c.want)
		}
	}
}

func TestFindPrefersReleaseOverSeed(t *testing.T) {
	seed := Runtime{Identifier: "com.apple.dmg.iPhoneSimulatorSDK26_0_b1", Platform: "com.apple.platform.iphoneos",
		Name: "iOS 26.0 Simulator Runtime", SimulatorVersion: Version{Version: "26.0", BuildUpdate: "23A5260l"}}
	release := Runtime{Identifier: "com.apple.dmg.iPhoneSimulatorSDK26_0", Platform: "com.apple.platform.iphoneos",
		Name: "iOS 26.0 Simulator Runtime", SimulatorVersion: Version{Version: "26.0", BuildUpdate: "23A343"}}
	got, err := Find([]Runtime{seed, release}, "26.0", "ios", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.SimulatorVersion.BuildUpdate != "23A343" {
		t.Errorf("picked %q, want the release build", got.SimulatorVersion.BuildUpdate)
	}
}

func TestDisplayVersionAndSource(t *testing.T) {
	list := sample()
	if got := list[3].DisplayVersion(); got != "17.4-beta3" {
		t.Errorf("DisplayVersion = %q, want 17.4-beta3", got)
	}
	if list[0].HasDirectSource() || !list[0].MobileAsset() {
		t.Error("26.5 should be a MobileAsset entry")
	}
	if !list[2].HasDirectSource() || list[2].MobileAsset() {
		t.Error("17.5 should be a direct entry")
	}
}

// TestLiveIndex fetches Apple's real index. Opt in with XCFETCH_NET_TESTS=1.
func TestLiveIndex(t *testing.T) {
	if os.Getenv("XCFETCH_NET_TESTS") != "1" {
		t.Skip("set XCFETCH_NET_TESTS=1 to fetch the runtime index")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	list, err := Load(ctx, http.DefaultClient)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(list) < 100 {
		t.Fatalf("only %d runtimes", len(list))
	}
	var mobile, direct int
	for _, r := range list {
		if r.MobileAsset() {
			mobile++
		} else {
			direct++
		}
	}
	if mobile == 0 || direct == 0 {
		t.Fatalf("expected both MobileAsset and direct entries, got %d/%d", mobile, direct)
	}
	newest, err := Find(list, "26.5", "ios", "arm64")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if newest.SimulatorVersion.BuildUpdate == "" {
		t.Error("newest runtime has no build")
	}
	t.Logf("%d runtimes (%d mobileAsset, %d direct); newest 26.5 build %s", len(list), mobile, direct, newest.SimulatorVersion.BuildUpdate)
}
