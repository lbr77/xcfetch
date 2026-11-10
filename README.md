# xcfetch

Fetch Apple simulator runtimes and Xcode archives from Linux (or any Unix),
without Xcode and — for runtimes — without an Apple ID.

```
xcfetch runtime list                 # what Apple offers (public index)
xcfetch runtime fetch 26.5           # 8 GB .aar -> decrypted -> .simruntime tree
xcfetch xcode login                  # Apple ID + 2FA, cookies persisted
xcfetch xcode list                   # authenticated developer downloads
xcfetch xcode download "Xcode 26.4"  # download the .xip
```

## Why

* Simulator runtimes from iOS 18 onward are MobileAsset downloads resolved by
  the public Pallas service (`gdmf.apple.com`), not by a developer-portal URL.
  They are Apple Encrypted Archives (`AEA1`, profile 1) containing an Apple
  Archive whose payload is the runtime disk image. None of that needs macOS:
  the archive key is public metadata.
* Xcode archives still need a developer session. That is plain HTTPS with an
  Apple ID SRP login; `xcodes` proves the whole flow works with cookies alone.

What this tool **cannot** do: run the simulator. CoreSimulator needs Darwin, so
on Linux the runtime is only useful as files (frameworks, dyld caches, binaries).

## Install

```sh
go build -o xcfetch .          # needs Go 1.27+
# optional, to unpack the runtime disk images on Linux:
sudo apt install p7zip-full    # 7-Zip >= 22 reads APFS/HFS+ inside .dmg
```

On macOS, `hdiutil` is used instead of 7-Zip when no 7z is found.

## Commands

### `runtime list`

Reads `index2.dvtdownloadableindex` (no authentication) and prints platform,
version, build, architecture, artifact type, size and how the artifact is
resolved (`pallas` or `direct`). `--beta` includes betas and seeds,
`--platform all` shows every platform.

### `runtime fetch <version|build|identifier>`

1. Resolves the runtime in the index.
2. For iOS 18+ it asks Pallas for the asset matching the build number, and gets
   the CDN URL, SHA-1/SHA-256 and the AEA symmetric key back.
3. Downloads with resume (`Range`), verifying the checksums.
4. Decrypts AEA and extracts the Apple Archive in one streaming pass (the
   plaintext never hits disk), then unpacks the inner disk image(s).

```
xcfetch runtime fetch 26.5 --arch arm64 --out ~/runtimes
xcfetch runtime fetch 23F77 --no-extract        # keep the .aar only
xcfetch runtime fetch 17.5 --dmg-tool hdiutil   # old direct-source runtime
```

Result: `…/iOS 26.5 Simulator Runtime/<files>/iOS 26.5.simruntime`.

### `xcode login` / `logout` / `status`

Signs in with SRP-6a against `idmsa.apple.com` (SHA-256, RFC 5054 2048-bit
group), mints Apple's hashcash challenge, completes SMS/trusted-device 2FA and
stores the cookies in `~/.config/xcfetch/cookies.json` (mode 0600).

Provide the Apple ID via `XCFETCH_APPLE_ID` (or `--apple-id`), the password via
a prompt or `XCFETCH_APPLE_PASSWORD`.

### `xcode list` / `xcode download`

`listDownloads.action` returns the account's archives; `download` resolves the
CDN URL through `developerservices2.apple.com` (which sets `ADCDownloadAuth`),
then downloads with resume.

```
xcfetch xcode download "Xcode 26.4" --out ~/Downloads
xcfetch xcode download "Xcode 26.4" --no-download   # just print the CDN URL
```

Unpack the result with `unxip` (Go-equivalent `xtool sdk build --xip` consumes
the .xip directly):

```sh
git clone https://github.com/saagarjha/unxip && cd unxip
go build -o unxip .            # upstream also builds on Linux (liblzma, zlib)
./unxip ~/Downloads/Xcode_26.4.xip
```

## Verified on real Apple data

Run end to end against Apple's live services (iOS 26.5, build 23F77, arm64):

```
runtime list          -> 443 entries, Pallas and direct sources
runtime fetch 26.5    -> 8,522,825,728 bytes from updates.cdn-apple.com
                         SHA-1 + SHA-256 match Apple's _Measurement values
                         AEA: 33 clusters, 8,467,635,820 bytes plaintext
                         Apple Archive: 4 metadata items -> nested pbz/XZ payloads
                         -> AssetData/Restore/094-56039-099.dmg (8,100 MiB)
hdiutil attach        -> /Library/Developer/CoreSimulator/Profiles/Runtimes/
                         iOS 26.5.simruntime  (17 GiB of runtime content)
```

Two bugs that only real data exposed, both fixed and covered by tests: the
cluster-chain MAC was aliased into a reused buffer (every archive larger than
one cluster failed), and modern assets are *containers* of nested `pbz`/XZ
payload archives rather than a plain file tree.

## What is verified

| Area | Verification |
|---|---|
| AEA decryption | vectors from Apple's `/usr/bin/aea` for lzfse/lzma/zlib/lz4/none, multi-cluster, SHA-256 checksums, wrong-key rejection |
| Apple Archive | vectors from Apple's `/usr/bin/aa` (raw/lzfse/zlib/lzma/lz4), nested dirs, symlinks, modes, 12 MiB multi-block stream |
| AEA→AA→files | end-to-end test on an `aea encrypt` of an `aa archive` of a runtime-shaped tree |
| Nested containers | synthetic container with nested payload archives and a data-less manifest, plus the real 8.5 GB asset |
| Cluster chaining | 13 MiB archive with 16 KiB segments crosses several clusters |
| SRP / PBKDF2 / hashcash | pinned to vectors produced by `swift-srp` + CommonCrypto, the exact library the Swift `xcodes` CLI uses |
| Login flow | full 2FA flow against a fake `idmsa` server (headers, hashcash, SMS request, code submit, trust) |
| Download | resume from a partial file, resume after a dropped connection, checksum failure, 403 |
| Disk images | extraction of a real APFS image created by `hdiutil`, bundle discovery, nested images |
| Developer downloads | listing/date decoding, newest-release selection, CDN redirect + `ADCDownloadAuth` cookie, 401 handling |
| Cookie jar | persistence round-trip, 0600 permissions, expiry filtering, unrelated hosts ignored |
| CLI | flag/positional reordering, dispatch, usage errors, signed-out guard |
| Index / Pallas | live tests (`XCFETCH_NET_TESTS=1`) against Apple's real services |

Known gaps: federated/SSO Apple IDs and hardware security keys are rejected with
explicit errors; legacy two-step verification is unsupported; `.pkg`-based
runtimes (iOS ≤ 15.5) are downloaded but not unpacked.

## Layout

```
main.go              CLI entry point
internal/runtime     downloadable runtime index (plist)
internal/pallas      MobileAsset asset resolution (public, JWT response)
internal/aea         Apple Encrypted Archive (profiles 0/1/2-decrypt, 5)
internal/aa          Apple Archive + pbz* stream decoding and extraction
internal/dmg         disk image extraction via 7z or hdiutil
internal/download    resumable, checksum-verified HTTP downloads
internal/session     persistent cookie jar
internal/adc         developer downloads list + CDN authorization
internal/appleid     Apple ID SRP login, hashcash, 2FA
internal/cli         command wiring
```
