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
go install github.com/lbr77/xcfetch@latest   # needs Go 1.27+
# or, from a checkout:
go build -o xcfetch .

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

### `runtime extract` — pull single files without the 8 GB download

```
xcfetch runtime extract 26.5 --match Restore.plist --list     # what is inside
xcfetch runtime extract 26.5 --path AssetData/Restore/Restore.plist --out ~/x
xcfetch runtime extract 26.5 --payload 2 --list               # scan one payload only
```

Everything above is served by HTTP `Range` requests: the AEA header, the cluster
header blocks, the pbz block headers and only the segments that hold the wanted
bytes.

**Cost model** (measured, not theoretical):

| Item | Cost |
|---|---|
| Startup | AEA prologue + one cluster header block per cluster walked (~18 KB each) |
| Per wanted file | its own bytes where segments and blocks are stored uncompressed; otherwise one AEA segment (1 MiB) and/or one pbz block (4 MiB) |
| Per 4 MiB of *skipped* payload | one pbz block header: a few bytes (AES-CTR seeks inside a segment stored uncompressed, and 32 headers are prefetched concurrently), or a whole 1 MiB AEA segment when the header sits in a compressed one |
| Repeat run | ~0, from the persisted block index (`~/.cache/xcfetch/pbz-index`, or `XCFETCH_CACHE_DIR`) |

Measured against the live iOS 26.5 runtime (8.5 GB asset, `Restore.plist`, 988 B):

| Run | Transferred | Requests | Wall |
|---|---|---|---|
| cold (index walk) | 199.8 MiB | 2535 | 20s |
| warm (cached index) | **5.2 MiB** | 103 | 2.7s |

(Before partial segment reads the cold walk cost 2.0 GiB and 2m35s.)

So a file in a small payload costs a few MiB; a file behind the 8 GB disk image
costs a few hundred MiB the first time (see below) and almost nothing after.
`--max-bytes` (default 4 GiB) aborts a runaway walk, `--payload N` skips payloads
you do not care about, and `--no-index-cache` keeps everything in memory.

### Files inside the runtime disk image: `--image`

The runtime's own files (`…simruntime/Contents/Resources/…`, for example
`update_dyld_sim_shared_cache` and the two order files it reads, which
CoreSimulator uses to build the simulator dyld cache locally) live inside
`AssetData/Restore/<build>.dmg`. `--image` reaches into that image without
materialising it:

```
xcfetch runtime extract 26.5 --image \
  'Library/Developer/CoreSimulator/Profiles/Runtimes/*.simruntime/Contents/Resources/{update_dyld_sim_shared_cache,dylib-order.txt,dirty-data-segments-order.txt}'
xcfetch runtime extract 26.5 --list --image 'Library/Developer/CoreSimulator/Profiles/Runtimes/*.simruntime/Contents/Resources'
xcfetch runtime extract --local 094-56039-099.dmg --image '…'    # a .dmg you already have
```

Each path component may be a glob, `{a,b}` expands to alternatives, a directory
is extracted recursively (or listed with `--list`), symlinks are kept as links.

The layers, all read on demand:

| Layer | What is read |
|---|---|
| UDIF (`internal/udif`) | koly trailer, XML block map, then only the runs (LZFSE/zlib/bzip2/LZMA/ADC/raw) holding wanted sectors |
| APFS (`internal/apfs`) | GPT, newest checkpoint, object maps, the B-tree nodes on each path, the file's extents |
| AEA | segments stored uncompressed are decrypted in place (AES-CTR seeks), so a 16-byte read costs 16 bytes |
| pbz | raw blocks are read in place; the header walk prefetches 32 headers ahead while blocks keep coming back raw |

Partial AEA reads cannot be authenticated by the segment MAC (it covers whole
segments), so every extracted file is instead checked against the sealed
volume's own SHA-256 data hashes, whose chain starts at the seal's root hash
(every file-system tree node is checked against the hash its parent records).
`--verify-segments` restores whole-segment authentication at a higher transfer
cost.

Two details of Apple's sealed runtime volume that are not in the published APFS
reference, both established on the iOS 26.5 image and checked by the node
hashes: the file-system tree's index nodes store child oids *relative to the
tree's root oid* (child oid = stored value + root oid), and the data-hash
records (`APFS_TYPE_FILE_INFO`) address the file by byte offset, not by block.
Nodes of that tree carry no object header (`BTNODE_NOHEADER`), and file extents
live in the separate file-extent tree.

Measured against the live iOS 26.5 asset (8.5 GB) for the three files above
(1.9 MiB):

| Run | Transferred | Requests | Wall |
|---|---|---|---|
| cold (pbz index walk) | 209.9 MiB | 2547 | 31s |
| warm (cached index) | **13.1 MiB** | 113 | 4.5s |

Of the image itself only 18 of 16,241 UDIF runs (2.9 MiB compressed) and 137
APFS metadata blocks are read. The cold cost is the pbz header walk across the
8 GB image: 1,988 of its 2,030 blocks are stored raw and their headers cost a
few bytes each, but 187 AEA segments are LZFSE-compressed by a few percent, and
a header that falls in one costs the whole 1 MiB segment.

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
| Range extraction | HTTP server that counts bytes: random reads agree with a linear decrypt; extracting a 42 KB file from a 96 MiB object transfers a bounded amount; index cache cuts a repeat walk's requests by >4x; budget guard aborts before the read that would cross it |
| Disk image run table | logical disk compared byte-for-byte with `hdiutil`'s raw conversion for UDRO, ULFO (LZFSE), UDZO (zlib), UDBZ (bzip2) and ULMO (LZMA) images |
| APFS | hdiutil-built volume (files, modes, symlinks, case-insensitive lookup, 600-entry directory); the real sealed iOS 26.5 image compared byte-for-byte with its mounted copy, seal hashes covering every byte, a flipped byte rejected (`XCFETCH_TEST_RUNTIME_DMG`/`_MOUNT`) |
| Partial AEA reads | seekable AES-CTR against a linear decrypt (including a counter carry); random reads of an `aea`-encrypted mix of stored and compressed segments; a 16-byte read costs 16 bytes |
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
internal/udif        UDIF (.dmg) run table, random access to the logical disk
internal/apfs        read-only APFS: checkpoints, object maps, B-trees, sealed volumes
internal/download    resumable, checksum-verified HTTP downloads
internal/session     persistent cookie jar
internal/adc         developer downloads list + CDN authorization
internal/appleid     Apple ID SRP login, hashcash, 2FA
internal/cli         command wiring
```
