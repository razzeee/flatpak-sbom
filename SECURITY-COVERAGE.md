# Security inventory coverage

Security usefulness is the primary goal: correct package identities, release
versions, detected shipped dependencies, and traceable vulnerability matches.
License enrichment is not a release criterion for this work.

## Initial installed-content baseline (2026-10-29)

These results use local installed deployments, Syft 1.55.0, and the embedded
ASAR metadata reader. App counts exclude runtime records. They are inventory
records, not a percentage of all dependencies and not an exploitability claim.

| App | Filename version candidates | Content package records | Content records with PURL and version | Remaining gap |
| --- | ---: | ---: | ---: | --- |
| VLC | 31 | 4 | 3 | Most native libraries still need better binary/build metadata |
| Heroic | 2 | 141 | 138 | Bundled/minified code without package metadata can remain hidden |
| Chrome | 2 | 1 | 1 | Main browser and its bundled libraries remain poorly covered |
| Flatseal | 0 | 0 | 0 | Source commit identified, but release version and application package metadata are missing |

Heroic's detected records include 134 npm package records read from its
`app.asar`, plus seven records from Syft. The ASAR reader reads package metadata
at bounded offsets; it does not extract or execute archive contents. Direct
Syft scanning alone found no npm packages in this deployment.

VLC's source declarations now recover candidates such as `lua` version `5.3.5`.
Chrome's extra-data filename now yields `google-chrome-stable` version
`156.0.8078.47-1`, explicitly marked as filename evidence. These are not
authoritative ecosystem mappings. The single detected Chrome content record is
`krb5`, not a complete inventory of Chrome itself.

All eight sampled manifest/content documents passed official CycloneDX 1.7 and
1.6 schema validation and unique-identity checks. Schema validity alone is not a
security coverage gate. The local verification also passed all 39 Rust tests
(including the separately run OSTree test), formatting, Clippy, and the
release-binary scanner acceptance suite.

## Native identification improvement (2026-10-29)

The subsequent native pass produced these results on the same Chrome and VLC
deployments, excluding runtime records:

| App | Content records before | Content records now | Versioned CPE records now | Main app identity recovered |
| --- | ---: | ---: | ---: | --- |
| Chrome | 1 | 8 | 2 | Google Chrome 156.0.8078.47 |
| VLC | 4 | 62 | 4 | VLC 3.0.23 |

These record counts preserve separate metadata evidence and are not unique
upstream-package totals. Chrome's main identity is corroborated by exact
NUL-delimited version/product strings in its installed ELF, plus its manifest
version. VLC's identity uses installed libvlc metadata, the corresponding native
library, and the VLC executable. Both receive explicit CPEs for advisory matching.

Additional native-library records come from `pkg-config` metadata with matching
shipped ELF/static libraries in the declared deployment library directory. This
includes libraries such as libass, dav1d, and libssh2. Generic PURLs provide
inventory identities, not a promise of vulnerability matching. Library API/ABI
versions (for example libavcodec 58.134.100) are not relabeled as upstream FFmpeg
release versions. App metadata cannot borrow runtime library files as evidence.

The release-binary acceptance suite detects advisories for fixtures representing
known-vulnerable Chrome 80.0.3987.87 and VLC 3.0.11 identities using real Grype, retaining
scope, commit, affected version, severity, fixed versions, match types, and
advisory URL. It rejects contradictory Chrome manifest/binary versions.
All 44 Rust tests, formatting, Clippy, and the scanner acceptance suite passed.
The regenerated Chrome/VLC documents passed both CycloneDX schemas.

## Build-version and remote-content improvement (2026-10-29)

VLC's installed files now provide two additional corroborated upstream identities:

- **FFmpeg 4.4.8:** `include/libavutil/ffversion.h` agrees with a complete version
  string in `lib/libavutil.so.56.70.100`. The library's own version 56.70.100 is
  deliberately not used as the FFmpeg release.
- **libssh2 1.11.1:** the build header and `pkg-config` metadata agree with its
  versioned SSH banner in the installed library.

Both records include CPEs and evidence locations. The updated real VLC document
passes CycloneDX 1.7 and 1.6 validation. Acceptance fixtures prove real Grype
matches for known-vulnerable FFmpeg 4.3 and libssh2 1.8.0 identities, and reject a
header that contradicts the binary. Header paths outside the collected content
tree and ambiguous version definitions are not accepted as evidence.

The compiled native fixtures contain representative metadata and version strings,
not the upstream implementations. They verify identification and advisory matching,
not exploitation or the presence of vulnerable implementation code.

Latest verification passed all 46 Rust tests (including the separately run
OSTree test), formatting, Clippy, the release build, and the real Syft 1.55.0 /
Grype 0.121.0 acceptance suite.

Content scanning now also works from remote OSTree commits without installing
the app. A local HTTP fixture proves discovery and vulnerability matching for
a shipped npm package absent from the source manifest. A ref-advancement test
proves checkout uses the recorded commit, and checks temporary-tree removal.
Extra-data payloads outside OSTree remain unacquired in remote mode, explicitly
reported as a coverage gap. JSON scan and scoped-report output now retain these
coverage gaps alongside findings.

A fresh live Flathub content attempt for Calculator still returned HTTP 403
while fetching its commit. Local HTTP transport is verified; live Flathub
content delivery is still an outstanding gate.

## Explicit extension gaps (2026-10-29)

Selected extension contents can now be scanned with repeatable `--extension`
and `--content-scanner syft`. The declaration's name/architecture/branch limits
selection; each ref is resolved and scanned at its own commit. Installed and
remote modes both work without an extension manifest. Selected groups become
`partially-inventoried`; untouched groups remain `not-inventoried`.

Coverage records selected inventories and their consuming parents separately
from the extension's build-parent ref. Findings retain scope `extension`, ref
and commit; OSV queries deduplicate identities across app/runtime/extensions
while retaining each evidence record. Extension extra-data declarations remain
visible as remote acquisition gaps. Activation is explicitly not evaluated.

Real acceptance fixtures cover two selected extensions, duplicate selections,
installed and HTTP acquisition, schemas and graphs, Grype/OSV provenance,
missing manifests, inherited base-runtime extension declarations, unavailable
refs and invalid selections. Installed Chrome and live remote Calculator scans
also detected and matched FFmpeg from their selected codecs extensions. This
extends shipped-content coverage without assuming all declared extensions are
installed, active or fully enumerated.

Generated documents now retain structured app/runtime extension declarations,
including the declaring ref and commit and all extension metadata. Coverage and
JSON scan/report output expose them with `status: "not-inventoried"`, even after
scanning the parent content tree. Conditions and multi-version declarations are
preserved rather than guessed into concrete installed extension refs.

Installed-sample checks expose VLC's `org.videolan.VLC.Plugin` extension at
`share/vlc/extra`, Heroic's i386 compatibility and GL32 extension points, and
runtime graphics/codec extension points. These declarations establish where
inventory is unresolved, not which extensions are actually mounted.

All 47 Rust tests (including the separately run OSTree test), Clippy, the release
build, and real Syft/Grype acceptance passed. The HTTP acceptance fixture verifies
app/runtime declaration separation, parent commits, conditions, and multi-version
metadata through generation, coverage, and scan/report, with both CycloneDX schemas.

## Headerless OpenSSL detection (2026-10-29)

The native cataloger now identifies stable OpenSSL 3 releases in collected ELF
`libcrypto.so*` files using a full release/date banner and the two version-API
strings. It retains a versioned CPE and library location. Multiple library copies
remain separate evidence records; conflicting banners within one library,
prereleases, and recognized fork banners are rejected. Development headers and
`pkg-config` metadata are not required, and libraries are never executed.

Real installed scans recovered OpenSSL 3.5.4 from VLC's KDE runtime commit
`1e9b0aa4623015cebd20350b36dc515124567b0f43c2235bd4ea8259fc2b18de`
and OpenSSL 3.5.9 from Chrome's Freedesktop runtime commit
`08713ee4ce58fee0b8ff2f5bb58e511ff2009c4d72209270d2ddd01fb0336a04`.
Both use `lib/x86_64-linux-gnu/libcrypto.so.3`. Both generated documents passed
CycloneDX 1.7 and 1.6 validation. This identifies a reported upstream release;
it does not determine downstream patch status or exploitability.

All 49 Rust tests (including the separately run OSTree test), Clippy, release
build, and real Syft/Grype acceptance passed. A compiled representative OpenSSL
3.0.0 fixture verifies advisory matches, fixed versions, and runtime commit
provenance without headers. A conflicting banner removes this detector's identity.
The fixture tests identification and matching, not upstream vulnerable code.

## Shared identity/advisory integration and Syft audit (2026-10-29)

`--cpe-mapping` now uses a pinned, offline SCANOSS purl2cpe index, rather than
dependency-specific mapping code. Its 21,284 repository identities and update
procedure are documented in [data/README.md](data/README.md). Exact bindings,
source revision, and unresolved candidates are preserved. Multiple products,
platform/edition restrictions, unhandled syntax and insufficient release
evidence prevent automatic enrichment; existing CPEs are not replaced.

Evaluation on installed manifests yielded mappings for VLC's libass 0.17.5,
libmtp v1.1.23, and libmicrodns 0.2.0 declarations. Chrome's runtime yielded 24
mapped source records, including zstd, lz4, harfbuzz and libseccomp. These are
manifest-source mappings, not new observations of shipped dependencies. The
shared dataset has ambiguous FFmpeg/OpenSSL repository bindings, which are
retained for review rather than chosen arbitrarily.

`scan --osv-commits` queries full manifest Git commits and retains a separate
`source_commit_scan` in scoped reports. A real public-OSV run for the installed
Chrome app/runtime successfully queried seven distinct commits (including
zypak and gnulib) and returned no advisories. It explicitly skipped 280 Git
source records without a full commit. This verifies transport and response
handling, not vulnerability recall or source safety. Local HTTP fixtures prove
positive advisories, cross-scope deduplication, pagination, withdrawn records,
Git fixed-commit preservation, failures, and empty results. A mapped libssh2
identity fixture also matches real Grype advisories without a native detector.

### Correction to earlier native-coverage interpretation

The audit of pinned Syft 1.55.0 (`f15c3343e29dfb20cf6d82c820e7090b49808c96`)
confirmed that our `image` selection already enables binary, ELF, Go-module,
Cargo-auditable, Java-archive and installed-package catalogers. Actual sample
records already included OpenSSL 3.5.4/3.5.9 in the VLC/Chrome runtimes and FFmpeg
4.4.8 in VLC. The custom OpenSSL/FFmpeg detectors added corroborating evidence
records there, not previously unknown unique package identities.

Syft also emitted FFmpeg records with library ABI versions 58.134.100 and
58.76.100 in the VLC sample. Its pinned
[binary classifier source](https://github.com/anchore/syft/blob/f15c3343e29dfb20cf6d82c820e7090b49808c96/syft/pkg/cataloger/binary/classifiers.go)
contains `Lavc`/`Lavf` fallback patterns that explain this. These upstream
misidentifications are now quarantined locally unless an exact release banner
corroborates the claimed version at each library match location. No replacement
release is inferred from an ABI number or another component's version.
Syft's full CPE objects, including source
information when supplied, are now retained in `flatpak:content-cpe-evidence`.
CycloneDX's singular CPE field still exposes only the first candidate to Grype.

Quarantined components retain the full original Syft artifact in
`flatpak:scanner-original-artifact`, with `flatpak:identity-status=quarantined`
and a review reason. Their normal version/PURL/CPE fields are omitted. The
Grype input projection excludes them (including graph references), preventing
name-based CPE inference from restoring the rejected identity. Coverage lists
`quarantined-scanner-identity`; JSON scans retain the components under
`flatpakIdentityReviews`, propagated by `report` as `identity_reviews`.

Real Syft fixtures verify both ABI fallbacks, continued matching of confirmed
release records, provenance and evidence retention. Unit tests cover read
boundaries, exact versions, missing metadata and location confinement. A full
installed VLC scan with OSV package queries confirmed both known ABI records
are quarantined and retained in its report. All 55 Rust tests and full
scanner/schema acceptance passed after this mitigation. Upstream classifier
correction and broader identity validation remain valuable follow-up work.

The general pipeline should prioritize shared data, upstream scanner fixes,
build/package metadata, and content acquisition. Further local per-package
detectors are not the default coverage strategy.

Verification passed all 52 Rust tests (including the separately run OSTree
test), formatting, Clippy, the release build, both CycloneDX schemas, and the
full real Syft/Grype acceptance suite with the local OSV transport fixtures.

## Executable security gates

### Live Flathub transport

The previous HTTP 403 is resolved locally: the server rejected the generic
`libostree/2026.4` User-Agent for the sampled commit URL. Using the application's
own `flatpak-sbom/<version>` identity succeeded without changing transport or
object verification. The HTTP acceptance fixture now requires that identity
through discovery, metadata and content pulls.

The live four-app manifest/schema gate passed for Calculator, KCalc, Element
(`im.riot.Riot`) and Spotify. Calculator additionally completed remote app/runtime
content acquisition, Syft, Grype and OSV package scanning. This closes the
observed local transport failure; CI and inventory/identity-accuracy gaps remain.

### OSV ecosystem package queries

`--osv-packages` adds direct shared-database queries for versioned ecosystem
PURLs. It supports npm, PyPI, Cargo, Go, Maven, NuGet and RubyGems without local
dependency-specific mappings. It retains source-declaration versus shipped-content
evidence per component, deduplicates requests across scopes, and reports skipped
identities instead of guessing missing versions or registry names.

All 54 Rust tests (including the separately run OSTree test), formatting, Clippy,
the release build, schema checks and real Syft/Grype acceptance passed. Local
OSV fixtures verify package pagination, cross-scope deduplication, package and
commit modes together, report propagation, unsupported identities and HTTP
failure handling. Unit tests cover seven ecosystem types, scoped names,
conflicting versions and unconfirmed release evidence.

A public OSV end-to-end run using a local OSTree source-declaration fixture
queried `pkg:pypi/requests@2.19.1` once and received 10 advisory records, retaining
both app and runtime component provenance. This exercises a known affected
package identity, not exploitation or proof that code was shipped. A separate
full installed-Chrome content/OSV attempt exceeded the 180-second command limit;
no completed result is claimed for that attempt.

### Full-scan timeout diagnosis and resolution

Stage measurements isolated the previously timed-out installed-Chrome scan:
content generation took 8.08 seconds and Grype alone took 4.42 seconds. The
combined manifest/content document contained 1,263 distinct ecosystem PURLs,
mostly Cargo build-source declarations, triggering one OSV request per identity.
A deterministic regression fixture reproduced 64 requests for 64 identities.

Large scans now use the documented OSV `querybatch` API with 100 queries per
batch, per-query pagination, and shared advisory-detail caching. Detail fetches
are limited to four concurrent requests. The fixture now uses one request for
64 empty results. Positive and 205-identity fixtures verify pagination alignment,
app/runtime attribution, chunk boundaries, withdrawal metadata, cached details,
and failure on missing results, repeated tokens, failed detail fetches and
mismatched advisory IDs. The fixture runs in the normal scanner acceptance gate.

The original full installed-Chrome command subsequently completed in 20.08
seconds and queried all 1,263 identities, receiving 55 unique advisory IDs.
Those IDs include manifest/build-source matches and do not establish 55
vulnerabilities in shipped Chrome code. This resolves the recorded timeout for
that measured run, not all inventory or identity-accuracy gaps.

The acceptance suite asserts:

- A known upstream Lua archive yields its expected name/version without an
  invented ecosystem PURL; a Chrome `.deb` filename remains a version candidate.
- Git commit hashes are retained as source evidence, not used as release versions.
- Coverage distinguishes app/runtime, filename candidates, missing identity,
  missing release versions, and whether content scanning ran.
- An actual ASAR fixture contains `lodash@4.17.20`; the generated SBOM must contain
  `pkg:npm/lodash@4.17.20` with its archive location and app provenance.
- An installed Python fixture contains `urllib3@1.24.1`; its identity and runtime
  provenance must survive scanning.
- Real Grype must find advisories for both deliberately vulnerable content
  packages and the report must retain their correct ref and commit.
- Corrupt ASAR metadata fails the requested content scan, preserving existing
  output. Bounds and overflow cases are covered by Rust tests.

Run the gates with the pinned tool versions on PATH:

```sh
cargo build --locked
TEST_SYFT=1 TEST_GRYPE=1 GRYPE_DB_AUTO_UPDATE=false .venv/bin/python tests/acceptance.py
```

Prepare a valid Grype database with `grype db update` first. CI installs pinned
Syft and Grype versions and enables both scanner gates.

## Reproduce a real-app measurement

```sh
flatpak-sbom generate app/com.heroicgameslauncher.hgl/x86_64/stable \
  --installed --content-scanner syft --output heroic.cdx.json
flatpak-sbom coverage heroic.cdx.json
flatpak-sbom scan app/com.heroicgameslauncher.hgl/x86_64/stable \
  --installed --content-scanner syft --format json > heroic-grype.json
flatpak-sbom report heroic-grype.json
```

Installed app updates and scanner/database updates change these measurements.
Keep the generated document (including commits, scanner version and evidence
paths) alongside the coverage report. Manifest build sources and detected
shipped packages are separate records; do not sum them as unique packages.

## Automatic discovery and remote payload inspection (2026-10-29)

`--installed --content-scanner syft --active-extensions` delegates enablement to
Flatpak for the app/runtime and records enabled extension refs, commits,
installations and partial subpaths. Parent/extension commit races fail the scan.
Installed Chrome selected four extensions, including locale and codecs, without
launching the application. This establishes host enablement, not running mounts.

`--content-scanner syft --acquire-extra-data` verifies declared SHA-256 and size,
then performs bounded archive inspection without executing scripts. Supported
containers include compressed tar, ZIP, Debian and SquashFS/Snap. Unsupported
payloads, skipped links and installation-transform uncertainty remain explicit.
Debian control-only projection lets Syft parse package metadata independently of
data decompression/license inspection. Payload evidence remains separate from
manifest declarations and installed contents, with `extra-data-content`, payload
SHA-256 and declaration commit retained through Grype and OSV reporting.

Real Chrome acquisition inspected 259 regular files and identified
`google-chrome-stable` from Debian metadata. Its unsupported OSV Debian ecosystem
is explicitly skipped; the remaining native binaries are not silently treated as
identified. Real Spotify acquisition inspected 121 regular files from its Snap,
but recovered no payload package identities. Successful extraction alone does not
establish useful vulnerability coverage for that payload.

`acquisition_complete` is separate from `inventory_complete`.
`completeness_limitations`, `extra_data_acquisitions` and `content_observations`
expose missing acquisition, opaque containers, scanner partial analysis and ELF
paths without independent package evidence. Attributed ELF paths do not prove all
embedded dependencies are identified. Composition remains incomplete for unknown
static/vendored code. The latest local validation passed all 61 Rust tests,
formatting, Clippy, release build and full pinned-scanner/schema acceptance.

## Next security gaps

1. Native binary identification, especially Chrome and VLC: consume trustworthy
   upstream build SBOMs to enumerate their remaining statically linked/vendored
   code. Main-app identities and metadata-backed libraries are now covered, but
   generic native-library records still need reliable advisory mappings.
2. Expand generic payload identification and supported container formats; verified
   acquisition now works, but Spotify illustrates unidentified extracted content.
   Obtain vendor build inventories for hidden dependencies and validate their
   relationship to the scanned payload.
3. Running mount observation and nested extension inventories beyond app/runtime
   host discovery. Add broader shipped-dependency fixtures.
4. More tested ecosystem/URL mappings, measured against expected identities.

No sample is claimed to have a complete installed dependency inventory. Live
Flathub delivery passes locally; observed passing CI remains outstanding as
recorded in READINESS.md.
