# flatpak-sbom

`flatpak-sbom` generates manifest-derived CycloneDX SBOMs for Flatpak apps from files published in a Flatpak OSTree remote.

```sh
flatpak-sbom generate app/org.example.App/x86_64/stable
flatpak-sbom generate app/org.example.App/x86_64/stable --output app.cdx.json
flatpak-sbom generate app/org.example.App/x86_64/stable --output -
flatpak-sbom generate app/org.example.App/x86_64/stable --content-scanner syft
flatpak-sbom scan app/org.example.App/x86_64/stable --scanner grype --format json
flatpak-sbom report grype-findings.json
flatpak-sbom generate app/com.heroicgameslauncher.hgl/x86_64/stable --installed --content-scanner syft --output heroic.cdx.json
flatpak-sbom coverage heroic.cdx.json
flatpak-sbom scan app/com.heroicgameslauncher.hgl/x86_64/stable --installed --content-scanner syft
flatpak-sbom generate app/org.example.App/x86_64/stable --cpe-mapping
flatpak-sbom scan app/org.example.App/x86_64/stable --installed --cpe-mapping --osv-commits > findings.json
flatpak-sbom scan app/org.example.App/x86_64/stable --installed --content-scanner syft --osv-packages > findings.json
flatpak-sbom report findings.json
```

The default remote is `https://dl.flathub.org/repo`; pass `--repo` to use another Flatpak remote. When `--output` is omitted, `generate` writes `<app-id>.cdx.json`, such as `im.riot.Riot.cdx.json`.

## Installation and operation

Build with `cargo build --release --locked`, or install with `cargo install --path . --locked`.
Linux with `ostree` on `PATH` is required. `scan` additionally requires Grype;
the acceptance suite tests Grype 0.121.0. `report` requires no external tools.
Installed input requires `flatpak`; content scanning additionally requires Syft
(tested with 1.55.0). `coverage` also needs no external tools.

The app and runtime must be available in the supplied repository, with published
JSON manifests. Reads are pinned to each resolved commit. The default mode fetches
only commit metadata and the requested manifest files; content mode downloads the
app/runtime `files` trees. The runtime is the current runtime ref at
generation time, not necessarily the runtime used to build or run the app.
Remote authenticity relies on HTTPS: this tool does not verify OSTree GPG signatures.

Output files are replaced atomically after successful generation. Existing file
permissions are preserved; new Unix files use `0666` filtered by the process umask.
Errors go to
stderr and return a nonzero exit status. A successful scan does not mean there
are no vulnerabilities; its exit status indicates scanner execution success.
For batch jobs, apply an overall deadline (for example, `timeout 10m flatpak-sbom
scan ...`). Grype's first database download needs network access and additional
time; prepare it with `grype db update` before running a batch.

## Scope

The baseline generator fetches `metadata`, app `files/manifest.json`, and the runtime manifest through the `ostree` CLI and emits CycloneDX 1.7 JSON. It records Flatpak scope, ref, commit, manifest path, module, source type, paths, URLs, checksums, and `extra-data` details where present. It also infers package URLs for source declarations with precise ecosystem identity, including GitHub repositories, PyPI wheels, Cargo `.crate` archives, NuGet flat-container packages, and Go proxy module zip archives.

The SBOM is intentionally marked with an incomplete composition because manifest-derived metadata does not inventory packages inside source archives, vendored trees, or binary `extra-data` payloads.

## Security coverage

`coverage <sbom.json>` reports app and runtime separately: package-source counts,
ecosystem and repository identities with release versions, filename-derived
version candidates, content-scanner results, and per-component gaps. These are
identity records, not unique-package totals or vulnerability-detection recall.
Scripts, patches, and ordinary supporting files are not counted as package
sources. Git commits remain provenance properties and are not emitted as release
versions. Generic archive and `.deb` filenames supply explicitly marked version
candidates; no ecosystem identity is invented from a filename alone. Filename
matches can produce false-positive vulnerability matches and need corroboration.

`--content-scanner syft` downloads and checks out the recorded app/runtime commits
into temporary directories without installing them. `--installed` instead reads
the selected installed deployment trees. Both modes retain
Syft's package URLs, versions, CPEs, cataloger names, and observed paths. It also
reads embedded Electron ASAR `package.json` records, which Syft alone missed in
the tested Heroic deployment. Native detection also reads installed `pkg-config`
metadata when its declared libraries are present as ELF/static-library files in
the matching deployment library directory. App scans do not borrow `/usr` runtime
libraries as evidence for app metadata.

Chrome receives a CPE identity only when the manifest's four-part version and
the product name both occur as complete strings in the installed ELF binary.
VLC receives a CPE identity from installed `libvlc.pc`, its shipped library, and
the VLC executable (including the `vlc.bin` wrapper layout). These checks do not
execute application code. FFmpeg's upstream release comes from its build header,
corroborated by an exact string in the shipped libavutil library. libssh2 uses its
build header, matching package metadata, and versioned SSH banner in the library.
Both receive CPE identities only when that evidence agrees.
For headerless OpenSSL 3 libraries, the scanner requires an ELF `libcrypto.so*`,
an unambiguous stable release banner, and both version-API strings in the binary.
It records a CPE and the individual library path without executing the library.
Conflicting banners, prereleases, and recognized fork banners are rejected by
this detector; older OpenSSL releases are not yet supported by it. These binary
identities do not establish whether downstream security patches were applied.
Other native libraries get generic identities; their
metadata versions are not automatically mapped to upstream release versions or
CPEs. For example, `libavcodec`'s library version is not FFmpeg's release version.

All detected package classes feed the existing Grype scan
and scoped-report commands. Content packages are attached to their app/runtime
artifact; this is an inventory relationship, not a recovered package dependency
graph. Manifest and detected records remain separate to preserve evidence.

Remote content mode checks out the pinned OSTree `files` trees. Add
`--acquire-extra-data` to download and inspect declared payloads; otherwise coverage
reports `extra-data-not-acquired-from-remote`. Full content downloads can be large and
are removed after scanning. Installed mode observes already-installed extra-data
files without executing the application or its installation scripts. The deployment commit identifies
the manifest; it does not authenticate the post-install extra-data contents.
Installed input is labeled `urn:flatpak:installed` instead of assuming that it
came from the default remote. The selected runtime is not a historical build
runtime. Extensions support explicit selection or installed host discovery;
application/user data are not scanned.

Content scanning still cannot enumerate every statically linked, stripped, or
vendored dependency. A successful scan with zero packages is visible as such in
coverage; it does not certify completeness. See [SECURITY-COVERAGE.md](SECURITY-COVERAGE.md)
for measured results and remaining security gaps.

Coverage counts versioned CPE identities separately from ecosystem identities.
`report` retains the affected package version, severity, fixed versions, match
types, and advisory URL alongside app/runtime provenance. Scanner matches still
need triage; generic identity counts do not establish advisory coverage.
JSON `scan` output adds `flatpakCoverage` to the Grype document; `report` carries
this as `coverage`, so the usual scan→report workflow preserves inventory gaps
even when no advisories matched. Plain external Grype reports remain supported.

Each scope's `extension_declarations` lists declared extension points with the
parent ref/commit, original metadata (including directory, versions, and loading
conditions), and `status: "not-inventoried"`. A declaration does not establish
that an extension is installed or mounted. Content scanning of the parent tree
does not resolve these declarations. Older SBOMs without this property yield an
empty list, which is not evidence that the deployment has no extensions.

### Selected extension contents

Use repeatable `--extension runtime/ID/ARCH/BRANCH` with `--content-scanner syft`
to include declared extensions. For example, with a GNOME 51 runtime:

```sh
flatpak-sbom scan app/org.gnome.Calculator/x86_64/stable \
  --content-scanner syft \
  --extension runtime/org.freedesktop.Platform.codecs-extra/x86_64/26.08-extra \
  --osv-packages > findings.json
```

Choose the branch from the selected app/runtime's declaration. Remote selections
use the same `--repo`; `--installed` reads pinned installed extension deployments.
Name, architecture and branch must match a declaration; subdirectory extension
families are supported. Each selection resolves once and its files are scanned
at that commit. Duplicate selections are scanned once; unavailable selections
fail the requested scan. Extension manifests are not required or inventoried.

Detected packages and findings use the separate `extension` scope with their
own ref/commit. Coverage includes `extension_inventories` with parent refs/commits,
declaration metadata and the extension's `built_for_ref`. The build parent can
differ from the consuming runtime, as with Freedesktop extensions used by GNOME.
Selected declaration groups are marked `partially-inventoried` with `selected_refs`.
Explicit selection alone leaves `activation` as `not-evaluated`. Composition
remains incomplete.

### Automatic installed extension discovery

```sh
flatpak-sbom scan app/com.google.Chrome/x86_64/stable \
  --installed --content-scanner syft --active-extensions > findings.json
```

`--active-extensions` asks Flatpak for enabled extensions of the selected app and
runtime. Flatpak evaluates host conditions and extension precedence. Discovery
records parent/extension commits, installation and partial-deployment subpaths;
changed commits or unpinnable extensions fail the scan. Coverage retains
`active_extension_discovery`, and selections use `enabled-by-flatpak-on-host`.
This is host enablement evidence, not observation of a running process's mounts.
Remote mode requires explicit `--extension` selections.

### Remote extra-data and completeness

```sh
flatpak-sbom scan app/com.spotify.Client/x86_64/stable \
  --content-scanner syft --acquire-extra-data --osv-packages > findings.json
```

Acquisition verifies SHA-256 and declared size before inspecting tar (gzip, xz,
bzip2, zstd), ZIP, Debian and SquashFS/Snap payloads. It requires content scanning
and cannot be combined with `--installed`. Downloads use HTTPS (loopback HTTP is
allowed for fixtures). Per-artifact budgets cap downloads at 2 GiB and expanded
files at 4 GiB; archive entry/path and decoder limits also apply. Traversal,
duplicate files and special entries are rejected; links are skipped and reported.
Unsupported formats remain `opaque-payload`. Installation scripts never run.

Detected payload packages use `inventory_kind=extra-data-content`, their payload
SHA-256 and the declaration's commit in Grype/OSV provenance. Debian control
metadata is projected separately for Syft while extracted data is scanned normally.
Archive inspection does not establish equivalence to installed files.

Coverage separates `acquisition_complete` from `inventory_complete` and lists
`completeness_limitations`. Per-scope `extra_data_acquisitions` and
`content_observations` retain extraction evidence, scanner partial-analysis
diagnostics, and ELF paths without package evidence. Acquisition can be complete
while dependency identification remains incomplete. Even attributed binaries may
contain unknown static/vendored dependencies; composition remains incomplete until
adequate upstream build evidence establishes their inventory.

`generate` writes CycloneDX 1.7. `scan --scanner grype` writes a temporary CycloneDX 1.6 document for Grype compatibility because current Grype/Syft releases reject CycloneDX 1.7 input.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
```

## Acceptance and release checks

### Shared identity and advisory data

`--cpe-mapping` enables the bundled, revision-pinned SCANOSS purl2cpe repository
index. Exact repository identities can acquire CPEs without per-dependency code.
Only single unrestricted bindings with numeric release evidence (optionally
prefixed by `v`) are applied. Other matches retain their candidate mappings and
appear as `cpe-mapping-needs-review` coverage gaps. It does not resolve arbitrary
tag prefixes, library ABI versions, or whether manifest sources actually ship.
See [data/README.md](data/README.md) for provenance, licensing and regeneration.

`scan --osv-commits` additionally sends full manifest Git commit hashes to OSV.
It requires JSON output and network access; `--osv-endpoint` selects a mirror's
query URL. Queries are deduplicated within a scan and paginated, with bounded
responses and timeouts. HTTP/protocol errors fail the scan rather than producing
a clean result. Tags, branches and abbreviated hashes are listed as skipped;
OSTree deployment commits are never substituted for Git source commits.

OSV results are returned in `flatpakOsv`, preserved by `report` as
`source_commit_scan`. Full advisory records preserve aliases, Git ranges and
withdrawn status; Git fixed commits are not presented as fixed release versions.
These are source-declaration matches, not proof of vulnerable shipped code.
Grype findings now also expose `inventory_kind` when recoverable from provenance.
Zero OSV matches does not establish that a commit is covered by the database.

`scan --osv-packages` queries OSV directly using versioned npm, PyPI, Cargo, Go,
Maven, NuGet and RubyGems PURLs. It works with manifest or content inventories
and can be combined with `--osv-commits`. JSON output and network access are
required; the same `--osv-endpoint` setting applies to both query modes.
Repeated package/version identities are queried once, retaining every component's
scope, deployment commit and `inventory_kind` (`manifest-source` or
`content-detected` or `extra-data-content`). Missing/conflicting versions, unsupported ecosystems,
qualified/subpath identities and unconfirmed release evidence are explicitly
listed in `skipped`; generic or repository names are not guessed into registries.

Package results appear in `flatpakOsvPackages`, preserved by `report` as
`package_scan`. Full advisory records retain affected ranges, fixes, aliases and
withdrawn status. Grype, OSV package and OSV commit results can overlap; their
record counts should not be added as unique vulnerability totals.

Known unreliable scanner identities are retained for review rather than used
for vulnerability matching. Currently this guards Syft's FFmpeg library ABI
fallbacks: a library release must be corroborated at its own match location.
Quarantined components retain the original Syft artifact in
`flatpak:scanner-original-artifact`, omit normal version/PURL/CPE fields, and
appear as coverage gaps. They are excluded from Grype input; JSON scans retain
them in `flatpakIdentityReviews`, exposed by `report` as `identity_reviews`.
This can leave a detected library's release unresolved; it is not a clean bill
of health for that library.

OSV scans with more than 32 distinct identities use `querybatch` in groups of
100. Pagination follows each query independently. Full advisory details are
fetched once per advisory ID within each query mode, with at most four detail
requests in flight. Large scans require the configured `/query` endpoint to
have sibling `/querybatch` and `/vulns/{id}` endpoints. Requests retain their
30-second timeouts; batch responses and details have an aggregate 128 MiB
response budget. Incomplete or inconsistent batch responses fail the scan.

Syft's complete CPE candidate/source objects are retained in the
`flatpak:content-cpe-evidence` property; CycloneDX's singular `cpe` field still
uses the first candidate. Scanner-generated CPEs and binary versions require
triage, especially where library ABI and upstream release versions differ.

### Running the gates

The content acceptance fixtures require a C compiler (`cc`) to build native
fixture binaries. They compile fixtures but never execute them.

```sh
python3 -m venv .venv
.venv/bin/pip install jsonschema==4.26.0
cargo build --locked
cargo test --locked real_repository_update -- --ignored
.venv/bin/python tests/acceptance.py
grype db update
TEST_SYFT=1 TEST_GRYPE=1 GRYPE_DB_AUTO_UPDATE=false .venv/bin/python tests/acceptance.py
TEST_FLATHUB=1 .venv/bin/python tests/acceptance.py
# Optional full remote-content gate (larger downloads):
TEST_FLATHUB=1 TEST_FLATHUB_CONTENT=1 ACCEPTANCE_TIMEOUT=600 .venv/bin/python tests/acceptance.py
```

The suite uses a real temporary OSTree repository, official schemas pinned to an
immutable CycloneDX revision, and known-vulnerable app/runtime packages. It checks
both CycloneDX versions, graph integrity, commit provenance, malformed reports,
output replacement, and scanner failure propagation. With Syft enabled, it also
checks a deliberately vulnerable npm package inside an ASAR archive and an
installed Python distribution, including Grype detection and scope attribution.
Malformed ASAR metadata, including invalid JSON in an indexed `package.json`
member, fails the entire scan without replacing the previous SBOM. Such members
are not silently skipped; valid package JSON lacking a name/version is not
identified as a package. The Rust acceptance test
updates a remote between resolution and reading/checkout to verify snapshot
consistency and temporary-tree cleanup. The HTTP fixture also tests finding and
scanning an undeclared shipped package without installing the app.

CI runs the local-repository and Grype gates on every change. Manually dispatch
the CI workflow to additionally run the live Flathub release gate. That gate
has a `live_content` input to enable full remote-content scanning. It
covers GNOME, KDE, Electron, and extra-data apps and records generated documents
under `target/acceptance`. See [READINESS.md](READINESS.md) for the current evidence
and outstanding release gate. To validate existing SBOMs, set `SBOM_CORPUS` to a
directory of JSON documents when running the acceptance script.
