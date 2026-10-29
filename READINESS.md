# Readiness evidence

## Release decision

**Not production-ready yet.** The full installed-Chrome scan timeout is resolved:
the release binary completed inventory, Grype and 1,263 OSV package-identity
queries in 20.08 seconds using batching and shared advisory-detail caching.
Live Flathub fetching now passes after identifying requests with the application's
User-Agent. The known Syft FFmpeg ABI-as-release error is now quarantined with
preserved evidence. Automatic installed extension discovery and checksum-verified
remote extra-data acquisition are implemented and locally verified. A passing
GitHub Actions run and complete stripped/vendored dependency inventories remain
outstanding.
Local acceptance evidence alone does not establish production readiness.

The manifest-derived generator has executable local acceptance coverage. Optional
installed/remote-content scanning and security-specific gates are documented in
[SECURITY-COVERAGE.md](SECURITY-COVERAGE.md). A
production release remains gated on the CI acceptance job. The local live
Flathub gate now passes; GitHub Actions has not yet been observed passing for
these changes.

The default scope is an inventory of source declarations. Optional content mode
adds detected packages from installed files and ASAR metadata, but does not
establish completeness or a vulnerability-free attestation. Stripped/vendored
code and extension contents can remain unidentified. The CycloneDX composition
explicitly records incompleteness.

Optional offline shared CPE mappings and networked OSV Git-commit queries now
have acceptance coverage; a public OSV query run also succeeded. This does not
replace the live Flathub gate, which now also passes locally. The Syft audit identified incorrect FFmpeg ABI
versions presented as releases in a real sample; these records are now withheld
from matching unless release evidence corroborates them at their own locations.
This mitigates the known defect, not all scanner identity errors. Details are in
SECURITY-COVERAGE.md.

## Discovery, acquisition and completeness verified on 2026-10-29

- Installed Chrome discovery selected four host-enabled extensions, including a
  partial locale deployment, with independent commits and installation provenance.
- Remote Chrome's verified Debian payload yielded 259 regular files and the
  `google-chrome-stable` package identity via Syft's Debian control parser.
- Remote Spotify's verified Snap payload yielded 121 regular files through
  SquashFS extraction. No payload package identities were recovered; scanner
  diagnostics and unattributed native binaries remain visible.
- Acquisition status is separate from package-inventory completeness. Raw payload
  findings retain SHA-256 and declaration commit; installation transforms are not
  evaluated. Arbitrary stripped/static/vendored inventories remain incomplete.
- All 61 Rust tests (including the separately invoked OSTree test), formatting,
  Clippy, release build and full Syft 1.55.0 / Grype 0.121.0 / schema acceptance
  passed. Tests cover discovery races, partial deployments, checksum/size failures,
  traversal, extraction bounds, opaque payloads, Debian metadata, scanner partial
  analysis, SquashFS files/links and raw-payload Grype/OSV provenance.

Reproduce with the commands in README.md. Remote host-specific activation and
running mount observation are not inferred; passing CI evidence is still required.

## Identity accuracy verified on 2026-10-29

- Real Syft fixtures reproduce the FFmpeg ABI-as-release defect and verify
  quarantine, preserved original records, coverage gaps and report propagation.
- Confirmed FFmpeg release banners remain matchable; evidence from unrelated
  files, longer release numbers and traversal paths cannot corroborate a claim.
- A full installed VLC Syft/Grype/OSV scan quarantined the known 58.134.100 and
  58.76.100 records. Its report retained both original records and deployment
  provenance; neither identity was used in vulnerability findings.
- All 55 Rust tests (including the separately run OSTree test), formatting,
  Clippy, release build and full scanner/schema acceptance passed.

## Selected extension contents verified on 2026-10-29

Repeatable `--extension` now includes explicitly selected declared extension
contents from pinned remote commits or installed deployments. Schema/graph,
duplicate selection, missing manifests, selection failures, extra-data gaps,
Grype attribution and cross-scope OSV deduplication have executable acceptance
coverage. A base-runtime build parent does not prevent a derived runtime from
consuming an extension it explicitly declares.

An installed Chrome scan with the 25.08-extra codecs extension detected FFmpeg
7.1.3 and retained extension-scoped findings. A live remote Calculator scan with
the 26.08-extra codecs extension detected FFmpeg 8.1.3, retaining its own commit
and GNOME 51 consuming-runtime provenance. Both included Grype and OSV package
queries. These are identity matches requiring triage, not exploitability claims.

All 56 Rust tests (including the separately run OSTree test), formatting, Clippy,
release build and full scanner/schema acceptance passed at that stage. The later
discovery/acquisition verification above supersedes those acquisition gaps;
running mount observation and stripped/vendored dependency completeness remain
unresolved. CI still needs observed passing evidence.

## Verified locally on 2026-10-28

- All 34 Rust tests passed (the real-OSTree test is run separately), along with
  formatting, Clippy with warnings denied, and an optimized release build.
- Real OSTree ref advancement and absent-file behavior; the CLI acceptance
  fixture is also served over local HTTP to exercise remote object transport.
- Official CycloneDX 1.7 and 1.6 schema validation of generated documents.
- Real Grype 0.121.0 detection of deliberately vulnerable packages, with app and
  runtime attribution recovered from the preserved component identifiers.
  The release-binary acceptance run produced 18 attributed findings with the
  2026-10-28 vulnerability database and jsonschema 4.26.0.
- Invalid report input fails rather than appearing as an empty findings list.
- Distinct identities for repeated module names and names with colliding escaped
  spellings; dependency targets resolve to existing components.
- Published manifests from installed Flatseal, VLC, Heroic, and Chrome, including
  their GNOME/KDE/Freedesktop runtimes, generated schema-valid documents with
  unique component IDs. These were copied into a temporary fixture repository;
  this establishes manifest compatibility, not live remote delivery or original
  commit authentication.

The acceptance fixtures caught and drove fixes for invalid schema fields,
boolean `builddir` parsing, mutable-ref provenance, duplicate module IDs,
missing scanner package identity/version, lost scanner scope properties, and
malformed reports being treated as clean scans.

## Live delivery verified on 2026-10-29

The earlier HTTP 403 was reproduced by changing only the request User-Agent:
curl's default identity returned 200, while `libostree/2026.4` returned 403 for
the same commit URL over either HTTP/1.1 or HTTP/2. OSTree pulls now use
`flatpak-sbom/<package-version>`. A local HTTP fixture rejects unidentified
clients and verifies discovery, metadata and commit-pinned content requests.

The release binary passed the live manifest gate for `org.gnome.Calculator`,
`org.kde.kcalc`, `im.riot.Riot`, and `com.spotify.Client`, including official
CycloneDX 1.7/1.6 schema validation. Calculator also completed a full remote
content scan with Syft, Grype and OSV package queries. These results establish
delivery, not complete inventories or absence of vulnerabilities.

All 54 Rust tests (including the separately invoked OSTree test), formatting,
Clippy and full pinned-scanner acceptance passed after the transport fix.
Reproduce the live manifest gate with:

```sh
SBOM_BINARY=target/release/flatpak-sbom TEST_FLATHUB=1 .venv/bin/python tests/acceptance.py
```

Alternatively, manually dispatch the CI workflow. A failure is a failed release
gate, not a skipped test. Keep the
generated documents and command output with the release evidence. Re-run all
acceptance gates when changing OSTree, Grype, schema revisions, or serialization.
