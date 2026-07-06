# flatpak-sbom

`flatpak-sbom` generates manifest-derived CycloneDX SBOMs for Flatpak apps from files published in a Flatpak OSTree remote.

```sh
flatpak-sbom generate app/org.example.App/x86_64/stable
flatpak-sbom generate app/org.example.App/x86_64/stable --output app.cdx.json
flatpak-sbom generate app/org.example.App/x86_64/stable --output -
flatpak-sbom scan app/org.example.App/x86_64/stable --scanner grype --format json
flatpak-sbom report grype-findings.json
```

The default remote is `https://dl.flathub.org/repo`; pass `--repo` to use another Flatpak remote. When `--output` is omitted, `generate` writes `<app-id>.cdx.json`, such as `im.riot.Riot.cdx.json`.

## Scope

The baseline generator fetches `metadata`, app `files/manifest.json`, and the runtime manifest through the `ostree` CLI and emits CycloneDX 1.7 JSON. It records Flatpak scope, ref, commit, manifest path, module, source type, paths, URLs, checksums, and `extra-data` details where present. It also infers package URLs for source declarations with precise ecosystem identity, including GitHub repositories, PyPI wheels, Cargo `.crate` archives, NuGet flat-container packages, and Go proxy module zip archives.

The SBOM is intentionally marked with an incomplete composition because manifest-derived metadata does not inventory packages inside source archives, vendored trees, or binary `extra-data` payloads. For example, an Electron app may appear as one declared archive source rather than a full npm package graph until an optional content scanner such as Syft is added.

`generate` writes CycloneDX 1.7. `scan --scanner grype` writes a temporary CycloneDX 1.6 document for Grype compatibility because current Grype/Syft releases reject CycloneDX 1.7 input.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
```
