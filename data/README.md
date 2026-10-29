# Offline identity mapping

`purl2cpe.json` is a generated repository-PURL index derived from
[SCANOSS purl2cpe](https://github.com/scanoss/purl2cpe) at revision
`798c1075e3bfcaba207b2191225acd14f9b345b3`. Its upstream MIT license is preserved
in `purl2cpe.LICENSE`.

The input archive SHA-256 is
`ccef2e252398cd45f9ec955b34de3b5936bb77860c8acc12c90f5f2a20da7c42`.
The index contains 21,284 repository PURL keys. This is a binding count, not a
count of verified packages or supported vulnerable versions.

Regenerate with Python and PyYAML:

```sh
python3 scripts/update-purl2cpe.py
# Or use an already-downloaded archive; the same checksum is required:
python3 scripts/update-purl2cpe.py /path/to/archive.tar.gz
```

The updater reads archive members without extracting files. Updating the source
requires changing both the pinned revision and checksum in the script. Generation
and scanning use the bundled JSON without downloading anything for mapping.

## Transformation and matching

- Keep unversioned, unqualified GitHub/GitLab/Bitbucket repository PURLs with one
  namespace and repository name. Normalize GitHub case. Do not guess identities
  from bare dependency names or broaden subpaths/qualifiers into a repository.
- Retain application CPE bindings; replace only their version with `*`, preserving
  update, edition, target software/hardware and other constraints. Deduplicate
  identical templates. Record repository keys with unhandled CPE syntax so
  partial parsing cannot produce an apparently unambiguous mapping.
- Only one unrestricted, supported template plus explicit manifest release
  evidence permits automatic enrichment. Numeric dotted releases and a leading
  `v` are supported. Other tag prefixes, prereleases, and library ABI-to-release
  translations are not inferred. Existing CPEs are preserved.
- Preserve candidate bindings and source revision as component properties.
  Ambiguous/constrained bindings and missing release evidence remain coverage
  gaps. Upstream bindings are external assertions, not proof of shipped contents.

Tests exercise both successful matching and refusal of ambiguous identities,
fork names, subpackages, commit versions and constrained CPEs. Snapshot changes
must pass the Rust and scanner acceptance suites before adoption.
