#!/usr/bin/env python3
"""Rebuild the offline repository-PURL index. Requires Python + PyYAML.

Usage: python3 scripts/update-purl2cpe.py [downloaded-tar.gz]
Updates require deliberately changing both REVISION and SHA256 below.
"""
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import tarfile
import urllib.request

import yaml

REVISION = "798c1075e3bfcaba207b2191225acd14f9b345b3"
SHA256 = "ccef2e252398cd45f9ec955b34de3b5936bb77860c8acc12c90f5f2a20da7c42"
URL = f"https://codeload.github.com/scanoss/purl2cpe/tar.gz/{REVISION}"


def build(data):
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("purl2cpe archive checksum mismatch")
    mappings = {}
    unsupported = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = {member.name: member for member in archive if member.isfile()}
        for name in sorted(members):
            if not re.fullmatch(r"[^/]+/data/[^/]+/[^/]+/purls.yml", name):
                continue
            purls = yaml.safe_load(archive.extractfile(members[name])) or {}
            keys = set()
            for purl in purls.get("purls") or []:
                # Repository identity only: no version, qualifier, or subpath
                # aliases are broadened into whole-repository mappings.
                if re.fullmatch(r"pkg:(github|gitlab|bitbucket)/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", purl):
                    keys.add(purl.lower() if purl.startswith("pkg:github/") else purl)
            if not keys:
                continue
            cpe_name = name.removesuffix("purls.yml") + "cpes.yml"
            cpes = yaml.safe_load(archive.extractfile(members[cpe_name])) or {}
            templates = set()
            for cpe in cpes.get("cpes") or []:
                fields = cpe.split(":")
                # Never turn a platform/edition-specific binding into a generic
                # one. Preserve every field except version. Such
                # constrained bindings remain candidates, not automatic CPEs.
                if fields[:3] in (["cpe", "2.3", "h"], ["cpe", "2.3", "o"]):
                    continue
                if len(fields) != 13 or fields[:3] != ["cpe", "2.3", "a"] or not all(
                    re.fullmatch(r"[A-Za-z0-9_.*-]+", field) for field in fields[3:]
                ):
                    unsupported.update(keys)
                    continue
                fields[5] = "*"
                # Preserve update restrictions too: no assumed prerelease mapping.
                templates.add(":".join(fields))
            for key in keys:
                mappings.setdefault(key, set()).update(templates)
        license_name = next(name for name in members if name.endswith("/LICENSE"))
        license_text = archive.extractfile(members[license_name]).read().decode()
    return {
        "source": "https://github.com/scanoss/purl2cpe",
        "revision": REVISION,
        "archive_sha256": SHA256,
        "unsupported_purls": sorted(unsupported),
        "mappings": {key: sorted(values) for key, values in sorted(mappings.items())},
    }, license_text


if __name__ == "__main__":
    if len(sys.argv) > 1:
        data = Path(sys.argv[1]).read_bytes()
    else:
        with urllib.request.urlopen(URL, timeout=120) as response:
            data = response.read()
    index, license_text = build(data)
    dest = Path(__file__).resolve().parents[1] / "data"
    dest.mkdir(exist_ok=True)
    (dest / "purl2cpe.json").write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")
    (dest / "purl2cpe.LICENSE").write_text(license_text)
    print(f"Indexed {len(index['mappings'])} repository PURLs at {REVISION}")
