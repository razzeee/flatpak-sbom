"""Real OSTree + official CycloneDX schema acceptance gate.

Run after cargo build: python3 tests/acceptance.py
Requires ostree and jsonschema; TEST_SYFT also requires cc.
Schemas are fetched at an immutable revision.
"""
import json
import os
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import struct
import tempfile
import time
from threading import Thread
import urllib.request

from jsonschema import Draft7Validator
from referencing import Registry, Resource

REVISION = "ad83dae28b236b8760286399da4daba77592de86"
BINARY = Path(os.environ.get("SBOM_BINARY", "target/debug/flatpak-sbom")).resolve()


def run(*args, success=True, umask=-1):
    result = subprocess.run(args, capture_output=True, text=True,
        umask=umask,
        timeout=int(os.environ.get("ACCEPTANCE_TIMEOUT", "120")))
    assert (result.returncode == 0) == success, result.stderr or result.stdout
    return result.stdout


def schemas():
    resources = []
    documents = {}
    for name in ["bom-1.7.schema.json", "bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json"]:
        url = f"https://raw.githubusercontent.com/CycloneDX/specification/{REVISION}/schema/{name}"
        with urllib.request.urlopen(url, timeout=30) as response:
            document = json.load(response)
        documents[name] = document
        resources.append((f"http://cyclonedx.org/schema/{name}", Resource.from_contents(document)))
        resources.append((f"https://cyclonedx.org/schema/{name}", Resource.from_contents(document)))
    return documents, Registry().with_resources(resources)


def main():
    documents, registry = schemas()

    def validate(bom):
        for version in ["1.7", "1.6"]:
            document = dict(bom, specVersion=version)
            document["$schema"] = f"https://cyclonedx.org/schema/bom-{version}.schema.json"
            errors = list(Draft7Validator(documents[f"bom-{version}.schema.json"], registry=registry).iter_errors(document))
            assert not errors, "\n".join(f"{list(e.path)}: {e.message[:300]}" for e in errors[:10])
        refs = [c["bom-ref"] for c in [bom["metadata"]["component"], *bom["components"]]]
        assert len(refs) == len(set(refs)), "duplicate component identities"
        ref_set = set(refs)
        for dependency in bom["dependencies"]:
            assert dependency["ref"] in ref_set
            assert all(ref in ref_set for ref in dependency.get("dependsOn", []))

    with tempfile.TemporaryDirectory(prefix="flatpak-sbom-acceptance-") as directory:
        root = Path(directory)
        repo, tree = root / "repo", root / "tree"
        (tree / "files").mkdir(parents=True)
        run("ostree", f"--repo={repo}", "init", "--mode=archive")
        app = "app/org.example.App/x86_64/stable"
        runtime = "runtime/org.example.Platform/x86_64/stable"

        def commit(ref, metadata, manifest):
            (tree / "metadata").write_text(metadata)
            (tree / "files/manifest.json").write_text(json.dumps(manifest))
            return run("ostree", f"--repo={repo}", "commit", f"--branch={ref}", f"--tree=dir={tree}", "--subject=acceptance").strip()

        runtime_metadata = "[Runtime]\nname=org.example.Platform\n[Extension org.example.GL]\ndirectory=lib/GL\nversions=24.08;25.08;\nsubdirectories=true\n"
        app_metadata = "[Application]\nruntime=org.example.Platform/x86_64/stable\n[Extension org.example.Codecs]\ndirectory=lib/codecs\nversion=stable\ndownload-if=active-gl-driver\n"
        runtime_commit = commit(runtime, runtime_metadata, {
            "modules": [{"name": "runtime-dependency", "sources": [{
                "type": "file", "url": "https://files.pythonhosted.org/packages/example/urllib3-1.24.1-py2.py3-none-any.whl"
            }]}]
        })
        # This shipped package is absent from manifest source declarations.
        node = tree / "files/node_modules/lodash"
        node.mkdir(parents=True)
        (node / "package.json").write_text('{"name":"lodash","version":"4.17.20"}')
        app_commit = commit(app, app_metadata, {
            "app-id": "org.example.App", "modules": [{"name": "example", "builddir": True, "sources": [
                {"type": "archive", "url": "https://files.pythonhosted.org/packages/example/requests-2.19.1-py2.py3-none-any.whl", "sha256": "a" * 64},
                {"type": "file", "path": "example.txt"},
                {"type": "archive", "url": "https://example.org/example.tar.gz"},
                {"type": "archive", "url": "https://www.lua.org/ftp/lua-5.3.5.tar.gz"},
                {"type": "extra-data", "url": "https://example.org/google-chrome-stable_156.0.8078.47-1_amd64.deb"},
                {"type": "git", "url": "https://github.com/example/project.git", "commit": "c" * 40},
            ]}, {"name": "example", "sources": []},
                {"name": "a/b", "sources": []}, {"name": "a_b", "sources": []}]
        })
        run("ostree", f"--repo={repo}", "summary", "--update")

        def check_extensions(coverage):
            for scope, name, reference, checksum, fields in [
                ("app", "org.example.Codecs", app, app_commit,
                    {"directory": "lib/codecs", "version": "stable", "download-if": "active-gl-driver"}),
                ("runtime", "org.example.GL", runtime, runtime_commit,
                    {"directory": "lib/GL", "versions": "24.08;25.08;", "subdirectories": "true"}),
            ]:
                assert coverage["scopes"][scope]["extension_declarations"] == [{
                    "name": name, "parent_ref": reference, "parent_commit": checksum,
                    "metadata": fields, "status": "not-inventoried"}], coverage

        class QuietHandler(SimpleHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                # Reproduce repositories rejecting the generic libostree UA.
                # All pull phases must identify the actual client, including
                # summary discovery and commit-pinned content requests.
                if not self.headers.get("User-Agent", "").startswith("flatpak-sbom/"):
                    self.send_error(403, "client identity required")
                    return
                super().do_GET()

        server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=str(repo)))
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            remote = f"http://127.0.0.1:{server.server_port}"
            bom = json.loads(run(str(BINARY), "generate", app, "--repo", remote, "--output", "-"))
            if os.environ.get("TEST_SYFT") == "1":
                remote_content = root / "remote-content.json"
                run(str(BINARY), "generate", app, "--repo", remote, "--content-scanner", "syft", "--output", str(remote_content))
                remote_bom = json.loads(remote_content.read_text())
                validate(remote_bom)
                lodash = next(c for c in remote_bom["components"] if c.get("purl") == "pkg:npm/lodash@4.17.20")
                assert any(p["name"] == "flatpak:content-origin" and p["value"] == "ostree-checkout" for p in lodash["properties"])
                coverage = json.loads(run(str(BINARY), "coverage", str(remote_content)))
                check_extensions(coverage)
                assert coverage["scopes"]["app"]["content_origin"] == "ostree-checkout"
                assert any("extra-data-not-acquired-from-remote" in gap["reasons"] for gap in coverage["scopes"]["app"]["gaps"])
                if os.environ.get("TEST_GRYPE") == "1":
                    findings = run(str(BINARY), "scan", app, "--repo", remote, "--content-scanner", "syft")
                    findings_path = root / "remote-findings.json"
                    findings_path.write_text(findings)
                    report = json.loads(run(str(BINARY), "report", str(findings_path)))
                    assert any(f["package"] == "lodash" and f["scope"] == "app" and f["commit"] == app_commit for f in report["findings"])
                    assert report["coverage"]["inventory_complete"] is False
                    check_extensions(report["coverage"])
                    assert any("extra-data-not-acquired-from-remote" in gap["reasons"] for gap in report["coverage"]["scopes"]["app"]["gaps"])
                print("PASS: remote HTTP checkout detects undeclared shipped dependency; extra-data gap remains explicit")
                from extensions import check as check_extensions_content
                check_extensions_content(run, BINARY, root, repo, remote, app, runtime, validate)
                from extra_data import check as check_extra_data
                check_extra_data(run, BINARY, root, repo, remote, runtime, validate)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        validate(bom)
        lua = next(c for c in bom["components"] if c["name"] == "lua")
        assert lua["version"] == "5.3.5" and "purl" not in lua
        chrome = next(c for c in bom["components"] if c["name"] == "google-chrome-stable")
        assert chrome["version"] == "156.0.8078.47-1" and "purl" not in chrome
        git = next(c for c in bom["components"] if c.get("purl") == "pkg:github/example/project")
        assert "version" not in git, "a Git commit must not masquerade as a release version"
        destination = root / "existing.json"
        destination.write_text("previous output")
        destination.chmod(0o640)
        run(str(BINARY), "generate", "invalid-ref", "--repo", repo.as_uri(), "--output", str(destination), success=False)
        assert destination.read_text() == "previous output"
        run(str(BINARY), "generate", app, "--repo", repo.as_uri(), "--output", str(destination), umask=0o077)
        assert destination.stat().st_mode & 0o777 == 0o640
        for mask in [0o022, 0o077]:
            new_output = root / f"permissions-{mask}.json"
            run(str(BINARY), "generate", app, "--repo", repo.as_uri(), "--output", str(new_output), umask=mask)
            assert new_output.stat().st_mode & 0o777 == 0o666 & ~mask
        validate(json.loads(destination.read_text()))
        coverage = json.loads(run(str(BINARY), "coverage", str(destination)))
        check_extensions(coverage)
        assert coverage["inventory_complete"] is False
        app_coverage = coverage["scopes"]["app"]
        assert app_coverage["filename_version_candidates"] == 2
        assert app_coverage["repository_identities_with_release_version"] == 0
        assert app_coverage["ecosystem_identities_with_release_version"] == 1
        assert app_coverage["content_scan"] == "not-performed"
        commits = {p["value"] for c in bom["components"] for p in c.get("properties", []) if p["name"] == "flatpak:commit"}
        assert commits == {app_commit, runtime_commit}
        invalid = root / "invalid.json"
        for value in [{}, {"matches": None}, {"matches": [{}]}]:
            invalid.write_text(json.dumps(value))
            run(str(BINARY), "report", str(invalid), success=False)
        invalid.write_text('{"matches": []}')
        assert json.loads(run(str(BINARY), "report", str(invalid))) == {"findings": []}
        if os.environ.get("TEST_GRYPE") == "1":
            findings = run(str(BINARY), "scan", app, "--repo", repo.as_uri())
            path = root / "findings.json"
            path.write_text(findings)
            report = json.loads(run(str(BINARY), "report", str(path)))
            assert report["coverage"]["scopes"]["app"]["content_scan"] == "not-performed"
            check_extensions(report["coverage"])
            assert report["findings"], "known-vulnerable requests fixture had no findings"
            expected = {"app": (app, app_commit), "runtime": (runtime, runtime_commit)}
            assert {f["scope"] for f in report["findings"]} == set(expected), report
            assert all((f["flatpak_ref"], f["commit"]) == expected[f["scope"]] for f in report["findings"]), report
            run(str(BINARY), "scan", app, "--repo", repo.as_uri(), "--format", "invalid-format", success=False)
            print(f"PASS: Grype round-trip, {len(report['findings'])} findings with app/runtime provenance; scanner failure propagated")
        from intelligence import check as check_intelligence
        check_intelligence(run, BINARY, root, commit, repo, validate)
        if os.environ.get("TEST_GRYPE") == "1":
            from intelligence import check_manifest_packages
            check_manifest_packages(run, BINARY, root, app, app_commit, runtime_commit, repo)
            from bulk_osv import check as check_bulk_osv
            check_bulk_osv(BINARY)
        if os.environ.get("TEST_SYFT") == "1":
            # Only deployment discovery is substituted. Syft, ASAR parsing,
            # serialization, and (optionally) vulnerability matching are real.
            deployments = {}
            for ref, checksum, metadata in [(app, app_commit, app_metadata),
                    (runtime, runtime_commit, runtime_metadata)]:
                deployment = root / "installed" / checksum
                (deployment / "files").mkdir(parents=True)
                (deployment / "metadata").write_text(metadata)
                (deployment / "files/manifest.json").write_text('{"modules":[]}')
                deployments[ref] = str(deployment)
            app_files = Path(deployments[app]) / "files"
            package = json.dumps({"name": "lodash", "version": "4.17.20"}).encode()
            header = json.dumps({"files": {"node_modules": {"files": {"lodash": {"files": {
                "package.json": {"offset": "0", "size": len(package)}
            }}}}}}).encode()
            padding = b"\0" * ((-len(header)) % 4)
            asar = app_files / "app.asar"
            asar.write_bytes(struct.pack("<4I", 4, len(header) + len(padding) + 8,
                len(header) + len(padding) + 4, len(header)) + header + padding + package)
            runtime_files = Path(deployments[runtime]) / "files"
            runtime_lodash = runtime_files / "node_modules/lodash"
            runtime_lodash.mkdir(parents=True)
            (runtime_lodash / "package.json").write_bytes(package)
            dist = runtime_files / "lib/python3.12/site-packages/urllib3-1.24.1.dist-info"
            dist.mkdir(parents=True)
            (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: urllib3\nVersion: 1.24.1\n")
            (dist / "RECORD").write_text("")
            # Representative release/API strings, not upstream vulnerable code.
            # No headers or pkg-config metadata are present in this runtime.
            crypto_source = root / "crypto.c"
            crypto_source.write_text('const char *OpenSSL_version(int type) { return "OpenSSL 3.0.0 7 Sep 2021"; }\n'
                'unsigned long OpenSSL_version_num(void) { return 0x30000000UL; }\n')
            crypto_library = runtime_files / "lib/libcrypto.so.3"
            run("cc", "-shared", "-fPIC", "-o", str(crypto_library), str(crypto_source))
            tools = root / "bin"
            tools.mkdir()
            flatpak = tools / "flatpak"
            flatpak.write_text("#!/usr/bin/env python3\nimport sys\npaths = " + repr(deployments) + "\nprint(paths[sys.argv[-1]])\n")
            flatpak.chmod(0o755)
            previous_path = os.environ["PATH"]
            os.environ["PATH"] = str(tools) + os.pathsep + previous_path
            try:
                content_path = root / "content.json"
                args = [str(BINARY), "generate", app, "--installed", "--content-scanner", "syft", "--output", str(content_path)]
                run(*args)
                content_bom = json.loads(content_path.read_text())
                validate(content_bom)
                lodash = next(c for c in content_bom["components"] if c.get("purl") == "pkg:npm/lodash@4.17.20")
                assert lodash["version"] == "4.17.20"
                assert any(p["name"] == "flatpak:content-path" and "app.asar!/node_modules/lodash/package.json" == p["value"] for p in lodash["properties"])
                assert any(c.get("purl") == "pkg:pypi/urllib3@1.24.1" for c in content_bom["components"])
                openssl = next(c for c in content_bom["components"] if any(
                    p["name"] == "flatpak:content-cataloger" and p["value"] == "flatpak-openssl-binary-version"
                    for p in c.get("properties", [])))
                assert openssl["version"] == "3.0.0"
                assert openssl["cpe"] == "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"
                assert any(p["name"] == "flatpak:content-path" and p["value"] == "lib/libcrypto.so.3" for p in openssl["properties"])
                coverage = json.loads(run(str(BINARY), "coverage", str(content_path)))
                assert coverage["scopes"]["app"]["content_packages_with_identity_and_version"] == 1
                assert coverage["scopes"]["runtime"]["content_packages_with_identity_and_version"] >= 1
                if os.environ.get("TEST_GRYPE") == "1":
                    findings = run(str(BINARY), "scan", app, "--installed", "--content-scanner", "syft")
                    content_findings = root / "content-findings.json"
                    content_findings.write_text(findings)
                    report = json.loads(run(str(BINARY), "report", str(content_findings)))
                    assert report["coverage"]["scopes"]["app"]["content_origin"] == "installed-deployment"
                    assert any(f["package"] == "lodash" and f["scope"] == "app" and f["commit"] == app_commit for f in report["findings"])
                    assert any(f["package"] == "urllib3" and f["scope"] == "runtime" and f["commit"] == runtime_commit for f in report["findings"])
                    crypto_findings = [f for f in report["findings"] if f["bom_ref"] == openssl["bom-ref"]]
                    assert crypto_findings, "OpenSSL binary identity did not match advisories"
                    assert all(f["scope"] == "runtime" and f["commit"] == runtime_commit and f["package_version"] == "3.0.0" for f in crypto_findings)
                    assert any(f["fixed_versions"] for f in crypto_findings)
                    from intelligence import check_content_packages
                    check_content_packages(run, BINARY, root, app, app_commit, runtime_commit)
                crypto_source.write_text(crypto_source.read_text() + 'const char other[] = "OpenSSL 3.0.1 14 Dec 2021";\n')
                run("cc", "-shared", "-fPIC", "-o", str(crypto_library), str(crypto_source))
                run(*args)
                ambiguous = json.loads(content_path.read_text())
                assert not any(p["name"] == "flatpak:content-cataloger" and p["value"] == "flatpak-openssl-binary-version"
                    for c in ambiguous["components"] for p in c.get("properties", []))
                print("PASS: headerless OpenSSL identity, runtime advisory provenance, ambiguous banner rejection")
                # A corrupt archive must fail the requested scan, preserving output.
                previous_output = content_path.read_bytes()
                # Valid container/header and extent, but malformed member JSON.
                archive_bytes = asar.read_bytes()
                asar.write_bytes(archive_bytes[:-len(package)] + b"!" * len(package))
                run(*args, success=False)
                assert content_path.read_bytes() == previous_output
                asar.write_bytes(b"invalid archive")
                run(*args, success=False)
                assert content_path.read_bytes() == previous_output
                print("PASS: embedded npm + installed Python identities, content coverage, ASAR corruption failure")
                for native_app, version, expected_name, product in [
                    ("com.google.Chrome", "80.0.3987.87", "google-chrome", "google:chrome"),
                    ("org.videolan.VLC", "3.0.11", "vlc", "videolan:vlc_media_player"),
                ]:
                    native_ref = f"app/{native_app}/x86_64/stable"
                    checksum = ("d" if native_app == "com.google.Chrome" else "e") * 64
                    deployment = root / native_app / checksum
                    files = deployment / "files"
                    files.mkdir(parents=True)
                    (deployment / "metadata").write_text("[Application]\nruntime=org.example.Platform/x86_64/stable\n")
                    manifest = {"modules": []}
                    c_source = root / "native.c"
                    c_source.write_text(f'const char product[] = "Google Chrome";\nconst char version[] = "{version}";\nint main(void) {{ return 0; }}\n')
                    if native_app == "com.google.Chrome":
                        manifest = {"modules": [{"name": "chrome", "sources": [{"type": "extra-data",
                            "url": f"https://example.org/google-chrome-stable_{version}-1_amd64.deb"}]}]}
                        (files / "extra").mkdir()
                        run("cc", "-o", str(files / "extra/chrome"), str(c_source))
                    else:
                        (files / "bin").mkdir()
                        (files / "lib/pkgconfig").mkdir(parents=True)
                        (files / "bin/vlc").write_text('#!/bin/sh\nexec /app/bin/vlc.bin "$@"\n')
                        run("cc", "-o", str(files / "bin/vlc.bin"), str(c_source))
                        run("cc", "-shared", "-fPIC", "-o", str(files / "lib/libvlc.so.5"), str(c_source))
                        (files / "lib/pkgconfig/libvlc.pc").write_text(
                            f"prefix=/app\nlibdir=${{prefix}}/lib\nrelease={version}\nName: LibVLC\nVersion: ${{release}}\nLibs: -L${{libdir}} -lvlc\n")
                        for name, library, pc_version, header, macro, release, binary_value in [
                            ("libavutil", "avutil", "56.51.100", "include/libavutil/ffversion.h", "FFMPEG_VERSION", "4.3", "4.3"),
                            ("libssh2", "ssh2", "1.8.0", "include/libssh2.h", "LIBSSH2_VERSION", "1.8.0", "SSH-2.0-libssh2_1.8.0"),
                        ]:
                            header_path = files / header
                            header_path.parent.mkdir(parents=True, exist_ok=True)
                            header_path.write_text(f'#define {macro} "{release}"\n')
                            (files / f"lib/pkgconfig/{name}.pc").write_text(f"Version: {pc_version}\nLibs: -L/app/lib -l{library}\n")
                            c_source.write_text(f'const char version[] = "{binary_value}";\n')
                            run("cc", "-shared", "-fPIC", "-o", str(files / f"lib/lib{library}.so.1"), str(c_source))
                        # Syft's Lavc/Lavf fallback mistakes ABI versions for
                        # FFmpeg releases. Keep the evidence, not that identity.
                        for library, banner in [("avcodec", "Lavc58.134.100"), ("avformat", "Lavf58.76.100")]:
                            c_source.write_text(f'const char version[] = "{banner}";\n')
                            run("cc", "-shared", "-fPIC", "-o", str(files / f"lib/lib{library}.so.58"), str(c_source))
                    (files / "manifest.json").write_text(json.dumps(manifest))
                    deployments[native_ref] = str(deployment)
                    flatpak.write_text("#!/usr/bin/env python3\nimport sys\npaths = " + repr(deployments) + "\nprint(paths[sys.argv[-1]])\n")
                    path = root / f"{native_app}.json"
                    run(str(BINARY), "generate", native_ref, "--installed", "--content-scanner", "syft", "--output", str(path))
                    native_bom = json.loads(path.read_text())
                    validate(native_bom)
                    native = next(c for c in native_bom["components"] if c.get("cpe", "").startswith(f"cpe:2.3:a:{product}:{version}:"))
                    assert native["name"] == expected_name and native["version"] == version
                    if native_app == "org.videolan.VLC":
                        ffmpeg = next(c for c in native_bom["components"] if c.get("cpe", "").startswith("cpe:2.3:a:ffmpeg:ffmpeg:"))
                        assert ffmpeg["version"] == "4.3", "library ABI version must not replace upstream release"
                        assert any(c.get("cpe", "").startswith("cpe:2.3:a:libssh2:libssh2:1.8.0:") for c in native_bom["components"])
                        rejected = [c for c in native_bom["components"] if any(
                            p["name"] == "flatpak:identity-status" and p["value"] == "quarantined"
                            for p in c.get("properties", []))]
                        assert len(rejected) == 2
                        assert all(not any(k in c for k in ["version", "purl", "cpe"]) for c in rejected)
                        originals = [json.loads(next(p["value"] for p in c["properties"]
                            if p["name"] == "flatpak:scanner-original-artifact")) for c in rejected]
                        assert {c["version"] for c in originals} == {"58.134.100", "58.76.100"}
                    coverage = json.loads(run(str(BINARY), "coverage", str(path)))
                    assert coverage["scopes"]["app"]["cpe_identities_with_release_version"] >= 1
                    if native_app == "org.videolan.VLC":
                        assert len([g for g in coverage["scopes"]["app"]["gaps"]
                            if "quarantined-scanner-identity" in g["reasons"]]) == 2
                    if os.environ.get("TEST_GRYPE") == "1":
                        findings = run(str(BINARY), "scan", native_ref, "--installed", "--content-scanner", "syft")
                        findings_path = root / "native-findings.json"
                        findings_path.write_text(findings)
                        scoped = json.loads(run(str(BINARY), "report", str(findings_path)))
                        matches = [f for f in scoped["findings"] if f["package"] == expected_name and f["scope"] == "app" and f["commit"] == checksum]
                        assert matches, scoped
                        assert all(f["package_version"] == version and f["severity"] and f["match_types"] and f["data_source"] for f in matches), matches
                        assert any(f["fixed_versions"] for f in matches), "known fixed native advisories lost remediation versions"
                        if native_app == "org.videolan.VLC":
                            assert len(scoped["identity_reviews"]) == 2
                            assert all(any(p["name"] == "flatpak:scanner-original-artifact"
                                for p in c["properties"]) for c in scoped["identity_reviews"])
                            assert not any(f["package"] == "ffmpeg" and f["package_version"] in
                                [None, "", "58.134.100", "58.76.100"] for f in scoped["findings"])
                            for package_name, release in [("ffmpeg", "4.3"), ("libssh2", "1.8.0")]:
                                assert any(f["package"] == package_name and f["package_version"] == release and f["scope"] == "app" and f["commit"] == checksum for f in scoped["findings"]), scoped
                    if native_app == "com.google.Chrome":
                        # A changed manifest must not override contradictory binary evidence.
                        manifest["modules"][0]["sources"][0]["url"] = "https://example.org/google-chrome-stable_81.0.3987.87-1_amd64.deb"
                        (files / "manifest.json").write_text(json.dumps(manifest))
                        run(str(BINARY), "generate", native_ref, "--installed", "--content-scanner", "syft", "--output", str(path))
                        changed = json.loads(path.read_text())
                        assert not any(c.get("cpe", "").startswith("cpe:2.3:a:google:chrome:") for c in changed["components"])
                    else:
                        # Valid Syft release banners still survive, even when
                        # an ABI banner occurs in the same library.
                        c_source.write_text('const char version[] = "FFmpeg version 4.3";\nconst char abi[] = "Lavc58.134.100";\n')
                        run("cc", "-shared", "-fPIC", "-o", str(files / "lib/libavcodec.so.58"), str(c_source))
                        run(str(BINARY), "generate", native_ref, "--installed", "--content-scanner", "syft", "--output", str(path))
                        corroborated = json.loads(path.read_text())
                        assert any(c.get("version") == "4.3" and any(p["name"] == "flatpak:content-cataloger"
                            and p["value"] == "binary-classifier-cataloger" for p in c.get("properties", []))
                            for c in corroborated["components"])
                        c_source.write_text('const char abi[] = "Lavc58.134.100";\n')
                        run("cc", "-shared", "-fPIC", "-o", str(files / "lib/libavcodec.so.58"), str(c_source))
                        (files / "include/libavutil/ffversion.h").write_text('#define FFMPEG_VERSION "5.0"\n')
                        run(str(BINARY), "generate", native_ref, "--installed", "--content-scanner", "syft", "--output", str(path))
                        changed = json.loads(path.read_text())
                        assert not any(c.get("cpe", "").startswith("cpe:2.3:a:ffmpeg:ffmpeg:") for c in changed["components"])
                print("PASS: native Chrome/VLC identities, CPE matching, and contradictory-version rejection")
                print("PASS: FFmpeg/libssh2 build identities and vulnerability matches; mismatched build header rejected")
                print("PASS: FFmpeg ABI identities quarantined with evidence; confirmed Syft releases retained")
            finally:
                os.environ["PATH"] = previous_path
        print("PASS: real OSTree, CycloneDX 1.7/1.6, graph integrity, provenance, report validation")
    if os.environ.get("SBOM_CORPUS"):
        for path in sorted(Path(os.environ["SBOM_CORPUS"]).glob("*.json")):
            validate(json.loads(path.read_text()))
            print(f"PASS: corpus {path.name}")
    if os.environ.get("TEST_FLATHUB") == "1":
        output = Path(os.environ.get("ACCEPTANCE_OUTPUT", "target/acceptance"))
        output.mkdir(parents=True, exist_ok=True)
        for app in ["org.gnome.Calculator", "org.kde.kcalc", "im.riot.Riot", "com.spotify.Client"]:
            start = time.monotonic()
            path = output / f"{app}.cdx.json"
            args = [str(BINARY), "generate", f"app/{app}/x86_64/stable", "--output", str(path)]
            if os.environ.get("TEST_FLATHUB_CONTENT") == "1":
                args.extend(["--content-scanner", "syft"])
            run(*args)
            bom = json.loads(path.read_text())
            validate(bom)
            print(f"PASS: Flathub {app}, {len(bom['components'])} components, {time.monotonic() - start:.1f}s")


if __name__ == "__main__":
    main()
