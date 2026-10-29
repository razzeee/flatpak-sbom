"""Checksum-verified payload acquisition through the real CLI and scanners."""
import hashlib
import io
import json
import os
import shlex
import tarfile
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread


def check(run, binary, root, repo, remote, runtime, validate):
    app = "app/org.example.Payload/x86_64/stable"
    tree = root / "extra-data-tree"
    (tree / "files").mkdir(parents=True)
    (tree / "files/manifest.json").write_text('{"modules":[]}')
    payload_dir = repo / "payloads"
    payload_dir.mkdir()
    package = b'{"name":"lodash","version":"4.17.20"}'
    marker = root / "installer-must-not-run"
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        for name, data in [("node_modules/lodash/package.json", package),
                ("install.sh", f"#!/bin/sh\ntouch {shlex.quote(str(marker))}\n".encode())]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("escape-link")
        link.type, link.linkname = tarfile.SYMTYPE, "../../outside"
        archive.addfile(link)
    data = payload.getvalue()
    archive_path = payload_dir / "test.tar.gz"
    archive_path.write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()

    def commit(checksum=sha, size=len(data), name="test.tar.gz"):
        (tree / "files/manifest.json").write_text(json.dumps({"modules":[{"name":"payload", "sources":[{
            "type":"extra-data", "url":f"{remote}/payloads/{name}", "sha256":checksum, "size":size}]}]}))
        (tree / "metadata").write_text(f"[Application]\nruntime={runtime.removeprefix('runtime/')}\n"
            f"[Extra Data]\nname={name}\nuri={remote}/payloads/{name}\nchecksum={checksum}\nsize={size}\n")
        value = run("ostree", f"--repo={repo}", "commit", f"--branch={app}", f"--tree=dir={tree}", "--subject=extra-data").strip()
        run("ostree", f"--repo={repo}", "summary", "--update")
        return value

    checksum = commit()
    path = root / "extra-data-bom.json"
    args = [str(binary), "generate", app, "--repo", remote, "--content-scanner", "syft", "--output", str(path)]
    run(*args)
    missing = json.loads(run(str(binary), "coverage", str(path)))
    assert "extra-data-acquisition-incomplete" in missing["completeness_limitations"]
    run(*args, "--acquire-extra-data")
    bom = json.loads(path.read_text())
    validate(bom)
    lodash = next(c for c in bom["components"] if c.get("purl") == "pkg:npm/lodash@4.17.20")
    props = {p["name"]: p["value"] for p in lodash["properties"]}
    assert props["flatpak:inventory-kind"] == "extra-data-content"
    assert props["flatpak:content-origin"] == "checksum-verified-extra-data"
    assert props["flatpak:extra-data-sha256"] == sha and props["flatpak:commit"] == checksum
    coverage = json.loads(run(str(binary), "coverage", str(path)))
    acquisition = coverage["scopes"]["app"]["extra_data_acquisitions"][0]
    assert acquisition["status"] == "archive-inspected" and acquisition["sha256"] == sha
    assert acquisition["skipped_links"] == 1 and acquisition["install_scripts_executed"] is False
    assert "extra-data-acquisition-incomplete" not in coverage["completeness_limitations"]
    assert "extra-data-installation-transform-not-evaluated" in coverage["completeness_limitations"]
    assert coverage["inventory_complete"] is False
    assert not marker.exists()
    if os.environ.get("TEST_GRYPE") == "1":
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                response = b'{"vulns":[{"id":"OSV-PAYLOAD-FIXTURE"}]}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            findings = run(str(binary), "scan", app, "--repo", remote, "--content-scanner", "syft", "--acquire-extra-data",
                "--osv-packages", "--osv-endpoint", f"http://127.0.0.1:{server.server_port}/query")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        scan_path = root / "extra-data-findings.json"
        scan_path.write_text(findings)
        report = json.loads(run(str(binary), "report", str(scan_path)))
        matches = [f for f in report["findings"] if f["package"] == "lodash"]
        assert matches and all(f["inventory_kind"] == "extra-data-content" and f["payload_sha256"] == sha
            and f["commit"] == checksum and f["scope"] == "app" for f in matches)
        query = next(q for q in report["package_scan"]["queries"] if q["package_purl"] == "pkg:npm/lodash@4.17.20")
        assert query["components"][0]["inventory_kind"] == "extra-data-content"
        assert query["components"][0]["payload_sha256"] == sha

    # Identical bytes at distinct URLs retain separate, unambiguous provenance.
    (payload_dir / "mirror.tar.gz").write_bytes(data)
    metadata = tree / "metadata"
    metadata.write_text(metadata.read_text() + f"\n[Extra Data mirror]\nname=mirror.tar.gz\n"
        f"uri={remote}/payloads/mirror.tar.gz\nchecksum={sha}\nsize={len(data)}\n")
    run("ostree", f"--repo={repo}", "commit", f"--branch={app}", f"--tree=dir={tree}", "--subject=duplicate-payload")
    run("ostree", f"--repo={repo}", "summary", "--update")
    run(*args, "--acquire-extra-data")
    document = json.loads(path.read_text())
    validate(document)
    ids = [c["bom-ref"] for c in document["components"]]
    assert len(ids) == len(set(ids))
    payload_packages = [c for c in document["components"] if c.get("purl") == "pkg:npm/lodash@4.17.20"]
    assert len(payload_packages) == 2
    urls = set()
    for component in payload_packages:
        props = {p["name"]: p["value"] for p in component["properties"]}
        assert props["flatpak:extra-data-sha256"] == sha
        urls.add(props["flatpak:extra-data-url"])
    assert urls == {f"{remote}/payloads/test.tar.gz", f"{remote}/payloads/mirror.tar.gz"}
    if os.environ.get("TEST_GRYPE") == "1":
        scan_path.write_text(run(str(binary), "scan", app, "--repo", remote,
            "--content-scanner", "syft", "--acquire-extra-data"))
        report = json.loads(run(str(binary), "report", str(scan_path)))
        matches = [f for f in report["findings"] if f["package"] == "lodash"]
        assert len({f["bom_ref"] for f in matches}) == 2
        assert all(f["payload_sha256"] == sha and f["inventory_kind"] == "extra-data-content" for f in matches)

    # Package metadata must survive independently of compressed payload data.
    def deb(control_name):
        control = io.BytesIO()
        text = b"Package: payload-example\nVersion: 1.2.3\nArchitecture: amd64\nMaintainer: Test\nDescription: fixture\n"
        with tarfile.open(fileobj=control, mode="w:gz") as archive:
            info = tarfile.TarInfo(control_name)
            info.size = len(text)
            archive.addfile(info, io.BytesIO(text))
        result = b"!<arch>\n"
        for name, member in [("debian-binary/", b"2.0\n"), ("control.tar.gz/", control.getvalue()), ("data.tar.gz/", data)]:
            result += f"{name:<16}{0:<12}{0:<6}{0:<6}{100644:<8}{len(member):<10}`\n".encode() + member
            if len(member) % 2:
                result += b"\n"
        return result

    for control_name in ["control", "missing-control"]:
        contents = deb(control_name)
        (payload_dir / "example.deb").write_bytes(contents)
        commit(hashlib.sha256(contents).hexdigest(), len(contents), "example.deb")
        run(*args, "--acquire-extra-data")
        document = json.loads(path.read_text())
        validate(document)
        summary = json.loads(run(str(binary), "coverage", str(path)))
        if control_name == "control":
            assert any(c["name"] == "payload-example" and c.get("version") == "1.2.3" for c in document["components"]), summary["scopes"]["app"]["content_observations"]
            assert summary["scopes"]["app"]["extra_data_acquisitions"][0]["package_metadata_projection"] == "debian-control-only"
        else:
            assert "scanner-partial-analysis" in summary["completeness_limitations"]

    previous = path.read_bytes()
    for digest, size in [("0" * 64, len(data)), (sha, len(data) + 1), (sha, len(data) - 1), ("invalid", len(data))]:
        commit(digest, size)
        run(*args, "--acquire-extra-data", success=False)
        assert path.read_bytes() == previous
    # A valid checksum must not make path traversal acceptable.
    malicious = io.BytesIO()
    with zipfile.ZipFile(malicious, "w") as archive:
        archive.writestr("../escape", "outside")
    bad = malicious.getvalue()
    (payload_dir / "bad.zip").write_bytes(bad)
    commit(hashlib.sha256(bad).hexdigest(), len(bad), "bad.zip")
    run(*args, "--acquire-extra-data", success=False)
    assert path.read_bytes() == previous
    # Unsupported installers are acquired and labeled opaque, never executed.
    opaque = b"#!/bin/sh\nexit 99\n"
    (payload_dir / "installer.run").write_bytes(opaque)
    commit(hashlib.sha256(opaque).hexdigest(), len(opaque), "installer.run")
    run(*args, "--acquire-extra-data")
    opaque_coverage = json.loads(run(str(binary), "coverage", str(path)))
    assert "opaque-extra-data-container" in opaque_coverage["completeness_limitations"]
    assert opaque_coverage["acquisition_complete"] is False
    run(str(binary), "generate", app, "--installed", "--content-scanner", "syft", "--acquire-extra-data", success=False)
    print("PASS: extra-data checksums, sizes, archive inspection, raw-payload provenance, traversal rejection, opaque gaps and atomic failures")
