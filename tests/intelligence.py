"""Shared mapping and OSV transport acceptance, invoked by acceptance.py."""
import json
import os
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread


def check(run, binary, root, commit, repo, validate):
    app = "app/org.example.Intelligence/x86_64/stable"
    runtime = "runtime/org.example.IntelligencePlatform/x86_64/stable"
    source_commit = "c" * 40
    shared = {"type": "git", "url": "https://github.com/example/shared.git", "commit": source_commit}
    runtime_commit = commit(runtime, "[Runtime]\n", {"modules": [{"name": "shared", "sources": [shared]}]})
    app_commit = commit(app, "[Application]\nruntime=org.example.IntelligencePlatform/x86_64/stable\n", {
        "modules": [{"name": "libraries", "sources": [shared,
            {"type": "git", "url": "https://github.com/libssh2/libssh2.git", "tag": "v1.8.0"},
            {"type": "git", "url": "https://github.com/FFmpeg/FFmpeg.git", "tag": "n4.3"},
        ]}]
    })
    run("ostree", f"--repo={repo}", "summary", "--update")
    args = [str(binary), "generate", app, "--repo", repo.as_uri(), "--cpe-mapping", "--output", "-"]
    bom = json.loads(run(*args))
    validate(bom)
    mapped = next(c for c in bom["components"] if c.get("purl", "").startswith("pkg:github/libssh2/libssh2@"))
    assert mapped["cpe"] == "cpe:2.3:a:libssh2:libssh2:1.8.0:*:*:*:*:*:*:*", mapped
    ffmpeg = next(c for c in bom["components"] if c.get("purl", "").lower().startswith("pkg:github/ffmpeg/ffmpeg@"))
    props = {p["name"]: p["value"] for p in ffmpeg["properties"]}
    assert "cpe" not in ffmpeg and props["flatpak:cpe-mapping-status"] == "ambiguous-or-unsupported-binding"
    assert len(json.loads(props["flatpak:cpe-mapping-candidates"])) > 1
    path = root / "intelligence.json"
    path.write_text(json.dumps(bom))
    coverage = json.loads(run(str(binary), "coverage", str(path)))
    assert any(g["bom_ref"] == ffmpeg["bom-ref"] and "cpe-mapping-needs-review" in g["reasons"]
        for g in coverage["scopes"]["app"]["gaps"])
    print("PASS: offline shared mapping, ambiguous bindings retained, both CycloneDX schemas")
    if os.environ.get("TEST_GRYPE") != "1":
        return

    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append(body)
            status = 200
            if self.path == "/error":
                status, response = 503, {"error": "temporarily unavailable"}
            elif self.path == "/malformed":
                response = {"vulns": None}
            elif self.path == "/loop":
                response = {"next_page_token": "repeat"}
            elif self.path == "/invalidtoken":
                response = {"next_page_token": 12}
            elif self.path == "/invalid-advisory":
                response = {"vulns": [{}]}
            elif self.path == "/empty":
                response = {}
            else:
                advisory = {"id": "OSV-FIXTURE-1", "aliases": ["CVE-FIXTURE-1"],
                    "affected": [{"ranges": [{"type": "GIT", "repo": shared["url"],
                        "events": [{"introduced": "0"}, {"fixed": "a" * 40}]}]}]}
                response = {"vulns": [advisory]}
                if "page_token" not in body:
                    response["next_page_token"] = "second"
                else:
                    response["vulns"].append({"id": "OSV-FIXTURE-WITHDRAWN", "withdrawn": "2026-01-01T00:00:00Z"})
            data = json.dumps(response).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_port}"
        scan = [str(binary), "scan", app, "--repo", repo.as_uri(), "--cpe-mapping", "--osv-commits", "--osv-endpoint"]
        findings = run(*scan, endpoint + "/query")
        assert requests == [{"commit": source_commit}, {"commit": source_commit, "page_token": "second"}]
        path.write_text(findings)
        report = json.loads(run(str(binary), "report", str(path)))
        source = report["source_commit_scan"]
        assert source["evidence_kind"] == "manifest-git-source"
        assert len(source["queries"]) == 1 and len(source["skipped"]) == 2
        query = source["queries"][0]
        assert query["source_commit"] == source_commit
        assert {c["scope"]: c["deployment_commit"] for c in query["components"]} == {"app": app_commit, "runtime": runtime_commit}
        assert len(query["vulnerabilities"]) == 2
        assert query["vulnerabilities"][0]["affected"][0]["ranges"][0]["events"][1]["fixed"] == "a" * 40
        assert query["vulnerabilities"][1]["withdrawn"]
        assert any(f["bom_ref"] == mapped["bom-ref"] and f["scope"] == "app" for f in report["findings"]), report
        assert all(f["inventory_kind"] == "manifest-source" for f in report["findings"])
        for route in ["error", "malformed", "loop", "invalidtoken", "invalid-advisory"]:
            assert run(*scan, endpoint + "/" + route, success=False) == ""
        empty = json.loads(run(*scan, endpoint + "/empty"))
        assert empty["flatpakOsv"]["queries"][0]["vulnerabilities"] == []
        # Both flags can share one endpoint without confusing Git identities
        # with ecosystem package identities. This fixture has only Git sources.
        combined = json.loads(run(*scan, endpoint + "/empty", "--osv-packages"))
        assert combined["flatpakOsvPackages"]["queries"] == []
        assert len(combined["flatpakOsvPackages"]["skipped"]) == 4
        run(*scan, endpoint + "/query", "--format", "table", success=False)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    print("PASS: mapped CPE advisory matching; OSV commit deduplication, pagination, provenance, withdrawal, empty results and failures")


@contextmanager
def package_api():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append(body)
            if self.path == "/error":
                status, response = 503, {"error": "unavailable"}
            else:
                status = 200
                response = {"vulns": [{"id": "OSV-PACKAGE-FIXTURE", "aliases": ["CVE-PACKAGE-FIXTURE"],
                    "affected": [{"package": body["package"], "ranges": [{"type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]}]}]}
                if "page_token" not in body:
                    response["next_page_token"] = "second"
            data = json.dumps(response).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def check_content_packages(run, binary, root, app, app_commit, runtime_commit):
    with package_api() as (endpoint, requests):
        args = [str(binary), "scan", app, "--installed", "--content-scanner", "syft",
            "--osv-packages", "--osv-endpoint"]
        result = json.loads(run(*args, endpoint + "/query"))
        expected = ["pkg:npm/lodash@4.17.20", "pkg:pypi/urllib3@1.24.1"]
        assert requests == [request for purl in expected for request in [
            {"package": {"purl": purl}}, {"package": {"purl": purl}, "page_token": "second"}]], requests
        assert "flatpakOsv" not in result
        path = root / "osv-package-report.json"
        path.write_text(json.dumps(result))
        report = json.loads(run(str(binary), "report", str(path)))
        packages = report["package_scan"]
        assert packages["evidence_kind"] == "ecosystem-package-identity"
        assert len(packages["queries"]) == 2
        lodash = packages["queries"][0]
        assert lodash["package_purl"] == expected[0]
        assert {c["scope"]: c["deployment_commit"] for c in lodash["components"]} == {"app": app_commit, "runtime": runtime_commit}
        assert all(c["inventory_kind"] == "content-detected" for q in packages["queries"] for c in q["components"])
        assert all(len(q["vulnerabilities"]) == 1 for q in packages["queries"])
        assert lodash["vulnerabilities"][0]["affected"][0]["ranges"][0]["events"][1]["fixed"] == "9.9.9"
        assert any(s["component"]["name"] == "openssl" and s["reason"] == "unsupported-osv-package-ecosystem" for s in packages["skipped"])
        assert run(*args, endpoint + "/error", success=False) == ""
        run(*args, endpoint + "/query", "--format", "table", success=False)
    print("PASS: OSV ecosystem queries, cross-scope content deduplication, pagination, report provenance and failures")


def check_manifest_packages(run, binary, root, app, app_commit, runtime_commit, repo):
    with package_api() as (endpoint, requests):
        result = json.loads(run(str(binary), "scan", app, "--repo", repo.as_uri(),
            "--osv-packages", "--osv-endpoint", endpoint + "/query"))
        packages = result["flatpakOsvPackages"]
        assert {q["package_purl"] for q in packages["queries"]} == {"pkg:pypi/requests@2.19.1", "pkg:pypi/urllib3@1.24.1"}
        sources = [c for q in packages["queries"] for c in q["components"]]
        assert all(c["inventory_kind"] == "manifest-source" for c in sources)
        assert {c["scope"]: c["deployment_commit"] for c in sources} == {"app": app_commit, "runtime": runtime_commit}
        assert all("commit" not in request and "version" not in request for request in requests)
        assert any(s["reason"] == "missing-package-identity" for s in packages["skipped"])
    print("PASS: OSV manifest package queries retain source-declaration evidence")
