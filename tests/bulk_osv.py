"""OSV request-count regression and batch protocol acceptance (real CLI/OSTree/Grype)."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread


def check(binary):
    requests = []
    mode = "empty"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def send_json(self, value, status=200):
            data = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append((self.path, body))
            if self.path == "/v1/query":
                self.send_json({})
                return
            if self.path != "/v1/querybatch":
                self.send_json({"error": "unexpected endpoint"}, 404)
                return
            results = []
            for i, query in enumerate(body["queries"]):
                if mode == "empty":
                    results.append({})
                elif "page_token" in query:
                    result = {"vulns": [{"id": "OSV-SECOND"}]}
                    if mode == "loop":
                        result["next_page_token"] = "next"
                    results.append(result)
                else:
                    result = {"vulns": [{"id": "OSV-COMMON"}]}
                    if i == 0:
                        result["next_page_token"] = "next"
                    results.append(result)
            if mode == "mismatched-results":
                results.pop()
            self.send_json({"results": results})

        def do_GET(self):
            requests.append((self.path, None))
            if mode == "detail-error":
                self.send_json({"error": "unavailable"}, 503)
            else:
                self.send_json({"id": "WRONG" if mode == "wrong-id" else self.path.rsplit("/", 1)[-1],
                    "aliases": ["CVE-FIXTURE"], "withdrawn": "2026-01-01T00:00:00Z"})

    with tempfile.TemporaryDirectory(prefix="sbom-osv-bulk-") as temporary:
        root = Path(temporary)
        repo, tree = root / "repo", root / "tree"
        (tree / "files").mkdir(parents=True)

        def ostree(*args):
            return subprocess.check_output(["ostree", f"--repo={repo}", *args], text=True)

        ostree("init", "--mode=archive")
        sources = [{"type": "archive", "url": f"https://static.crates.io/crates/sbom-fixture-{i}/sbom-fixture-{i}-1.0.0.crate"} for i in range(64)]
        (tree / "files/manifest.json").write_text(json.dumps({"modules": [{"name": "packages", "sources": sources}]}))
        for ref, metadata in [("runtime/org.example.BulkPlatform/x86_64/stable", "[Runtime]\n"),
                ("app/org.example.Bulk/x86_64/stable", "[Application]\nruntime=org.example.BulkPlatform/x86_64/stable\n")]:
            (tree / "metadata").write_text(metadata)
            ostree("commit", f"--branch={ref}", f"--tree=dir={tree}", "--subject=bulk-fixture")
        ostree("summary", "--update")
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            args = [str(binary), "scan", "app/org.example.Bulk/x86_64/stable", "--repo", repo.as_uri(),
                "--osv-packages", "--osv-endpoint", f"http://127.0.0.1:{server.server_port}/v1/query"]

            def scan(success=True):
                result = subprocess.run(args, capture_output=True, text=True, timeout=30)
                assert (result.returncode == 0) == success, result.stderr
                if not success:
                    assert result.stdout == "", "failed batches must not print partial clean reports"
                    return
                return json.loads(result.stdout)["flatpakOsvPackages"]

            report = scan()
            assert len(requests) == 1 and requests[0][0] == "/v1/querybatch", (
                f"FAIL: {len(requests)} requests for 64 identities; expected one batch")
            assert len(report["queries"]) == 64
            assert all(len(q["components"]) == 2 and not q["vulnerabilities"] for q in report["queries"])
            mode = "positive"
            requests.clear()
            report = scan()
            posts = [body for path, body in requests if path == "/v1/querybatch"]
            gets = [path for path, _ in requests if path.startswith("/v1/vulns/")]
            assert [len(p["queries"]) for p in posts] == [64, 1]
            assert sorted(gets) == ["/v1/vulns/OSV-COMMON", "/v1/vulns/OSV-SECOND"]
            assert sum(len(q["vulnerabilities"]) for q in report["queries"]) == 65
            assert all(v["aliases"] and v["withdrawn"] for q in report["queries"] for v in q["vulnerabilities"])
            assert all({c["scope"] for c in q["components"]} == {"app", "runtime"} for q in report["queries"])
            for mode in ["mismatched-results", "loop", "detail-error", "wrong-id"]:
                scan(success=False)
            # Exercise chunk boundaries: retain 64 runtime sources, but grow the
            # app to 205 unique identities. Pagination must stay tied to its
            # original query when a pending batch shrinks to one item.
            sources.extend({"type": "archive", "url": f"https://static.crates.io/crates/sbom-fixture-{i}/sbom-fixture-{i}-1.0.0.crate"} for i in range(64, 205))
            (tree / "files/manifest.json").write_text(json.dumps({"modules": [{"name": "packages", "sources": sources}]}))
            ostree("commit", "--branch=app/org.example.Bulk/x86_64/stable", f"--tree=dir={tree}", "--subject=larger-fixture")
            ostree("summary", "--update")
            mode = "positive"
            requests.clear()
            report = scan()
            posts = [body for path, body in requests if path == "/v1/querybatch"]
            assert [len(p["queries"]) for p in posts] == [100, 1, 100, 1, 5, 1]
            assert len([path for path, _ in requests if path.startswith("/v1/vulns/")]) == 2
            assert len(report["queries"]) == 205
            assert sum(len(q["components"]) for q in report["queries"]) == 269
            expected_paginated = {posts[i]["queries"][0]["package"]["purl"] for i in [0, 2, 4]}
            actual_paginated = {q["package_purl"] for q in report["queries"] if len(q["vulnerabilities"]) == 2}
            assert expected_paginated == actual_paginated
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
    print("PASS: OSV bulk request budget, pagination, cached advisory details, provenance and protocol failures")


if __name__ == "__main__":
    check(Path(os.environ.get("SBOM_BINARY", "target/release/flatpak-sbom")).resolve())
