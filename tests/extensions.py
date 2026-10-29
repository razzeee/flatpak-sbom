"""Explicit extension content acquisition and advisory provenance acceptance."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread


def check(run, binary, root, repo, remote, app, runtime, validate):
    tree = root / "extension-tree"
    package = tree / "files/node_modules/lodash"
    package.mkdir(parents=True)
    (package / "package.json").write_text('{"name":"lodash","version":"4.17.20"}')
    refs = ["runtime/org.example.Codecs/x86_64/stable", "runtime/org.example.GL.default/x86_64/24.08"]
    commits = {}
    for ref, parent in zip(refs, [app, runtime]):
        (tree / "metadata").write_text(f"[Runtime]\n[ExtensionOf]\nref={parent}\n[Extra Data]\nuri=https://example.org/payload\n")
        commits[ref] = run("ostree", f"--repo={repo}", "commit", f"--branch={ref}",
            f"--tree=dir={tree}", "--subject=extension").strip()
    run("ostree", f"--repo={repo}", "summary", "--update")
    selection = ["--extension", refs[0], "--extension", refs[1], "--extension", refs[0]]
    path = root / "extension-bom.json"
    run(str(binary), "generate", app, "--repo", remote, "--content-scanner", "syft", *selection, "--output", str(path))
    bom = json.loads(path.read_text())
    validate(bom)
    components = []
    for c in bom["components"]:
        props = {p["name"]: p["value"] for p in c.get("properties", [])}
        if props.get("flatpak:scope") == "extension" and c.get("purl") == "pkg:npm/lodash@4.17.20":
            assert props["flatpak:commit"] == commits[props["flatpak:ref"]]
            assert props["flatpak:content-origin"] == "ostree-checkout"
            components.append(c)
    assert len(components) == 2, "duplicate selections must not duplicate inventory"
    coverage = json.loads(run(str(binary), "coverage", str(path)))
    inventories = coverage["scopes"]["extension"]["extension_inventories"]
    assert len(inventories) == 2
    assert all(i["activation"] == "not-evaluated" and i["inventory"] == "content-only" for i in inventories)
    assert coverage["inventory_complete"] is False
    assert len([g for g in coverage["scopes"]["extension"]["gaps"] if "extra-data-not-acquired-from-remote" in g["reasons"]]) == 2
    for scope, ref in zip(["app", "runtime"], refs):
        declaration = coverage["scopes"][scope]["extension_declarations"][0]
        assert declaration["status"] == "partially-inventoried" and declaration["selected_refs"] == [ref]

    # The same selections also pin installed deployments, including extensions
    # without manifests. Mock discovery only; checkout and Syft are real.
    deployments = {}
    for index, ref in enumerate([app, runtime, *refs]):
        checksum = run("ostree", f"--repo={repo}", "rev-parse", ref).strip()
        deployment = root / "extension-deployments" / str(index) / checksum
        deployment.parent.mkdir(parents=True)
        run("ostree", f"--repo={repo}", "checkout", "--user-mode", checksum, str(deployment))
        deployments[ref] = str(deployment)
    bin_dir = root / "extension-bin"
    bin_dir.mkdir()
    flatpak = bin_dir / "flatpak"
    flatpak.write_text("#!/usr/bin/env python3\nimport sys\npaths = " + repr(deployments) + "\nprint(paths[sys.argv[-1]])\n")
    flatpak.chmod(0o755)
    previous_path = os.environ["PATH"]
    try:
        os.environ["PATH"] = str(bin_dir) + os.pathsep + previous_path
        installed_path = root / "installed-extensions.json"
        run(str(binary), "generate", app, "--installed", "--content-scanner", "syft", *selection, "--output", str(installed_path))
        installed = json.loads(installed_path.read_text())
        validate(installed)
        installed_coverage = json.loads(run(str(binary), "coverage", str(installed_path)))
        assert installed_coverage["scopes"]["extension"]["content_origin"] == "installed-deployment"
        assert {i["ref"]: i["commit"] for i in installed_coverage["scopes"]["extension"]["extension_inventories"]} == commits
        # Let Flatpak, not our own condition evaluator, select active refs.
        parents = {ref: run("ostree", f"--repo={repo}", "rev-parse", ref).strip() for ref in [app, runtime]}
        discovery = {parent: parent + " " + parents[parent] + "\n" +
            f" Extension: {ref}\n Commit: {commits[ref]}\n Installation: system\n Subpaths: /en\n"
            for parent, ref in zip([app, runtime], refs)}
        flatpak.write_text("#!/usr/bin/env python3\nimport sys\npaths = " + repr(deployments) +
            "\ndiscovery = " + repr(discovery) + "\nprint(discovery[sys.argv[-1]] if '--show-extensions' in sys.argv else paths[sys.argv[-1]])\n")
        run(str(binary), "generate", app, "--installed", "--content-scanner", "syft", "--active-extensions", "--output", str(installed_path))
        active = json.loads(run(str(binary), "coverage", str(installed_path)))
        assert len(active["active_extension_discovery"]) == 2
        assert all(i["activation"] == "enabled-by-flatpak-on-host" for i in active["scopes"]["extension"]["extension_inventories"])
        assert active["acquisition_complete"] is True and active["inventory_complete"] is False
        # A race must not turn into an apparently successful partial scan.
        discovery[app] = discovery[app].replace(parents[app], "0" * 64)
        flatpak.write_text("#!/usr/bin/env python3\nimport sys\npaths = " + repr(deployments) +
            "\ndiscovery = " + repr(discovery) + "\nprint(discovery[sys.argv[-1]] if '--show-extensions' in sys.argv else paths[sys.argv[-1]])\n")
        previous = installed_path.read_bytes()
        run(str(binary), "generate", app, "--installed", "--content-scanner", "syft", "--active-extensions", "--output", str(installed_path), success=False)
        assert installed_path.read_bytes() == previous
    finally:
        os.environ["PATH"] = previous_path

    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append(body)
            data = json.dumps({"vulns": [{"id": "OSV-EXTENSION-FIXTURE"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    if os.environ.get("TEST_GRYPE") == "1":
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            findings = json.loads(run(str(binary), "scan", app, "--repo", remote,
                "--content-scanner", "syft", *selection, "--osv-packages",
                "--osv-endpoint", f"http://127.0.0.1:{server.server_port}/query"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
        path.write_text(json.dumps(findings))
        report = json.loads(run(str(binary), "report", str(path)))
        matched = [f for f in report["findings"] if f["scope"] == "extension"]
        assert {f["flatpak_ref"]: f["commit"] for f in matched} == commits
        assert all(f["inventory_kind"] == "content-detected" for f in matched)
        query = next(q for q in report["package_scan"]["queries"] if q["package_purl"] == "pkg:npm/lodash@4.17.20")
        assert {c["flatpak_ref"]: c["deployment_commit"] for c in query["components"] if c["scope"] == "extension"} == commits
        assert len([r for r in requests if r["package"]["purl"] == query["package_purl"]]) == 1

    for ref in ["runtime/org.example.Unknown/x86_64/stable", "runtime/org.example.Codecs/aarch64/stable",
            "runtime/org.example.Codecs/x86_64/wrong", "app/org.example.Codecs/x86_64/stable",
            "runtime/org.example.GL.missing/x86_64/24.08"]:
        run(str(binary), "generate", app, "--repo", remote, "--content-scanner", "syft", "--extension", ref, success=False)
    run(str(binary), "generate", app, "--extension", refs[0], success=False)
    # Derived runtimes can consume extensions built for another base runtime.
    (tree / "metadata").write_text("[Runtime]\n[ExtensionOf]\nref=runtime/org.example.Other/x86_64/stable\n")
    run("ostree", f"--repo={repo}", "commit", f"--branch={refs[0]}", f"--tree=dir={tree}", "--subject=wrong-parent")
    run("ostree", f"--repo={repo}", "summary", "--update")
    run(str(binary), "generate", app, "--repo", remote, "--content-scanner", "syft", "--extension", refs[0], "--output", str(path))
    derived = json.loads(run(str(binary), "coverage", str(path)))
    assert derived["scopes"]["extension"]["extension_inventories"][0]["built_for_ref"] == "runtime/org.example.Other/x86_64/stable"
    print("PASS: selected extension content, absent manifests, deduplication, schema/graph integrity, Grype/OSV provenance and selection failures")
