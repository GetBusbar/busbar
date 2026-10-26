#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""candidate: build one release CANDIDATE in the layout scripts/release/publish_gate.py verifies.

ModernCI runs this from `.ci/qa.yaml` on the qa -> main move. Each slice runs on a backend that can
build it, and `assemble` merges the slices. Nothing here holds a key or publishes anything. Every
plugin is packed UNSIGNED, and the owner signs later on his hardware keys. A mistake here is caught
by the gate, which refuses by rule name; a mistake is never shipped.

  candidate.py core <target> --out DIR
      scripts/release-build.sh for one row of .github/release-targets.json. A published row goes
      to DIR/artifacts; an image-feeding musl row goes to DIR/internal. Then its CycloneDX SBOM goes
      to DIR/sboms (named by the target, or by the image platform the row feeds).
  candidate.py plugins <target> --kit-commit SHA --out DIR
      for each first-party plugin in plugins.yaml (except an empty repo): its newest vX.Y.Z tag
      whose .busbar-ref names the test kit's commit, built for <target> the way
      .github/workflows/plugin-release.yml builds it, and packed UNSIGNED with this tree's
      busbar-plugin-pack. Writes DIR/plugins/ and DIR/plugins.json.
  candidate.py image --out DIR
      the multi-platform image from DIR/internal's two musl binaries, as an OCI layout archive
      (DIR/oci/busbar.oci.tar). Needs docker buildx and RUST_ALPINE=rust:alpine@sha256:… (pinned).
  candidate.py assemble --kit-tag TAG --kit-commit SHA --out OUT DIR...
      merges the slices, copies the OpenAPI document, and writes SHA256SUMS, IMAGES and
      candidate.json.

Tools: git, cargo (rust-toolchain.toml), python3; cargo-cyclonedx (CYCLONEDX=<path>, pinned by the
caller); docker buildx for `image`; a C compiler for C plugins.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import publish_gate as pg  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def sh(cmd, cwd=None, env=None, out=False):
    print("+", " ".join(map(str, cmd)), flush=True)
    p = subprocess.run(cmd, cwd=cwd, env={**os.environ, **(env or {})}, capture_output=out)
    if p.returncode != 0:
        sys.exit(f"candidate: {' '.join(map(str, cmd))} failed ({p.returncode})"
                 + (f": {p.stderr.decode(errors='replace')}" if out else ""))
    return p.stdout.decode() if out else ""


def version() -> str:
    m = re.search(r'^\s*version\s*=\s*"([^"]+)"', (ROOT / "crates/busbar/Cargo.toml").read_text(), re.M)
    return m.group(1)


def target_row(target: str) -> dict:
    for t in pg.release_targets(ROOT):
        if t["target"] == target:
            return t
    sys.exit(f"candidate: {target} is not a row of .github/release-targets.json")


def sbom(triple: str, name: str, out: Path) -> None:
    tool = os.environ.get("CYCLONEDX")
    if not tool:
        sys.exit("candidate: CYCLONEDX=<pinned cargo-cyclonedx> is required")
    tmp = Path(tempfile.mkdtemp())
    sh([tool, "cyclonedx", "--manifest-path", str(ROOT / "crates/busbar/Cargo.toml"), "--format", "json",
        "--target", triple, "--override-filename", "bom"], cwd=ROOT)
    produced = ROOT / "crates/busbar/bom.json"
    (out / "sboms").mkdir(parents=True, exist_ok=True)
    shutil.move(produced, out / "sboms" / name)
    shutil.rmtree(tmp)


def cmd_core(target: str, out: Path) -> None:
    row = target_row(target)
    if row.get("kind") != "binary":
        sys.exit(f"candidate: {target} is not a binary row")
    sub = "artifacts" if row.get("published") else "internal"
    (out / sub).mkdir(parents=True, exist_ok=True)
    keys = pg.commit_key_list(ROOT)
    sh(["scripts/release-build.sh", target, "--out-dir", str(out / sub), "--evidence-dir", str(out / "evidence" / target)],
       cwd=ROOT, env={"BUSBAR_RELEASE_PUBKEY": keys, "SOURCE_DATE_EPOCH": sh(["git", "log", "-1", "--format=%ct"], cwd=ROOT, out=True).strip()})
    v = version()
    triple = row.get("triple", target)
    feeds = row.get("packaged_into", "")
    sbom(triple, f"busbar-v{v}-{feeds or target}.cdx.json", out)


def plugin_tag(repo: str, kit: str) -> tuple:
    """The newest vX.Y.Z tag of GetBusbar/<repo> whose .busbar-ref names `kit`, and its commit."""
    refs = sh(["git", "ls-remote", "--tags", f"https://github.com/GetBusbar/{repo}.git"], out=True)
    tags = {}
    for line in refs.splitlines():
        sha, ref = line.split("\t")
        m = re.fullmatch(r"refs/tags/(v\d+\.\d+\.\d+)(\^\{\})?", ref)
        if m:
            if m.group(2) or m.group(1) not in tags:
                tags[m.group(1)] = sha
    for tag in sorted(tags, key=lambda t: tuple(int(x) for x in t[1:].split(".")), reverse=True):
        tmp = Path(tempfile.mkdtemp())
        sh(["git", "clone", "-q", "--depth", "1", "--branch", tag, f"https://github.com/GetBusbar/{repo}.git", str(tmp)])
        ref = (tmp / ".busbar-ref").read_text().split()[0] if (tmp / ".busbar-ref").is_file() else ""
        if ref == kit:
            return tag, tags[tag], tmp
        shutil.rmtree(tmp)
    sys.exit(f"candidate: {repo} has no vX.Y.Z tag pinned to the test kit {kit}; re-pin and tag it")


def cmd_plugins(target: str, kit: str, out: Path) -> None:
    spec = {t: (ext, prefix) for t, ext, prefix in pg.PLUGIN_TARGETS}
    if target not in spec:
        sys.exit(f"candidate: {target} is not a plugin target")
    ext, prefix = spec[target]
    sh(["cargo", "build", "--release", "--locked", "-p", "busbar-plugin-loader", "--features", "pack", "--bin", "busbar-plugin-pack"], cwd=ROOT)
    pack = str(ROOT / "target/release" / ("busbar-plugin-pack.exe" if os.name == "nt" else "busbar-plugin-pack"))
    (out / "plugins").mkdir(parents=True, exist_ok=True)
    rows = []
    for e in pg.registry_entries(ROOT):
        if e.get("pending_crate", "false") == "true":
            continue
        repo = e["repo"]
        tag, commit, src = plugin_tag(repo, kit)
        ver, crate = tag[1:], e["crate"]
        lib = src / "target" / target / "release" / f"{prefix}{crate.replace('-', '_')}.{ext}"
        if e.get("lang") == "c":
            lib.parent.mkdir(parents=True, exist_ok=True)
            cdir = src / e["declares"].strip('"').split("/")[0]
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-O2", "-shared", "-fPIC",
                     "-I", str(ROOT / "crates/busbar-contract/include")]
            sh(["cc", *flags, "-o", str(lib), *map(str, sorted(cdir.glob("*.c")))])
        else:
            meta = json.loads(sh(["cargo", "metadata", "--format-version", "1", "--no-deps"], cwd=src, out=True))
            feats = next((p["features"] for p in meta["packages"] if p["name"] == crate), {})
            cmd = ["cargo", "build", "--release", "--locked", "--target", target, "-p", crate]
            if e.get("lib_only", "false") == "true":
                cmd.append("--lib")
            if "dropped-in" in feats:
                cmd += ["--features", "dropped-in"]
            sh(cmd, cwd=src)
        args = ["pack", "--lib", str(lib), "--name", repo, "--alias", e["alias"].strip('"'), "--kind", e["kind"],
                "--version", ver, "--publisher", "busbar", "--description", e["description"].strip('"'),
                "--license", "Apache-2.0", "--allow-unsigned",
                "--out", str(out / "plugins" / f"{repo}-{ver}-{target}.tar.gz")]
        for k in ("needs_prompt", "needs_user"):
            if e.get(k):
                args += [f"--{k.replace('_', '-')}", e[k].strip('"')]
        if e.get("declares"):
            d = src / e["declares"].strip('"')
            args += ["--declares-file", str(d)]
            top = (json.loads(d.read_text()).get("contract_abi") or {}).get("max")
            if top:
                args += ["--abi-version", str(top)]
        for n in re.findall(r"[a-z0-9-]+", e.get("former_names", "")):
            args += ["--former-name", n]
        p = subprocess.run([pack, *args])
        if p.returncode != 0:
            sys.exit(f"candidate: packing {repo} for {target} failed")
        rows.append({"repo": repo, "version": ver, "tag": tag, "commit": commit})
        shutil.rmtree(src)
    (out / "plugins.json").write_text(json.dumps(rows, indent=2) + "\n")


def cmd_image(out: Path) -> None:
    base = os.environ.get("RUST_ALPINE", "")
    if not re.fullmatch(r"rust:alpine@sha256:[0-9a-f]{64}", base):
        sys.exit("candidate: RUST_ALPINE must be rust:alpine@sha256:<64 hex> (pinned)")
    ctx = Path(tempfile.mkdtemp())
    for t in pg.release_targets(ROOT):
        feeds = t.get("packaged_into", "")
        if t.get("kind") != "binary" or not feeds.startswith("image-linux-"):
            continue
        arch = feeds.rsplit("-", 1)[1]
        (ctx / "binaries" / arch).mkdir(parents=True)
        with tarfile.open(out / "internal" / f"busbar-{t['target']}.{t['archive']}") as tf:
            m = next(x for x in tf.getmembers() if x.isfile() and x.name.rsplit("/", 1)[-1] == "busbar")
            (ctx / "binaries" / arch / "busbar").write_bytes(tf.extractfile(m).read())
        os.chmod(ctx / "binaries" / arch / "busbar", 0o755)
        lib = ctx / "plugins" / arch / "lib"
        lib.mkdir(parents=True)
        sh(["docker", "run", "--rm", "--platform", f"linux/{arch}", "-v", f"{lib}:/out", base, "sh", "-ec",
            "cp /lib/ld-musl-*.so.1 /usr/lib/libgcc_s.so.1 /usr/lib/libstdc++.so.6 /out/"])
    for f in ("Dockerfile", "providers.yaml"):
        shutil.copy(ROOT / f, ctx / f)
    shutil.copytree(ROOT / "docker", ctx / "docker")
    (out / "oci").mkdir(parents=True, exist_ok=True)
    epoch = sh(["git", "log", "-1", "--format=%ct"], cwd=ROOT, out=True).strip()
    sh(["docker", "buildx", "build", "--platform", "linux/amd64,linux/arm64", "--provenance=false", "--sbom=false",
        "--build-arg", f"SOURCE_DATE_EPOCH={epoch}", "--label", f"org.opencontainers.image.version={version()}",
        "--output", f"type=oci,dest={out / 'oci' / 'busbar.oci.tar'},rewrite-timestamp=true", str(ctx)],
       env={"SOURCE_DATE_EPOCH": epoch})
    shutil.rmtree(ctx)


def cmd_assemble(out: Path, slices: list, kit_tag: str, kit_commit: str) -> None:
    for sub in ("artifacts", "sboms", "internal", "plugins", "oci"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    plugins: dict = {}
    for s in map(Path, slices):
        for sub in ("artifacts", "sboms", "internal", "plugins", "oci"):
            for f in (s / sub).glob("*") if (s / sub).is_dir() else []:
                dest = out / sub / f.name
                if dest.exists() and pg.sha256_file(dest) != pg.sha256_file(f):
                    sys.exit(f"candidate: two slices built different {sub}/{f.name}")
                shutil.copy(f, dest)
        if (s / "plugins.json").is_file():
            for r in json.loads((s / "plugins.json").read_text()):
                if plugins.setdefault(r["repo"], r) != r:
                    sys.exit(f"candidate: slices disagree on {r['repo']}'s tag")
    v = version()
    shutil.copy(ROOT / "crates/busbar-core-admin/src/v1/json/openapi.json", out / "artifacts" / f"busbar-openapi-v{v}.json")
    files = [f for sub in ("artifacts", "sboms") for f in (out / sub).iterdir()]
    pg.write_sums(out / "SHA256SUMS", files)
    with tarfile.open(out / "oci" / "busbar.oci.tar") as t:
        index = json.loads(t.extractfile("index.json").read())
    (out / "IMAGES").write_text(f"busbar {index['manifests'][0]['digest']}\n")
    commit = sh(["git", "rev-parse", "HEAD"], cwd=ROOT, out=True).strip()
    (out / "candidate.json").write_text(json.dumps({
        "version": v, "commit": commit, "repo": pg.REPO,
        "test_kit": {"tag": kit_tag, "commit": kit_commit},
        "plugins": sorted(plugins.values(), key=lambda r: r["repo"])}, indent=2) + "\n")
    print(f"candidate: assembled {v} at {commit} with {len(plugins)} plugins")


def main(argv: list) -> None:
    if not argv:
        sys.exit(__doc__)
    cmd, rest = argv[0], argv[1:]
    pos, opts, it = [], {}, iter(rest)
    for a in it:
        if a.startswith("--"):
            opts[a[2:]] = next(it, "")
        else:
            pos.append(a)
    out = Path(opts.get("out") or sys.exit("candidate: --out DIR is required"))
    if cmd == "core" and len(pos) == 1:
        cmd_core(pos[0], out)
    elif cmd == "plugins" and len(pos) == 1 and opts.get("kit-commit"):
        cmd_plugins(pos[0], opts["kit-commit"], out)
    elif cmd == "image":
        cmd_image(out)
    elif cmd == "assemble" and pos and opts.get("kit-tag") and opts.get("kit-commit"):
        cmd_assemble(out, pos, opts["kit-tag"], opts["kit-commit"])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
