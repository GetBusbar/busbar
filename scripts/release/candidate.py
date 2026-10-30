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
      to DIR/artifacts (an unpublished one to DIR/internal). Then its CycloneDX SBOM goes to
      DIR/sboms, named by the target, plus one named by the image platform the row feeds, if any.
      Then the W17 linking proof: the in-tree stub store is built for the target and packed
      (scripts/release/dropin-probe.sh, kept as DIR/evidence/<target>/dropin-probe.tar.gz), and
      scripts/release/linking-proof.py requires the built binary to need only the OS C runtime
      (glibc <= the row's glibc_max) and to boot with that plugin dropped in. A linux-gnu row runs
      all of this inside the glibc baseline (scripts/release/in-baseline.sh).
  candidate.py pgo-train <target> --out DIR
      trains the PGO profile for one row (scripts/pgo-build.sh with PGO_TRAIN_ONLY) on a backend
      native to it, and writes DIR/<target>.profdata plus DIR/<target>.profdata.meta (toolchain,
      commit, sha256). A person reviews it and commits it to release/pgo/. Releases build only from
      committed profiles (owner decision D4), so a second builder reproduces the same bytes.
  candidate.py pins --kit-commit SHA
      writes release/plugin-pins.tsv: for each first-party plugin in plugins.yaml (except an empty
      repo), its newest vX.Y.Z tag whose .busbar-ref names the test kit's commit. Run by a person,
      reviewed and committed; the checks never resolve tags themselves.
  candidate.py plugins <target> --out DIR
      every plugin in release/plugin-pins.tsv, at its pinned commit: a kind:store plugin must first
      pass scripts/fleet/verify-abi-completeness.sh against this tree; then it is built for <target>
      (cargo at the pin, or the C sources from busbar_plugin.h) and packed UNSIGNED with this tree's
      busbar-plugin-pack. Writes DIR/plugins/ and DIR/plugins.json.
  candidate.py image <amd64|arm64> --from COREDIR --out DIR
      that platform's image, PACKAGING the linux-gnu binary `core` already built into COREDIR (the
      row whose packaged_into names this platform), byte for byte: a single-platform OCI layout
      archive (DIR/oci/busbar-<arch>.oci.tar) on the Dockerfile's distroless glibc base. No second
      build, and no musl: a static musl binary cannot dlopen a dropped-in plugin (W17). Then the
      image is loaded and linking-proof.py requires it to carry those bytes and to boot with
      COREDIR's drop-in probe mounted. Refuses a BuildKit older than 0.13 (rewrite-timestamp).
  candidate.py assemble --kit-tag TAG --kit-commit SHA --out OUT DIR...
      merges the slices (the owner runs it locally from the `artifact` downloads), joins the
      per-platform images into one multi-platform index (OUT/oci/busbar.oci.tar), copies the
      OpenAPI document, and writes SHA256SUMS, IMAGES and candidate.json.

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


def cmd_pgo_train(target: str, out: Path) -> None:
    row = target_row(target)
    if not row.get("pgo"):
        sys.exit(f"candidate: {target} does not declare pgo in .github/release-targets.json")
    out.mkdir(parents=True, exist_ok=True)
    prof = out / f"{target}.profdata"
    env = {"BUSBAR_RELEASE_PUBKEY": pg.commit_key_list(ROOT), "PGO_TRAIN_ONLY": str(prof),
           "PGO_TARGET": row.get("triple", target)}
    if row.get("baseline"):
        env["BUSBAR_ARM64_BASELINE"] = "1"
    sh(["scripts/pgo-build.sh"], cwd=ROOT, env=env)
    toolchain = re.search(r'channel\s*=\s*"([^"]+)"', (ROOT / "rust-toolchain.toml").read_text()).group(1)
    commit = sh(["git", "rev-parse", "HEAD"], cwd=ROOT, out=True).strip()
    (out / f"{target}.profdata.meta").write_text(
        f"target={target}\ntoolchain={toolchain}\ntrained_at_commit={commit}\nsha256={pg.sha256_file(prof)}\n")
    print(f"candidate: {prof} trained at {commit} with {toolchain}; review and commit it to release/pgo/")


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
    sbom(triple, f"busbar-v{v}-{target}.cdx.json", out)
    if feeds:
        # The image packages these very bytes, so its SBOM is this build's.
        shutil.copy(out / "sboms" / f"busbar-v{v}-{target}.cdx.json", out / "sboms" / f"busbar-v{v}-{feeds}.cdx.json")
    linking_proof(row, out / sub / f"busbar-{target}.{row['archive']}", out / "evidence" / target)


def linking_proof(row: dict, archive: Path, evidence: Path) -> None:
    """W17: the built binary needs only the OS C runtime and loads a dropped-in plugin."""
    evidence.mkdir(parents=True, exist_ok=True)
    probe = evidence / "dropin-probe.tar.gz"
    for script in ("scripts/release/dropin-probe.sh", "scripts/release/linking-proof.py"):
        if not (ROOT / script).is_file():
            sys.exit(f"candidate: {script} is missing; this tree predates the W17 linking design")
    sh(["scripts/release/dropin-probe.sh", row.get("triple", row["target"]), str(probe)], cwd=ROOT)
    sh([sys.executable, "scripts/release/linking-proof.py", "--target", row["target"],
        "--archive", str(archive), "--dropin-plugin", str(probe)], cwd=ROOT)


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


PINS = ROOT / "release" / "plugin-pins.tsv"


def read_pins() -> list:
    rows = []
    for i, line in enumerate(PINS.read_text().splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 3 or not re.fullmatch(r"v\d+\.\d+\.\d+", parts[1]) or not re.fullmatch(r"[0-9a-f]{40}", parts[2]):
            sys.exit(f"candidate: {PINS.name}:{i} is not <repo>\\t<vX.Y.Z>\\t<40-hex commit>")
        rows.append({"repo": parts[0], "tag": parts[1], "commit": parts[2]})
    if not rows:
        sys.exit(f"candidate: {PINS.name} pins no plugin; run `candidate.py pins` and commit it")
    return rows


def cmd_pins(kit: str) -> None:
    lines = [l for l in PINS.read_text().splitlines() if l.startswith("#")] if PINS.is_file() else []
    for e in pg.registry_entries(ROOT):
        if e.get("pending_crate", "false") == "true":
            continue
        tag, commit, src = plugin_tag(e["repo"], kit)
        shutil.rmtree(src)
        lines.append(f"{e['repo']}\t{tag}\t{commit}")
    PINS.write_text("\n".join(lines) + "\n")
    print(f"candidate: wrote {PINS} ({len(lines)} lines); review and commit it")


def clone_at(repo: str, tag: str, commit: str) -> Path:
    tmp = Path(tempfile.mkdtemp())
    sh(["git", "clone", "-q", "--depth", "1", "--branch", tag, f"https://github.com/GetBusbar/{repo}.git", str(tmp)])
    head = sh(["git", "rev-parse", "HEAD"], cwd=tmp, out=True).strip()
    if head != commit:
        sys.exit(f"candidate: {repo} {tag} is {head}, but release/plugin-pins.tsv pins {commit}; a moved tag is refused")
    return tmp


def cmd_plugins(target: str, out: Path) -> None:
    spec = {t: (ext, prefix) for t, ext, prefix in pg.PLUGIN_TARGETS}
    if target not in spec:
        sys.exit(f"candidate: {target} is not a plugin target")
    ext, prefix = spec[target]
    sh(["cargo", "build", "--release", "--locked", "-p", "busbar-plugin-loader", "--features", "pack", "--bin", "busbar-plugin-pack"], cwd=ROOT)
    pack = str(ROOT / "target/release" / ("busbar-plugin-pack.exe" if os.name == "nt" else "busbar-plugin-pack"))
    (out / "plugins").mkdir(parents=True, exist_ok=True)
    rows = []
    entries = {e["repo"]: e for e in pg.registry_entries(ROOT)}
    for pin in read_pins():
        repo, tag, commit = pin["repo"], pin["tag"], pin["commit"]
        if repo not in entries:
            sys.exit(f"candidate: release/plugin-pins.tsv pins {repo}, which plugins.yaml does not register")
        e = entries[repo]
        src = clone_at(repo, tag, commit)
        if e["kind"] == "store":
            # Every RecordStore method the store implements is ROUTED by this tree's store_dispatch:
            # a method with a default body compiles, ships and silently drops writes otherwise.
            sh(["bash", str(ROOT / "scripts/fleet/verify-abi-completeness.sh"), str(src), str(ROOT)])
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


def require_buildkit() -> None:
    info = sh(["docker", "buildx", "inspect", "--bootstrap"], out=True)
    m = re.search(r"BuildKit version:\s*v?(\d+)\.(\d+)", info) or re.search(r"Buildkit:\s*v?(\d+)\.(\d+)", info)
    if not m or (int(m.group(1)), int(m.group(2))) < (0, 13):
        sys.exit(f"candidate: BuildKit >= 0.13 is required (rewrite-timestamp); found {m.group(0) if m else 'no version'}")


def cmd_image(arch: str, out: Path, core: Path) -> None:
    rows = [t for t in pg.release_targets(ROOT) if t.get("kind") == "binary" and t.get("packaged_into") == f"image-linux-{arch}"]
    if len(rows) != 1:
        sys.exit(f"candidate: no single linux-gnu row feeds image-linux-{arch} in .github/release-targets.json")
    t = rows[0]
    archive = core / ("artifacts" if t.get("published") else "internal") / f"busbar-{t['target']}.{t['archive']}"
    probe = core / "evidence" / t["target"] / "dropin-probe.tar.gz"
    for f in (archive, probe):
        if not f.is_file():
            sys.exit(f"candidate: {f} is missing; run `candidate.py core {t['target']} --out {core}` first. "
                     "The image packages that build's bytes and never builds its own.")
    require_buildkit()
    ctx = Path(tempfile.mkdtemp())
    (ctx / "binaries" / arch).mkdir(parents=True)
    with tarfile.open(archive) as tf:
        m = next(x for x in tf.getmembers() if x.isfile() and x.name.rsplit("/", 1)[-1] == "busbar")
        (ctx / "binaries" / arch / "busbar").write_bytes(tf.extractfile(m).read())
    os.chmod(ctx / "binaries" / arch / "busbar", 0o755)
    for f in ("Dockerfile", "providers.yaml"):
        shutil.copy(ROOT / f, ctx / f)
    shutil.copytree(ROOT / "docker", ctx / "docker")
    (out / "oci").mkdir(parents=True, exist_ok=True)
    oci = out / "oci" / f"busbar-{arch}.oci.tar"
    epoch = sh(["git", "log", "-1", "--format=%ct"], cwd=ROOT, out=True).strip()
    sh(["docker", "buildx", "build", "--platform", f"linux/{arch}", "--provenance=false", "--sbom=false",
        "--build-arg", f"SOURCE_DATE_EPOCH={epoch}", "--label", f"org.opencontainers.image.version={version()}",
        "--output", f"type=oci,dest={oci},rewrite-timestamp=true", str(ctx)],
       env={"SOURCE_DATE_EPOCH": epoch})
    # The linking proof on the image itself: load the exact OCI archive, then require it to carry
    # the core build's bytes and to boot with the drop-in probe mounted.
    loaded = sh(["docker", "load", "-i", str(oci)], out=True)
    m = re.search(r"Loaded image(?: ID)?: (\S+)", loaded)
    if not m:
        sys.exit(f"candidate: docker load named no image: {loaded!r}")
    sh([sys.executable, "scripts/release/linking-proof.py", "--target", f"image-linux-{arch}", "--image", m.group(1),
        "--packaged-from", str(ctx / "binaries" / arch / "busbar"), "--dropin-plugin", str(probe)], cwd=ROOT)
    shutil.rmtree(ctx)


def join_images(parts: list, dest: Path) -> str:
    """One multi-platform OCI layout from single-platform ones; returns the new index digest."""
    import hashlib
    import io

    blobs: dict = {}
    descs = []
    for part in parts:
        with tarfile.open(part) as t:
            for m in t.getmembers():
                if m.isfile() and m.name.startswith("blobs/sha256/"):
                    blobs[m.name] = t.extractfile(m).read()
            idx = json.loads(t.extractfile("index.json").read())
        for d in idx["manifests"]:
            doc = json.loads(blobs[f"blobs/sha256/{d['digest'].split(':')[1]}"])
            if "manifests" in doc:  # an index of one platform: take its manifests
                descs.extend(doc["manifests"])
            else:
                cfg = json.loads(blobs[f"blobs/sha256/{doc['config']['digest'].split(':')[1]}"])
                descs.append({"mediaType": d.get("mediaType", "application/vnd.oci.image.manifest.v1+json"),
                              "digest": d["digest"], "size": d["size"],
                              "platform": {"architecture": cfg["architecture"], "os": cfg["os"]}})
    descs.sort(key=lambda d: d["platform"]["architecture"])
    index = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                        "manifests": descs}, separators=(",", ":"), sort_keys=True).encode()
    digest = hashlib.sha256(index).hexdigest()
    blobs[f"blobs/sha256/{digest}"] = index
    top = json.dumps({"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.oci.image.index.v1+json",
                      "digest": f"sha256:{digest}", "size": len(index)}]}).encode()
    files = {"oci-layout": b'{"imageLayoutVersion":"1.0.0"}', "index.json": top, **blobs}
    with tarfile.open(dest, "w") as t:
        for name in sorted(files):
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime = len(files[name]), 0
            t.addfile(ti, io.BytesIO(files[name]))
    return f"sha256:{digest}"


def cmd_assemble(out: Path, slices: list, kit_tag: str, kit_commit: str) -> None:
    for sub in ("artifacts", "sboms", "internal", "plugins", "oci"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    plugins: dict = {}
    parts: list = []
    for s in map(Path, slices):
        for sub in ("artifacts", "sboms", "internal", "plugins", "oci"):
            for f in (s / sub).glob("*") if (s / sub).is_dir() else []:
                if sub == "oci":
                    parts.append(f)
                    continue
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
    if len(parts) != 2:
        sys.exit(f"candidate: expected the amd64 and arm64 image slices, found {[p.name for p in parts]}")
    digest = join_images(sorted(parts), out / "oci" / "busbar.oci.tar")
    (out / "IMAGES").write_text(f"busbar {digest}\n")
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
    if cmd == "pins" and opts.get("kit-commit"):
        cmd_pins(opts["kit-commit"])
        return
    out = Path(opts.get("out") or sys.exit("candidate: --out DIR is required"))
    if cmd == "pgo-train" and len(pos) == 1:
        cmd_pgo_train(pos[0], out)
    elif cmd == "core" and len(pos) == 1:
        cmd_core(pos[0], out)
    elif cmd == "plugins" and len(pos) == 1:
        cmd_plugins(pos[0], out)
    elif cmd == "image" and len(pos) == 1 and pos[0] in ("amd64", "arm64") and opts.get("from"):
        cmd_image(pos[0], out, Path(opts["from"]))
    elif cmd == "assemble" and pos and opts.get("kit-tag") and opts.get("kit-commit"):
        cmd_assemble(out, pos, opts["kit-tag"], opts["kit-commit"])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
