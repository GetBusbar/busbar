#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""publish-gate: verify, sign and publish one busbar release. It refuses anything it cannot prove.

ModernCI judges the qa -> main move and builds the CANDIDATE (`.ci/qa.yaml` check `candidate` on the
`modernci-config` branch). It holds no signing key and publishes nothing. This script is the rest,
run by the owner from his own clone at the release commit with his hardware keys present:

  verify    every rule below over the candidate and the owner's trust file. Offline apart from
            read-only GitHub and registry lookups. Writes `release-evidence.json`.
  sign      verify again, then show the full commit, the key-list diff and the digests. ONE
            release manifest lists every plugin tarball (name, version, target, canonical sha256);
            the release signer signs it ONCE (--release-sign-cmd), and `busbar-plugin-pack seal`
            puts it, with the trust file's root-signed keys document, into each tarball and
            verifies the chain (docs/design/release-trust.md). K2 (the release key, FIDO2 ed25519-sk)
            signs SHA256SUMS, SHA256SUMS.plugins, IMAGES and release-evidence.json, and each
            signature is checked against the trusted allowed_signers.
  upload    pushes the images by digest (untagged), cosign-signs and verifies them, creates the
            GitHub Release as a draft, uploads to Rekor, publishes, tags, and verifies everything
            again as a user would. Only then does it move X.Y, X and latest.
  plugin-release <repo> <tag> --plugins DIR
            the same flow for one plugin released between core releases. Its unsigned tarballs come
            from the candidate-plugins checks, built from the committed pins.
  spot-rebuild
            rebuilds the host target locally and byte-compares it with the candidate. Report only;
            the result is recorded in the evidence.

THE RULE SET IS THIS FILE. No flag, environment variable or config skips a rule. A rule that is
not here is recorded as `not-run` in the evidence, and the site claims nothing for it. A rule that
cannot run (a missing tool, an unreachable service) exits 3, never 0. Every refusal is one line:

  REFUSED <rule> <subject>: expected <x>; found <y>. <what to do>

Exit: 0 verified, 1 refused, 2 usage, 3 a rule could not run.

The candidate layout this reads, written by ModernCI's `candidate` check (docs/verify.md, "For
builders"):

  candidate.json   {"version","commit","repo","test_kit":{"tag","commit"},
                    "plugins":[{"repo","version","tag","commit"}]}
  artifacts/       busbar-<target>.<archive> for every published target, busbar-openapi-v<V>.json
  plugins/         <repo>-<version>-<target>.tar.gz, UNSIGNED, for every plugin and plugin target
  sboms/           busbar-v<V>-<target>.cdx.json for every published target and image platform
  internal/        busbar-<target>.tar.gz for any unpublished binary row (none since W17: the image
                   carries the published linux-gnu binary from artifacts/)
  oci/             busbar.oci.tar (an OCI layout of the multi-platform image)
  SHA256SUMS       every file of artifacts/ and sboms/ (bare names)
  IMAGES           `busbar sha256:<index digest>`
  rebuild/         (optional) the second builder's artifacts/, byte-compared (report mode)
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

REPO = "GetBusbar/busbar"
IMAGE_REPOS = ("docker.io/getbusbar/busbar", "ghcr.io/getbusbar/busbar")
PLUGIN_TARGETS = (
    ("x86_64-unknown-linux-gnu", "so", "lib"),
    ("aarch64-unknown-linux-gnu", "so", "lib"),
    ("x86_64-apple-darwin", "dylib", "lib"),
    ("aarch64-apple-darwin", "dylib", "lib"),
    ("x86_64-pc-windows-msvc", "dll", ""),
)
# K2 signs release FILES under this sshsig namespace only. Release STATEMENTS (ModernCI RP-2) are
# signed by the same hardware key under STATEMENT_NAMESPACE, so a file signature can never be
# replayed as a statement, nor a statement as a file signature: sshsig binds the namespace into what
# is signed, and allowed_signers restricts each key to one namespace (G-14).
K2_NAMESPACE = "busbar-release"
STATEMENT_NAMESPACE = "busbar-release-statement"
K2_IDENTITY = "busbar-release"
# A K2 key must be a FIDO2 hardware key: the key type proves it.
K2_HARDWARE_TYPES = ("sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
EXIT_OK, EXIT_REFUSED, EXIT_USAGE, EXIT_CANNOT_RUN = 0, 1, 2, 3


class CannotRun(Exception):
    """A rule could not run: exit 3, never a pass."""


# ── the verdict ──────────────────────────────────────────────────────────────────────────────────


@dataclass
class Verdict:
    refusals: list = field(default_factory=list)
    checked: dict = field(default_factory=dict)  # rule -> count of subjects checked
    evidence: dict = field(default_factory=dict)

    def ok(self, rule: str, n: int = 1) -> None:
        self.checked[rule] = self.checked.get(rule, 0) + n

    def refuse(self, rule: str, subject: str, expected: str, found: str, todo: str) -> None:
        line = f"REFUSED {rule} {subject}: expected {expected}; found {found}. {todo}"
        self.refusals.append(line)
        print(line)


# ── small helpers ────────────────────────────────────────────────────────────────────────────────


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise CannotRun(f"`{name}` is not on PATH; this rule cannot run without it")
    return path


def run(cmd: list, *, stdin: bytes | None = None, check: bool = False) -> subprocess.CompletedProcess:
    p = subprocess.run(cmd, input=stdin, capture_output=True)
    if check and p.returncode != 0:
        raise CannotRun(f"{' '.join(map(str, cmd))} failed: {p.stderr.decode(errors='replace').strip()}")
    return p


def read_sums(p: Path) -> dict:
    """`<64 hex>  <name>` lines -> {name: hex}. A malformed line or a repeated name is an error."""
    out: dict = {}
    for i, line in enumerate(p.read_text().splitlines(), 1):
        if not line.strip():
            continue
        m = re.fullmatch(r"([0-9a-f]{64})[ \t]+\*?(\S+)", line.strip())
        if not m:
            raise ValueError(f"{p.name}:{i} is not `<sha256>  <name>`")
        if m.group(2) in out:
            raise ValueError(f"{p.name}:{i} names {m.group(2)} twice")
        out[m.group(2)] = m.group(1)
    return out


def write_sums(p: Path, files: list) -> None:
    p.write_text("".join(f"{sha256_file(f)}  {f.name}\n" for f in sorted(files, key=lambda f: f.name)))


# ── the outside world, injectable for tests ──────────────────────────────────────────────────────


class Net:
    """Read-only lookups. Tests replace this; the CLI uses the real one."""

    def release_exists(self, repo: str, tag: str) -> bool:
        p = run([tool("gh"), "release", "view", tag, "-R", repo, "--json", "tagName"])
        if p.returncode == 0:
            return True
        err = p.stderr.decode(errors="replace").lower()
        if "not found" in err or "release not found" in err:
            return False
        raise CannotRun(f"gh release view {tag} -R {repo}: {err.strip()}")

    def release_published(self, repo: str, tag: str) -> bool:
        p = run([tool("gh"), "release", "view", tag, "-R", repo, "--json", "isDraft", "-q", ".isDraft"])
        if p.returncode == 0:
            return p.stdout.decode().strip() == "false"
        err = p.stderr.decode(errors="replace").lower()
        if "not found" in err:
            return False
        raise CannotRun(f"gh release view {tag} -R {repo}: {err.strip()}")

    def registry_digest(self, ref: str) -> str | None:
        p = run([tool("skopeo"), "inspect", "--raw", f"docker://{ref}"])
        if p.returncode == 0:
            return "sha256:" + sha256_bytes(p.stdout)
        err = p.stderr.decode(errors="replace").lower()
        if "manifest unknown" in err or "not found" in err or "name unknown" in err:
            return None
        raise CannotRun(f"skopeo inspect {ref}: {err.strip()}")

    def repo_file(self, repo: str, path: str, ref: str) -> str:
        p = run([tool("gh"), "api", f"repos/{repo}/contents/{path}?ref={ref}", "-q", ".content"])
        if p.returncode != 0:
            raise CannotRun(f"gh api {repo}/{path}@{ref}: {p.stderr.decode(errors='replace').strip()}")
        import base64

        return base64.b64decode(p.stdout).decode()


# ── inputs ───────────────────────────────────────────────────────────────────────────────────────


@dataclass
class Inputs:
    root: Path  # the owner's clone at the release commit
    cand: Path  # the candidate directory
    trust: dict  # the owner-held trust file
    pack: str  # the owner-built busbar-plugin-pack
    net: Net
    require_hardware_k2: bool = True  # only a test harness passes False; the CLI cannot


def load_trust(path: Path) -> dict:
    """The owner-held trust file: `k1` (the ROOT key list busbar embeds, BUSBAR_RELEASE_PUBKEY),
    `release_signer` (the release signer's public key, `p256:<hex>`), `keys_doc` (the path of the
    current root-signed keys document naming it), `k2_allowed_signers`."""
    t = json.loads(path.read_text())
    for k in ("k1", "release_signer", "keys_doc", "k2_allowed_signers"):
        if k not in t:
            raise ValueError(f"trust file {path} has no `{k}`")
    keys_doc = Path(t["keys_doc"]).expanduser()
    if not keys_doc.is_absolute():
        keys_doc = path.parent / keys_doc
    t["keys_doc"] = str(keys_doc)
    return t


def commit_key_list(root: Path) -> str:
    text = (root / ".cargo" / "config.toml").read_text()
    m = re.search(r'^\s*BUSBAR_RELEASE_PUBKEY\s*=\s*"([^"]*)"', text, re.M)
    if not m:
        raise ValueError(".cargo/config.toml sets no BUSBAR_RELEASE_PUBKEY")
    return m.group(1)


def release_targets(root: Path) -> list:
    return json.loads((root / ".github" / "release-targets.json").read_text())["targets"]


def registry_entries(root: Path) -> list:
    """The entries under `plugins:` in plugins.yaml, as {field: raw value}. There is no YAML parser
    here: each entry is a `  - repo:` line followed by `    field: value` lines."""
    lines = (root / "plugins.yaml").read_text().splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if re.fullmatch(r"plugins:\s*", l))
    except StopIteration:
        raise ValueError("plugins.yaml has no top-level `plugins:` list") from None
    entries: list = []
    for line in lines[start + 1:]:
        if line and not line.startswith((" ", "#", "-")):
            break  # the next top-level key
        m = re.match(r"^  - repo:\s*([A-Za-z0-9._-]+)\s*$", line)
        if m:
            entries.append({"repo": m.group(1)})
            continue
        m = re.match(r"^    ([a-z_]+):\s*(.*?)\s*$", line)
        if m and entries:
            entries[-1][m.group(1)] = m.group(2)
    if not entries:
        raise ValueError("plugins.yaml lists no plugins")
    return entries


def registry_plugins(root: Path) -> list:
    """The first-party plugins a release owes: every registered repo except an empty one
    (`pending_crate: true`, which has no crate to build)."""
    return [e["repo"] for e in registry_entries(root) if e.get("pending_crate", "false") != "true"]


# ── the rules ────────────────────────────────────────────────────────────────────────────────────


def expected_files(inp: Inputs, cj: dict) -> tuple:
    """(published core files, sbom files, internal files, plugin tarballs) the candidate owes."""
    v = cj["version"]
    pub, sboms, internal, plugins = set(), set(), set(), set()
    for t in release_targets(inp.root):
        if t.get("kind") == "binary" and t.get("published"):
            pub.add(f"busbar-{t['target']}.{t['archive']}")
            sboms.add(f"busbar-v{v}-{t['target']}.cdx.json")
        elif t.get("kind") == "binary":
            internal.add(f"busbar-{t['target']}.{t['archive']}")
        elif t.get("kind") == "image":
            sboms.add(f"busbar-v{v}-{t['target']}.cdx.json")
    pub.add(f"busbar-openapi-v{v}.json")
    for p in cj["plugins"]:
        for target, _, _ in PLUGIN_TARGETS:
            plugins.add(f"{p['repo']}-{p['version']}-{target}.tar.gz")
    return pub, sboms, internal, plugins


def g1_version(inp: Inputs, cj: dict, vd: Verdict) -> None:
    v = cj["version"]
    cargo = (inp.root / "crates" / "busbar" / "Cargo.toml").read_text()
    m = re.search(r'^\s*version\s*=\s*"([^"]+)"', cargo, re.M)
    if not m or m.group(1) != v:
        vd.refuse("G-1", "crates/busbar/Cargo.toml", f"version {v}", m.group(1) if m else "none",
                  "Bump with RELEASE.md's commands on dev, or fix candidate.json.")
    top = re.search(r"^## \[([^\]]+)\]", (inp.root / "CHANGELOG.md").read_text(), re.M)
    # `[Unreleased]` above the version is allowed only when empty: take the first versioned heading.
    heads = re.findall(r"^## \[([^\]]+)\]", (inp.root / "CHANGELOG.md").read_text(), re.M)
    first = next((h for h in heads if h.lower() != "unreleased"), None)
    if first != v:
        vd.refuse("G-1", "CHANGELOG.md", f"newest section [{v}]", f"[{first}]",
                  "Roll the changelog (RELEASE.md).")
    head = run(["git", "-C", str(inp.root), "rev-parse", "HEAD"], check=True).stdout.decode().strip()
    if head != cj["commit"]:
        vd.refuse("G-1", "clone", f"your clone at {cj['commit']}", head,
                  "Check out the release commit in your own clone; the gate reads its keys and rules from there.")
    if not re.fullmatch(r"[0-9a-f]{40}", cj.get("commit", "")):
        vd.refuse("G-1", "candidate.json", "a 40-hex commit", repr(cj.get("commit")), "Fix the candidate.")
    if cj.get("repo") != REPO:
        vd.refuse("G-1", "candidate.json", f"repo {REPO}", repr(cj.get("repo")),
                  "A release is built only from the canonical repo (no forks).")
    del top
    vd.ok("G-1")


def g2_not_published(inp: Inputs, cj: dict, vd: Verdict) -> None:
    v = cj["version"]
    if inp.net.release_exists(REPO, f"v{v}"):
        vd.refuse("G-2", f"v{v}", "no GitHub Release for this version", "one exists",
                  "A version is published once; bump the version.")
    for p in cj["plugins"]:
        if inp.net.release_published(f"GetBusbar/{p['repo']}", p["tag"]):
            vd.refuse("G-2", f"{p['repo']} {p['tag']}", "no published release (a draft is fine)", "published",
                      "A plugin version is published once; tag a new one.")
    images = read_images(inp.cand / "IMAGES")
    for repo in IMAGE_REPOS:
        d = inp.net.registry_digest(f"{repo}:{v}")
        if d is not None and d != images.get("busbar"):
            vd.refuse("G-2", f"{repo}:{v}", f"absent or {images.get('busbar')}", d,
                      "That tag already holds another image; bump the version.")
    vd.ok("G-2")


def read_images(p: Path) -> dict:
    out = {}
    for line in p.read_text().splitlines():
        if line.strip():
            name, digest = line.split()
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                raise ValueError(f"IMAGES: {digest!r} is not a sha256 digest")
            out[name] = digest
    return out


def g3_g4_sets_and_sums(inp: Inputs, cj: dict, vd: Verdict) -> None:
    pub, sboms, internal, plugins = expected_files(inp, cj)
    for sub, want in (("artifacts", pub), ("sboms", sboms), ("internal", internal), ("plugins", plugins)):
        d = inp.cand / sub
        have = {f.name for f in d.iterdir() if f.is_file()} if d.is_dir() else set()
        for name in sorted(want - have):
            vd.refuse("G-3", f"{sub}/{name}", "present", "missing",
                      "Every declared target and plugin is owed; a missing one is never skipped.")
        for name in sorted(have - want):
            vd.refuse("G-3", f"{sub}/{name}", "absent (not declared)", "present",
                      "Only declared artifacts ship; declare it in release-targets.json/plugins.yaml or drop it.")
        vd.ok("G-3", len(want))
    # The plugin set equals the committed pins (release/plugin-pins.tsv) at the release commit.
    pins = {}
    try:
        for line in (inp.root / "release" / "plugin-pins.tsv").read_text().splitlines():
            if line.strip() and not line.startswith("#"):
                repo, tag, commit = line.split("\t")
                pins[repo] = (tag, commit)
    except (OSError, ValueError) as e:
        vd.refuse("G-3", "release/plugin-pins.tsv", "<repo>\\t<tag>\\t<commit> lines", str(e), "Run candidate.py pins and commit it.")
    for p in cj["plugins"]:
        want = pins.get(p["repo"])
        got = (p.get("tag"), p.get("commit"))
        if want != got or p.get("version") != (want or ("v?",))[0][1:]:
            vd.refuse("G-3", f"plugin {p['repo']}", f"pinned {want}", f"{got} version {p.get('version')}",
                      "The candidate must build exactly the committed pins.")
    for r in sorted(set(pins) - {p["repo"] for p in cj["plugins"]}):
        vd.refuse("G-3", f"plugin {r}", "built (pinned in release/plugin-pins.tsv)", "absent from candidate.json", "Rebuild the plugins slice.")
    # The plugin set equals the registry.
    reg = set(registry_plugins(inp.root))
    got = {p["repo"] for p in cj["plugins"]}
    for r in sorted(reg - got):
        vd.refuse("G-3", f"plugin {r}", "released with this version (plugins.yaml)", "absent from candidate.json",
                  "Tag and build every first-party plugin, or remove it from plugins.yaml in a judged change.")
    for r in sorted(got - reg):
        vd.refuse("G-3", f"plugin {r}", "in plugins.yaml", "not registered",
                  "Only registered first-party plugins are released.")
    # SHA256SUMS covers exactly artifacts/ + sboms/, and every line matches the bytes.
    try:
        sums = read_sums(inp.cand / "SHA256SUMS")
    except (OSError, ValueError) as e:
        vd.refuse("G-4", "SHA256SUMS", "a well-formed sums file", str(e), "The candidate must write it.")
        return
    listed = set(sums)
    files = {}
    for sub in ("artifacts", "sboms"):
        d = inp.cand / sub
        if d.is_dir():
            files.update({f.name: f for f in d.iterdir() if f.is_file()})
    for name in sorted(set(files) ^ listed):
        vd.refuse("G-4", name, "listed in SHA256SUMS exactly when present", "listed" if name in listed else "unlisted",
                  "SHA256SUMS must name every published file and nothing else.")
    for name in sorted(set(files) & listed):
        got = sha256_file(files[name])
        if got != sums[name]:
            vd.refuse("G-4", name, sums[name], got, "The bytes changed after the build; do not publish.")
    vd.ok("G-4", len(listed))


def pack_out(inp: Inputs, args: list) -> tuple:
    p = run([inp.pack, *args])
    return p.returncode, (p.stdout + p.stderr).decode(errors="replace").strip()


def kv(line: str) -> dict:
    return dict(re.findall(r"(\S+?)=(\S+)", line))


def g5_plugins_unsigned(inp: Inputs, cj: dict, vd: Verdict) -> list:
    """Pre-sign: every plugin tarball is first-party, unsigned and its expected self. Returns rows."""
    rows = []
    for p in cj["plugins"]:
        for target, _, _ in PLUGIN_TARGETS:
            name = f"{p['repo']}-{p['version']}-{target}.tar.gz"
            f = inp.cand / "plugins" / name
            if not f.is_file():
                continue  # G-3 refused it
            code, out = pack_out(inp, ["canonical", str(f)])
            if code != 0:
                vd.refuse("G-5", name, "a plugin tarball", out, "Rebuild it with busbar-plugin-pack pack.")
                continue
            m = kv(out)
            for k, want in (("name", p["repo"]), ("version", p["version"]), ("publisher", "busbar"), ("signed", "false")):
                if m.get(k) != want:
                    vd.refuse("G-5", name, f"{k}={want}", f"{k}={m.get(k)}",
                              "CI packs first-party plugins UNSIGNED, with the registry name and the tag's version.")
            rows.append({"repo": p["repo"], "target": target, "file": name,
                         "canonical_sha256": m.get("canonical-sha256"), "lib_sha256": m.get("lib-sha256")})
            vd.ok("G-5")
    return rows


def unpack_binary(archive: Path) -> bytes:
    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as z:
            names = [n for n in z.namelist() if n.rsplit("/", 1)[-1] in ("busbar.exe", "busbar")]
            if len(names) != 1:
                raise ValueError(f"{archive.name}: expected one busbar binary, found {names}")
            return z.read(names[0])
    with tarfile.open(archive) as t:
        members = [m for m in t.getmembers() if m.isfile() and m.name.rsplit("/", 1)[-1] in ("busbar", "busbar.exe")]
        if len(members) != 1:
            raise ValueError(f"{archive.name}: expected one busbar binary, found {[m.name for m in members]}")
        return t.extractfile(members[0]).read()


def g6_embedded_keys(inp: Inputs, cj: dict, vd: Verdict) -> None:
    keys = inp.trust["k1"].encode()
    for sub in ("artifacts", "internal"):
        for f in sorted((inp.cand / sub).glob("busbar-*")):
            if f.name.startswith("busbar-openapi") or not (f.name.endswith(".tar.gz") or f.name.endswith(".zip")):
                continue
            try:
                b = unpack_binary(f)
            except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as e:
                vd.refuse("G-6", f.name, "an archive holding the busbar binary", str(e), "Rebuild.")
                continue
            if keys not in b:
                vd.refuse("G-6", f.name, f"the trusted key list ({inp.trust['k1'][:24]}…) embedded",
                          "not embedded", "The build dropped BUSBAR_RELEASE_PUBKEY (#52); rebuild.")
            vd.ok("G-6")


def g8_sboms(inp: Inputs, cj: dict, vd: Verdict) -> None:
    for f in sorted((inp.cand / "sboms").glob("*.cdx.json")):
        try:
            d = json.loads(f.read_text())
        except (OSError, ValueError) as e:
            vd.refuse("G-8", f.name, "CycloneDX JSON", str(e), "Regenerate the SBOM.")
            continue
        ver = (((d.get("metadata") or {}).get("component") or {}).get("version"))
        if d.get("bomFormat") != "CycloneDX" or ver != cj["version"]:
            vd.refuse("G-8", f.name, f"CycloneDX for version {cj['version']}",
                      f"bomFormat={d.get('bomFormat')} version={ver}", "Regenerate the SBOM for this build.")
        vd.ok("G-8")


def oci_blob(t: tarfile.TarFile, digest: str) -> bytes:
    algo, hexd = digest.split(":", 1)
    m = t.extractfile(f"blobs/{algo}/{hexd}")
    if m is None:
        raise ValueError(f"blob {digest} missing")
    b = m.read()
    if sha256_bytes(b) != hexd:
        raise ValueError(f"blob {digest} does not hash to its name")
    return b


def g10_image(inp: Inputs, cj: dict, vd: Verdict) -> None:
    arch_to_internal = {}
    for t in release_targets(inp.root):
        if t.get("kind") == "binary" and t.get("packaged_into", "").startswith("image-linux-"):
            # W17: the image packages the PUBLISHED linux-gnu binary (artifacts/); an unpublished
            # feeding row (the retired musl builds) would be in internal/.
            sub = "artifacts" if t.get("published") else "internal"
            arch_to_internal[t["packaged_into"].rsplit("-", 1)[1]] = inp.cand / sub / f"busbar-{t['target']}.{t['archive']}"
    try:
        images = read_images(inp.cand / "IMAGES")
        want = images["busbar"]
        with tarfile.open(inp.cand / "oci" / "busbar.oci.tar") as t:
            index = json.loads(t.extractfile("index.json").read())
            descs = index.get("manifests", [])
            if len(descs) != 1:
                raise ValueError(f"index.json holds {len(descs)} descriptors, expected the one image index")
            top = descs[0]["digest"]
            if top != want:
                vd.refuse("G-10", "IMAGES", want, top, "IMAGES must name the archive's image index digest.")
            top_doc = json.loads(oci_blob(t, top))
            plats = {m["platform"]["architecture"]: m["digest"] for m in top_doc.get("manifests", [])
                     if m.get("platform", {}).get("os") == "linux"}
            if set(plats) != set(arch_to_internal):
                vd.refuse("G-10", "image index", f"platforms {sorted(arch_to_internal)}", f"{sorted(plats)}",
                          "The image must carry exactly the declared platforms.")
            for arch, mdig in sorted(plats.items()):
                man = json.loads(oci_blob(t, mdig))
                cfg = json.loads(oci_blob(t, man["config"]["digest"]))
                user = (cfg.get("config") or {}).get("User")
                if user != "65532:65532":
                    vd.refuse("G-10", f"image linux/{arch}", "User 65532:65532", repr(user), "The Dockerfile's USER is the contract.")
                found = None
                for layer in man["layers"]:
                    with tarfile.open(fileobj=io.BytesIO(oci_blob(t, layer["digest"]))) as lt:
                        for m in lt.getmembers():
                            if m.isfile() and m.name.lstrip("./") == "busbar":
                                found = lt.extractfile(m).read()
                if found is None:
                    vd.refuse("G-10", f"image linux/{arch}", "/busbar in a layer", "none", "Rebuild the image.")
                    continue
                src = arch_to_internal.get(arch)
                if src is None or not src.is_file():
                    vd.refuse("G-10", f"image linux/{arch}", "the binary its packaged_into row built", "missing", "Rebuild.")
                    continue
                if sha256_bytes(found) != sha256_bytes(unpack_binary(src)):
                    vd.refuse("G-10", f"image linux/{arch}", f"/busbar == {src.name}'s binary",
                              "different bytes", "The image must carry the binary that was built and signed.")
                vd.ok("G-10")
    except (OSError, KeyError, ValueError, tarfile.TarError) as e:
        vd.refuse("G-10", "oci/busbar.oci.tar", "a readable OCI layout of the image", str(e), "Rebuild the image archive.")


def g11_compiled_in(inp: Inputs, cj: dict, vd: Verdict) -> None:
    lock = inp.root / "dist" / "default" / "Cargo.lock"
    if not lock.is_file():
        vd.refuse("G-11", "dist/default/Cargo.lock", "the distribution's lock (step 5)", "missing",
                  "1.6.0 ships the default distribution; land step 5 first.")
        return
    commits = {p["repo"]: p["commit"] for p in cj["plugins"]}
    pins = re.findall(r'source = "git\+https://github\.com/GetBusbar/([A-Za-z0-9._-]+?)(?:\.git)?(?:\?[^#"]*)?#([0-9a-f]{40})"',
                      lock.read_text())
    for repo, sha in sorted(set(pins)):
        if repo in commits and commits[repo] != sha:
            vd.refuse("G-11", f"dist/default pin {repo}", commits[repo], sha,
                      "The linked plugin must be the released plugin's commit; re-pin dist/default.")
        vd.ok("G-11")


def g12_test_kit(inp: Inputs, cj: dict, vd: Verdict) -> None:
    tk = cj.get("test_kit") or {}
    tag, commit = tk.get("tag"), tk.get("commit")
    if tag != f"test-kit-v{cj['version']}" or not commit:
        vd.refuse("G-12", "test kit", f"test-kit-v{cj['version']} with its commit", repr(tk), "Tag the test kit on dev.")
        return
    got = run(["git", "-C", str(inp.root), "rev-parse", f"{tag}^{{commit}}"]).stdout.decode().strip()
    if got != commit:
        vd.refuse("G-12", tag, commit, got or "no such tag in your clone", "Fetch tags; the tag must name the kit's commit.")
    if run(["git", "-C", str(inp.root), "merge-base", "--is-ancestor", commit, "HEAD"]).returncode != 0:
        vd.refuse("G-12", tag, "an ancestor of the release commit", "not an ancestor", "Release from a commit that contains the kit.")
    for p in cj["plugins"]:
        ref = inp.net.repo_file(f"GetBusbar/{p['repo']}", ".busbar-ref", p["commit"]).split()[0]
        if ref != commit:
            vd.refuse("G-12", f"{p['repo']}@{p['commit'][:12]}", f".busbar-ref {commit}", ref,
                      "Re-pin the plugin to the released test kit and re-tag it.")
        vd.ok("G-12")


def g13_rebuild(inp: Inputs, vd: Verdict) -> str:
    rb = inp.cand / "rebuild" / "artifacts"
    if not rb.is_dir():
        return "not-run"
    diffs = []
    for f in sorted(rb.iterdir()):
        mine = inp.cand / "artifacts" / f.name
        if not mine.is_file() or sha256_file(mine) != sha256_file(f):
            diffs.append(f.name)
    for d in diffs:
        print(f"REPORT G-13 {d}: the second build differs (reproducibility is report-only in 1.6.0; not claimed)")
    return "false" if diffs else "true"


def g14_trust(inp: Inputs, vd: Verdict) -> None:
    try:
        mine = commit_key_list(inp.root)
    except (OSError, ValueError) as e:
        vd.refuse("G-14", ".cargo/config.toml", "a BUSBAR_RELEASE_PUBKEY key list", str(e), "Commit the K1 list.")
        return
    if mine != inp.trust["k1"]:
        vd.refuse("G-14", "BUSBAR_RELEASE_PUBKEY", f"exactly your trust file's K1 list ({inp.trust['k1'][:32]}…)",
                  f"{mine[:32]}…", "A key list you did not put in your trust file is never trusted. "
                  "Read the diff; change your trust file only for a change signed by a key already in it.")
    signers = inp.root / "release" / "allowed_signers"
    try:
        committed = [l.strip() for l in signers.read_text().splitlines() if l.strip() and not l.startswith("#")]
    except OSError:
        committed = None
    if committed != [l.strip() for l in inp.trust["k2_allowed_signers"]]:
        vd.refuse("G-14", "release/allowed_signers", "exactly your trust file's K2 allowed_signers",
                  "different or missing", "Users verify against the committed file; it must be yours.")
    for line in inp.trust["k2_allowed_signers"]:
        m = re.search(r'(?:^|\s|,)namespaces="([^"]*)"', line)
        if not m or m.group(1) != K2_NAMESPACE:
            vd.refuse("G-14", "K2 allowed_signers", f'namespaces="{K2_NAMESPACE}" and nothing else',
                      m.group(0).strip() if m else "no namespaces= restriction",
                      f"Restrict each line to {K2_NAMESPACE}; statements ({STATEMENT_NAMESPACE}) are checked from ModernCI's own list.")
        if inp.require_hardware_k2 and not any(t in line.split() for t in K2_HARDWARE_TYPES):
            vd.refuse("G-14", "K2", f"a hardware key type ({' or '.join(K2_HARDWARE_TYPES)})", line.split()[2] if len(line.split()) > 2 else line,
                      "K2 lives on the YubiKey (ssh-keygen -t ed25519-sk).")
    vd.ok("G-14")


def verify_all(inp: Inputs) -> tuple:
    vd = Verdict()
    try:
        cj = json.loads((inp.cand / "candidate.json").read_text())
        for k in ("version", "commit", "repo", "plugins", "test_kit"):
            if k not in cj:
                raise ValueError(f"candidate.json has no `{k}`")
    except (OSError, ValueError) as e:
        vd.refuse("G-0", "candidate.json", "the candidate manifest", str(e), "Fetch the candidate's outputs.")
        return vd, {}, []
    g14_trust(inp, vd)
    g1_version(inp, cj, vd)
    g3_g4_sets_and_sums(inp, cj, vd)
    rows = g5_plugins_unsigned(inp, cj, vd)
    g6_embedded_keys(inp, cj, vd)
    g8_sboms(inp, cj, vd)
    g10_image(inp, cj, vd)
    g11_compiled_in(inp, cj, vd)
    g2_not_published(inp, cj, vd)
    g12_test_kit(inp, cj, vd)
    repro = g13_rebuild(inp, vd)
    if (inp.cand / "provenance").exists():
        vd.refuse("G-9", "provenance/", "no provenance (G-9 is not in 1.6.0's rule set)", "present",
                  "Land G-9 with ModernCI's pinned builder key before shipping provenance; an unchecked file is never published.")
    # G-0: every class ran on something.
    for rule in ("G-1", "G-2", "G-3", "G-4", "G-5", "G-6", "G-8", "G-10", "G-11", "G-12", "G-14"):
        if not vd.checked.get(rule):
            vd.refuse("G-0", rule, "at least one subject checked", "none", "A rule that checked nothing is not a pass.")
    vd.evidence = {
        "version": cj["version"], "commit": cj["commit"], "repo": REPO,
        "rules": {r: ("pass" if not any(x.split()[1] == r for x in vd.refusals) else "refused") for r in sorted(vd.checked)},
        "not_run": {"G-9": "no provenance producer for 1.6.0 (ModernCI phase 2b)"},
        "plugins_signed_by_hardware_key": "pending-sign",
        "release_signed_by_hardware_key": "pending-sign",
        "sbom": not any(x.split()[1] == "G-8" for x in vd.refusals),
        "slsa_provenance": "not-run",
        "transparency_log": "pending-upload",
        "reproducible": {"true": "not-proven", "false": False, "not-run": "not-run"}[repro] if repro != "true" else "second-build-matched",
        "local_spot_rebuild": "not-run",
        "k1_keys": [e.split(":")[0] for e in inp.trust["k1"].split(",")],
    }
    return vd, cj, rows


# ── commands ─────────────────────────────────────────────────────────────────────────────────────


def finish(vd: Verdict) -> int:
    n = len(vd.refusals)
    print()
    print(f"publish-gate: {sum(vd.checked.values())} checks over {len(vd.checked)} rules; {n} refusal(s).")
    if n:
        print("publish-gate: REFUSED. Nothing may be signed or published.")
        return EXIT_REFUSED
    print("publish-gate: VERIFIED.")
    return EXIT_OK


def cmd_verify(inp: Inputs, out: Path) -> int:
    vd, _, rows = verify_all(inp)
    if not vd.refusals:
        out.mkdir(parents=True, exist_ok=True)
        (out / "release-evidence.json").write_text(json.dumps(vd.evidence, indent=2, sort_keys=True) + "\n")
        (out / "plugins.tsv").write_text("".join(
            f"{r['repo']}\t{r['target']}\t{r['file']}\t{r['canonical_sha256']}\n" for r in rows))
    return finish(vd)


def k2_sign_and_check(inp: Inputs, key: str, files: list) -> None:
    signers = Path(tempfile.mkstemp()[1])
    signers.write_text("\n".join(inp.trust["k2_allowed_signers"]) + "\n")
    for f in files:
        sig = Path(str(f) + ".sig")
        sig.unlink(missing_ok=True)
        print(f"K2: touch the YubiKey to sign {f.name}")
        run([tool("ssh-keygen"), "-Y", "sign", "-f", key, "-n", K2_NAMESPACE, str(f)], check=True)
        p = run([tool("ssh-keygen"), "-Y", "verify", "-f", str(signers), "-I", K2_IDENTITY, "-n", K2_NAMESPACE,
                 "-s", str(sig)], stdin=f.read_bytes())
        if p.returncode != 0:
            raise CannotRun(f"G-7 {f.name}: the K2 signature does not verify against your trusted allowed_signers: "
                            f"{p.stderr.decode(errors='replace').strip()}")
    signers.unlink()


def seal_release(inp: Inputs, vd: Verdict, tarballs: list, out: Path, sign_cmd: str) -> None:
    """ONE SIGNATURE PER RELEASE. `tarballs` is [(unsigned tarball, target, name, version)].
    `busbar-plugin-pack release-manifest` writes the bytes of the one release manifest listing them
    all; `sign_cmd` is called ONCE as `CMD <manifest-file> <sig-out>`; `envelope` wraps the
    signature (refusing one that does not verify with the trust file's release signer); then each
    tarball is sealed with the keys document and the release manifest into out/signed/ and
    verified for its target. Writes out/release-manifest.json. The gate spells no byte of either
    document: busbar-plugin-pack (release_trust::wire) does."""
    keys_doc = Path(inp.trust["keys_doc"])
    try:
        expires = json.loads(keys_doc.read_text())["signed"]["expires"]
    except (OSError, KeyError, ValueError, TypeError) as e:
        vd.refuse("G-5", str(keys_doc), "the trust file's keys document", str(e), "Point keys_doc at the root-signed keys document.")
        return
    work = Path(tempfile.mkdtemp())
    signed_bytes, sig, manifest = work / "release-manifest.signed", work / "release-manifest.sig", out / "release-manifest.json"
    # The release manifest's version only rises: the signing time.
    code, outp = pack_out(inp, ["release-manifest", "--version", str(int(time.time())), "--expires", expires,
                                "--out", str(signed_bytes), *[f"{f}={t}" for f, t, _, _ in tarballs]])
    if code != 0:
        vd.refuse("G-5", "release manifest", "every plugin tarball listed", outp, "Rebuild the plugins slice.")
        return
    print(f"release manifest: {len(tarballs)} tarballs, {outp}")
    print("release signer: sign the release manifest (once)")
    p = run(["/bin/sh", "-c", f'{sign_cmd} "$0" "$1"', str(signed_bytes), str(sig)])
    if p.returncode != 0 or not sig.is_file():
        raise CannotRun(f"signing the release manifest failed: {p.stderr.decode(errors='replace').strip()}")
    code, outp = pack_out(inp, ["envelope", "--signed", str(signed_bytes), "--key", inp.trust["release_signer"],
                                "--signature", str(sig), "--out", str(manifest)])
    if code != 0:
        vd.refuse("G-5", "release manifest", "a signature by your release signer", outp, "Check the signer command and key.")
        return
    signed = out / "signed"
    signed.mkdir(parents=True, exist_ok=True)
    for f, target, name, version in tarballs:
        code, outp = pack_out(inp, ["seal", str(f), "--keys-doc", str(keys_doc), "--release", str(manifest),
                                    "--target", target, "--keys", inp.trust["k1"], "--out", str(signed / f.name)])
        if code != 0:
            vd.refuse("G-5", f.name, "sealed through the chain to your root list", outp, "Do not publish this plugin.")
            continue
        code, outp = pack_out(inp, ["verify", str(signed / f.name), "--keys", inp.trust["k1"], "--target", target,
                                    "--name", name, "--version", version])
        if code != 0:
            vd.refuse("G-5", f.name, "VERIFIED", outp, "Do not publish this plugin.")
        vd.ok("G-5")
    shutil.rmtree(work)


def cmd_sign(inp: Inputs, out: Path, k1_cmd: str, k2_key: str) -> int:
    vd, cj, rows = verify_all(inp)
    if vd.refusals:
        return finish(vd)
    old = run(["git", "-C", str(inp.root), "show", "v1.5.5:.cargo/config.toml"]).stdout.decode()
    m = re.search(r'BUSBAR_RELEASE_PUBKEY\s*=\s*"([^"]*)"', old)
    print("\n================ WHAT YOU ARE ABOUT TO SIGN ================")
    print(f"version   {cj['version']}")
    print(f"commit    {cj['commit']}   <- compare with `git rev-parse HEAD` in YOUR clone")
    print(f"K1 list   {inp.trust['k1']}")
    print(f"  v1.5.5  {m.group(1) if m else '(none)'}")
    print(f"artifacts {len(read_sums(inp.cand / 'SHA256SUMS'))} files; SHA256SUMS {sha256_file(inp.cand / 'SHA256SUMS')}")
    print(f"images    {read_images(inp.cand / 'IMAGES')}")
    print(f"plugins   {len(rows)} tarballs in ONE release manifest, signed once by {inp.trust['release_signer'][:24]}…")
    print("=============================================================")
    if input(f"Type the first 12 characters of the commit to sign: ").strip() != cj["commit"][:12]:
        print("publish-gate: not confirmed; nothing signed.")
        return EXIT_REFUSED
    signed = out / "signed"
    signed.mkdir(parents=True, exist_ok=True)
    versions = {p["repo"]: p["version"] for p in cj["plugins"]}
    for r in rows:
        code, outp = pack_out(inp, ["canonical", str(inp.cand / "plugins" / r["file"])])
        if code != 0 or kv(outp).get("canonical-sha256") != r["canonical_sha256"]:
            vd.refuse("G-5", r["file"], r["canonical_sha256"], outp, "The tarball changed after verify; start again.")
    if vd.refusals:
        return finish(vd)
    seal_release(inp, vd, [(inp.cand / "plugins" / r["file"], r["target"], r["repo"], versions[r["repo"]]) for r in rows],
                 out, k1_cmd)
    if vd.refusals:
        return finish(vd)
    write_sums(out / "SHA256SUMS.plugins", sorted(signed.iterdir()))
    shutil.copy(inp.cand / "SHA256SUMS", out / "SHA256SUMS")
    shutil.copy(inp.cand / "IMAGES", out / "IMAGES")
    ev = dict(vd.evidence)
    ev["plugins_signed_by_hardware_key"] = True
    ev["release_signed_by_hardware_key"] = True
    ev["plugin_release_manifest"] = sha256_file(out / "release-manifest.json")
    ev["plugin_keys_document"] = sha256_file(Path(inp.trust["keys_doc"]))
    ev["sha256sums"] = sha256_file(out / "SHA256SUMS")
    ev["sha256sums_plugins"] = sha256_file(out / "SHA256SUMS.plugins")
    ev["images"] = read_images(out / "IMAGES")
    (out / "release-evidence.json").write_text(json.dumps(ev, indent=2, sort_keys=True) + "\n")
    k2_sign_and_check(inp, k2_key, [out / "SHA256SUMS", out / "SHA256SUMS.plugins", out / "IMAGES",
                                    out / "release-evidence.json"])
    vd.ok("G-7", 4)
    return finish(vd)


def cmd_upload(inp: Inputs, out: Path) -> int:
    """Publish in the order that never exposes an unverified byte under a public name."""
    vd, cj, _ = verify_all(inp)
    if vd.refusals:
        return finish(vd)
    v, tag = cj["version"], f"v{cj['version']}"
    signers = Path(tempfile.mkstemp()[1])
    signers.write_text("\n".join(inp.trust["k2_allowed_signers"]) + "\n")
    signed_files = [out / n for n in ("SHA256SUMS", "SHA256SUMS.plugins", "IMAGES", "release-evidence.json")]
    for f in signed_files:  # G-7 again: nothing unsigned leaves this machine.
        p = run([tool("ssh-keygen"), "-Y", "verify", "-f", str(signers), "-I", K2_IDENTITY, "-n", K2_NAMESPACE,
                 "-s", str(f) + ".sig"], stdin=f.read_bytes())
        if p.returncode != 0:
            vd.refuse("G-7", f.name, "a K2 signature verifying against your allowed_signers", "none", "Run `sign` first.")
    if (out / "SHA256SUMS").read_bytes() != (inp.cand / "SHA256SUMS").read_bytes():
        vd.refuse("G-4", "SHA256SUMS", "the signed file equals the candidate's", "different", "Run `sign` again.")
    plugin_sums = read_sums(out / "SHA256SUMS.plugins")
    for name, digest in plugin_sums.items():
        if sha256_file(out / "signed" / name) != digest:
            vd.refuse("G-4", f"signed/{name}", digest, "different bytes", "Run `sign` again.")
    if vd.refusals:
        return finish(vd)
    digest = read_images(out / "IMAGES")["busbar"]
    cos = inp.trust.get("cosign") or {}
    if not cos.get("identity") or not cos.get("issuer"):
        raise CannotRun("trust file has no cosign identity/issuer (D1); images cannot be signed or verified")
    # 1. images by digest, untagged; 2. cosign sign; 3. cosign verify on the registry copy.
    for repo in IMAGE_REPOS:
        run([tool("skopeo"), "copy", "--all", "--preserve-digests",
             f"oci-archive:{inp.cand / 'images' / 'busbar.oci.tar'}", f"docker://{repo}@{digest}"], check=True)
        run([tool("cosign"), "sign", "--yes", f"{repo}@{digest}"], check=True)
        run([tool("cosign"), "verify", "--certificate-identity", cos["identity"],
             "--certificate-oidc-issuer", cos["issuer"], f"{repo}@{digest}"], check=True)
    # 4. the GitHub Release as a draft, with every byte and signature.
    core = read_sums(out / "SHA256SUMS")
    assets = [inp.cand / "artifacts" / n for n in core if (inp.cand / "artifacts" / n).is_file()]
    assets += [inp.cand / "sboms" / n for n in core if (inp.cand / "sboms" / n).is_file()]
    assets += signed_files + [Path(str(f) + ".sig") for f in signed_files]
    run([tool("gh"), "release", "create", tag, "-R", REPO, "--draft", "--target", cj["commit"],
         "--title", f"busbar {v}", "--notes-file", "-"], stdin=b"See CHANGELOG.md and docs/verify.md.", check=True)
    run([tool("gh"), "release", "upload", tag, "-R", REPO, *map(str, assets)], check=True)
    # 5. Rekor: every K2 signature in the public log.
    k2pub = Path(tempfile.mkstemp(suffix=".pub")[1])
    k2pub.write_text(" ".join(inp.trust["k2_allowed_signers"][0].split()[2:4]) + "\n")
    rekor = {}
    for f in signed_files:
        p = run([tool("rekor-cli"), "upload", "--artifact", str(f), "--signature", str(f) + ".sig",
                 "--pki-format", "ssh", "--public-key", str(k2pub)], check=True)
        rekor[f.name] = p.stdout.decode().strip()
    # 6. publish; 7. tag the images.
    run([tool("gh"), "release", "edit", tag, "-R", REPO, "--draft=false", "--latest"], check=True)
    for repo in IMAGE_REPOS:
        run([tool("skopeo"), "copy", "--all", "--preserve-digests", f"docker://{repo}@{digest}", f"docker://{repo}:{v}"], check=True)
    # The plugins, each to its own repo's release at its tag (plugins.fetch resolves there).
    for p in cj["plugins"]:
        prepo = f"GetBusbar/{p['repo']}"
        files = [out / "signed" / f"{p['repo']}-{p['version']}-{t}.tar.gz" for t, _, _ in PLUGIN_TARGETS]
        if not inp.net.release_exists(prepo, p["tag"]):
            run([tool("gh"), "release", "create", p["tag"], "-R", prepo, "--draft", "--target", p["commit"],
                 "--title", f"{p['repo']} {p['tag']}", "--notes-file", "-"], stdin=b"Signed with the busbar plugin key.", check=True)
        run([tool("gh"), "release", "upload", p["tag"], "-R", prepo, "--clobber", *map(str, files),
             str(out / "SHA256SUMS.plugins"), str(out / "SHA256SUMS.plugins.sig")], check=True)
        run([tool("gh"), "release", "edit", p["tag"], "-R", prepo, "--draft=false", "--latest"], check=True)
    # 8. verify as a user would; 9. only then the floating tags.
    dl = Path(tempfile.mkdtemp())
    run([tool("gh"), "release", "download", tag, "-R", REPO, "-D", str(dl)], check=True)
    for f in ("SHA256SUMS", "SHA256SUMS.plugins", "IMAGES", "release-evidence.json"):
        p = run([tool("ssh-keygen"), "-Y", "verify", "-f", str(signers), "-I", K2_IDENTITY, "-n", K2_NAMESPACE,
                 "-s", str(dl / (f + ".sig"))], stdin=(dl / f).read_bytes())
        if p.returncode != 0:
            vd.refuse("G-7", f"published {f}", "verifies", "does not", "Pull the release back to draft at once.")
    for name, want in read_sums(dl / "SHA256SUMS").items():
        if (dl / name).is_file() and sha256_file(dl / name) != want:
            vd.refuse("G-4", f"published {name}", want, sha256_file(dl / name), "Pull the release back to draft at once.")
    for repo in IMAGE_REPOS:
        got = inp.net.registry_digest(f"{repo}:{v}")
        if got != digest:
            vd.refuse("G-7", f"{repo}:{v}", digest, str(got), "The tag does not hold the signed image; fix before moving latest.")
    if vd.refusals:
        return finish(vd)
    major, minor = v.split(".")[:2]
    for repo in IMAGE_REPOS:
        for t in (f"{major}.{minor}", major, "latest"):
            run([tool("skopeo"), "copy", "--all", "--preserve-digests", f"docker://{repo}@{digest}", f"docker://{repo}:{t}"], check=True)
    # The rows rekor_watch.py compares the public log with: commit them to release/released.tsv.
    (out / "released.tsv").write_text("".join(f"{v}\t{f.name}\t{sha256_file(f)}\n" for f in signed_files))
    print(f"Commit {out / 'released.tsv'}'s rows to release/released.tsv (the Rekor watch reads it).")
    print("Rekor entries:")
    for k, line in rekor.items():
        print(f"  {k}: {line}")
    print("Next: open the homebrew and helm bump PRs with digests from the signed SHA256SUMS and IMAGES.")
    vd.ok("G-7")
    return finish(vd)


def cmd_plugin_release(inp: Inputs, out: Path, repo: str, tag: str, plugins: Path, k1_cmd: str, k2_key: str) -> int:
    """One plugin between core releases. Its unsigned tarballs come from the candidate-plugins checks
    (fetched with `modernci call artifact`). One release manifest lists them, the release signer signs
    it once, each tarball is sealed and verified, K2 signs, and the release is published."""
    vd = Verdict()
    g14_trust(inp, vd)
    if vd.refusals:
        return finish(vd)
    if not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        vd.refuse("G-1", tag, "vX.Y.Z", tag, "Plugin releases are versioned tags.")
        return finish(vd)
    if repo not in registry_plugins(inp.root):
        vd.refuse("G-3", repo, "a registered first-party plugin", "not in plugins.yaml", "Register it in a judged change.")
        return finish(vd)
    ver = tag[1:]
    pinned = None
    for line in (inp.root / "release" / "plugin-pins.tsv").read_text().splitlines():
        if line.strip() and not line.startswith("#") and line.split("\t")[0] == repo:
            pinned = line.split("\t")
    if not pinned or pinned[1] != tag:
        vd.refuse("G-3", f"{repo} {tag}", "pinned in release/plugin-pins.tsv at this commit", str(pinned),
                  "Pin the plugin release in a judged change; the candidate-plugins checks build exactly the pins.")
        return finish(vd)
    commit = pinned[2]
    if inp.net.release_published(f"GetBusbar/{repo}", tag):
        vd.refuse("G-2", f"{repo} {tag}", "not yet published", "published", "A plugin version is published once; tag a new one.")
        return finish(vd)
    dl = plugins
    want = {f"{repo}-{ver}-{t}.tar.gz" for t, _, _ in PLUGIN_TARGETS}
    have = {f.name for f in dl.iterdir() if f.name.endswith(".tar.gz") and f.name.startswith(f"{repo}-")}
    for n in sorted(want - have):
        vd.refuse("G-3", n, "present in --plugins", "missing", "Every plugin target is owed; fetch every candidate-plugins slice.")
    for n in sorted(have - want):
        vd.refuse("G-3", n, "absent", "present", "Only declared targets ship.")
    if vd.refusals:
        return finish(vd)
    for n in sorted(want):
        code, outp = pack_out(inp, ["canonical", str(dl / n)])
        m = kv(outp)
        if code != 0 or m.get("name") != repo or m.get("version") != ver or m.get("publisher") != "busbar" or m.get("signed") != "false":
            vd.refuse("G-5", n, f"unsigned busbar plugin {repo} {ver}", outp, "Re-run the plugin's release workflow.")
    if vd.refusals:
        return finish(vd)
    out.mkdir(parents=True, exist_ok=True)
    seal_release(inp, vd, [(dl / f"{repo}-{ver}-{t}.tar.gz", t, repo, ver) for t, _, _ in PLUGIN_TARGETS], out, k1_cmd)
    if vd.refusals:
        return finish(vd)
    signed = out / "signed"
    sums = out / "SHA256SUMS"
    write_sums(sums, sorted(signed.iterdir()))
    k2_sign_and_check(inp, k2_key, [sums])
    if not inp.net.release_exists(f"GetBusbar/{repo}", tag):
        run([tool("gh"), "release", "create", tag, "-R", f"GetBusbar/{repo}", "--draft", "--target", commit,
             "--title", f"{repo} {tag}", "--notes-file", "-"], stdin=b"Signed with the busbar plugin key.", check=True)
    run([tool("gh"), "release", "upload", tag, "-R", f"GetBusbar/{repo}", "--clobber",
         *map(str, sorted(signed.iterdir())), str(sums), str(sums) + ".sig"], check=True)
    run([tool("gh"), "release", "edit", tag, "-R", f"GetBusbar/{repo}", "--draft=false", "--latest"], check=True)
    back = Path(tempfile.mkdtemp())
    run([tool("gh"), "release", "download", tag, "-R", f"GetBusbar/{repo}", "-D", str(back)], check=True)
    for n in sorted(want):
        target = n[len(f"{repo}-{ver}-"):-len(".tar.gz")]
        code, outp = pack_out(inp, ["verify", str(back / n), "--keys", inp.trust["k1"], "--target", target,
                                    "--name", repo, "--version", ver])
        if code != 0:
            vd.refuse("G-5", f"published {n}", "VERIFIED", outp, "Pull the release back to draft at once.")
    vd.ok("G-7")
    return finish(vd)


def cmd_spot_rebuild(inp: Inputs, out: Path, target: str) -> int:
    """Report only: rebuild one target here and byte-compare its binary with the candidate's."""
    cj = json.loads((inp.cand / "candidate.json").read_text())
    tmp = Path(tempfile.mkdtemp())
    p = subprocess.run(["scripts/release-build.sh", target, "--out-dir", str(tmp), "--evidence-dir", str(tmp / "ev")],
                       cwd=inp.root, env={**os.environ, "BUSBAR_RELEASE_PUBKEY": inp.trust["k1"]})
    if p.returncode != 0:
        raise CannotRun(f"release-build.sh {target} failed")
    mine = next(tmp.glob(f"busbar-{target}.*"))
    theirs = inp.cand / "artifacts" / mine.name
    same = sha256_bytes(unpack_binary(mine)) == sha256_bytes(unpack_binary(theirs))
    ev_path = out / "spot-rebuild.json"
    ev_path.write_text(json.dumps({"version": cj["version"], "commit": cj["commit"], "target": target,
                                   "binary_identical": same}, indent=2) + "\n")
    print(f"REPORT G-13 spot rebuild {target}: binary {'IDENTICAL' if same else 'DIFFERENT'} (report only)")
    shutil.rmtree(tmp)
    return EXIT_OK


USAGE = """usage:
  publish_gate.py verify          --candidate DIR --trust FILE --pack BIN --out DIR
  publish_gate.py sign            --candidate DIR --trust FILE --pack BIN --out DIR --k1-sign-cmd CMD --k2-key FILE
  publish_gate.py upload          --candidate DIR --trust FILE --pack BIN --out DIR
  publish_gate.py plugin-release  REPO TAG --plugins DIR --trust FILE --pack BIN --out DIR --k1-sign-cmd CMD --k2-key FILE
  publish_gate.py spot-rebuild    TARGET --candidate DIR --trust FILE --pack BIN --out DIR

Run from your own clone at the release commit, with busbar-plugin-pack built there by you.
--k1-sign-cmd is the RELEASE SIGNER, called ONCE per release as `CMD <release-manifest-file> <signature-out>`;
it writes the raw signature (DER for P-256): scripts/release/sign-*.sh (docs/design/release-trust.md).
--k2-key is the ed25519-sk key handle (`ssh-keygen -K` writes it from the YubiKey)."""


def main(argv: list) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(USAGE)
        return EXIT_USAGE if not argv else EXIT_OK
    cmd, rest = argv[0], argv[1:]
    pos, opts = [], {}
    it = iter(rest)
    for a in it:
        if a.startswith("--"):
            if a[2:] in opts:
                print(f"--{a[2:]} given twice\n{USAGE}")
                return EXIT_USAGE
            opts[a[2:]] = next(it, None)
        else:
            pos.append(a)
    need = {"verify": ["candidate", "trust", "pack", "out"], "sign": ["candidate", "trust", "pack", "out", "k1-sign-cmd", "k2-key"],
            "upload": ["candidate", "trust", "pack", "out"], "plugin-release": ["plugins", "trust", "pack", "out", "k1-sign-cmd", "k2-key"],
            "spot-rebuild": ["candidate", "trust", "pack", "out"]}
    if cmd not in need or any(not opts.get(k) for k in need[cmd]) or set(opts) - set(need[cmd]):
        print(USAGE)
        return EXIT_USAGE
    root = Path(run(["git", "rev-parse", "--show-toplevel"], check=True).stdout.decode().strip())
    try:
        inp = Inputs(root=root, cand=Path(opts.get("candidate") or "."), trust=load_trust(Path(opts["trust"]).expanduser()),
                     pack=opts["pack"], net=Net())
        out = Path(opts["out"])
        if cmd == "verify":
            return cmd_verify(inp, out)
        if cmd == "sign":
            return cmd_sign(inp, out, opts["k1-sign-cmd"], opts["k2-key"])
        if cmd == "upload":
            return cmd_upload(inp, out)
        if cmd == "plugin-release":
            if len(pos) != 2:
                print(USAGE)
                return EXIT_USAGE
            return cmd_plugin_release(inp, out, pos[0], pos[1], Path(opts["plugins"]), opts["k1-sign-cmd"], opts["k2-key"])
        if cmd == "spot-rebuild":
            if len(pos) != 1:
                print(USAGE)
                return EXIT_USAGE
            return cmd_spot_rebuild(inp, out, pos[0])
    except CannotRun as e:
        print(f"CANNOT RUN: {e}")
        print("publish-gate: a rule could not run; this is never a pass.")
        return EXIT_CANNOT_RUN
    except (OSError, ValueError, KeyError) as e:
        print(f"CANNOT RUN: {type(e).__name__}: {e}")
        return EXIT_CANNOT_RUN
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
