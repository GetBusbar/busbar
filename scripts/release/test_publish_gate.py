#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Offline proof that publish_gate.py passes a good release and refuses each bad one, naming the rule.

  PACK=<path to busbar-plugin-pack> python3 scripts/release/test_publish_gate.py

It builds, in a temporary directory, a repo at a "release commit" and a candidate as ModernCI's
`candidate` check writes it. It runs `verify` and `sign` against them, then breaks one thing at a time.
K1 is an in-memory Ed25519 key (openssl) standing in for the PIV key. K2 is a software ssh key
standing in for the FIDO2 key; only this harness may relax the hardware-type check, and the CLI has
no way to.
"""

from __future__ import annotations

import builtins
import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import publish_gate as pg  # noqa: E402

PACK = os.environ.get("PACK", "")
VERSION = "1.6.0"
PLUGIN = "busbar-store-fake"
PVER = "1.6.0"


def sh(*cmd, cwd=None, inp=None):
    return subprocess.run(cmd, cwd=cwd, input=inp, capture_output=True, check=True).stdout


def tgz(members: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in members.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def blob(layout: dict, data: bytes) -> str:
    d = hashlib.sha256(data).hexdigest()
    layout[f"blobs/sha256/{d}"] = data
    return f"sha256:{d}"


class FakeNet(pg.Net):
    def __init__(self, kit_commit):
        self.kit = kit_commit
        self.released = set()
        self.registry = {}

    def release_exists(self, repo, tag):
        return (repo, tag) in self.released

    def release_published(self, repo, tag):
        return (repo, tag) in self.released

    def registry_digest(self, ref):
        return self.registry.get(ref)

    def repo_file(self, repo, path, ref):
        return f"{self.kit} {VERSION}\n"

    def repo_full_name(self, repo):
        return None

    def remote_tag(self, repo, tag):
        return None


class World:
    """A release commit plus a candidate, built fresh per test."""

    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="publish-gate-test-"))
        self.root, self.cand, self.out = self.tmp / "repo", self.tmp / "cand", self.tmp / "out"
        self.keys = self.tmp / "keys"
        for d in (self.root, self.cand, self.keys):
            d.mkdir()
        # K1, the ROOT: a P-256 key in a PEM (stand-in for the Cloud KMS root) and its SEC1 point.
        # The release signer: another P-256 key (stand-in for the interim signer). The keys document
        # the root signs names the signer; the sign command signs the release manifest once.
        def p256(name):
            sh("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
               "-out", str(self.keys / f"{name}.pem"))
            der = sh("openssl", "pkey", "-in", str(self.keys / f"{name}.pem"), "-pubout", "-outform", "DER")
            return f"p256:{der[-65:].hex()}"
        root, self.release_signer = p256("root"), p256("signer")
        self.k1_list = f"busbar-plugins-root:{root}"
        spec = self.keys / "keys-spec.json"
        spec.write_text(json.dumps({"version": 1, "expires": "2099-01-01T00:00:00Z", "signers": [self.release_signer]}))
        sh(PACK, "keys-doc", "--spec", str(spec), "--out", str(self.keys / "keys.signed"))
        sh("openssl", "dgst", "-sha256", "-sign", str(self.keys / "root.pem"), "-out", str(self.keys / "keys.sig"),
           str(self.keys / "keys.signed"))
        sh(PACK, "envelope", "--signed", str(self.keys / "keys.signed"), "--key", root,
           "--signature", str(self.keys / "keys.sig"), "--out", str(self.keys / "keys.json"))
        # The sign command is called ONCE as `CMD <release-manifest> <sig-out>` and writes DER.
        (self.keys / "k1-sign").write_text(
            f'#!/bin/sh\nexec openssl dgst -sha256 -sign "{self.keys / "signer.pem"}" -out "$2" "$1"\n')
        os.chmod(self.keys / "k1-sign", 0o755)
        # K2: a software ssh key (stand-in for ed25519-sk).
        sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "busbar-release-2026a", "-f", str(self.keys / "k2"))
        pub = (self.keys / "k2.pub").read_text().split()
        self.signer = f'busbar-release namespaces="busbar-release" {pub[0]} {pub[1]} busbar-release-2026a'
        self.tag_signer = f'busbar-release namespaces="git" {pub[0]} {pub[1]} busbar-release-2026a'
        self.trust = {"k1": self.k1_list, "release_signer": self.release_signer,
                      "keys_doc": str(self.keys / "keys.json"), "k2_allowed_signers": [self.signer, self.tag_signer],
                      "cosign": {"identity": "release@getbusbar.com", "issuer": "https://accounts.google.com"}}
        self._repo()
        self._candidate()

    def _repo(self):
        r = self.root
        (r / ".cargo").mkdir()
        (r / ".cargo" / "config.toml").write_text(f'[env]\nBUSBAR_RELEASE_PUBKEY = "{self.k1_list}"\n')
        (r / "crates" / "busbar").mkdir(parents=True)
        (r / "crates" / "busbar" / "Cargo.toml").write_text(f'[package]\nname = "busbar"\nversion = "{VERSION}"\n')
        (r / "CHANGELOG.md").write_text(f"# Changelog\n\n## [Unreleased]\n\n## [{VERSION}] - 2026-10-26\n\n## [1.5.5]\n")
        (r / "plugins.yaml").write_text(f"fleet:\n  x: 1\n\nplugins:\n  - repo: {PLUGIN}\n    kind: store\n\nother: 1\n")
        (r / ".github").mkdir()
        (r / ".github" / "release-targets.json").write_text(json.dumps({"targets": [
            {"target": "x86_64-unknown-linux-gnu", "kind": "binary", "published": True, "archive": "tar.gz", "packaged_into": ""},
            {"target": "x86_64-pc-windows-msvc", "kind": "binary", "published": True, "archive": "zip", "packaged_into": ""},
            {"target": "x86_64-unknown-linux-musl", "kind": "binary", "published": False, "archive": "tar.gz", "packaged_into": "image-linux-amd64"},
            {"target": "aarch64-unknown-linux-musl", "kind": "binary", "published": False, "archive": "tar.gz", "packaged_into": "image-linux-arm64"},
            {"target": "image-linux-amd64", "kind": "image", "published": False, "archive": "oci"},
            {"target": "image-linux-arm64", "kind": "image", "published": False, "archive": "oci"},
        ]}))
        (r / "release").mkdir()
        (r / "release" / "allowed_signers").write_text("# K2\n" + self.signer + "\n" + self.tag_signer + "\n")
        self.plugin_commit = "c" * 40
        (r / "release" / "plugin-pins.tsv").write_text(f"# pins\n{PLUGIN}\tv{PVER}\t{self.plugin_commit}\n")
        sh("git", "init", "-q", cwd=r)
        sh("git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "kit", cwd=r)
        self.kit = sh("git", "rev-parse", "HEAD", cwd=r).decode().strip()
        sh("git", "tag", f"test-kit-v{VERSION}", cwd=r)
        (r / "dist" / "default").mkdir(parents=True)
        (r / "dist" / "default" / "Cargo.lock").write_text(
            f'[[package]]\nname = "x"\nsource = "git+https://github.com/GetBusbar/{PLUGIN}?rev=abc#{self.plugin_commit}"\n')
        sh("git", "add", "-A", cwd=r)
        sh("git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "release", cwd=r)
        self.commit = sh("git", "rev-parse", "HEAD", cwd=r).decode().strip()
        # The version tag, signed by K2 under the git namespace (G-15).
        sh("git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "gpg.format=ssh",
           "-c", f"user.signingkey={self.keys / 'k2'}", "tag", "-s", f"v{VERSION}", "-m", f"busbar {VERSION}", cwd=r)

    def binary(self, tag: str) -> bytes:
        return b"\x7fELF busbar " + tag.encode() + b" key=" + self.k1_list.encode() + b" end"

    def _candidate(self):
        c = self.cand
        for d in ("artifacts", "sboms", "internal", "plugins", "oci"):
            (c / d).mkdir()
        (c / "artifacts" / "busbar-x86_64-unknown-linux-gnu.tar.gz").write_bytes(tgz({"busbar": self.binary("gnu")}))
        zbuf = io.BytesIO()
        import zipfile
        with zipfile.ZipFile(zbuf, "w") as z:
            z.writestr("busbar.exe", self.binary("win"))
        (c / "artifacts" / "busbar-x86_64-pc-windows-msvc.zip").write_bytes(zbuf.getvalue())
        (c / "artifacts" / f"busbar-openapi-v{VERSION}.json").write_text("{}\n")
        musl = {"amd64": self.binary("musl-amd64"), "arm64": self.binary("musl-arm64")}
        (c / "internal" / "busbar-x86_64-unknown-linux-musl.tar.gz").write_bytes(tgz({"busbar": musl["amd64"]}))
        (c / "internal" / "busbar-aarch64-unknown-linux-musl.tar.gz").write_bytes(tgz({"busbar": musl["arm64"]}))
        for t in ("x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", "image-linux-amd64", "image-linux-arm64"):
            (c / "sboms" / f"busbar-v{VERSION}-{t}.cdx.json").write_text(json.dumps(
                {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"name": "busbar", "version": VERSION}}}))
        # The image: an OCI layout with an index over two platform manifests.
        self.layout = {}
        mans = []
        for arch in ("amd64", "arm64"):
            layer = gzip.compress(self._raw_tar({"busbar": musl[arch]}))
            ld = blob(self.layout, layer)
            cfg = blob(self.layout, json.dumps({"config": {"User": "65532:65532"}, "architecture": arch, "os": "linux"}).encode())
            man = blob(self.layout, json.dumps({"schemaVersion": 2, "config": {"digest": cfg}, "layers": [{"digest": ld}]}).encode())
            mans.append({"digest": man, "platform": {"os": "linux", "architecture": arch}})
        self.index = blob(self.layout, json.dumps({"schemaVersion": 2, "manifests": mans}).encode())
        self.layout["index.json"] = json.dumps({"schemaVersion": 2, "manifests": [{"digest": self.index}]}).encode()
        self.write_layout()
        (c / "IMAGES").write_text(f"busbar {self.index}\n")
        # The plugin: real unsigned tarballs made by busbar-plugin-pack.
        lib = self.tmp / "libfake.so"
        lib.write_bytes(os.urandom(2048))
        for target, _, _ in pg.PLUGIN_TARGETS:
            sh(PACK, "pack", "--lib", str(lib), "--name", PLUGIN, "--alias", "fake", "--kind", "store", "--version", PVER,
               "--publisher", "busbar", "--allow-unsigned", "--out", str(c / "plugins" / f"{PLUGIN}-{PVER}-{target}.tar.gz"))
        (c / "candidate.json").write_text(json.dumps({
            "version": VERSION, "commit": self.commit, "repo": "GetBusbar/busbar",
            "test_kit": {"tag": f"test-kit-v{VERSION}", "commit": self.kit},
            "plugins": [{"repo": PLUGIN, "version": PVER, "tag": f"v{PVER}", "commit": self.plugin_commit}]}))
        (c / "artifacts" / "plugin-index.json").write_bytes(pg.render_plugin_index(
            self.root, c, json.loads((c / "candidate.json").read_text())["plugins"], FakeNet(self.kit)))
        self.sums()

    @staticmethod
    def _raw_tar(members):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            for name, data in members.items():
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
        return buf.getvalue()

    def write_layout(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            for name, data in self.layout.items():
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
        (self.cand / "oci" / "busbar.oci.tar").write_bytes(buf.getvalue())

    def sums(self):
        files = [f for d in ("artifacts", "sboms") for f in (self.cand / d).iterdir()]
        pg.write_sums(self.cand / "SHA256SUMS", files)

    def inputs(self, net=None):
        self.net = net or FakeNet(self.kit)
        return pg.Inputs(root=self.root, cand=self.cand, trust=self.trust, pack=PACK, net=self.net,
                         require_hardware_k2=False)

    def verify(self, net=None):
        vd, _, _ = pg.verify_all(self.inputs(net))
        return vd.refusals

    def close(self):
        shutil.rmtree(self.tmp)


@unittest.skipUnless(PACK and Path(PACK).is_file() and shutil.which("openssl") and shutil.which("ssh-keygen"),
                     "needs PACK=<busbar-plugin-pack>, openssl and ssh-keygen")
class Gate(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.cwd = os.getcwd()
        os.chdir(self.w.root)

    def tearDown(self):
        os.chdir(self.cwd)
        self.w.close()

    def refused(self, rule, needle=""):
        r = self.w.verify()
        hit = [x for x in r if x.split()[1] == rule and needle in x]
        self.assertTrue(hit, f"expected a {rule} refusal containing {needle!r}; got {r}")

    def test_a_good_release_verifies(self):
        self.assertEqual(self.w.verify(), [])

    def test_g1_clone_not_at_the_release_commit(self):
        sh("git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "x", cwd=self.w.root)
        self.refused("G-1", "clone")

    def test_g1_changelog_behind(self):
        (self.w.root / "CHANGELOG.md").write_text("## [1.5.5]\n")
        self.refused("G-1", "CHANGELOG")

    def test_g2_already_published(self):
        net = FakeNet(self.w.kit)
        net.released.add(("GetBusbar/busbar", f"v{VERSION}"))
        r = self.w.verify(net)
        self.assertTrue(any(x.startswith("REFUSED G-2") for x in r), r)

    def test_g2_registry_tag_holds_another_image(self):
        net = FakeNet(self.w.kit)
        net.registry[f"ghcr.io/getbusbar/busbar:{VERSION}"] = "sha256:" + "0" * 64
        r = self.w.verify(net)
        self.assertTrue(any(x.startswith("REFUSED G-2") for x in r), r)

    def test_g3_missing_target_is_named(self):
        (self.w.cand / "artifacts" / "busbar-x86_64-pc-windows-msvc.zip").unlink()
        self.w.sums()
        self.refused("G-3", "busbar-x86_64-pc-windows-msvc.zip")

    def test_g3_undeclared_file_is_refused(self):
        (self.w.cand / "artifacts" / "extra.bin").write_bytes(b"x")
        self.w.sums()
        self.refused("G-3", "extra.bin")

    def test_g3_plugin_missing_from_candidate(self):
        (self.w.root / "plugins.yaml").write_text(f"plugins:\n  - repo: {PLUGIN}\n  - repo: busbar-auth-other\n")
        self.refused("G-3", "busbar-auth-other")

    def test_g4_bytes_changed_after_the_sums(self):
        (self.w.cand / "artifacts" / f"busbar-openapi-v{VERSION}.json").write_text('{"x":1}\n')
        self.refused("G-4", "busbar-openapi")

    def test_g5_wrong_plugin_version(self):
        cj = json.loads((self.w.cand / "candidate.json").read_text())
        cj["plugins"][0]["version"] = "1.6.1"
        (self.w.cand / "candidate.json").write_text(json.dumps(cj))
        self.refused("G-3")

    def test_g6_binary_without_the_key_list(self):
        (self.w.cand / "artifacts" / "busbar-x86_64-unknown-linux-gnu.tar.gz").write_bytes(tgz({"busbar": b"no key here"}))
        self.w.sums()
        self.refused("G-6", "linux-gnu")

    def test_g8_sbom_for_another_version(self):
        f = self.w.cand / "sboms" / f"busbar-v{VERSION}-x86_64-unknown-linux-gnu.cdx.json"
        f.write_text(json.dumps({"bomFormat": "CycloneDX", "metadata": {"component": {"version": "1.5.5"}}}))
        self.w.sums()
        self.refused("G-8")

    def test_g9_unverified_provenance_is_never_published(self):
        (self.w.cand / "provenance").mkdir()
        self.refused("G-9")

    def test_g10_image_binary_differs(self):
        (self.w.cand / "internal" / "busbar-x86_64-unknown-linux-musl.tar.gz").write_bytes(tgz({"busbar": self.w.binary("other")}))
        self.refused("G-10", "amd64")

    def test_g10_images_file_names_another_digest(self):
        (self.w.cand / "IMAGES").write_text("busbar sha256:" + "1" * 64 + "\n")
        self.refused("G-10", "IMAGES")

    def test_g11_linked_plugin_pin_differs(self):
        lock = self.w.root / "dist" / "default" / "Cargo.lock"
        lock.write_text(lock.read_text().replace(self.w.plugin_commit, "d" * 40))
        sh("git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "x", cwd=self.w.root)
        cj = json.loads((self.w.cand / "candidate.json").read_text())
        cj["commit"] = sh("git", "rev-parse", "HEAD", cwd=self.w.root).decode().strip()
        (self.w.cand / "candidate.json").write_text(json.dumps(cj))
        self.refused("G-11")

    def test_g12_plugin_pinned_to_another_core(self):
        class N(FakeNet):
            def repo_file(self, repo, path, ref):
                return "e" * 40 + "\n"
        r = self.w.verify(N(self.w.kit))
        self.assertTrue(any(x.startswith("REFUSED G-12") for x in r), r)

    def test_g14_key_list_not_in_the_owners_trust_file(self):
        self.w.trust = dict(self.w.trust, k1="busbar-plugins-root:" + "ab" * 32)
        self.refused("G-14", "BUSBAR_RELEASE_PUBKEY")

    def test_g14_k2_line_must_be_limited_to_the_file_namespace(self):
        line = self.w.signer.replace('namespaces="busbar-release" ', "")
        self.w.trust = dict(self.w.trust, k2_allowed_signers=[line])
        (self.w.root / "release" / "allowed_signers").write_text(line + "\n")
        self.refused("G-14", "no namespaces=")
        line2 = self.w.signer.replace('namespaces="busbar-release"', 'namespaces="busbar-release,busbar-release-statement"')
        self.w.trust = dict(self.w.trust, k2_allowed_signers=[line2])
        (self.w.root / "release" / "allowed_signers").write_text(line2 + "\n")
        self.refused("G-14", "busbar-release-statement")

    def test_g3_candidate_plugin_differs_from_the_committed_pins(self):
        cj = json.loads((self.w.cand / "candidate.json").read_text())
        cj["plugins"][0]["commit"] = "d" * 40
        (self.w.cand / "candidate.json").write_text(json.dumps(cj))
        self.refused("G-3", "pinned")

    def test_g14_software_k2_refused_by_the_real_rule(self):
        vd = pg.Verdict()
        inp = self.w.inputs()
        inp.require_hardware_k2 = True
        pg.g14_trust(inp, vd)
        self.assertTrue(any("hardware key type" in x for x in vd.refusals), vd.refusals)

    def test_sign_seals_every_plugin_with_one_signature_and_everything_verifies(self):
        inp = self.w.inputs()
        orig = builtins.input
        builtins.input = lambda *_: self.w.commit[:12]
        try:
            calls = self.w.keys / "calls"
            counting = self.w.keys / "k1-sign-counted"
            counting.write_text(f'#!/bin/sh\necho x >> "{calls}"\nexec "{self.w.keys / "k1-sign"}" "$1" "$2"\n')
            os.chmod(counting, 0o755)
            code = pg.cmd_sign(inp, self.w.out, str(counting), str(self.w.keys / "k2"))
        finally:
            builtins.input = orig
        self.assertEqual(code, pg.EXIT_OK)
        self.assertEqual(calls.read_text().count("x"), 1, "the release signer signs once per release")
        self.assertTrue((self.w.out / "release-manifest.json").is_file())
        for n in ("SHA256SUMS", "SHA256SUMS.plugins", "IMAGES", "release-evidence.json"):
            self.assertTrue((self.w.out / (n + ".sig")).is_file(), n)
        signed = sorted((self.w.out / "signed").iterdir())
        self.assertEqual(len(signed), len(pg.PLUGIN_TARGETS))
        for f in signed:
            target = f.name[len(f"{PLUGIN}-{PVER}-"):-len(".tar.gz")]
            p = subprocess.run([PACK, "verify", str(f), "--keys", self.w.k1_list, "--target", target,
                                "--name", PLUGIN, "--version", PVER],
                               capture_output=True)
            self.assertEqual(p.returncode, 0, p.stdout)
        ev = json.loads((self.w.out / "release-evidence.json").read_text())
        self.assertIs(ev["plugins_signed_by_hardware_key"], True)
        self.assertEqual(ev["slsa_provenance"], "not-run")

    def test_sign_refuses_without_the_typed_commit(self):
        orig = builtins.input
        builtins.input = lambda *_: "nope"
        try:
            code = pg.cmd_sign(self.w.inputs(), self.w.out, str(self.w.keys / "k1-sign"), str(self.w.keys / "k2"))
        finally:
            builtins.input = orig
        self.assertEqual(code, pg.EXIT_REFUSED)
        self.assertFalse((self.w.out / "signed").exists())



GIT = ("git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "tag.gpgSign=false")


class IndexNet(pg.Net):
    """GitHub's answer to `repos/<org>/<name>`: the repository a name redirects to, or None."""

    def __init__(self, redirects=None):
        self.redirects = redirects or {}

    def repo_full_name(self, repo):
        return self.redirects.get(repo)


@unittest.skipUnless(shutil.which("git") and shutil.which("ssh-keygen"), "needs git and ssh-keygen")
class VersionTag(unittest.TestCase):
    """G-15: the version tag is annotated, signed by K2 under the `git` namespace, and names the
    release commit. Needs no busbar-plugin-pack."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="publish-gate-tag-"))
        self.root, self.keys = self.tmp / "repo", self.tmp / "keys"
        self.root.mkdir()
        self.keys.mkdir()
        for k in ("k2", "other"):
            sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", k, "-f", str(self.keys / k))
        pub = (self.keys / "k2.pub").read_text().split()
        self.file_line = f'busbar-release namespaces="busbar-release" {pub[0]} {pub[1]} busbar-release-2026a'
        self.git_line = f'busbar-release namespaces="git" {pub[0]} {pub[1]} busbar-release-2026a'
        self.k1 = "busbar-plugins-root:p256:" + "04" * 65
        (self.root / ".cargo").mkdir()
        (self.root / ".cargo" / "config.toml").write_text(f'[env]\nBUSBAR_RELEASE_PUBKEY = "{self.k1}"\n')
        (self.root / "release").mkdir()
        self.set_signers([self.file_line, self.git_line])
        sh(*GIT, "init", "-q", cwd=self.root)
        sh(*GIT, "add", "-A", cwd=self.root)
        sh(*GIT, "commit", "-q", "-m", "release", cwd=self.root)
        self.commit = sh("git", "rev-parse", "HEAD", cwd=self.root).decode().strip()
        self.cj = {"version": VERSION, "commit": self.commit}

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def set_signers(self, lines):
        self.trust = {"k1": self.k1, "release_signer": "p256:00", "keys_doc": "keys.json", "k2_allowed_signers": lines}
        (self.root / "release" / "allowed_signers").write_text("# K2\n" + "".join(l + "\n" for l in lines))

    def tag(self, key=None, annotated=True, at="HEAD"):
        name = f"v{VERSION}"
        if key:
            sh(*GIT, "-c", "gpg.format=ssh", "-c", f"user.signingkey={self.keys / key}",
               "tag", "-s", name, "-m", f"busbar {VERSION}", at, cwd=self.root)
        elif annotated:
            sh(*GIT, "tag", "-a", name, "-m", f"busbar {VERSION}", at, cwd=self.root)
        else:
            sh(*GIT, "tag", name, at, cwd=self.root)

    def inputs(self):
        return pg.Inputs(root=self.root, cand=self.tmp, trust=self.trust, pack="", net=IndexNet(),
                         require_hardware_k2=False)

    def g15(self):
        vd = pg.Verdict()
        pg.g15_version_tag(self.inputs(), self.cj, vd)
        return vd

    def assert_refused(self, vd, needle=""):
        hit = [x for x in vd.refusals if x.split()[1] == "G-15" and needle in x]
        self.assertTrue(hit, f"expected a G-15 refusal containing {needle!r}; got {vd.refusals}")

    def test_an_unsigned_version_tag_refuses_the_publish(self):
        self.assert_refused(self.g15(), f"v{VERSION}")  # no tag at all
        self.tag(annotated=False)
        self.assert_refused(self.g15(), "annotated")  # a lightweight tag
        sh("git", "tag", "-d", f"v{VERSION}", cwd=self.root)
        self.tag(annotated=True)
        self.assert_refused(self.g15(), "signed")  # annotated, but unsigned

    def test_a_tag_signed_by_a_key_not_in_allowed_signers_refuses(self):
        self.tag(key="other")
        self.assert_refused(self.g15(), "signed")

    def test_a_tag_verified_only_by_a_git_line_for_another_key_refuses(self):
        # A `git` line whose key is not a K2 file-signing key would let any key sign the tag.
        pub = (self.keys / "other.pub").read_text().split()
        self.set_signers([self.file_line, f'busbar-release namespaces="git" {pub[0]} {pub[1]} other'])
        self.tag(key="other")
        self.assert_refused(self.g15(), "release key")

    def test_a_signed_tag_on_another_commit_refuses(self):
        sh(*GIT, "commit", "-q", "--allow-empty", "-m", "later", cwd=self.root)
        self.tag(key="k2")
        self.assert_refused(self.g15(), self.commit)

    def test_a_version_tag_signed_by_k2_verifies(self):
        self.tag(key="k2")
        vd = self.g15()
        self.assertEqual(vd.refusals, [])
        self.assertTrue(vd.checked.get("G-15"))

    def test_g14_allows_a_k2_line_limited_to_the_git_tag_namespace(self):
        vd = pg.Verdict()
        pg.g14_trust(self.inputs(), vd)
        self.assertEqual(vd.refusals, [])
        both = self.file_line.replace('namespaces="busbar-release"', 'namespaces="busbar-release,git"')
        self.set_signers([both])
        vd = pg.Verdict()
        pg.g14_trust(self.inputs(), vd)
        self.assertTrue(any(x.split()[1] == "G-14" for x in vd.refusals), vd.refusals)


INDEX_PLUGIN = "busbar-store-stub"


def parser_keys() -> list:
    """The key lists `Index::parse` (crates/busbar/src/root/config_migrate.rs) accepts, in order:
    the document, a plugin, a release. The binary refuses any other key."""
    import re
    src = (Path(__file__).resolve().parents[2] / "crates/busbar/src/root/config_migrate.rs").read_text()
    body = src[src.index("pub fn parse(bytes: &[u8])"):src.index("fn by_repo(")]
    return [re.findall(r'"([a-z_]+)"', m) for m in re.findall(r"&\[\s*((?:\"[a-z_]+\",?\s*)+)\]", body)]


@unittest.skipUnless(shutil.which("git"), "needs git")
class PluginIndex(unittest.TestCase):
    """plugin-index.json: owed by G-3, listed in SHA256SUMS, rendered from the candidate's plugins in
    the shape `busbar --migrate-config` parses. Needs no busbar-plugin-pack."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="publish-gate-index-"))
        self.root, self.cand = self.tmp / "repo", self.tmp / "cand"
        r, c = self.root, self.cand
        (r / ".github").mkdir(parents=True)
        (r / ".github" / "release-targets.json").write_text(json.dumps({"targets": [
            {"target": "x86_64-unknown-linux-gnu", "kind": "binary", "published": True, "archive": "tar.gz"}]}))
        (r / "plugins.yaml").write_text(
            "plugins:\n"
            f"  - repo: {INDEX_PLUGIN}\n    kind: store\n    alias: stub\n    crate: {INDEX_PLUGIN}-plugin\n"
            f"    former_names: [{INDEX_PLUGIN}-plugin, busbar-stub-db]\n"
            "  - repo: busbar-auth-empty\n    kind: auth\n    alias: empty\n    crate: busbar-auth-empty\n"
            "    pending_crate: true\n")
        (r / "release").mkdir()
        (r / "release" / "plugin-pins.tsv").write_text(f"# pins\n{INDEX_PLUGIN}\tv{PVER}\t{'c' * 40}\n")
        for d in ("artifacts", "sboms", "plugins"):
            (c / d).mkdir(parents=True)
        (c / "artifacts" / "busbar-x86_64-unknown-linux-gnu.tar.gz").write_bytes(tgz({"busbar": b"bin"}))
        (c / "artifacts" / f"busbar-openapi-v{VERSION}.json").write_text("{}\n")
        (c / "sboms" / f"busbar-v{VERSION}-x86_64-unknown-linux-gnu.cdx.json").write_text("{}\n")
        manifest = json.dumps({"name": INDEX_PLUGIN, "alias": "stub", "kind": "store", "version": PVER,
                               "abi_version": 7}).encode()
        for target, _, _ in pg.PLUGIN_TARGETS:
            (c / "plugins" / f"{INDEX_PLUGIN}-{PVER}-{target}.tar.gz").write_bytes(
                tgz({"libstub.so": b"lib", "manifest.json": manifest}))
        self.cj = {"version": VERSION, "commit": "a" * 40, "repo": "GetBusbar/busbar",
                   "test_kit": {"tag": f"test-kit-v{VERSION}", "commit": "b" * 40},
                   "plugins": [{"repo": INDEX_PLUGIN, "version": PVER, "tag": f"v{PVER}", "commit": "c" * 40}]}
        # GitHub still redirects the 1.5.5 repository name to the plugin; the other candidates are not repos.
        self.net = IndexNet({"GetBusbar/store-stub": f"GetBusbar/{INDEX_PLUGIN}"})
        self.sums()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def sums(self):
        pg.write_sums(self.cand / "SHA256SUMS", [f for d in ("artifacts", "sboms") for f in (self.cand / d).iterdir()])

    def inputs(self):
        return pg.Inputs(root=self.root, cand=self.cand, trust={}, pack="", net=self.net, require_hardware_k2=False)

    def g3(self):
        vd = pg.Verdict()
        pg.g3_g4_sets_and_sums(self.inputs(), self.cj, vd)
        return vd.refusals

    def render(self):
        (self.cand / "artifacts" / "plugin-index.json").write_bytes(
            pg.render_plugin_index(self.root, self.cand, self.cj["plugins"], self.net))
        self.sums()

    def test_a_candidate_without_plugin_index_json_refuses(self):
        r = self.g3()
        self.assertTrue(any(x.startswith("REFUSED G-3 artifacts/plugin-index.json") for x in r), r)

    def test_a_candidate_with_the_rendered_index_passes_and_sums_list_it(self):
        self.render()
        self.assertEqual(self.g3(), [])
        self.assertIn("plugin-index.json", pg.read_sums(self.cand / "SHA256SUMS"))

    def test_an_index_that_is_not_the_render_of_the_candidate_refuses(self):
        self.render()
        f = self.cand / "artifacts" / "plugin-index.json"
        doc = json.loads(f.read_text())
        doc["plugins"][0]["releases"][0]["tag"] = "v9.9.9"
        f.write_text(json.dumps(doc, indent=2) + "\n")
        self.sums()
        r = self.g3()
        self.assertTrue(any(x.startswith("REFUSED G-3 artifacts/plugin-index.json") for x in r), r)

    def test_the_rendered_index_is_the_document_the_binary_parses(self):
        top, plugin, release = parser_keys()
        self.assertEqual(top, ["plugins"])
        doc = json.loads(pg.render_plugin_index(self.root, self.cand, self.cj["plugins"], self.net))
        self.assertEqual(sorted(doc), sorted(top))
        self.assertEqual(len(doc["plugins"]), 1)
        p = doc["plugins"][0]
        self.assertEqual(sorted(p), sorted(plugin))
        for r in p["releases"]:
            self.assertEqual(sorted(r), sorted(release))
        self.assertEqual(p["repo"], f"GetBusbar/{INDEX_PLUGIN}")
        self.assertEqual(p["former_repos"], ["GetBusbar/store-stub"])
        self.assertEqual(p["kind"], "store")
        self.assertEqual(p["answers_to"], [INDEX_PLUGIN, "stub", f"{INDEX_PLUGIN}-plugin", "busbar-stub-db"])
        # The ABI version is read off the built tarball's manifest, never assumed.
        self.assertEqual(p["releases"], [{"tag": f"v{PVER}", "abi_version": 7}])

if __name__ == "__main__":
    unittest.main(verbosity=2)
