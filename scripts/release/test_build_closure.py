"""Targeted build inventory and archive custody regression tests."""

import io
from pathlib import Path
import tarfile
import tempfile
import unittest

import build_closure as b
import native_provenance as p


def closure_fixture(
    root,
    artifact,
    target="x86_64-unknown-linux-gnu",
    source="a" * 40,
    binary_bytes=b"native executable",
):
    binary = root / "busbar"
    binary.write_bytes(binary_bytes)
    with tarfile.open(artifact, "w:gz") as archive:
        member = tarfile.TarInfo("busbar")
        member.mode, member.size = 0o755, len(binary_bytes)
        archive.addfile(member, io.BytesIO(binary_bytes))
    metadata = root / "cargo-metadata.json"
    metadata.write_bytes(
        p.canonical(
            {
                "packages": [
                    {
                        "id": "root",
                        "name": "busbar",
                        "version": "1.6.0",
                        "source": None,
                    },
                    {
                        "id": "dep",
                        "name": "dep",
                        "version": "1.0.0",
                        "source": "registry+https://github.com/rust-lang/crates.io-index",
                    },
                ],
                "resolve": {
                    "nodes": [
                        {
                            "id": "root",
                            "features": [],
                            "deps": [{"pkg": "dep", "dep_kinds": [{"kind": None}]}],
                        },
                        {"id": "dep", "features": [], "deps": []},
                    ]
                },
            }
        )
    )
    lock = root / "Cargo.lock"
    lock.write_text(
        '[[package]]\nname="busbar"\nversion="1.6.0"\n[[package]]\nname="dep"\nversion="1.0.0"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="'
        + "a" * 64
        + '"\n'
    )
    messages = root / "cargo-messages.jsonl"
    messages.write_bytes(
        b"".join(
            p.canonical(row)
            for row in [
                {
                    "reason": "compiler-artifact",
                    "package_id": "dep",
                    "filenames": [],
                    "features": ["actual-feature"],
                },
                {
                    "reason": "compiler-artifact",
                    "package_id": "root",
                    "filenames": [str(binary)],
                    "features": [],
                },
                {"reason": "build-finished", "success": True},
            ]
        )
    )
    return b.collect(
        artifact,
        metadata,
        lock,
        messages,
        binary,
        "busbar",
        "busbar",
        source,
        target,
        "busbar",
        "1.6.0",
    )


class BuildClosureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.artifact = self.root / "busbar.tar.gz"
        self.closure = closure_fixture(self.root, self.artifact)
        self.plan = {
            "source_commit": "a" * 40,
            "target": self.closure["target"],
            "artifact_name": self.artifact.name,
            "artifact_sha256": p.digest(self.artifact),
        }

    def collect(self):
        return b.collect(
            self.artifact,
            self.root / "cargo-metadata.json",
            self.root / "Cargo.lock",
            self.root / "cargo-messages.jsonl",
            self.root / "busbar",
            "busbar",
            "busbar",
            "a" * 40,
            self.plan["target"],
            "busbar",
            "1.6.0",
        )

    def test_actual_messages_locked_graph_and_packaged_bytes_bind_sbom(self):
        b.validate(self.closure, self.plan, self.artifact, "busbar", "1.6.0")
        bom = b.sbom(self.closure)
        self.assertEqual(len(bom["components"]), 2)
        dep = next(row for row in bom["components"] if row["name"] == "dep")
        self.assertEqual(dep["properties"][0]["value"], "actual-feature")
        self.assertEqual(
            bom["metadata"]["component"]["hashes"][0]["content"],
            p.digest(self.artifact),
        )
        self.assertNotIn(str(self.root), p.canonical(self.closure).decode())

    def test_truncated_failed_stream_missing_lock_and_wrong_compiler_output_refuse(
        self,
    ):
        messages = self.root / "cargo-messages.jsonl"
        original = messages.read_bytes()
        for changed in (
            original.rsplit(b"\n", 2)[0] + b"\n",
            original.replace(b'"success":true', b'"success":false'),
            original.replace(str(self.root / "busbar").encode(), b"/different/output"),
        ):
            messages.write_bytes(changed)
            with self.assertRaises(ValueError):
                self.collect()
        messages.write_bytes(original)
        (self.root / "Cargo.lock").write_text(
            '[[package]]\nname="busbar"\nversion="1.6.0"\n'
        )
        with self.assertRaises(ValueError):
            self.collect()

    def test_archive_and_build_substitution_refuse(self):
        (self.root / "busbar").write_bytes(b"different")
        with self.assertRaises(ValueError):
            self.collect()
        for change in (
            {"source_commit": "b" * 40},
            {"target": "aarch64-unknown-linux-gnu"},
            {"members": {}},
            {"binaries": {"not-present": "root"}},
        ):
            with self.assertRaises(ValueError):
                b.validate(
                    {**self.closure, **change},
                    self.plan,
                    self.artifact,
                    "busbar",
                    "1.6.0",
                )

    def test_duplicate_link_and_traversal_members_refuse(self):
        for names, kind in (
            (["busbar", "./busbar"], tarfile.REGTYPE),
            (["../busbar"], tarfile.REGTYPE),
            (["busbar"], tarfile.SYMTYPE),
            (["busbar"], tarfile.LNKTYPE),
        ):
            with tarfile.open(self.artifact, "w") as archive:
                for name in names:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.linkname = "/outside"
                    archive.addfile(member, io.BytesIO(b""))
            with self.assertRaises(ValueError):
                b.archive_members(self.artifact)


if __name__ == "__main__":
    unittest.main()
