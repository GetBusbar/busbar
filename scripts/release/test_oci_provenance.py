"""OCI closure/policy fixtures; registry crypto remains delegated to pinned Cosign."""

import base64
import copy
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import native_provenance as p
import oci_provenance as oci
import release_verifier as v
import test_release_verifier as fixtures


def oci_fixture(
    path, extra=None, corrupt=False, foreign=False, binary=None, overlays=()
):
    blobs = {}

    def blob(value, media_type):
        raw = value if isinstance(value, bytes) else p.canonical(value)
        digest = hashlib.sha256(raw).hexdigest()
        blobs["blobs/sha256/" + digest] = raw
        return {"mediaType": media_type, "digest": "sha256:" + digest, "size": len(raw)}

    if binary is not None:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as layer:
            entry = tarfile.TarInfo("busbar")
            entry.mode, entry.size = 0o755, len(binary)
            layer.addfile(entry, io.BytesIO(binary))
        layer_bytes = [stream.getvalue(), *overlays]
    else:
        layer_bytes = [b"fixture-layer"]
    config_data = {"os": "linux", "architecture": "amd64"}
    if binary is not None:
        config_data["config"] = {"Entrypoint": ["/busbar"]}
        config_data["rootfs"] = {
            "type": "layers",
            "diff_ids": [
                "sha256:" + hashlib.sha256(raw).hexdigest() for raw in layer_bytes
            ],
        }
    config = blob(config_data, "application/vnd.oci.image.config.v1+json")
    layers = [
        blob(raw, "application/vnd.oci.image.layer.v1.tar") for raw in layer_bytes
    ]
    layer = layers[0]
    if foreign:
        layer["urls"] = ["https://untrusted.invalid/layer"]
    manifest = blob(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": config,
            "layers": layers,
        },
        "application/vnd.oci.image.manifest.v1+json",
    )
    manifest["platform"] = {"os": "linux", "architecture": "amd64"}
    index = p.canonical(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [manifest],
        }
    )
    files = {
        "index.json": index,
        "oci-layout": p.canonical({"imageLayoutVersion": "1.0.0"}),
        **blobs,
    }
    if extra:
        files.update(extra)
    if corrupt:
        files["blobs/sha256/" + layer["digest"][7:]] = b"corrupt"
    with tarfile.open(path, "w") as tar:
        for name, raw in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))
    return "registry.example/busbar@sha256:" + hashlib.sha256(index).hexdigest()


class OciTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "image.tar"
        self.ref = oci_fixture(self.archive)
        self.plan = {
            "artifact_sha256": "a" * 64,
            "target": "x86_64-unknown-linux-gnu",
            "source_commit": "b" * 40,
        }
        self.platforms = {"linux/amd64": "busbar.tar.gz"}

    def inspect(self):
        return oci.inspect_archive(
            self.archive, self.ref, self.platforms, {"busbar.tar.gz": self.plan}
        )

    def test_complete_export_binds_every_platform_and_native_subject(self):
        closure, raw = self.inspect()
        self.assertEqual(closure["platforms"][0]["artifact_sha256"], "a" * 64)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), self.ref.rsplit(":", 1)[1])

    def test_extra_corrupt_foreign_and_traversal_members_refuse(self):
        for kwargs in (
            {"extra": {"unexpected": b"extra"}},
            {"corrupt": True},
            {"foreign": True},
            {"extra": {"../escape": b"extra"}},
            {
                "extra": {
                    "blobs/sha256/" + hashlib.sha256(b"extra").hexdigest(): b"extra"
                }
            },
        ):
            with self.subTest(kwargs=kwargs):
                self.ref = oci_fixture(self.archive, **kwargs)
                with self.assertRaises(ValueError):
                    self.inspect()

    def test_missing_platform_wrong_target_and_mutable_reference_refuse(self):
        for platforms, plan, ref in (
            ({"linux/arm64": "busbar.tar.gz"}, self.plan, self.ref),
            (
                self.platforms,
                {**self.plan, "target": "aarch64-unknown-linux-gnu"},
                self.ref,
            ),
            (self.platforms, self.plan, "registry.example/busbar:latest"),
        ):
            with self.assertRaises(ValueError):
                oci.inspect_archive(
                    self.archive, ref, platforms, {"busbar.tar.gz": plan}
                )

    def test_final_binary_equivalence_honors_whiteouts_overlays_and_links(self):
        from test_build_closure import closure_fixture

        native = self.root / "native.tar.gz"
        closure = closure_fixture(self.root, native)
        plan = {**self.plan, "artifact_sha256": p.digest(native)}
        platforms = {
            "linux/amd64": {
                "artifact": "busbar.tar.gz",
                "member": "busbar",
                "path": "/busbar",
            }
        }

        def inspect(overlays=()):
            ref = oci_fixture(
                self.archive, binary=b"native executable", overlays=overlays
            )
            return oci.inspect_archive(
                self.archive,
                ref,
                platforms,
                {"busbar.tar.gz": plan},
                closures={"busbar.tar.gz": closure},
            )

        result, _ = inspect()
        self.assertEqual(
            result["platforms"][0]["binary"]["sha256"],
            closure["members"]["busbar"]["sha256"],
        )
        for name, kind, data in (
            (".wh.busbar", tarfile.REGTYPE, b""),
            (".wh..wh..opq", tarfile.REGTYPE, b""),
            ("busbar", tarfile.REGTYPE, b"substituted"),
            ("busbar", tarfile.SYMTYPE, b""),
            ("busbar", tarfile.LNKTYPE, b""),
            ("busbar", tarfile.DIRTYPE, b""),
            ("../busbar", tarfile.REGTYPE, b""),
        ):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w") as layer:
                entry = tarfile.TarInfo(name)
                entry.type, entry.size, entry.mode = kind, len(data), 0o755
                entry.linkname = "elsewhere"
                layer.addfile(entry, io.BytesIO(data))
            with self.subTest(name=name, kind=kind), self.assertRaises(ValueError):
                inspect([stream.getvalue()])

    def test_registry_result_must_be_exact_approved_statement(self):
        closure, _ = self.inspect()
        expected = oci.statement(
            self.ref, closure, "1.6.0", "urn:busbar:builder:fixture:v1"
        )
        envelope = {
            "payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(p.canonical(expected)).decode(),
        }
        config = {"cosign": "/trusted/cosign", "trusted_root": "/trusted/root"}
        with mock.patch.object(
            p, "cosign_trust", return_value=["--key", "/trusted/key"]
        ):
            with mock.patch.object(
                p, "command", return_value=p.canonical(envelope)
            ) as command:
                oci.verify_registry(self.ref, expected, config)
                self.assertEqual(command.call_args.args[0][-1], self.ref)
                self.assertNotIn("--insecure-ignore-tlog", command.call_args.args[0])
            with mock.patch.object(p, "command", return_value=b"[]"), self.assertRaises(
                ValueError
            ):
                oci.verify_registry(self.ref, expected, config)
            other = copy.deepcopy(expected)
            other["predicate"]["release"] = "1.5.5"
            with mock.patch.object(
                p, "command", return_value=p.canonical(envelope)
            ), self.assertRaises(ValueError):
                oci.verify_registry(self.ref, other, config)

    def test_v2_consumer_requires_sbom_and_oci_bundles_and_registry_match(self):
        f = fixtures.ReleaseVerifierTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        inventory = f.inventory
        inventory["schema"] = v.SCHEMA_V2
        row = inventory["artifacts"][0]

        def binding(path):
            return {"name": path.name, "sha256": p.digest(path)}

        sbom_statement = f.release / "sbom.intoto.json"
        sbom_statement.write_bytes(
            p.canonical(
                v.sbom_statement(f.plan, p.load(f.release / row["sbom"]["name"]))
            )
        )
        sbom_bundle = f.release / "sbom.sigstore.json"
        sbom_bundle.write_bytes(p.canonical(f.bundle(sbom_statement)))
        row.update(
            sbom_statement=binding(sbom_statement), sbom_bundle=binding(sbom_bundle)
        )
        archive = f.release / "image.tar"
        ref = oci_fixture(archive)
        platforms = {"linux/amd64": f.plan["artifact_name"]}
        closure, index_bytes = oci.inspect_archive(
            archive, ref, platforms, {f.plan["artifact_name"]: f.plan}
        )
        index = f.release / "image.index.json"
        index.write_bytes(index_bytes)
        statement = f.release / "image.intoto.json"
        expected = oci.statement(ref, closure, "1.6.0", f.plan["builder_id"])
        statement.write_bytes(p.canonical(expected))
        bundle = f.release / "image.sigstore.json"
        bundle.write_bytes(p.canonical(f.bundle(statement)))
        inventory["oci"] = [
            {
                "reference": ref,
                "platforms": platforms,
                "archive": binding(archive),
                "index": binding(index),
                "statement": binding(statement),
                "bundle": binding(bundle),
            }
        ]
        f.write_inventory()
        envelope = {
            "payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(p.canonical(expected)).decode(),
        }
        with mock.patch.object(
            p, "command", return_value=p.canonical(envelope)
        ) as command:
            result = f.verify()
            self.assertEqual(result["oci_indexes"], 1)
            self.assertTrue(result["registry_verified"])
            self.assertEqual(command.call_count, 5)
        with mock.patch.object(p, "command", return_value=b"[]"), self.assertRaises(
            ValueError
        ):
            f.verify()


if __name__ == "__main__":
    unittest.main()
