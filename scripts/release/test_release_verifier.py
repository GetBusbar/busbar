#!/usr/bin/env python3
"""Public policy fixtures; no production keys, log writes, or activation."""

import base64
import copy
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import native_provenance as p
import release_verifier as v


class ReleaseVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.release = self.root / "download"
        self.release.mkdir()
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        public = self.key.public_key()
        key_path = self.root / "public.pem"
        key_path.write_bytes(
            public.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        key_hash = hashlib.sha256(
            public.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()
        tool = self.root / "cosign"
        tool.write_bytes(b"fixture tool")
        roots = self.root / "roots.json"
        roots.write_bytes(b"fixture roots")
        builder = "urn:busbar:builder:native-controller:v1"
        self.trust = self.root / "trust.json"
        self.trust.write_bytes(
            p.canonical(
                {
                    "version": 2,
                    "purpose": "release-attestation",
                    "mode": "key",
                    "builder_id": builder,
                    "key_algorithm": "ed25519",
                    "public_key": str(key_path),
                    "public_key_sha256": key_hash,
                    "cosign": str(tool),
                    "cosign_sha256": p.digest(tool),
                    "trusted_root": str(roots),
                    "trusted_root_sha256": p.digest(roots),
                }
            )
        )
        artifact = self.release / "busbar-linux.tar.gz"
        artifact.write_bytes(b"fixture artifact")
        self.plan = {
            "stage": "qa",
            "source_commit": "a" * 40,
            "target": "x86_64-unknown-linux-gnu",
            "builder_id": builder,
            "invocation_id": "job-1",
            "artifact_name": artifact.name,
            "artifact_sha256": p.digest(artifact),
            "inputs": {name: "b" * 64 for name in p.INPUTS},
            "started_on": "2026-11-10T00:00:00Z",
            "finished_on": "2026-11-10T00:01:00Z",
        }
        receipt = {
            **self.plan,
            "exit_code": 0,
            "native": True,
            "host_target": self.plan["target"],
        }
        statement = self.release / "busbar-linux.intoto.json"
        statement.write_bytes(p.canonical(p.statement(self.plan, receipt, artifact)))
        sbom = self.release / "busbar-linux.cdx.json"
        sbom.write_bytes(
            p.canonical(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "metadata": {"component": {"name": "busbar", "version": "1.6.0"}},
                    "components": [{"name": "fixture", "version": "1.0"}],
                }
            )
        )
        bundle = self.release / "busbar-linux.sigstore.json"
        bundle.write_bytes(p.canonical(self.bundle(statement)))

        def binding(path):
            return {"name": path.name, "sha256": p.digest(path)}

        self.inventory = {
            "schema": v.SCHEMA,
            "release": "1.6.0",
            "artifacts": [
                {
                    "plan": self.plan,
                    "statement": binding(statement),
                    "bundle": binding(bundle),
                    "sbom": binding(sbom),
                    "component_name": "busbar",
                }
            ],
        }
        self.write_inventory()

    def bundle(self, statement, logged=True):
        payload = statement.read_bytes()
        kind = b"application/vnd.in-toto+json"
        pae = (
            b"DSSEv1 "
            + str(len(kind)).encode()
            + b" "
            + kind
            + b" "
            + str(len(payload)).encode()
            + b" "
            + payload
        )
        material = {"publicKey": {"hint": "fixture"}}
        if logged:
            # Only control-flow fixtures mock cosign: this is never a valid log proof.
            material["tlogEntries"] = [
                {"inclusionProof": {"checkpoint": {"envelope": "fixture"}}}
            ]
        return {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": material,
            "dsseEnvelope": {
                "payloadType": kind.decode(),
                "payload": base64.b64encode(payload).decode(),
                "signatures": [{"sig": base64.b64encode(self.key.sign(pae)).decode()}],
            },
        }

    def write_inventory(self):
        path = self.release / v.INVENTORY
        path.write_bytes(p.canonical(self.inventory))
        self.inventory_hash = p.digest(path)
        statement = self.release / v.STATEMENT
        statement.write_bytes(
            p.canonical(
                v.inventory_statement(
                    self.inventory, self.inventory_hash, self.plan["builder_id"]
                )
            )
        )
        (self.release / v.BUNDLE).write_bytes(p.canonical(self.bundle(statement)))

    def verify(self):
        return v.verify(
            self.release, self.inventory_hash, self.trust, p.digest(self.trust)
        )

    def test_complete_policy_calls_crypto_for_inventory_and_each_subject(self):
        with mock.patch.object(p, "command") as command:
            result = self.verify()
            self.assertEqual(result["artifacts"], 1)
            self.assertEqual(result["slsa_build_level"], "not-assessed")
            self.assertEqual(command.call_count, 2)
            predicates = [
                call.args[0][call.args[0].index("--type") + 1]
                for call in command.call_args_list
            ]
            self.assertEqual(predicates, [v.PREDICATE, p.PREDICATE])
            self.assertTrue(
                all(
                    "--insecure-ignore-tlog" not in call.args[0]
                    for call in command.call_args_list
                )
            )

    def test_each_file_tamper_refuses(self):
        for path in self.release.iterdir():
            original = path.read_bytes()
            with self.subTest(path=path.name):
                path.write_bytes(original + b"changed")
                with mock.patch.object(p, "command"), self.assertRaises(
                    (ValueError, KeyError)
                ):
                    self.verify()
                path.write_bytes(original)

    def test_extra_missing_symlink_and_reused_files_refuse(self):
        extra = self.release / "extra"
        extra.write_text("extra")
        with self.assertRaises(ValueError):
            self.verify()
        extra.unlink()
        artifact = self.release / self.plan["artifact_name"]
        data = artifact.read_bytes()
        artifact.unlink()
        with self.assertRaises(ValueError):
            self.verify()
        outside = self.root / "outside"
        outside.write_bytes(data)
        artifact.symlink_to(outside)
        with self.assertRaises(ValueError):
            self.verify()
        artifact.unlink()
        artifact.write_bytes(data)
        self.inventory["artifacts"].append(
            copy.deepcopy(self.inventory["artifacts"][0])
        )
        self.write_inventory()
        with self.assertRaises(ValueError):
            self.verify()

    def test_wrong_trust_pin_and_wrong_inventory_pin_refuse_before_crypto(self):
        with mock.patch.object(p, "command") as command:
            for inventory_hash, trust_hash in (
                ("0" * 64, p.digest(self.trust)),
                (self.inventory_hash, "0" * 64),
            ):
                with self.assertRaises(ValueError):
                    v.verify(self.release, inventory_hash, self.trust, trust_hash)
            command.assert_not_called()

    def test_substituted_plan_builder_source_target_or_private_field_refuses(self):
        original = copy.deepcopy(self.inventory)
        for key, value in (
            ("source_commit", "c" * 40),
            ("target", "wrong-target"),
            ("builder_id", "urn:busbar:builder:other:v1"),
            ("private_url", "private"),
        ):
            self.inventory = copy.deepcopy(original)
            self.inventory["artifacts"][0]["plan"][key] = value
            self.write_inventory()
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify()

    def test_validly_bound_wrong_sbom_release_refuses(self):
        sbom = self.release / self.inventory["artifacts"][0]["sbom"]["name"]
        data = p.load(sbom)
        data["metadata"]["component"]["version"] = "1.5.5"
        sbom.write_bytes(p.canonical(data))
        self.inventory["artifacts"][0]["sbom"]["sha256"] = p.digest(sbom)
        self.write_inventory()
        with self.assertRaises(ValueError):
            self.verify()

    def test_crypto_failure_and_unlogged_inventory_refuse(self):
        with mock.patch.object(
            p, "command", side_effect=ValueError("invalid signature")
        ):
            with self.assertRaises(ValueError):
                self.verify()
        (self.release / v.BUNDLE).write_bytes(
            p.canonical(self.bundle(self.release / v.STATEMENT, logged=False))
        )
        with mock.patch.object(p, "command") as command, self.assertRaises(ValueError):
            self.verify()
        command.assert_not_called()

    def test_artifact_mutation_during_external_verification_refuses(self):
        def tamper(_):
            (self.release / self.plan["artifact_name"]).write_bytes(b"tampered")

        with mock.patch.object(p, "command", side_effect=tamper), self.assertRaises(
            ValueError
        ):
            self.verify()

    def test_inventory_bundle_mutation_during_external_verification_refuses(self):
        def tamper(_):
            (self.release / v.BUNDLE).write_bytes(b"tampered")

        with mock.patch.object(p, "command", side_effect=tamper), self.assertRaises(
            ValueError
        ):
            self.verify()

    def test_real_cosign_inventory_dsse_offline_fixture(self):
        cosign = shutil.which("cosign")
        self.assertIsNotNone(cosign)
        bundle = self.root / "offline.bundle.json"
        bundle.write_bytes(
            p.canonical(self.bundle(self.release / v.STATEMENT, logged=False))
        )
        argv = [
            cosign,
            "verify-blob-attestation",
            "--bundle",
            str(bundle),
            "--key",
            str(self.root / "public.pem"),
            "--type",
            v.PREDICATE,
            "--insecure-ignore-tlog",
            str(self.release / v.INVENTORY),
        ]
        # Offline fixture only. Production always requires a verified checkpoint.
        result = subprocess.run(argv, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        (self.release / v.INVENTORY).write_bytes(b"tampered")
        self.assertNotEqual(
            subprocess.run(argv, capture_output=True, timeout=30).returncode, 0
        )


if __name__ == "__main__":
    unittest.main()
