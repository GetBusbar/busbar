#!/usr/bin/env python3
"""Targeted offline controls. Fixture keys never become production trust."""

import base64
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec

import native_provenance as p
import provenance_stage as stages


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.artifact = self.root / "busbar-native-fixture"
        self.artifact.write_bytes(b"offline artifact fixture\n")
        self.inputs = {}
        for name in p.INPUTS:
            path = self.root / name
            path.write_text(name)
            self.inputs[name] = str(path)
        self.plan = {
            "stage": "qa",
            "source_commit": "a" * 40,
            "target": "aarch64-unknown-linux-gnu",
            "builder_id": "urn:busbar:builder:native-controller:v1",
            "invocation_id": "fixture-1",
            "artifact_name": self.artifact.name,
            "artifact_sha256": p.digest(self.artifact),
            "started_on": "2026-11-05T00:00:00Z",
            "finished_on": "2026-11-05T00:01:00Z",
            "inputs": {name: p.digest(path) for name, path in self.inputs.items()},
        }
        self.receipt = {
            **copy.deepcopy(self.plan),
            "exit_code": 0,
            "native": True,
            "host_target": self.plan["target"],
            "started_on": "2026-11-05T00:00:00Z",
            "finished_on": "2026-11-05T00:01:00Z",
            "private_url": "https://forgejo.private.invalid/private",
            "private_runner": "/home/runner/private/work",
        }
        self.statement = self.root / "provenance.intoto.json"
        self.statement.write_bytes(
            p.canonical(p.statement(self.plan, self.receipt, self.artifact))
        )
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.public = self.root / "fixture.pub"
        self.public.write_bytes(
            self.key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        self.key_digest = hashlib.sha256(
            self.key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest()

    def test_generation_and_exact_input_bytes(self):
        p.check_inputs(self.plan, self.inputs)
        p.check_statement(self.statement, self.plan, self.receipt, self.artifact)
        self.assertNotIn(b"private", self.statement.read_bytes())
        self.assertEqual(
            json.loads(self.statement.read_bytes())["predicateType"], p.PREDICATE
        )
        Path(self.inputs["lockgraph"]).write_text("changed")
        with self.assertRaises(ValueError):
            p.check_inputs(self.plan, self.inputs)

    def trust(self):
        tool = self.root / "cosign"
        tool.write_bytes(b"pinned fixture tool")
        root = self.root / "trusted-root.json"
        root.write_bytes(b"pinned fixture root")
        return {
            "version": 2,
            "purpose": "release-attestation",
            "mode": "key",
            "cosign": str(tool),
            "cosign_sha256": p.digest(tool),
            "trusted_root": str(root),
            "trusted_root_sha256": p.digest(root),
            "public_key": str(self.public),
            "public_key_sha256": self.key_digest,
            "key_algorithm": "ed25519",
        }

    def test_release_key_does_not_broaden_tooling_trust(self):
        config = self.trust()
        self.assertEqual(p.cosign_trust(config), ["--key", str(self.public)])
        for update in (
            {"version": 1},
            {"version": True},
            {"purpose": "plugin-signing"},
            {"public_key_sha256": "0" * 64},
            {"key_algorithm": "rsa"},
        ):
            with self.subTest(update=update), self.assertRaises(ValueError):
                p.cosign_trust({**config, **update})

    def test_trust_paths_cannot_verify_one_file_then_execute_from_path(self):
        config = self.trust()
        for field in ("cosign", "trusted_root", "public_key"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                p.cosign_trust({**config, field: "relative-fixture"})

    def test_release_p256_key_and_curve_are_pinned(self):
        config = self.trust()
        for curve, allowed in ((ec.SECP256R1(), True), (ec.SECP384R1(), False)):
            key = ec.generate_private_key(curve).public_key()
            self.public.write_bytes(
                key.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            config["public_key_sha256"] = hashlib.sha256(
                key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ).hexdigest()
            config["key_algorithm"] = "ecdsa-p256-sha256"
            if allowed:
                self.assertEqual(p.cosign_trust(config), ["--key", str(self.public)])
            else:
                with self.assertRaises(ValueError):
                    p.cosign_trust(config)

    def test_identity_requires_exact_local_gitlab_issuer_and_config(self):
        config = {
            **self.trust(),
            "mode": "identity",
            "issuer": "https://github.com",
            "identity": "https://github.com/GetBusbar/release-signing//.gitlab-ci.yml@refs/heads/main",
        }
        self.assertIn("--certificate-identity", p.cosign_trust(config))
        for update in (
            {"issuer": "https://token.actions.githubusercontent.com"},
            {"issuer": "https://gitlab.com"},
            {"issuer": "https://github.com/"},
            {"identity": config["identity"].replace("/main", "/dev")},
            {"identity": "https://github.com/.*"},
        ):
            with self.subTest(update=update), self.assertRaises(ValueError):
                p.cosign_trust({**config, **update})

    def test_each_binding_and_native_failure_is_refused(self):
        for key in (
            "stage",
            "source_commit",
            "target",
            "builder_id",
            "invocation_id",
            "artifact_name",
            "artifact_sha256",
            "inputs",
            "host_target",
            "native",
            "exit_code",
            "started_on",
            "finished_on",
        ):
            with self.subTest(key=key):
                receipt = copy.deepcopy(self.receipt)
                receipt[key] = "changed"
                with self.assertRaises(ValueError):
                    p.statement(self.plan, receipt, self.artifact)

    def test_artifact_tamper_and_extra_statement_fields_refused(self):
        data = p.load(self.statement)
        data["predicate"]["private_path"] = "/home/runner"
        self.statement.write_bytes(p.canonical(data))
        with self.assertRaises(ValueError):
            p.check_statement(self.statement, self.plan, self.receipt, self.artifact)
        self.artifact.write_text("changed")
        with self.assertRaises(ValueError):
            p.statement(self.plan, self.receipt, self.artifact)

    def test_unknown_input_stage_and_private_labels_refused(self):
        for key, value in (
            ("stage", "dev"),
            ("invocation_id", "/home/runner"),
            ("builder_id", "https://private.internal"),
            ("artifact_name", "bad\nname"),
        ):
            with self.subTest(key=key):
                plan = {**self.plan, key: value}
                receipt = {**self.receipt, key: value}
                with self.assertRaises(ValueError):
                    p.statement(plan, receipt, self.artifact)

    def test_existing_detached_contract_crypto_and_wrong_name(self):
        signature = self.root / "provenance.sig"
        signature.write_bytes(
            base64.b64encode(self.key.sign(p.detached_message(self.statement)))
        )
        with mock.patch.object(p, "TOOLING_KEY", self.key_digest):
            p.verify_detached(self.statement, signature, self.public)
            renamed = self.root / "changed.intoto.json"
            renamed.write_bytes(self.statement.read_bytes())
            with self.assertRaises(Exception):
                p.verify_detached(renamed, signature, self.public)
        with self.assertRaises(ValueError):
            p.verify_detached(self.statement, signature, self.public)

    def test_signer_digest_checked_before_execution(self):
        signer = self.root / "signer"
        signer.write_text("fixture executable")
        with (
            mock.patch.object(p, "TOOLING_KEY", self.key_digest),
            mock.patch.object(p, "command") as run,
        ):
            with self.assertRaises(ValueError):
                p.sign_detached(
                    self.statement, self.root / "sig", self.public, signer, "0" * 64
                )
            run.assert_not_called()

    def bundle(self):
        payload = self.statement.read_bytes()
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
        return {
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {"publicKey": {"hint": self.key_digest}},
            "dsseEnvelope": {
                "payloadType": kind.decode(),
                "payload": base64.b64encode(payload).decode(),
                "signatures": [{"sig": base64.b64encode(self.key.sign(pae)).decode()}],
            },
        }

    def test_real_cosign_offline_dsse_fixture(self):
        cosign = shutil.which("cosign")
        self.assertIsNotNone(
            cosign, "cosign is required for the targeted integration test"
        )
        bundle = self.root / "fixture.bundle.json"
        bundle.write_bytes(p.canonical(self.bundle()))
        # Only this isolated fixture test disables tlog. Production cannot opt out.
        argv = [
            cosign,
            "verify-blob-attestation",
            "--bundle",
            str(bundle),
            "--key",
            str(self.public),
            "--type",
            p.PREDICATE,
            "--insecure-ignore-tlog",
            str(self.artifact),
        ]
        result = subprocess.run(argv, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.artifact.write_text("tampered")
        self.assertNotEqual(
            subprocess.run(argv, capture_output=True, timeout=30).returncode, 0
        )

    def test_production_rejects_unlogged_bundle(self):
        bundle = self.root / "fixture.bundle.json"
        bundle.write_bytes(p.canonical(self.bundle()))
        with (
            mock.patch.object(
                p, "cosign_trust", return_value=["--key", str(self.public)]
            ),
            mock.patch.object(p, "command") as run,
        ):
            with self.assertRaises(ValueError):
                p.verify_bundle(
                    self.statement,
                    bundle,
                    self.artifact,
                    {"builder_id": self.plan["builder_id"]},
                )
            run.assert_not_called()

    def test_log_presence_still_requires_crypto_verification(self):
        data = self.bundle()
        data["verificationMaterial"]["tlogEntries"] = [
            {"inclusionProof": {"checkpoint": {"envelope": "invalid fixture"}}}
        ]
        bundle = self.root / "fixture.bundle.json"
        bundle.write_bytes(p.canonical(data))
        config = {
            "cosign": "cosign",
            "trusted_root": "root.json",
            "builder_id": self.plan["builder_id"],
        }
        with (
            mock.patch.object(
                p, "cosign_trust", return_value=["--key", str(self.public)]
            ),
            mock.patch.object(
                p, "command", side_effect=ValueError("bad log proof")
            ) as run,
        ):
            with self.assertRaises(ValueError):
                p.verify_bundle(self.statement, bundle, self.artifact, config)
            args = run.call_args.args[0]
            self.assertNotIn("--insecure-ignore-tlog", args)
            self.assertIn("--trusted-root", args)

    def test_public_payload_approval_checked_before_signing(self):
        with (
            mock.patch.object(p, "cosign_trust"),
            mock.patch.object(p, "command") as run,
        ):
            with self.assertRaises(ValueError):
                p.attest(
                    self.statement, self.root / "bundle", self.artifact, {}, "0" * 64
                )
            run.assert_not_called()

    def test_operator_adapter_uses_exact_existing_contract(self):
        signer = self.root / "signer"
        signer.write_text("fixture executable")
        signature = self.root / "signed.sig"
        encoded = base64.b64encode(self.key.sign(p.detached_message(self.statement)))
        with (
            mock.patch.object(p, "TOOLING_KEY", self.key_digest),
            mock.patch.object(p, "command", return_value=encoded) as run,
        ):
            p.sign_detached(
                self.statement, signature, self.public, signer, p.digest(signer)
            )
            self.assertEqual(
                run.call_args.args[0],
                [
                    signer,
                    "release-signing",
                    "sign",
                    self.statement.name,
                    p.digest(self.statement),
                ],
            )
            p.verify_detached(self.statement, signature, self.public)

    def test_wrong_signer_builder_pair_refused(self):
        with (
            mock.patch.object(p, "cosign_trust"),
            mock.patch.object(p, "command") as run,
        ):
            with self.assertRaises(ValueError):
                p.verify_bundle(
                    self.statement,
                    self.root / "unused",
                    self.artifact,
                    {"builder_id": "urn:other"},
                )
            run.assert_not_called()

    def test_duplicate_keys_and_existing_output_refused(self):
        bad = self.root / "bad.json"
        bad.write_text('{"a":1,"a":2}')
        with self.assertRaises(ValueError):
            p.load(bad)
        with self.assertRaises(FileExistsError):
            p.write(self.statement, b"replace")

    def inventory(self):
        files = {}
        for name, data in (
            ("plan", self.plan),
            ("receipt", self.receipt),
            ("input_files", self.inputs),
        ):
            path = self.root / (name + ".json")
            path.write_bytes(p.canonical(data))
            files[name] = str(path)
        files.update(
            {
                "artifact": str(self.artifact),
                "statement": str(self.statement),
                "plan_sha256": p.digest(files["plan"]),
            }
        )
        path = self.root / "inventory.json"
        path.write_bytes(
            p.canonical({"version": 1, "stage": "qa", "artifacts": [files]})
        )
        return path

    def test_stage_prepare_checks_inventory_and_does_not_sign(self):
        inventory = self.inventory()
        self.statement.unlink()
        with mock.patch.object(p, "command") as run:
            result = stages.stage("prepare", "qa", inventory, p.digest(inventory))
            self.assertFalse(result["sigstore_verified"])
            self.assertEqual(len(result["artifacts"]), 1)
            run.assert_not_called()
        with self.assertRaises(ValueError):
            stages.stage("prepare", "qa", inventory, "0" * 64)
        with self.assertRaises(KeyError):
            stages.stage("verify", "qa", inventory, p.digest(inventory))

    def test_main_refuses_rebuild_changed_qa_set_and_prepare(self):
        qa = self.inventory()
        main = self.root / "main.json"
        data = {
            **p.load(qa),
            "stage": "main",
            "qualified_qa_inventory": str(qa),
            "qualified_qa_inventory_sha256": p.digest(qa),
        }
        main.write_bytes(p.canonical(data))
        with self.assertRaises(ValueError):
            stages.stage("prepare", "main", main, p.digest(main))
        data["artifacts"][0]["plan_sha256"] = "0" * 64
        main.write_bytes(p.canonical(data))
        with self.assertRaises(ValueError):
            stages.stage("verify", "main", main, p.digest(main))


if __name__ == "__main__":
    unittest.main()
