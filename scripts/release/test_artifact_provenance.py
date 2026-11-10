#!/usr/bin/env python3
"""The artifact contract must select GitLab-native trust and refuse missing inputs."""

import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import release_verifier

SPEC = importlib.util.spec_from_file_location(
    "artifact_verifier", Path(__file__).parents[1] / "verify-artifact.py"
)
artifact = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact)


class ArtifactProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        path = Path(self.temp.name) / "busbar.tar.gz"
        path.write_bytes(b"fixture")
        self.ctx = SimpleNamespace(
            archive=str(path),
            version="v1.6.0",
            target="native-target",
            provenance_directory=self.temp.name,
            provenance_inventory_sha256="a" * 64,
            provenance_trust="trusted.json",
            provenance_trust_sha256="b" * 64,
        )
        self.result = {
            "release": "1.6.0",
            "subjects": [
                {
                    "name": path.name,
                    "sha256": artifact.sha256_file(path),
                    "target": self.ctx.target,
                    "source_commit": "c" * 40,
                }
            ],
        }

    def test_existing_release_contract_default_is_present(self):
        self.assertTrue(Path(artifact.DEFAULT_CONTRACT).is_file())

    def test_missing_activation_inputs_refuse_without_external_command(self):
        with mock.patch.object(artifact, "run") as run:
            with self.assertRaises(artifact.RowFailure):
                artifact.row_attestation(SimpleNamespace())
            run.assert_not_called()

    def test_archive_row_uses_native_verifier_and_exact_subject(self):
        with mock.patch.object(
            release_verifier, "verify", return_value=self.result
        ) as verify:
            self.assertIn("GitLab-native", artifact.row_attestation(self.ctx))
            verify.assert_called_once_with(
                self.ctx.provenance_directory, "a" * 64, "trusted.json", "b" * 64
            )

    def test_wrong_archive_target_release_and_crypto_failure_refuse(self):
        for field, value in (
            ("target", "other"),
            ("sha256", "d" * 64),
            ("name", "other.tar.gz"),
        ):
            result = {
                **self.result,
                "subjects": [{**self.result["subjects"][0], field: value}],
            }
            with mock.patch.object(
                release_verifier, "verify", return_value=result
            ), self.assertRaises(artifact.RowFailure):
                artifact.row_attestation(self.ctx)
        with mock.patch.object(
            release_verifier, "verify", return_value={**self.result, "release": "1.5.5"}
        ), self.assertRaises(artifact.RowFailure):
            artifact.row_attestation(self.ctx)
        with mock.patch.object(
            release_verifier, "verify", side_effect=ValueError("fixture secret")
        ), self.assertRaises(artifact.RowFailure) as error:
            artifact.row_attestation(self.ctx)
        self.assertNotIn("fixture secret", str(error.exception))


if __name__ == "__main__":
    unittest.main()
