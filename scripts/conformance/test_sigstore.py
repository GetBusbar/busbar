# SPDX-License-Identifier: Apache-2.0
"""Release identity and artifact binding regressions; no claim of live signing."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("sigstore_check", ROOT / "testing/conformance/sigstore.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReceiptTests(unittest.TestCase):
    def test_receipt_binds_the_source_and_exact_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "artifact"
            artifact.write_bytes(b"tested artifact")
            receipt = {"sha": "a" * 40, "artifact_sha256": module.digest(artifact)}
            module.check_receipt(receipt, artifact, "a" * 40)
            with self.assertRaises(ValueError):
                module.check_receipt(receipt, artifact, "b" * 40)
            artifact.write_bytes(b"changed artifact")
            with self.assertRaises(ValueError):
                module.check_receipt(receipt, artifact, "a" * 40)


if __name__ == "__main__":
    unittest.main()
