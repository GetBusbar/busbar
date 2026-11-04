# SPDX-License-Identifier: Apache-2.0
import importlib.util
import copy
import json
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("ci_coverage", Path(__file__).with_name("ci_coverage.py"))
coverage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage)


class RosterTests(unittest.TestCase):
    def test_product_sdk_override_is_required_in_evidence_binding(self):
        data = json.loads(coverage.OUTPUT.read_text())
        pins = json.loads((coverage.ROOT / "scripts/ci-product-pins.json").read_text())
        sdk = "9" * 40
        next(p for p in pins["products"] if p["repo"] == "busbar-plane-a2a")["sdk"] = sdk
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ["conformance", "testing"]:
                (root / name).symlink_to(coverage.ROOT / name, target_is_directory=True)
            (root / "scripts").mkdir()
            (root / "scripts/ci-product-pins.json").write_text(json.dumps(pins))
            with patch.object(coverage, "ROOT", root):
                with self.assertRaisesRegex(ValueError, "SDK binding"):
                    coverage.validate(data)
                data["suites"]["a2a"]["core_pin"] = sdk
                coverage.validate(data)

    def test_valid_commands_and_comments(self):
        self.assertEqual(coverage.roster(b"# suite\nws\tbash testing/ws/run.sh\n"), {"ws": "bash testing/ws/run.sh"})

    def test_a_literal_backslash_t_is_not_a_delimiter(self):
        with self.assertRaises(ValueError):
            coverage.roster(b"ws\\tbash testing/ws/run.sh\n")

    def test_duplicate_suite_cannot_overwrite_an_execution(self):
        with self.assertRaises(ValueError):
            coverage.roster(b"ws\tbash testing/ws/run.sh\nws\tbash testing/other.sh\n")

    def test_coverage_cannot_silently_move_or_drop_a_suite(self):
        data = json.loads(coverage.OUTPUT.read_text())
        coverage.validate(data)
        for field, value in [("stage", "main"), ("check", "no-op"), ("core_pin", "0" * 40)]:
            wrong = copy.deepcopy(data)
            wrong["suites"]["a2a"][field] = value
            with self.assertRaises(ValueError):
                coverage.validate(wrong)
        del data["suites"]["a2a"]
        with self.assertRaises(ValueError):
            coverage.validate(data)


if __name__ == "__main__":
    unittest.main()
