#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Focused provenance checks; no TLS connections or product build."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "tls_assess", Path(__file__).parents[2] / "scripts/release/tls_assess.py")
assess = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assess)
BANNER = "  testssl.sh version 3.2.4 from https://testssl.sh/\n"


class ScannerMetadata(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.scan, self.log = self.root / "scan.json", self.root / "scan.log"
        self.scan.write_text("[]")
        self.log.write_text(BANNER)

    def test_flat_scan_uses_actual_banner_and_binds_both_files(self):
        identity = assess.scanner_identity(self.scan, self.log)
        self.assertEqual(identity["tool"], "testssl.sh 3.2.4")
        self.assertEqual(set(identity["tool_evidence"]), {"scan_sha256", "scan_log_sha256"})

    def test_unknown_duplicate_and_conflicting_versions_fail_closed(self):
        with self.assertRaises(ValueError):
            assess.scanner_identity(self.scan)
        for banner in ("", BANNER * 2, BANNER.replace("3.2.4", "unknown")):
            self.log.write_text(banner)
            with self.subTest(banner=banner), self.assertRaises(ValueError):
                assess.scanner_identity(self.scan, self.log)
        self.scan.write_text(json.dumps({"version": "3.2.3", "scanResult": []}))
        self.log.write_text(BANNER)
        with self.assertRaises(ValueError):
            assess.scanner_identity(self.scan, self.log)

    def test_pretty_scan_can_supply_its_own_upstream_version(self):
        self.scan.write_text(json.dumps({"version": "3.2.4 ", "scanResult": []}))
        self.assertEqual(assess.scanner_identity(self.scan)["tool"], "testssl.sh 3.2.4")

    def test_aggregate_refuses_a_stale_scanner_version(self):
        old = {"version": "subject", "image_digest": "sha256:fixture", "tool": "testssl.sh 3.2.0"}
        (self.root / "assertions-old.json").write_text(json.dumps(old))
        (self.root / "assertions.json").write_text("stale aggregate")
        args = {"version": "subject", "image-digest": "sha256:fixture", "host": "localhost:443",
                "variant": "control", "out": str(self.root), "testssl": str(self.scan),
                "scan-log": str(self.log)}
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(assess.cmd_judge(args), 3)
        self.assertFalse((self.root / "assertions.json").exists())

    def test_run_records_measured_version_without_passing_empty_scan(self):
        tool = self.root / "scanner"
        tool.touch()

        def scanner(argv, stdout, stderr):
            Path(argv[argv.index("--jsonfile") + 1]).write_text("[]")
            stdout.write(BANNER.encode())

        args = {"version": "subject", "image-digest": "sha256:fixture", "host": "localhost:443",
                "variant": "control", "out": str(self.root / "out")}
        with mock.patch.dict(os.environ, TESTSSL=str(tool)), \
                mock.patch.object(assess.subprocess, "run", side_effect=scanner), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(assess.cmd_run(args), 1)
        report = json.loads((self.root / "out/assertions-control.json").read_text())
        self.assertEqual(report["tool"], "testssl.sh 3.2.4")
        self.assertTrue(any(row["name"] == "protocols" and row["result"] == "fail"
                            for row in report["assertions"]))


if __name__ == "__main__":
    unittest.main()
