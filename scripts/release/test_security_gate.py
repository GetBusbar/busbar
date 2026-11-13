"""The G-S evidence contract the release gate writes, held on the Python scanner module.

The release gate's G-S now runs in Rust (tools/publish-gate/src/security.rs, with its parity cases
in tools/publish-gate/tests/parity.rs). It writes the evidence shape scripts/security/artifacts.py
defines: release-evidence.json's `security_scans` and a plugin release's plugin-security.json.
These tests keep that shape, and the scanner's refusals, pinned on the Python module until the
security tooling itself moves to Rust.
"""
from pathlib import Path
import json
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'security'))
import artifacts

POLICY = Path(__file__).resolve().parents[2] / 'ci/security'


def fake_scanner(scans):
    return SimpleNamespace(policy=POLICY, prepare=lambda: {'sha256': 'a' * 64}, steps=[],
                           scan=lambda *args: scans.append(args), trivy=lambda *args: args)


class SecurityGateEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def candidate(self):
        for directory in ('artifacts', 'sboms', 'internal', 'plugins', 'oci'):
            (self.root / directory).mkdir()
        (self.root / 'artifacts/busbar').write_bytes(b'fixture binary')
        (self.root / 'oci/busbar.oci.tar').write_bytes(b'fixture image')
        (self.root / 'sboms/fixture.cdx.json').write_text(json.dumps({
            'bomFormat': 'CycloneDX', 'components': [{'name': 'fixture', 'version': '1'}]}))

    def test_release_scan_evidence_keeps_the_schema_the_gate_writes(self):
        self.candidate()
        scans = []
        with patch.object(artifacts, 'Scanner', side_effect=lambda *_: fake_scanner(scans)):
            evidence = artifacts.scan_candidate(self.root, self.root, ['linux/amd64'])
        self.assertEqual(set(evidence), {'schema', 'status', 'subjects', 'database', 'steps', 'policy_files'})
        self.assertEqual((evidence['schema'], evidence['status']), ('busbar.artifact-security/1', 'pass'))
        self.assertEqual(evidence['subjects'], artifacts.candidate_inventory(self.root))
        self.assertEqual([args[0] for args in scans], ['sboms/fixture.cdx.json', 'image:linux/amd64'])

    def test_release_scan_refuses_an_undeclared_image_platform(self):
        self.candidate()
        with patch.object(artifacts, 'Scanner', side_effect=lambda *_: fake_scanner([])), \
                self.assertRaisesRegex(ValueError, 'unsupported release image platform'):
            artifacts.scan_candidate(self.root, self.root, ['linux/riscv64'])

    def test_plugin_scan_evidence_keeps_the_schema_the_gate_writes(self):
        archive = 'busbar-store-fixture-1.6.0-x86_64-unknown-linux-gnu.tar.gz'
        (self.root / archive).write_bytes(b'unsigned fixture')
        (self.root / 'fixture.cdx.json').write_text(json.dumps({
            'bomFormat': 'CycloneDX', 'components': [{'name': 'dep', 'version': '1'}],
            'metadata': {'component': {'name': 'busbar-store-fixture', 'version': '1.6.0'}}}))
        (self.root / 'security-sboms.json').write_text(json.dumps({
            'schema': 'busbar.plugin-sboms/1', 'repository': 'GetBusbar/busbar-store-fixture',
            'version': '1.6.0', 'source': 'a' * 40, 'subjects': [{
                'artifact': archive, 'artifact_sha256': artifacts.digest(self.root / archive),
                'sbom': 'fixture.cdx.json', 'sbom_sha256': artifacts.digest(self.root / 'fixture.cdx.json')}]}))
        with patch.object(artifacts, 'Scanner', side_effect=lambda *_: fake_scanner([])):
            evidence = artifacts.scan_plugin_candidate(POLICY.parent.parent, self.root, {archive},
                                                       'GetBusbar/busbar-store-fixture', '1.6.0', 'a' * 40)
        self.assertEqual(set(evidence), {'schema', 'status', 'repository', 'version', 'source', 'subjects',
                                         'database', 'inventory_sha256', 'steps', 'policy_files'})
        self.assertEqual(evidence['schema'], 'busbar.plugin-security/1')
        self.assertEqual(set(evidence['subjects'][archive]), {'artifact_sha256', 'sbom', 'sbom_sha256'})


if __name__ == '__main__':
    unittest.main()
