"""Artifact binding and failure tests using tiny local candidates."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import artifacts


class ArtifactScans(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ('artifacts', 'sboms', 'internal', 'plugins', 'oci'):
            (self.root / directory).mkdir()
        (self.root / 'artifacts/busbar').write_bytes(b'fixture binary')
        (self.root / 'oci/busbar.oci.tar').write_bytes(b'fixture image')
        (self.root / 'sboms/fixture.cdx.json').write_text(json.dumps({
            'bomFormat': 'CycloneDX', 'components': [{'name': 'fixture', 'version': '1'}]}))
        self.policy = Path(__file__).resolve().parents[2] / 'ci/security'

    def scanner(self, *_args):
        from types import SimpleNamespace
        return SimpleNamespace(policy=self.policy, prepare=lambda: {'sha256': 'a' * 64},
                               steps=[], scan=self.execute, trivy=lambda *args: args)

    def execute(self, *args):
        self.scans.append(args)

    def run_scan(self):
        self.scans = []
        with patch.object(artifacts, 'Scanner', side_effect=self.scanner):
            return artifacts.scan_candidate(self.root, self.root, ['linux/amd64', 'linux/arm64'])

    def test_all_platforms_and_sboms_bind_exact_candidate_bytes(self):
        evidence = self.run_scan()
        self.assertEqual({row[0] for row in self.scans},
                         {'sboms/fixture.cdx.json', 'image:linux/amd64', 'image:linux/arm64'})
        self.assertEqual(evidence['subjects'], artifacts.candidate_inventory(self.root))

    def test_mutation_or_finding_refuses(self):
        def mutate(*args):
            (self.root / 'artifacts/busbar').write_bytes(b'changed')
        self.execute = mutate
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.run_scan()
        def fail(*args):
            raise ValueError('findings')
        self.execute = fail
        with self.assertRaisesRegex(ValueError, 'findings'):
            self.run_scan()

    def test_collected_build_closures_are_bound_and_cannot_change_during_scan(self):
        directory = self.root / 'closures'
        directory.mkdir()
        closure = directory / 'fixture.build-closure.json'
        closure.write_text('{}')
        self.assertIn('closures/fixture.build-closure.json', self.run_scan()['subjects'])
        def mutate(*_args):
            closure.write_text('{"changed":true}')
        self.execute = mutate
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.run_scan()

    def test_empty_sbom_refuses(self):
        (self.root / 'sboms/fixture.cdx.json').write_text('{"bomFormat":"CycloneDX","components":[]}')
        with self.assertRaisesRegex(ValueError, 'empty'):
            self.run_scan()


class PluginScans(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = 'busbar-store-fixture-1.6.0-x86_64-unknown-linux-gnu.tar.gz'
        (self.root / self.archive).write_bytes(b'unsigned fixture')
        self.sbom = 'fixture-x86_64.cdx.json'
        (self.root / self.sbom).write_text(json.dumps({'bomFormat': 'CycloneDX',
            'metadata': {'component': {'name': 'busbar-store-fixture', 'version': '1.6.0'}},
            'components': [{'name': 'fixture-dependency', 'version': '1'}]}))
        self.manifest = dict(schema='busbar.plugin-sboms/1', repository='GetBusbar/busbar-store-fixture',
            version='1.6.0', source='a' * 40, subjects=[dict(artifact=self.archive,
                artifact_sha256=artifacts.digest(self.root / self.archive), sbom=self.sbom,
                sbom_sha256=artifacts.digest(self.root / self.sbom))])
        self.write()

    def write(self):
        (self.root / 'security-sboms.json').write_text(json.dumps(self.manifest))

    def inventory(self):
        return artifacts.plugin_inventory(self.root, {self.archive}, 'GetBusbar/busbar-store-fixture', '1.6.0', 'a' * 40)

    def test_complete_binding_accepts(self):
        self.assertEqual(self.inventory()[self.archive]['sbom'], self.sbom)

    def test_missing_wrong_source_duplicate_and_digest_substitution_refuse(self):
        import copy
        good = copy.deepcopy(self.manifest)
        cases = [dict(good, subjects=[]), dict(good, source='b' * 40),
                 dict(good, subjects=good['subjects'] * 2)]
        changed = copy.deepcopy(good)
        changed['subjects'][0]['sbom_sha256'] = '0' * 64
        cases.append(changed)
        for manifest in cases:
            self.manifest = manifest
            self.write()
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                self.inventory()
        (self.root / 'security-sboms.json').unlink()
        with self.assertRaises(ValueError):
            self.inventory()

    def test_sbom_for_another_plugin_refuses_even_with_matching_digest(self):
        path = self.root / self.sbom
        doc = json.loads(path.read_text())
        doc['metadata']['component']['name'] = 'another-plugin'
        path.write_text(json.dumps(doc))
        self.manifest['subjects'][0]['sbom_sha256'] = artifacts.digest(path)
        self.write()
        with self.assertRaises(ValueError):
            self.inventory()

    def test_scanner_failure_or_mutation_cannot_produce_receipt(self):
        from types import SimpleNamespace
        policy = Path(__file__).resolve().parents[2] / 'ci/security'
        for mutate in (False, True):
            def run(*args):
                if mutate:
                    (self.root / self.archive).write_bytes(b'changed')
                else:
                    raise ValueError('findings')
            fake = SimpleNamespace(policy=policy, prepare=lambda: {}, scan=run,
                                   steps=[], trivy=lambda *args: args)
            with patch.object(artifacts, 'Scanner', return_value=fake), self.assertRaises(ValueError):
                artifacts.scan_plugin_candidate(policy.parent.parent, self.root, {self.archive},
                    'GetBusbar/busbar-store-fixture', '1.6.0', 'a' * 40)
