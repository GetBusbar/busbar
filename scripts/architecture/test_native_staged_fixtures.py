"""Typed legacy input and generated-source boundary regressions."""

import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from check import Violation
from native_staged_fixtures import stage
from test_native_confinement import Fixture


class StagedFixtures(Fixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.source = self.base / 'published-fixture'
        self.source.mkdir()
        (self.source / 'governance.db').write_bytes(b'unit database; never presented as a real migration')
        (self.source / 'rows.json').write_text('{}')
        rows = ['busbar\tv1.5.5 busbar-x86_64-unknown-linux-gnu ' + 'a' * 64,
                'plugin\tv1.0.6 plugin.tar.gz ' + 'b' * 64,
                'backend\tsqlite', 'recorder\t' + 'c' * 40,
                'requests\t200 200 200 503 200 200']
        for name in ('governance.db', 'rows.json'):
            rows.append('file\t' + name + ' ' + hashlib.sha256((self.source / name).read_bytes()).hexdigest())
        (self.source / 'MANIFEST.tsv').write_text('\n'.join(rows) + '\n')
        tables = self.roots['trusted'] / 'testing/shadow-oracle'
        tables.mkdir(parents=True)
        (tables / 'golden-digests.tsv').write_text('1.5.5\tbusbar-x86_64-unknown-linux-gnu\t' + 'a' * 64 + '\n')
        (tables / 'plugin-digests.tsv').write_text('store-sqlite\tv1.0.6\tplugin.tar.gz\t' + 'b' * 64 + '\n')
        self.plan = {'schema': 'busbar.native-staged-fixtures/1', 'fixtures': {'sqlite-1.5.5': {
            'path': str(self.source), 'files': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.source.iterdir()},
            'origin': {'repository': 'GetBusbar/busbar-store-sqlite', 'revision': 'd' * 40,
                       'path': 'store-sqlite/tests/fixtures/1.5.5'}}}}
        self.q = SimpleNamespace(root=self.roots['checkout'], work=self.roots['candidate'],
                                 trusted=self.roots['trusted'], control=self.control,
                                 execution=self.execution(), receipt={})

    def run_stage(self):
        path = self.control / 'plan.json'
        path.write_text(json.dumps(self.plan))
        return stage(self.q, path, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_controller_stages_complete_measured_fixture_readonly(self):
        result = self.run_stage()['sqlite-1.5.5']
        self.assertIn(result, self.q.execution.extra_readonly)
        self.assertEqual((result / 'governance.db').stat().st_mode & 0o222, 0)
        self.assertEqual((result / 'governance.db').read_bytes(), (self.source / 'governance.db').read_bytes())
        self.assertIn('sqlite-1.5.5', self.q.receipt['staged_fixture_inputs']['fixtures'])

    def test_mutated_unlisted_and_indirect_fixture_inputs_refuse(self):
        path = self.source / 'governance.db'
        path.write_bytes(b'changed')
        with self.assertRaisesRegex(Violation, 'digest differs'):
            self.run_stage()
        path.unlink()
        path.symlink_to(self.control / 'secret')
        with self.assertRaisesRegex(Violation, 'indirect'):
            self.run_stage()

    def test_generated_projects_are_registered_before_trusted_harness_reads(self):
        root = self.roots['candidate'] / 'generated/example'
        root.mkdir(parents=True)
        (root / 'Cargo.toml').write_text('[workspace]\n')
        self.q.execution.register_generated(root)
        path, expected = self.q.execution.write_context()
        from native_confinement import Execution
        self.assertIn(root, Execution.from_context(path, expected).extra_readonly)
        (root / 'secret').symlink_to(self.control / 'secret')
        with self.assertRaisesRegex(ValueError, 'indirect'):
            self.q.execution.register_generated(root)


if __name__ == '__main__':
    unittest.main()
