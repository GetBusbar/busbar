"""Typed offline instrument intake rejects mutable and indirect tool inputs."""

import hashlib
import json
import tarfile
from pathlib import Path
from types import SimpleNamespace
import unittest

from check import Violation
from native_conformance_inputs import stage, pack, unpack
from test_native_confinement import Fixture


class Instruments(Fixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.source = self.base / 'public-inputs'
        self.source.mkdir()
        (self.source / 'judge').write_bytes(b'fixed public instrument bytes')
        self.plan = {'schema': 'busbar.native-conformance-inputs/1', 'bundles': {'example': {
            'path': str(self.source), 'files': {'judge': {
                'sha256': hashlib.sha256((self.source / 'judge').read_bytes()).hexdigest(),
                'executable': True}}, 'provenance': [{'uri': 'https://example.invalid/pinned.tar.gz', 'sha256': 'a' * 64}]}}}
        self.q = SimpleNamespace(root=self.roots['checkout'], work=self.roots['candidate'],
            control=self.control, execution=self.execution(), receipt={})

    def intake(self):
        manifest = self.control / 'input-plan.json'
        manifest.write_text(json.dumps(self.plan))
        stage(self.q, manifest, hashlib.sha256(manifest.read_bytes()).hexdigest())

    def test_measured_tools_are_readonly_and_fixed_mounts_survive_context(self):
        self.intake()
        source, target = self.q.execution.conformance_mounts[0]
        self.assertEqual(str(target), '/opt/busbar-conformance/example')
        self.assertEqual((source / 'judge').stat().st_mode & 0o777, 0o555)
        self.assertEqual(self.q.execution.environment({'BUSBAR_CONFORMANCE_INPUTS': '/forged'})[
            'BUSBAR_CONFORMANCE_INPUTS'], '/__busbar_conformance_inputs.json')
        path, expected = self.q.execution.write_context()
        from native_confinement import Execution
        self.assertEqual(Execution.from_context(path, expected).conformance_mounts,
                         self.q.execution.conformance_mounts)

    def test_portable_archive_roundtrip_rebinds_only_under_protected_package(self):
        manifest = self.control / 'input-plan.json'
        manifest.write_text(json.dumps(self.plan))
        receipt = pack(manifest, hashlib.sha256(manifest.read_bytes()).hexdigest(), self.base / 'tools.tar.gz')
        published = unpack(receipt['archive'], receipt['archive_sha256'],
                           receipt['manifest_sha256'], self.base / 'unpacked')
        portable = json.loads(Path(published['manifest']).read_text())
        self.assertEqual(portable['bundles']['example']['path'], 'bundles/example')
        stage(self.q, published['manifest'], published['manifest_sha256'])
        self.assertEqual((self.control / 'conformance-tools-example/judge').read_bytes(),
                         b'fixed public instrument bytes')

    def test_archive_symlink_refuses_and_removes_partial_extraction(self):
        archive = self.base / 'hostile.tar.gz'
        with tarfile.open(archive, 'w:gz') as stream:
            link = tarfile.TarInfo('bundles/example/escape')
            link.type, link.linkname = tarfile.SYMTYPE, '/etc/passwd'
            stream.addfile(link)
        with self.assertRaisesRegex(Violation, 'unsafe conformance archive'):
            unpack(archive, hashlib.sha256(archive.read_bytes()).hexdigest(), 'a' * 64,
                   self.base / 'unpacked')
        self.assertFalse((self.base / 'unpacked').exists())

    def test_mutated_and_indirect_files_refuse(self):
        (self.source / 'judge').write_bytes(b'changed')
        with self.assertRaisesRegex(Violation, 'digest differs'):
            self.intake()
        (self.source / 'judge').unlink()
        (self.source / 'judge').symlink_to(self.control / 'private')
        with self.assertRaisesRegex(Violation, 'indirect'):
            self.intake()

    def test_candidate_tool_roots_and_credential_origins_refuse(self):
        self.plan['bundles']['example']['path'] = str(self.roots['candidate'])
        with self.assertRaisesRegex(Violation, 'candidate writable'):
            self.intake()
        self.plan['bundles']['example']['path'] = str(self.source)
        self.plan['bundles']['example']['provenance'][0]['uri'] = 'https://secret@example.invalid/archive'
        with self.assertRaisesRegex(Violation, 'credential-free'):
            self.intake()


if __name__ == '__main__':
    unittest.main()
