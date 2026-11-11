"""Typed offline instrument intake rejects mutable and indirect tool inputs."""

import hashlib
import json
import subprocess
import tarfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import native
import linux_job_isolation

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

    def python_runtime(self):
        self.q.execution.config['python'] = '/usr/bin/python3'
        self.plan['bundles']['python-runtime'] = self.plan['bundles'].pop('example')
        identity = {'schema': 'busbar.native-python-runtime/1', 'platform': 'linux/amd64',
            'python_version': '3.11.2', 'base_python': '/usr/bin/python3',
            'image_manifest_sha256': self.q.execution.config['image'].split('sha256:')[-1],
            'image_config_sha256': 'b' * 64,
            'executable_sha256': hashlib.sha256(b'pinned Python executable').hexdigest()}
        (self.source / 'bin').mkdir()
        (self.source / 'bin/python3').write_bytes(b'pinned Python executable')
        (self.source / 'identity.json').write_text(json.dumps(identity))
        (self.source / 'pyvenv.cfg').write_text(
            'home = /usr/bin\ninclude-system-site-packages = false\nversion = 3.11.2\n')
        self.plan['bundles']['python-runtime']['files'] = {
            str(path.relative_to(self.source)): {
                'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                'executable': path.name == 'python3'}
            for path in self.source.rglob('*') if path.is_file()}

    def test_python_runtime_uses_bound_readonly_path_and_preserves_controller_python(self):
        self.python_runtime()
        controller_python = self.q.execution.config['python']
        original_path = self.q.execution.config['environment']['PATH']
        self.intake()
        self.assertEqual(self.q.execution.environment({'PATH': '/candidate/forged'})['PATH'],
            '/opt/busbar-conformance/python-runtime/bin:' + original_path)
        self.assertEqual(self.q.execution.config['python'], controller_python)
        path, expected = self.q.execution.write_context()
        from native_confinement import Execution, canonical
        execution = Execution.from_context(path, expected)
        binding = self.q.receipt['conformance_inputs']['python_runtime']
        self.assertEqual(binding['configuration_sha256'],
                         hashlib.sha256(canonical(execution.config)).hexdigest())
        self.assertEqual(execution.config['environment'], self.q.execution.config['environment'])

    def test_parent_child_and_bundle_digests_agree_without_losing_approved_input(self):
        self.python_runtime()
        # The approved input's formatting deliberately differs from canonical
        # serialization, so raw approval and active execution are distinct pins.
        approved = hashlib.sha256(json.dumps(self.q.execution.config, indent=3).encode()).hexdigest()
        self.q.receipt['execution_boundary'] = {
            'approved_configuration_sha256': approved, 'configuration_sha256': approved, 'observations': []}
        self.q.evidence = self.control / 'evidence'
        self.q.evidence.mkdir()
        self.intake()
        path, expected = self.q.execution.write_context()
        from native_confinement import Execution
        child = Execution.from_context(path, expected)

        def client(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1 if argv[0] == 'create' else 0,
                stdout=json.dumps({'SecurityOptions': ['name=userns']}) if argv[0] == 'info' else '',
                stderr='intentional create refusal')

        with patch.object(linux_job_isolation, 'prepare_writable', return_value={}), \
                patch.object(linux_job_isolation, 'validate_userns', return_value={}), \
                patch.object(child, '_client', side_effect=client):
            with self.assertRaisesRegex(ValueError, 'creation failed'):
                with child.invocation(['python3', '-c', 'pass'], self.q.root, {}):
                    self.fail('refused container must never execute')
        self.assertEqual(len(child.observations), 1)
        self.q.execution.observations.extend(child.observations)
        self.q.receipt['execution_boundary']['observations'] = self.q.execution.observations
        native.Qualification.save(self.q)
        receipt = json.loads((self.q.evidence / 'receipt.json').read_text())
        parent = receipt['execution_boundary']
        self.assertEqual(parent['approved_configuration_sha256'], approved)
        self.assertNotEqual(parent['configuration_sha256'], approved)
        self.assertEqual(parent['configuration_sha256'], child.observations[0]['configuration_sha256'])
        self.assertEqual(parent['configuration_sha256'],
                         receipt['conformance_inputs']['python_runtime']['configuration_sha256'])
        self.q.execution.config['resources']['pids'] += 1
        with self.assertRaisesRegex(Violation, 'retained observations'):
            native.Qualification.save(self.q)

    def test_python_runtime_rejects_other_image_abi(self):
        self.python_runtime()
        self.q.execution.config['image'] = 'sha256:' + 'c' * 64
        with self.assertRaisesRegex(Violation, 'selected image ABI'):
            self.intake()

    def test_python_runtime_rejects_system_site_packages(self):
        self.python_runtime()
        path = self.source / 'pyvenv.cfg'
        path.write_text(path.read_text().replace('false', 'true'))
        self.plan['bundles']['python-runtime']['files']['pyvenv.cfg']['sha256'] = (
            hashlib.sha256(path.read_bytes()).hexdigest())
        with self.assertRaisesRegex(Violation, 'closed standard virtual environment'):
            self.intake()

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
