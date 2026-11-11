"""Private service imports retain protected catalog and execution identities."""
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import native_service_inputs as inputs


class ServiceInputs(unittest.TestCase):
    def test_only_policy_services_are_selected_and_registry_origin_is_fixed(self):
        trusted = Path(__file__).parents[2]
        with patch.object(inputs, 'native_settings', return_value={'services': ['valkey']}):
            selected = inputs.selection(trusted, 'GetBusbar/example')
        self.assertEqual(list(selected), ['valkey'])
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory)
            (root / 'ci').mkdir()
            (root / 'testing/fleet-fixtures').mkdir(parents=True)
            plan = json.loads((trusted / 'ci/native-service-images.json').read_text())
            plan['services']['valkey']['archive_url'] = plan['services']['valkey']['archive_url'].replace('/projects/3/', '/projects/4/')
            (root / 'ci/native-service-images.json').write_text(json.dumps(plan))
            (root / 'testing/fleet-fixtures/service-images.tsv').write_bytes((trusted / 'testing/fleet-fixtures/service-images.tsv').read_bytes())
            with patch.object(inputs, 'read', return_value={}), patch.object(inputs, 'native_settings', return_value={'services': ['valkey']}):
                with self.assertRaisesRegex(ValueError, 'origin'):
                    inputs.selection(root, 'GetBusbar/example')

    def test_platform_membership_and_loaded_content_are_verified(self):
        config = {'os': 'linux', 'architecture': 'amd64', 'config': {'Cmd': ['fixed']},
                  'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + 'a' * 64]}}
        blobs = {}
        def blob(value):
            raw = json.dumps(value).encode()
            checksum = hashlib.sha256(raw).hexdigest()
            blobs[checksum] = raw
            return checksum
        config_sha = blob(config)
        manifest_sha = blob({'config': {'digest': 'sha256:' + config_sha}})
        index_sha = blob({'manifests': [{'digest': 'sha256:' + manifest_sha, 'platform': {'os': 'linux', 'architecture': 'amd64'}}]})
        row = {'reference': 'fixture@sha256:' + index_sha, 'manifest_sha256': manifest_sha, 'config_sha256': config_sha}
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            archive = Path(directory) / 'image.tar'
            with tarfile.open(archive, 'w') as output:
                for checksum, raw in blobs.items():
                    item = tarfile.TarInfo('blobs/sha256/' + checksum)
                    item.size = len(raw)
                    output.addfile(item, io.BytesIO(raw))
            self.assertEqual(inputs.metadata(archive, row), config)
            with self.assertRaisesRegex(ValueError, 'anchored'):
                inputs.metadata(archive, dict(row, manifest_sha256='f' * 64))
        actual = {'Id': 'sha256:' + manifest_sha, 'RepoDigests': [row['reference']], 'Os': 'linux', 'Architecture': 'amd64', 'Config': config['config'],
                  'RootFS': {'Type': 'layers', 'Layers': config['rootfs']['diff_ids']}}
        inputs.verify_import(actual, row, config)
        with self.assertRaisesRegex(ValueError, 'catalog'):
            inputs.verify_import(dict(actual, RepoDigests=['fixture@sha256:' + manifest_sha]), row, config)
        with self.assertRaisesRegex(ValueError, 'execution'):
            inputs.verify_import(dict(actual, Architecture='arm64'), row, config)
    def test_only_erased_legacy_build_parent_is_normalized(self):
        expected = {'Image': 'sha256:' + 'a' * 64, 'User': '', 'WorkingDir': '',
                    'Cmd': ['fixed'], 'Env': ['PATH=/bin']}
        actual = dict(expected, Image='')
        self.assertTrue(inputs.config_matches(actual, expected))
        for key, value in [('User', '1001'), ('WorkingDir', '/changed'), ('Cmd', ['changed']),
                           ('Env', ['PATH=/candidate']), ('Image', 'sha256:' + 'b' * 64)]:
            with self.subTest(key=key):
                self.assertFalse(inputs.config_matches(dict(actual, **{key: value}), expected))
        self.assertFalse(inputs.config_matches({'Image': ''}, {'Image': 'floating:tag'}))
        self.assertFalse(inputs.config_matches({}, {'Image': 'sha256:' + 'a' * 64}))
        self.assertFalse(inputs.config_matches({'Image': None}, {'Image': 'sha256:' + 'a' * 64}))

    def test_required_index_attestation_closure_is_checked_before_import(self):
        config = {'os': 'linux', 'architecture': 'amd64'}
        blobs = {}
        def blob(value):
            raw = json.dumps(value).encode()
            checksum = hashlib.sha256(raw).hexdigest()
            blobs[checksum] = raw
            return checksum
        config_sha = blob(config)
        manifest_sha = blob({'config': {'digest': 'sha256:' + config_sha}})
        evidence_sha = blob({'attestation': 'pinned external metadata'})
        attestation_sha = blob({'config': {'digest': 'sha256:' + config_sha, 'size': len(blobs[config_sha])},
                                'layers': [{'digest': 'sha256:' + evidence_sha, 'size': len(blobs[evidence_sha])}]})
        index_sha = blob({'manifests': [
            {'digest': 'sha256:' + manifest_sha, 'platform': {'os': 'linux', 'architecture': 'amd64'}},
            {'digest': 'sha256:' + attestation_sha, 'platform': {'os': 'unknown', 'architecture': 'unknown'},
             'annotations': {'vnd.docker.reference.type': 'attestation-manifest'}}]})
        row = {'reference': 'fixture@sha256:' + index_sha, 'manifest_sha256': manifest_sha, 'config_sha256': config_sha}
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            archive = Path(directory) / 'image.tar'
            for missing, corrupt in [(True, False), (False, True), (False, False)]:
                with tarfile.open(archive, 'w') as output:
                    for checksum, raw in blobs.items():
                        if checksum == evidence_sha and missing:
                            continue
                        if checksum == evidence_sha and corrupt:
                            raw = b'x' * len(raw)
                        item = tarfile.TarInfo('blobs/sha256/' + checksum)
                        item.size = len(raw)
                        output.addfile(item, io.BytesIO(raw))
                if missing:
                    with self.assertRaisesRegex(ValueError, 'missing pinned content'):
                        inputs.metadata(archive, row)
                elif corrupt:
                    with self.assertRaisesRegex(ValueError, 'content digest differs'):
                        inputs.metadata(archive, row)
                else:
                    self.assertEqual(inputs.metadata(archive, row), config)


if __name__ == '__main__':
    unittest.main()
