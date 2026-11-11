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
        actual = {'RepoDigests': [row['reference']], 'Os': 'linux', 'Architecture': 'amd64', 'Config': config['config'],
                  'RootFS': {'Type': 'layers', 'Layers': config['rootfs']['diff_ids']}}
        inputs.verify_import(actual, row, config)
        with self.assertRaisesRegex(ValueError, 'catalog'):
            inputs.verify_import(dict(actual, RepoDigests=['fixture@sha256:' + manifest_sha]), row, config)
        with self.assertRaisesRegex(ValueError, 'execution'):
            inputs.verify_import(dict(actual, Architecture='arm64'), row, config)


if __name__ == '__main__':
    unittest.main()
