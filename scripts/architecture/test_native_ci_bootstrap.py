"""Boundaries of the fixed-source native administrator bootstrap."""
import hashlib
import io
import json
import os
import shutil
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

import native_ci_bootstrap as bootstrap


class Bootstrap(unittest.TestCase):
    def environment(self):
        return {'CI_SERVER_URL': 'https://github.com', 'CI_SERVER_HOST': 'github.com',
                'CI_PROJECT_ID': '3', 'CI_JOB_ID': '19', 'CI_PIPELINE_ID': '11',
                'CI_PROJECT_PATH': 'GetBusbar/busbar', 'CI_JOB_NAME': 'native-isolation-diagnostic',
                'CI_COMMIT_SHA': 'a' * 40, 'CI_JOB_TOKEN': 'fixture-token',
                'CI_CONFIG_REF_URI': 'github.com/GetBusbar/busbar//ci/architecture-pipeline.yml@GetBusbar/busbar:' + 'b' * 40 + '@refs/heads/diagnostic'}

    def test_configuration_identity_is_fixed_and_untrusted_environment_is_dropped(self):
        env = self.environment() | {'LD_PRELOAD': '/candidate.so', 'PYTHONPATH': '/candidate', 'AWS_SECRET_ACCESS_KEY': 'secret'}
        selected = bootstrap.ci_environment(env)
        self.assertEqual(bootstrap.approved_revision(selected), 'b' * 40)
        self.assertFalse({'LD_PRELOAD', 'PYTHONPATH', 'AWS_SECRET_ACCESS_KEY'} & selected.keys())
        for key, value in [('CI_JOB_NAME', 'candidate-command'), ('CI_SERVER_URL', 'https://attacker.invalid'),
                           ('CI_JOB_ID', '../escape'), ('CI_PROJECT_PATH', 'Other/project')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                bootstrap.ci_environment(self.environment() | {key: value})
        with self.assertRaises(ValueError):
            bootstrap.approved_revision(selected | {'CI_CONFIG_REF_URI': selected['CI_CONFIG_REF_URI'].replace('b' * 40, 'dev')})

    def test_plugin_host_binding_cannot_float_or_disappear(self):
        env = self.environment() | {'CI_PROJECT_PATH': 'GetBusbar/busbar-plane-mcp', 'CI_JOB_NAME': 'native-qualification'}
        with self.assertRaisesRegex(ValueError, 'immutable host'):
            bootstrap.ci_environment(env)
        with self.assertRaisesRegex(ValueError, 'immutable'):
            bootstrap.ci_environment(env | {'BUSBAR_ADMISSION_CORE_REVISION': 'dev'})
        bound = bootstrap.ci_environment(env | {'BUSBAR_ADMISSION_CORE_REVISION': 'c' * 40})
        self.assertEqual(bound['BUSBAR_ADMISSION_CORE_REVISION'], 'c' * 40)

    def test_privilege_is_only_the_verified_fixed_controller_entry(self):
        argv = bootstrap.entry_command(Path('/trusted/native_ci_bootstrap.py'), 'a' * 64,
                                       'local@sha256:' + 'b' * 64, 'job-19')
        self.assertIn('--privileged', argv)
        self.assertIn('--network=none', argv)
        self.assertNotIn('--env', argv)
        self.assertNotIn('--mount', argv[:argv.index('/usr/bin/nsenter')])
        code = argv[-1]
        self.assertIn('hashlib.sha256(p.read_bytes()).hexdigest()', code)
        self.assertIn('"--root"', code)
        self.assertNotIn('CI_JOB_TOKEN', ' '.join(argv))
        self.assertNotIn('candidate', ' '.join(argv))

    def test_candidate_and_collector_identities_endpoints_and_storage_are_distinct(self):
        root = Path('/srv/busbar-native-ci/job-19')
        config = bootstrap.runtime_configuration(root, 'unix:///private.sock', 'image@sha256:' + 'a' * 64, False)
        self.assertEqual(config['isolation']['storage_bytes'], 24 * 1024**3)
        self.assertEqual(config['isolation']['storage_reserve_bytes'], 6 * 1024**3)
        self.assertEqual(config['isolation']['storage_kind'], 'loop-ext4')
        self.assertNotEqual(config['docker_host'], config['collector']['docker_host'])
        self.assertEqual(config['collector']['uid'], config['isolation']['uid_map'][1] + config['uid'])
        self.assertEqual(config['collector']['gid'], config['isolation']['gid_map'][1] + config['gid'])
        self.assertNotIn('CI_JOB_TOKEN', config['environment'])
        diagnostic = bootstrap.runtime_configuration(root, 'unix:///private.sock', 'image@sha256:' + 'a' * 64, True)
        self.assertEqual(diagnostic['isolation']['storage_kind'], 'tmpfs')
        self.assertNotIn('storage_image', diagnostic['isolation'])

    def test_credential_redirect_cannot_leave_the_package_origin(self):
        request = urllib.request.Request(bootstrap.PACKAGE, headers={'JOB-TOKEN': 'fixture-token'})
        with self.assertRaisesRegex(ValueError, 'origin'):
            bootstrap.SameOrigin().redirect_request(request, None, 302, '', {}, 'https://other.invalid/archive')

    def test_published_judge_plan_selects_only_each_job_required_owners(self):
        plan = json.loads((Path(__file__).parents[2] / 'ci/native-judge-inputs.json').read_text())
        self.assertEqual(bootstrap.judge_selection(plan, 'GetBusbar/busbar', 'core-conformance'), ['core', 'tls', 'oidf'])
        self.assertEqual(bootstrap.judge_selection(plan, 'GetBusbar/busbar', 'native-qualification'), [])
        self.assertEqual(bootstrap.judge_selection(plan, 'GetBusbar/busbar-plane-mcp', 'native-qualification'), ['mcp'])
        self.assertEqual(bootstrap.judge_selection(plan, 'GetBusbar/busbar-plane-llm', 'external-conformance'), [])
        self.assertEqual(bootstrap.judge_selection(plan, 'GetBusbar/busbar-plane-decisions', 'native-qualification'), [])
        row = dict(plan['owners']['mcp'])
        for bad in (row['archive_url'].replace('/projects/3/', '/projects/4/'),
                    row['archive_url'].replace('github.com', 'other.invalid'),
                    row['archive_url'] + '?token=secret'):
            with self.subTest(url=bad), self.assertRaises(ValueError):
                bootstrap.verify_judge_record('mcp', dict(row, archive_url=bad))

    def test_judge_staging_binds_verified_archive_and_keeps_it_outside_candidate_roots(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory)
            trusted, store = root / 'trusted', root / 'store'
            (trusted / 'ci').mkdir(parents=True)
            store.mkdir()
            content = b'fixed external instrument'
            manifest = {'schema': 'busbar.native-conformance-inputs/1', 'bundles': {
                'mcp-tools': {'path': 'bundles/mcp-tools', 'files': {
                    'tool': {'sha256': hashlib.sha256(content).hexdigest(), 'executable': False}},
                    'provenance': [{'uri': 'https://example.invalid/pinned', 'sha256': hashlib.sha256(content).hexdigest()}]}}}
            raw = (json.dumps(manifest, sort_keys=True) + '\n').encode()
            archive = root / 'input.tar.gz'
            with tarfile.open(archive, 'w:gz') as output:
                for name, data in [('manifest.json', raw), ('bundles/mcp-tools/tool', content)]:
                    item = tarfile.TarInfo(name)
                    item.size, item.mode = len(data), 0o444
                    output.addfile(item, io.BytesIO(data))
            checksum = bootstrap.digest(archive)
            row = {'archive_url': 'https://github.com/api/v4/projects/3/packages/generic/busbar-native-conformance-mcp/20261111-' + checksum + '/mcp.tar.gz',
                'archive_sha256': checksum, 'portable_manifest_sha256': hashlib.sha256(raw).hexdigest(),
                'bytes': archive.stat().st_size, 'expanded_bytes': len(content), 'bundles': ['mcp-tools']}
            plan = {'schema': 'busbar.native-judge-inputs/1', 'owners': {'mcp': row},
                    'repositories': {'GetBusbar/busbar-plane-mcp': ['mcp']}}
            (trusted / 'ci/native-judge-inputs.json').write_text(json.dumps(plan))
            def fetched(selected, destination, token):
                self.assertEqual(token, 'fixture-job-token')
                shutil.copyfile(archive, destination)
            with patch.object(bootstrap, 'fetch_judge_archive', side_effect=fetched):
                result = bootstrap.stage_judges(trusted, 'GetBusbar/busbar-plane-mcp', 'native-qualification', store, 'fixture-job-token')
            combined = json.loads(Path(result['manifest']).read_text())
            bundle = Path(combined['bundles']['mcp-tools']['path'])
            self.assertTrue(bundle.is_relative_to(store / 'judge-inputs'))
            self.assertEqual((bundle / 'tool').read_bytes(), content)
            self.assertFalse((store / 'judge-inputs/mcp.tar.gz').exists())
            self.assertEqual(result['sha256'], bootstrap.digest(result['manifest']))
            self.assertEqual(result['suite_verdict'], 'not implied by input staging')

    def test_registry_serves_pinned_blobs_and_has_no_filesystem_or_proxy_route(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            archive = Path(directory) / 'image.tar'
            manifest = json.dumps({'mediaType': 'application/vnd.oci.image.manifest.v1+json'}).encode()
            value = hashlib.sha256(manifest).hexdigest()
            with tarfile.open(archive, 'w') as output:
                info = tarfile.TarInfo('blobs/sha256/' + value)
                info.size = len(manifest)
                output.addfile(info, io.BytesIO(manifest))
            with patch.object(bootstrap, 'MANIFEST', value):
                registry = bootstrap.Registry(archive)
                try:
                    url = 'http://127.0.0.1:' + str(registry.port)
                    with urllib.request.urlopen(url + '/v2/busbar-native-tools/manifests/sha256:' + value) as response:
                        self.assertEqual(response.read(), manifest)
                        self.assertEqual(response.headers['Docker-Content-Digest'], 'sha256:' + value)
                    for suffix in ('/etc/passwd', '/v2/other/blobs/sha256:' + value,
                                   '/v2/busbar-native-tools/blobs/sha256:' + '0' * 64):
                        with self.subTest(suffix=suffix), self.assertRaises(urllib.error.HTTPError) as error:
                            urllib.request.urlopen(url + suffix)
                        self.assertEqual(error.exception.code, 404)
                        error.exception.close()
                finally:
                    registry.close()


if __name__ == '__main__':
    unittest.main()
