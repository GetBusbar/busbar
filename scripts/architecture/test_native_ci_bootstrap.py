"""Boundaries of the fixed-source native administrator bootstrap."""
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
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

    def test_server_ref_protection_reaches_the_controller(self):
        # Producer and dev-credit checks read CI_COMMIT_REF_PROTECTED inside the
        # root controller; dropping it here refused every protected producer run.
        for value in ('true', 'false'):
            selected = bootstrap.ci_environment(self.environment() | {'CI_COMMIT_REF_PROTECTED': value})
            self.assertEqual(selected['CI_COMMIT_REF_PROTECTED'], value)
        self.assertNotIn('CI_COMMIT_REF_PROTECTED', bootstrap.ci_environment(self.environment()))
        with self.assertRaisesRegex(ValueError, 'ref protection'):
            bootstrap.ci_environment(self.environment() | {'CI_COMMIT_REF_PROTECTED': 'yes'})

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
        self.assertIn('--cgroup', argv[argv.index('/usr/bin/nsenter') + 1:])

    def test_controller_refuses_a_private_mount_or_cgroup_namespace(self):
        for changed in ('mnt', 'cgroup'):
            def namespace(path):
                inode = 2 if path == '/proc/self/ns/' + changed else 1
                return SimpleNamespace(st_ino=inode)
            with self.subTest(namespace=changed), patch.object(bootstrap.os, 'geteuid', return_value=0), \
                    patch.object(bootstrap.os, 'stat', side_effect=namespace):
                with self.assertRaisesRegex(ValueError, 'host ' + changed + ' namespace'):
                    bootstrap.require_host_controller()
        with patch.object(bootstrap.os, 'geteuid', return_value=0), \
                patch.object(bootstrap.os, 'stat', return_value=SimpleNamespace(st_ino=1)):
            bootstrap.require_host_controller()
        with patch.object(bootstrap.os, 'geteuid', return_value=1001):
            with self.assertRaisesRegex(ValueError, 'host root'):
                bootstrap.require_host_controller()

    def test_verified_entry_recovers_a_removed_inherited_working_directory(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory).resolve()
            helper = root / 'fixed-controller.py'
            helper.write_text('import os,sys; assert sys.argv[1:] == ["--root"]; print(os.getcwd())\n')
            command = bootstrap.entry_command(helper, bootstrap.digest(helper), 'sha256:' + 'a' * 64, 'fixture')
            self.assertIn('--wd', command)
            self.assertNotIn('--wd=/', command)
            inherited = root / 'removed'
            inherited.mkdir()
            launcher = 'import os,sys; os.chdir(sys.argv[1]); os.rmdir(sys.argv[1]); exec(sys.argv[2])'
            result = subprocess.run([sys.executable, '-I', '-B', '-c', launcher,
                                     str(inherited), command[-1]], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), '/')

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

    def test_job_parent_allows_remapped_traversal_without_listing_or_writes(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path = Path(directory)
            private = path / 'private'
            private.mkdir(mode=0o700)
            with patch.object(bootstrap, 'root_directory', return_value=path) as protected:
                self.assertEqual(bootstrap.job_directory(path), path)
            protected.assert_called_once_with(path, fresh=True)
            self.assertEqual(path.stat().st_mode & 0o777, 0o711)
            self.assertEqual(private.stat().st_mode & 0o777, 0o700)

    def test_credential_redirect_cannot_leave_the_package_origin(self):
        request = urllib.request.Request(bootstrap.PACKAGE, headers={'JOB-TOKEN': 'fixture-token'})
        with self.assertRaisesRegex(ValueError, 'origin'):
            bootstrap.SameOrigin().redirect_request(request, None, 302, '', {}, 'https://other.invalid/archive')

    def test_published_judge_plan_selects_only_each_job_required_owners(self):
        plan = json.loads((Path(__file__).parents[2] / 'ci/native-judge-inputs.json').read_text())
        self.assertEqual(bootstrap.judge_selection(plan, 'GetBusbar/busbar', 'core-conformance'), ['core', 'tls', 'oidf', 'release-engineering'])
        self.assertEqual(bootstrap.judge_selection(plan, 'GetBusbar/busbar', 'native-qualification'), [])
        self.assertEqual(bootstrap.judge_selection(plan, 'GetBusbar/busbar-plane-mcp', 'native-qualification'), ['mcp'])
        self.assertEqual(bootstrap.judge_selection(plan, 'GetBusbar/busbar', 'core-conformance-debug'),
                         ['core', 'tls', 'oidf', 'release-engineering'])
        for job in ('core-build', 'core-clippy', 'core-test'):
            self.assertEqual(bootstrap.judge_selection(plan, 'GetBusbar/busbar', job), [])
        self.assertEqual(bootstrap.judge_selection(plan, 'GetBusbar/busbar-plane-decisions', 'native-qualification'), [])
        self.assertEqual(bootstrap.judge_selection(plan, 'GetBusbar/busbar-secret-c', 'native-qualification'), ['python-schema'])
        self.assertEqual([repo for repo, owners in plan['repositories'].items() if 'python-schema' in owners],
                         ['GetBusbar/busbar-secret-c'])
        row = dict(plan['owners']['mcp'])
        for bad in (row['archive_url'].replace('/projects/3/', '/projects/4/'),
                    row['archive_url'].replace('github.com', 'other.invalid'),
                    row['archive_url'] + '?token=secret'):
            with self.subTest(url=bad), self.assertRaises(ValueError):
                bootstrap.verify_judge_record('mcp', dict(row, archive_url=bad))

    def test_core_test_is_a_core_mode_job_with_service_peers(self):
        self.assertEqual(bootstrap.ci_environment(self.environment() | {'CI_JOB_NAME': 'core-test'})['CI_JOB_NAME'],
                         'core-test')
        # Dispatched as native.py --core-test; unlike build and lints its tests need the peers.
        self.assertEqual(bootstrap.CORE_MODE_JOBS, ('core-build', 'core-clippy', 'core-test'))
        self.assertNotIn('core-test', bootstrap.NO_SERVICE_JOBS)
        self.assertNotIn('core-test', bootstrap.CONFORMANCE_JOBS)

    def test_core_judge_oidc_source_matches_distribution_lock(self):
        # The core archive's oidc-source bundle is refused by oidf.py when its
        # source-identity rev differs from dist/default/Cargo.lock. Fail here,
        # before the conformance run, when a re-pin leaves the archive stale.
        # Republishing the archive means recording its staged OIDC rev below.
        staged_oidc_rev = {
            '7e7c4657d25acda296c4175fb1229ac8bcb9640c9c504b5c892ad88d857b4096':
                '8441cdda02e3e35d8d1ec8d035ee7a8dae8e9f44',
        }
        checkout = Path(__file__).parents[2]
        plan = json.loads((checkout / 'ci/native-judge-inputs.json').read_text())
        archive = plan['owners']['core']['archive_sha256']
        self.assertIn(archive, staged_oidc_rev, 'record the OIDC rev staged by the new core judge archive')
        spec = importlib.util.spec_from_file_location('oidf_lock', checkout / 'testing/oidf-conformance/oidf.py')
        oidf = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(oidf)
        self.assertEqual(staged_oidc_rev[archive], oidf.oidc_pin(str(checkout))['rev'],
                         'core judge archive stages a stale oidc-source; republish it for the locked OIDC rev')

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
            row['expanded_bytes'] += len(raw)
            (trusted / 'ci/native-judge-inputs.json').write_text(json.dumps(plan))
            with patch.object(bootstrap, 'fetch_judge_archive', side_effect=fetched):
                with self.assertRaisesRegex(ValueError,
                        r'expanded judge size differs for mcp \(mcp\.tar\.gz\): expected '
                        + str(row['expanded_bytes']) + ', actual ' + str(len(content))):
                    bootstrap.stage_judges(trusted, 'GetBusbar/busbar-plane-mcp', 'native-qualification', store, 'fixture-job-token')
            shutil.rmtree(store / 'judge-inputs')
            row['expanded_bytes'] = len(content)
            (trusted / 'ci/native-judge-inputs.json').write_text(json.dumps(plan))
            with patch.object(bootstrap, 'fetch_judge_archive', side_effect=fetched):
                result = bootstrap.stage_judges(trusted, 'GetBusbar/busbar-plane-mcp', 'native-qualification', store, 'fixture-job-token')
            combined = json.loads(Path(result['manifest']).read_text())
            bundle = Path(combined['bundles']['mcp-tools']['path'])
            self.assertTrue(bundle.is_relative_to(store / 'judge-inputs'))
            self.assertEqual((bundle / 'tool').read_bytes(), content)
            self.assertFalse((store / 'judge-inputs/mcp.tar.gz').exists())
            self.assertEqual(result['sha256'], bootstrap.digest(result['manifest']))
            self.assertEqual(result['suite_verdict'], 'not implied by input staging')

    def test_import_failure_is_bounded_and_redacts_job_credentials(self):
        error = subprocess.CalledProcessError(1, ['docker', 'image', 'load'],
            stderr='prefix' * 1000 + '\x1b[31m token-secret invalid archive: missing manifest.json')
        with patch.dict(os.environ, {'CI_JOB_TOKEN': 'token-secret'}):
            message = str(bootstrap.import_failure(error))
        self.assertNotIn('token-secret', message)
        self.assertNotIn('\x1b', message)
        self.assertIn('[redacted]', message)
        self.assertIn('missing manifest.json', message)
        self.assertLess(len(message), 4200)

    def test_offline_import_checks_execution_bytes_without_registry_or_tls_changes(self):
        config = {'architecture': 'amd64', 'os': 'linux', 'config': {'Cmd': ['fixed'], 'Env': ['PATH=/bin']},
                  'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + 'a' * 64]}}
        config_raw = json.dumps(config).encode()
        config_sha = hashlib.sha256(config_raw).hexdigest()
        manifest_raw = json.dumps({'config': {'digest': 'sha256:' + config_sha}}).encode()
        manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            archive = Path(directory) / 'image.tar'
            with tarfile.open(archive, 'w') as output:
                for checksum, raw in [(config_sha, config_raw), (manifest_sha, manifest_raw)]:
                    item = tarfile.TarInfo('blobs/sha256/' + checksum)
                    item.size = len(raw)
                    output.addfile(item, io.BytesIO(raw))
            actual = {'Id': 'sha256:' + config_sha, 'Config': config['config'], 'Os': 'linux',
                      'Architecture': 'amd64', 'RootFS': {'Type': 'layers', 'Layers': config['rootfs']['diff_ids']}}
            def execute(argv, **kwargs):
                self.assertNotIn('pull', argv)
                self.assertNotIn('insecure', ' '.join(argv))
                self.assertEqual(argv[1:3], ['--host', 'unix:///fixed.sock'])
                if 'load' in argv:
                    if '--input' in argv:
                        self.assertEqual(argv[-1], str(archive))
                    else:
                        self.assertIn('stdin', kwargs)
                    return subprocess.CompletedProcess(argv, 0, 'Loaded image: fixed:tag\n')
                return subprocess.CompletedProcess(argv, 0, json.dumps([actual]))
            with patch.object(bootstrap, 'MANIFEST', manifest_sha), patch.object(bootstrap, 'run', side_effect=execute):
                self.assertEqual(bootstrap.load_tool_image(archive, 'unix:///fixed.sock', {}), actual['Id'])
                producer = Mock(stdout=io.BytesIO(b'fixed compatibility archive'))
                producer.wait.return_value = 0
                producer.poll.return_value = 0
                with patch.object(bootstrap.subprocess, 'Popen', return_value=producer) as exported:
                    self.assertEqual(bootstrap.load_tool_image(archive, 'unix:///fixed.sock', {},
                                     source_image='sha256:' + manifest_sha), actual['Id'])
                self.assertEqual(exported.call_args.args[0][-4:],
                                 ['save', '--platform', 'linux/amd64', 'sha256:' + manifest_sha])
                self.assertTrue(producer.stdout.closed)
                # The collector reuses the administrator's host import: inspect only.
                calls = []
                def inspect(argv, **kwargs):
                    calls.append(argv)
                    return execute(argv, **kwargs)
                with patch.object(bootstrap, 'run', side_effect=inspect):
                    self.assertEqual(bootstrap.inspect_tool_image(
                        archive, 'unix:///fixed.sock', {}, actual['Id']), actual['Id'])
                self.assertEqual([argv[3:5] for argv in calls], [['image', 'inspect']])
                with self.assertRaisesRegex(ValueError, 'unverified'):
                    bootstrap.load_tool_image(archive, 'unix:///fixed.sock', {}, source_image='floating:tag')
                actual['RootFS'] = {'Type': 'layers', 'Layers': ['sha256:' + 'f' * 64]}
                with self.assertRaisesRegex(ValueError, 'execution content'):
                    bootstrap.load_tool_image(archive, 'unix:///fixed.sock', {})
                with self.assertRaisesRegex(ValueError, 'execution content'):
                    bootstrap.inspect_tool_image(archive, 'unix:///fixed.sock', {}, actual['Id'])
                actual['Id'] = 'sha256:' + 'f' * 64
                with self.assertRaisesRegex(ValueError, 'identity'):
                    bootstrap.load_tool_image(archive, 'unix:///fixed.sock', {})


    def tool_fixture(self, directory):
        config = {'architecture': 'amd64', 'os': 'linux', 'config': {'Cmd': ['fixed']},
                  'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + 'a' * 64]}}
        config_raw = json.dumps(config).encode()
        config_sha = hashlib.sha256(config_raw).hexdigest()
        manifest_raw = json.dumps({'config': {'digest': 'sha256:' + config_sha}}).encode()
        manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
        archive = Path(directory) / 'image.tar'
        with tarfile.open(archive, 'w') as output:
            for checksum, raw in [(config_sha, config_raw), (manifest_sha, manifest_raw)]:
                item = tarfile.TarInfo('blobs/sha256/' + checksum)
                item.size = len(raw)
                output.addfile(item, io.BytesIO(raw))
        actual = {'Id': 'sha256:' + config_sha, 'Config': config['config'], 'Os': 'linux',
                  'Architecture': 'amd64', 'RootFS': {'Type': 'layers', 'Layers': config['rootfs']['diff_ids']}}
        return archive, manifest_sha, actual

    def test_collector_inspects_present_image_loads_only_when_absent_and_refuses_mismatch(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            archive, manifest_sha, actual = self.tool_fixture(directory)
            calls = []
            state = {'present': True}
            def execute(argv, **kwargs):
                calls.append(argv[3:5])
                if argv[3:5] == ['image', 'inspect']:
                    if not state['present']:
                        raise subprocess.CalledProcessError(1, argv, stderr='No such image')
                    return subprocess.CompletedProcess(argv, 0, json.dumps([actual]))
                if argv[3:5] == ['image', 'load']:
                    state['present'] = True
                    return subprocess.CompletedProcess(argv, 0, 'Loaded image: fixed:tag\n')
                self.fail(argv)
            with patch.object(bootstrap, 'MANIFEST', manifest_sha), patch.object(bootstrap, 'run', side_effect=execute):
                # Present and identical: inspect only, no load.
                self.assertEqual(bootstrap.inspect_tool_image(archive, 'unix:///h.sock', {}, actual['Id']), actual['Id'])
                self.assertEqual(calls, [['image', 'inspect']])
                # Absent: None, so the caller falls back to the full load path.
                state['present'] = False
                calls.clear()
                self.assertIsNone(bootstrap.inspect_tool_image(archive, 'unix:///h.sock', {}, actual['Id']))
                self.assertEqual(bootstrap.load_tool_image(archive, 'unix:///h.sock', {}), actual['Id'])
                self.assertEqual(calls, [['image', 'inspect'], ['image', 'load'], ['image', 'inspect']])
                # Present but different content or identity: refuse, never load.
                state['present'] = True
                calls.clear()
                actual['RootFS'] = {'Type': 'layers', 'Layers': ['sha256:' + 'f' * 64]}
                with self.assertRaisesRegex(ValueError, 'execution content'):
                    bootstrap.inspect_tool_image(archive, 'unix:///h.sock', {}, 'sha256:' + manifest_sha)
                actual['Id'] = 'sha256:' + 'f' * 64
                with self.assertRaisesRegex(ValueError, 'identity'):
                    bootstrap.inspect_tool_image(archive, 'unix:///h.sock', {}, 'sha256:' + manifest_sha)
                with self.assertRaisesRegex(ValueError, 'unverified'):
                    bootstrap.inspect_tool_image(archive, 'unix:///h.sock', {}, 'floating:tag')
                self.assertNotIn(['image', 'load'], calls)

    def test_archive_is_hashed_once_on_download_and_once_on_the_trust_boundary_copy(self):
        content = b'pinned archive bytes'
        pin = hashlib.sha256(content).hexdigest()
        class Source(io.BytesIO):
            def __enter__(self):
                return self
        opener = Mock()
        opener.open.return_value = Source(content)
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory, \
                patch.object(bootstrap, 'ARCHIVE_SHA256', pin), patch.object(bootstrap, 'ARCHIVE_BYTES', len(content)), \
                patch.object(bootstrap.urllib.request, 'build_opener', return_value=opener), \
                patch.object(bootstrap, 'digest', side_effect=AssertionError('file re-hash')) as rehash, \
                patch.object(sys, 'stdout', io.StringIO()):
            downloaded = Path(directory) / 'public-tools.tar'
            bootstrap.fetch_archive(downloaded, 'token')
            self.assertEqual(downloaded.read_bytes(), content)
            self.assertEqual(downloaded.stat().st_mode & 0o777, 0o444)
            copied = Path(directory) / 'image.tar'
            bootstrap.copy_verified(downloaded, copied)
            self.assertEqual(copied.read_bytes(), content)
            self.assertEqual(copied.stat().st_mode & 0o777, 0o444)
            rehash.assert_not_called()
            # A tampered source is refused and leaves no copy behind.
            downloaded.chmod(0o644)
            downloaded.write_bytes(b'tampered archive byte')
            with self.assertRaisesRegex(ValueError, 'copied public tooling archive differs'):
                bootstrap.copy_verified(downloaded, Path(directory) / 'second.tar')
            self.assertFalse((Path(directory) / 'second.tar').exists())
            # A tampered download is refused by the single streaming hash.
            opener.open.return_value = Source(b'x' * len(content))
            with self.assertRaisesRegex(ValueError, 'protected pin'):
                bootstrap.fetch_archive(Path(directory) / 'bad.tar', 'token')

    def test_concurrent_branches_are_all_joined_and_either_failure_fails_the_step(self):
        for failing in ('storage', 'archive'):
            with self.subTest(failing=failing):
                finished = []
                def branch(name):
                    def task():
                        if name == failing:
                            raise RuntimeError(name + ' failed')
                        time.sleep(.05)
                        finished.append(name)
                    return task
                with self.assertRaisesRegex(RuntimeError, failing + ' failed'):
                    bootstrap.concurrently(storage=branch('storage'), archive=branch('archive'))
                # The healthy branch ran to completion before the failure surfaced.
                self.assertEqual(finished, [name for name in ('storage', 'archive') if name != failing])
        self.assertEqual(bootstrap.concurrently(a=lambda: 1, b=lambda: 2), {'a': 1, 'b': 2})

    def test_timing_lines_follow_the_native_preparation_shape(self):
        out = io.StringIO()
        with patch.object(sys, 'stdout', out):
            with bootstrap.timed('checkout_copy'):
                pass
            with self.assertRaises(KeyError), bootstrap.timed('private_image_load'):
                raise KeyError('x')
        rows = [json.loads(line)['native_preparation'] for line in out.getvalue().splitlines()]
        self.assertEqual([(row['name'], row['status']) for row in rows],
                         [('bootstrap.checkout_copy', 'pass'), ('bootstrap.private_image_load', 'fail')])
        self.assertTrue(all({'started_at', 'finished_at', 'elapsed_seconds'} <= row.keys() for row in rows))


if __name__ == '__main__':
    unittest.main()
