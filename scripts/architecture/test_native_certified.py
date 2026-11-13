"""The one certified core binary: its build recipe, its consumers and the MAIN check."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from check import Violation
import native
import native_certified as certified
import release_certification

SOURCE, POLICY = 'a' * 40, 'b' * 40
CONFIG_URI = 'github.com/GetBusbar/busbar//ci/architecture-pipeline.yml@GetBusbar/busbar:' + POLICY + '@refs/heads/qa'


def discard(q):
    import shutil
    directory = q.control / certified.SUBJECT
    if directory.is_dir() and not directory.is_symlink():
        directory.chmod(0o755)
        shutil.rmtree(directory)
BINARY = b'\x7fELF certified'
SHA = hashlib.sha256(BINARY).hexdigest()


def receipt(job_id=11, pipeline=5, **changes):
    value = {'schema': certified.SCHEMA, 'status': 'pass', 'source': SOURCE, 'policy_revision': POLICY,
             'pipeline_id': str(pipeline), 'job_id': str(job_id), 'repository': 'GetBusbar/busbar',
             'binary_sha256': SHA, 'config_uri': CONFIG_URI,
             'certified_binary': {'sha256': SHA, 'bytes': len(BINARY), 'command': ['cargo', *certified.BUILD],
                                  'rustc_wrapper': '', 'clippy_args': []}}
    value.update(changes)
    return value


class Api:
    def __init__(self, jobs, files, pipelines=()):
        self.jobs, self.files, self.pipelines = jobs, files, list(pipelines)

    def json(self, path):
        if '/jobs?' in path:
            return self.jobs
        if 'pipelines?' in path:
            return self.pipelines
        raise AssertionError(path)

    def raw(self, path, limit):
        return self.files[path.split('/artifacts/', 1)[1] + '@' + path.split('/jobs/', 1)[1].split('/', 1)[0]]


class Recipe(unittest.TestCase):
    def test_one_build_is_a_plain_release_build(self):
        self.assertEqual(certified.BUILD, ['build', '--release', '--locked', '--manifest-path',
                                           'dist/default/Cargo.toml', '--bin', 'busbar'])
        env = certified.plain_environment({'RUSTC_WRAPPER': 'clippy-driver', 'CLIPPY_ARGS': '-D', 'PATH': '/bin'})
        self.assertEqual(env, {'RUSTC_WRAPPER': '', 'RUSTC_WORKSPACE_WRAPPER': '', 'PATH': '/bin'})
        # The release build keeps the conservative one-job budget until measured.
        self.assertIn(certified.STEP, native.OPTIMIZED_STEPS)
        scheduling = native.native_scheduling(type('E', (), {'config': {'resources': {
            'cpus': 4, 'memory_bytes': 6 * 1024**3}}})())
        self.assertEqual(native.step_build_jobs(certified.STEP, ['python3', 'capture'], scheduling), 1)

    def test_build_records_the_plain_command_and_measured_memory_peak(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'host/scripts').mkdir(parents=True)
            (base / 'host/dist/default').mkdir(parents=True)
            (base / 'host/scripts/ci-product-pins.json').write_text(json.dumps({'sdk': 'c' * 40}))
            (base / 'host/Cargo.lock').write_text('lock')
            (base / 'host/dist/default/Cargo.lock').write_text('lock')
            (base / 'trusted/ci').mkdir(parents=True)
            (base / 'trusted/ci/architecture-pipeline.yml').write_text('pipeline')

            class Q:
                pass
            q = Q()
            q.work, q.evidence, q.trusted = base / 'work', base / 'evidence', base / 'trusted'
            q.work.mkdir()
            q.evidence.mkdir()
            q.env = {'CARGO_TARGET_DIR': str(base / 'target'), 'RUSTC_WRAPPER': ''}
            q.receipt = {'source': SOURCE, 'policy_revision': POLICY, 'steps': [],
                         'native_scheduling': {'candidate_memory_bytes': 6 * 1024**3}}
            q.save, q.host = (lambda: None), (lambda: base / 'host')
            q.execution = type('E', (), {'container_path': staticmethod(
                lambda path: str(path).replace(str(base / 'target'), '/__busbar_candidate/target'))})()
            seen = {}

            def run(name, argv):
                seen['env'] = dict(q.env)
                q.receipt['steps'].append({'name': name, 'build_jobs': 1, 'resources': {
                    'memory_peak_bytes': 5 * 1024**3, 'memory_anon_peak_bytes': 3 * 1024**3,
                    'samples': 40, 'elapsed_seconds': 600.0}})
            q.run = run

            def controller(name, argv):
                seen['compiler_output'] = argv[argv.index('--compiler-output') + 1]
                (q.evidence / 'development-artifact/receipt.json').write_text('{}')
            q.run_controller = controller

            def collect(q_, source, destination, **kwargs):
                Path(destination).write_bytes(BINARY)
                return Path(destination)
            with patch('native.collect_output', collect):
                record = certified.build(q)
            self.assertEqual(seen['env']['RUSTC_WRAPPER'], '')
            self.assertNotIn('CLIPPY_ARGS', seen['env'])
            self.assertEqual(seen['compiler_output'], '/__busbar_candidate/target/release/busbar')
            self.assertEqual((record['rustc_wrapper'], record['clippy_args'], record['step']), ('', [], 'certified-build'))
            self.assertEqual(record['build_resources']['memory_peak_bytes'], 5 * 1024**3)
            self.assertEqual(record['build_resources']['build_jobs'], 1)
            self.assertEqual(record['build_resources']['memory_limit_bytes'], 6 * 1024**3)
            self.assertEqual(q.receipt['binary_sha256'], SHA)

    def test_profile_slot_is_inert_until_a_pinned_profile_is_given(self):
        env = {'CARGO_ENCODED_RUSTFLAGS': ''}
        self.assertEqual(certified.profile_environment(env), (env, None))
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / 'busbar.profdata'
            profile.write_bytes(b'profile')
            digest = hashlib.sha256(b'profile').hexdigest()
            changed, record = certified.profile_environment(env, {'path': profile, 'sha256': digest})
            self.assertEqual(changed['CARGO_ENCODED_RUSTFLAGS'], '-Cprofile-use=' + str(profile))
            self.assertEqual(record, {'sha256': digest})
            with self.assertRaisesRegex(Violation, 'differs'):
                certified.profile_environment(env, {'path': profile, 'sha256': '0' * 64})

    def test_dev_tier_tests_are_exactly_the_qa_root_workspace_steps(self):
        nextest = ['--no-fail-fast', '--test-threads', '4', '--tool-config-file', 'admission:/t/ci/native-nextest.toml']
        qa = dict(native.qa_test_commands(nextest))
        dev = native.core_test_commands(nextest)
        self.assertEqual([name for name, _ in dev], ['workspace-doctests', 'root-runtime'])
        # The same commands, features and nextest configuration as QA's steps.
        for name, command in dev:
            self.assertEqual(command, qa[name])
        root = dict(dev)['root-runtime']
        self.assertEqual(root[:6], ['cargo', 'nextest', 'run', '--workspace', '--locked', '--features'])
        self.assertEqual(root[6], 'busbar-kernel/timing,busbar-kernel/openapi-schema,busbar-core-admin/openapi-schema')
        self.assertEqual(root[7:], nextest)
        # Test steps keep the wider test compiler slot.
        scheduling = native.native_scheduling(None)
        scheduling.update(build_jobs=1, unoptimized_build_jobs=3, test_build_jobs=2)
        for name, command in dev:
            self.assertEqual(native.step_build_jobs(name, command, scheduling), 2)

    def test_lints_are_their_own_job_and_qa_tests_the_shipped_features(self):
        self.assertEqual([name for name, _ in native.CORE_CLIPPY_COMMANDS], ['root-clippy', 'default-clippy'])
        for _, command in native.CORE_CLIPPY_COMMANDS:
            self.assertEqual(command[:2], ['cargo', 'clippy'])
            self.assertIn('--all-targets', command)
            self.assertIn('--all-features', command)
            self.assertEqual(command[-2:], ['-D', 'warnings'])
        steps = dict(native.qa_test_commands(['--no-fail-fast']))
        shipped = steps['default-shipped-features']
        self.assertIn('dist/default/Cargo.toml', shipped)
        self.assertFalse(any(arg.startswith('--features') or arg == '--all-features' for arg in shipped))

    def test_dev_tier_policy_steps_cover_both_workspaces(self):
        names = [name for name, _, _ in native.CORE_POLICY_COMMANDS]
        self.assertEqual(names, ['dependency-policy', 'dependency-vet', 'default-dependency-policy',
                                 'default-dependency-vet'])


class Consumers(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        control = Path(self.dir.name)

        class Q:
            pass
        self.q = Q()
        self.q.control, self.q.execution = control, None
        self.q.receipt = {'source': SOURCE, 'policy_revision': POLICY}
        self.q.save = lambda: None
        self.env = patch.dict(os.environ, CI_PROJECT_ID='3', CI_PIPELINE_ID='5')
        self.env.start()

    def tearDown(self):
        self.env.stop()
        discard(self.q)
        self.dir.cleanup()

    def api(self, jobs=None, **files):
        jobs = jobs or [{'name': 'core-build', 'status': 'success', 'id': 11}]
        data = {'boundary-evidence/receipt.json@11': json.dumps(receipt()).encode(),
                'boundary-evidence/busbar@11': BINARY}
        data.update(files)
        return Api(jobs, data)

    def test_verified_binary_is_staged_read_only_with_its_digest(self):
        binary, staged = certified.stage(self.q, self.api())
        self.assertEqual(binary.read_bytes(), BINARY)
        self.assertEqual(staged['sha256'], SHA)
        self.assertEqual(self.q.receipt['binary_sha256'], SHA)
        self.assertFalse(os.access(binary.parent, os.W_OK) and os.getuid() != 0)
        certified.verify_unchanged(binary, staged)

    def test_anything_else_is_refused(self):
        cases = {
            'no job': self.api(jobs=[{'name': 'core-build', 'status': 'failed', 'id': 11}]),
            'two jobs': self.api(jobs=[{'name': 'core-build', 'status': 'success', 'id': 11}] * 2),
            'bytes': self.api(**{'boundary-evidence/busbar@11': BINARY + b'x'}),
            'source': self.api(**{'boundary-evidence/receipt.json@11': json.dumps(receipt(source='c' * 40)).encode()}),
            'job': self.api(**{'boundary-evidence/receipt.json@11': json.dumps(receipt(job_id=12)).encode()}),
            'pipeline': self.api(**{'boundary-evidence/receipt.json@11': json.dumps(receipt(pipeline=6)).encode()}),
            'command': self.api(**{'boundary-evidence/receipt.json@11': json.dumps(receipt(
                certified_binary={'sha256': SHA, 'bytes': len(BINARY), 'command': ['cargo', 'build'],
                                  'rustc_wrapper': '', 'clippy_args': []})).encode()}),
            'linted': self.api(**{'boundary-evidence/receipt.json@11': json.dumps(receipt(
                certified_binary={'sha256': SHA, 'bytes': len(BINARY), 'command': ['cargo', *certified.BUILD],
                                  'rustc_wrapper': 'clippy-driver', 'clippy_args': ['-D', 'warnings']})).encode()}),
        }
        for name, api in cases.items():
            with self.subTest(name=name), self.assertRaises(Violation):
                certified.stage(self.q, api)
            discard(self.q)

    def test_a_changed_subject_is_detected(self):
        binary, staged = certified.stage(self.q, self.api())
        binary.parent.chmod(0o755)
        binary.chmod(0o755)
        binary.write_bytes(b'other')
        with self.assertRaisesRegex(Violation, 'changed'):
            certified.verify_unchanged(binary, staged)


class SubjectBuild(unittest.TestCase):
    def test_conformance_suites_judge_the_staged_subject_without_building(self):
        import importlib.util
        path = Path(__file__).resolve().parents[2] / 'testing/conformance/subject_build.py'
        spec = importlib.util.spec_from_file_location('subject_build_under_test', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            subject = Path(directory) / 'busbar'
            subject.write_bytes(BINARY)
            with patch.dict(os.environ, {module.SUBJECT_ENV: str(subject), module.SUBJECT_SHA256_ENV: SHA}):
                self.assertEqual(module.busbar_path('/t'), str(subject))
                self.assertEqual(module.subject_argvs('/c', '/t'), [module.pack_argv('/t')])
                self.assertEqual(module.subject_argvs('/c', '/t', pack=False), [])
            with patch.dict(os.environ, {module.SUBJECT_ENV: str(subject), module.SUBJECT_SHA256_ENV: '0' * 64}):
                with self.assertRaises(SystemExit):
                    module.busbar_path('/t')
            env = {k: v for k, v in os.environ.items() if k != module.SUBJECT_ENV}
            with patch.dict(os.environ, env, clear=True):
                self.assertEqual(module.subject_argvs('/c', '/t')[0], module.busbar_argv('/c', '/t'))


class ReleaseCertification(unittest.TestCase):
    """QA retains the certified evidence without expiry; main certifies only from it."""
    BASE = {'CI_PROJECT_PATH': 'GetBusbar/busbar', 'CI_COMMIT_SHA': SOURCE, 'CI_PROJECT_ID': '3',
            'CI_COMMIT_REF_PROTECTED': 'true', 'CI_SERVER_HOST': 'github.com',
            'CI_CONFIG_REF_URI': CONFIG_URI}
    QA = dict(BASE, CI_PIPELINE_SOURCE='push', CI_COMMIT_BRANCH='qa', CI_PIPELINE_ID='5', CI_JOB_ID='30')
    MAIN = dict(BASE, CI_PIPELINE_SOURCE='push', CI_COMMIT_BRANCH='main', CI_PIPELINE_ID='90', CI_JOB_ID='91')

    def qa_files(self, native_sha=SHA, policy=POLICY):
        ids = {name: index for index, name in enumerate(release_certification.REQUIRED, start=11)}
        files = {'boundary-evidence/receipt.json@11': json.dumps(receipt(job_id=11, pipeline=5, policy_revision=policy)).encode(),
                 'boundary-evidence/busbar@11': BINARY}
        for name in release_certification.RECEIPT_JOBS[1:]:
            digest = native_sha if name == 'native-qualification' else SHA
            value = {'status': 'pass', 'source': SOURCE, 'job_id': str(ids[name]), 'pipeline_id': '5',
                     'policy_revision': policy, 'config_uri': CONFIG_URI}
            if name in release_certification.CERTIFYING:
                value.update(binary_sha256=digest, certified_binary={'sha256': digest})
            if name == 'core-conformance':
                value['conformance_subject'] = {'kind': 'certified-release', 'sha256': SHA}
            if name == 'core-conformance-debug':
                value['conformance_subject'] = {'kind': 'debug-assertions', 'profile': 'dev'}
            if name == 'core-clippy':
                value['schema'] = 'busbar.core-clippy/1'
            files[f'boundary-evidence/receipt.json@{ids[name]}'] = json.dumps(value).encode()
        jobs = [{'name': name, 'status': 'success', 'id': job_id} for name, job_id in ids.items()]
        return jobs, files

    def record(self, **changes):
        jobs, files = self.qa_files(**changes)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'boundary-evidence/qa-certification.json'
            output.parent.mkdir()
            record = release_certification.record_qa(Api(jobs, files), self.QA, output)
            output.write_text(json.dumps(record))
            retained = {'boundary-evidence/qa-certification.json@30': output.read_bytes(),
                        'boundary-evidence/qa-certified/busbar@30': (output.parent / 'qa-certified/busbar').read_bytes()}
            for path in (output.parent / 'qa-certified/receipts').iterdir():
                retained['boundary-evidence/qa-certified/receipts/' + path.name + '@30'] = path.read_bytes()
        return record, jobs + [{'name': 'qa-certification', 'status': 'success', 'id': 30}], retained

    def main_api(self, jobs, retained):
        return Api(jobs, retained, [{'id': 5, 'source': 'push', 'sha': SOURCE, 'ref': 'qa'}])

    def test_qa_record_then_main_releases_only_the_qa_certified_digest(self):
        record, jobs, retained = self.record()
        self.assertEqual((record['schema'], record['signed']), (release_certification.QA_SCHEMA, False))
        self.assertEqual(record['after_signing'], ['sigstore', 'slsa-verifier'])
        # Main reads only qa-certification's never-expiring artifacts.
        result = release_certification.certify(self.main_api(jobs, retained), self.MAIN)
        self.assertEqual(result['certified_binary']['sha256'], SHA)
        self.assertEqual((result['builds'], result['qa_pipeline_id'], result['qa_certification_job_id']), (0, 5, 30))

    def test_mismatch_or_missing_qa_means_no_release(self):
        jobs, files = self.qa_files(native_sha='e' * 64)
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(Violation, 'different binaries'):
            release_certification.record_qa(Api(jobs, files), self.QA, Path(directory) / 'r.json')
        _, jobs, retained = self.record()
        failed = [dict(job, status='failed') if job['name'] == 'security-scans' else job for job in jobs]
        with self.assertRaisesRegex(Violation, 'security-scans'):
            release_certification.certify(self.main_api(failed, retained), self.MAIN)
        without = [job for job in jobs if job['name'] != 'qa-certification']
        with self.assertRaisesRegex(Violation, 'qa-certification'):
            release_certification.certify(self.main_api(without, retained), self.MAIN)
        empty = self.main_api(jobs, retained)
        empty.pipelines = []
        with self.assertRaisesRegex(Violation, 'no successful qa'):
            release_certification.certify(empty, self.MAIN)
        with self.assertRaisesRegex(Violation, 'protected core main'):
            release_certification.certify(self.main_api(jobs, retained), dict(self.MAIN, CI_COMMIT_REF_PROTECTED='false'))
        tampered = dict(retained, **{'boundary-evidence/qa-certified/busbar@30': BINARY + b'x'})
        with self.assertRaisesRegex(Violation, 'binary differs'):
            release_certification.certify(self.main_api(jobs, tampered), self.MAIN)

    def test_controller_revision_must_be_the_approved_one(self):
        _, jobs, retained = self.record()
        other = CONFIG_URI.replace(POLICY, 'd' * 40)
        with self.assertRaisesRegex(Violation, 'not the approved'):
            release_certification.certify(self.main_api(jobs, retained), dict(self.MAIN, CI_CONFIG_REF_URI=other))
        jobs_, files = self.qa_files(policy='d' * 40)
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(Violation, 'approved'):
            release_certification.record_qa(Api(jobs_, files), self.QA, Path(directory) / 'r.json')


if __name__ == '__main__':
    unittest.main()
