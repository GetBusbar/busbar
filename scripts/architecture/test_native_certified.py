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
BINARY = b'\x7fELF certified'
SHA = hashlib.sha256(BINARY).hexdigest()


def receipt(job_id=11, pipeline=5, **changes):
    value = {'schema': certified.SCHEMA, 'status': 'pass', 'source': SOURCE, 'policy_revision': POLICY,
             'pipeline_id': str(pipeline), 'job_id': str(job_id), 'repository': 'GetBusbar/busbar',
             'binary_sha256': SHA,
             'certified_binary': {'sha256': SHA, 'bytes': len(BINARY), 'command': ['cargo', *certified.BUILD]}}
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
    def test_one_build_is_the_release_binary_linted_by_clippy(self):
        self.assertEqual(certified.BUILD, ['build', '--release', '--locked', '--manifest-path',
                                           'dist/default/Cargo.toml', '--bin', 'busbar'])
        env = certified.lint_environment({'RUSTC_WRAPPER': '', 'PATH': '/bin'})
        self.assertEqual(env['RUSTC_WRAPPER'], 'clippy-driver')
        self.assertEqual(env['RUSTC_WORKSPACE_WRAPPER'], '')
        self.assertEqual(env['CLIPPY_ARGS'], '-D__CLIPPY_HACKERY__warnings__CLIPPY_HACKERY__')
        self.assertIn('certified-build', native.OPTIMIZED_STEPS)

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
        certified.discard(self.q)
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
                certified_binary={'sha256': SHA, 'bytes': len(BINARY), 'command': ['cargo', 'build']})).encode()}),
        }
        for name, api in cases.items():
            with self.subTest(name=name), self.assertRaises(Violation):
                certified.stage(self.q, api)
            certified.discard(self.q)

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
    ENV = {'CI_PIPELINE_SOURCE': 'push', 'CI_COMMIT_BRANCH': 'main', 'CI_COMMIT_REF_PROTECTED': 'true',
           'CI_PROJECT_PATH': 'GetBusbar/busbar', 'CI_COMMIT_SHA': SOURCE, 'CI_PROJECT_ID': '3',
           'CI_PIPELINE_ID': '90', 'CI_JOB_ID': '91'}

    def api(self, native_sha=SHA, failed=None):
        jobs = [{'name': name, 'status': 'failed' if name == failed else 'success', 'id': index}
                for index, name in enumerate(release_certification.REQUIRED, start=11)]
        files = {'boundary-evidence/receipt.json@11': json.dumps(receipt(job_id=11, pipeline=5)).encode(),
                 'boundary-evidence/busbar@11': BINARY}
        for job_id, digest in ((12, SHA), (13, native_sha)):
            files[f'boundary-evidence/receipt.json@{job_id}'] = json.dumps({
                'status': 'pass', 'source': SOURCE, 'job_id': str(job_id), 'pipeline_id': '5',
                'policy_revision': POLICY, 'binary_sha256': digest,
                'certified_binary': {'sha256': digest}}).encode()
        return Api(jobs, files, [{'id': 5, 'source': 'push', 'sha': SOURCE, 'ref': 'qa'}])

    def test_main_releases_only_the_qa_certified_digest(self):
        record = release_certification.certify(self.api(), self.ENV)
        self.assertEqual(record['certified_binary']['sha256'], SHA)
        self.assertEqual(record['builds'], 0)
        self.assertEqual(record['qa_pipeline_id'], 5)

    def test_mismatch_or_missing_qa_means_no_release(self):
        with self.assertRaisesRegex(Violation, 'different binaries'):
            release_certification.certify(self.api(native_sha='e' * 64), self.ENV)
        with self.assertRaisesRegex(Violation, 'security-scans'):
            release_certification.certify(self.api(failed='security-scans'), self.ENV)
        empty = self.api()
        empty.pipelines = []
        with self.assertRaisesRegex(Violation, 'no successful qa'):
            release_certification.certify(empty, self.ENV)
        with self.assertRaisesRegex(Violation, 'protected core main'):
            release_certification.certify(self.api(), dict(self.ENV, CI_COMMIT_REF_PROTECTED='false'))


if __name__ == '__main__':
    unittest.main()
