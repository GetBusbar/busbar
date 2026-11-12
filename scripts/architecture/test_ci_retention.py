"""Negative controls for the in-CI retention decision (ci_retention.py)."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_retention as retention  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
POLICY = 'a' * 40
HOST = 'git.example.test'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def git(root, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@example.test', GIT_COMMITTER_NAME='t',
               GIT_COMMITTER_EMAIL='t@example.test', GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1')
    return subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True,
                          text=True, env=env).stdout.strip()


def archive(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zipped:
        for name, raw in members.items():
            zipped.writestr('boundary-evidence/' + name, raw)
    return buffer.getvalue()


class FakeApi:
    def __init__(self):
        self.rows, self.raws, self.calls = {}, {}, []

    def json(self, path):
        self.calls.append(path)
        if path not in self.rows:
            raise retention.Fresh('CI_JOB_TOKEN read of ' + path.split('?')[0] + ' refused (HTTP 404)')
        return copy.deepcopy(self.rows[path])

    def raw(self, path, limit=None):
        self.calls.append(path)
        if path not in self.raws:
            raise retention.Fresh('CI_JOB_TOKEN read of ' + path + ' refused (HTTP 404)')
        return self.raws[path]


class Fixture(unittest.TestCase):
    project, kind = retention.CORE, 'native-qualification'

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.root = Path(self.tmp.name) / 'repo'
        self.root.mkdir()
        git(self.root, 'init', '-q', '-b', 'dev')
        self.write({'Cargo.toml': '[workspace]\n', 'crates/a/src/lib.rs': 'pub fn a() {}\n',
                    'README.md': '# readme\n', 'docs/guide.md': '# guide\n',
                    'CONTRIBUTING.md': 'contribute\n', '.gitlab/issue_templates/bug.md': 'bug\n',
                    '.busbar-ref': 'f' * 40 + '\n'})
        self.original = self.commit()
        self.api = FakeApi()
        self.add_job(100, 50, self.original)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, files):
        for name, text in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

    def commit(self, files=None):
        if files:
            self.write(files)
        git(self.root, 'add', '-A')
        git(self.root, 'commit', '-q', '--allow-empty', '-m', 'c')
        return git(self.root, 'rev-parse', 'HEAD')

    def job(self, job_id, pipeline_id, source, *, size=None):
        return {'id': job_id, 'name': self.kind, 'status': 'success', 'ref': 'dev', 'tag': False,
                'allow_failure': False, 'commit': {'id': source}, 'runner': {'id': 32},
                'finished_at': '2026-11-11T00:00:00Z', 'artifacts_file': {'size': size},
                'pipeline': {'id': pipeline_id, 'project_id': 3, 'ref': 'dev', 'sha': source, 'source': 'push'}}

    def receipt(self, job_id, pipeline_id, source, host=None):
        value = {'schema': retention.RECEIPT_SCHEMAS[self.kind], 'status': 'pass', 'repository': self.project,
                 'source': source, 'job_id': str(job_id), 'pipeline_id': str(pipeline_id),
                 'policy_revision': POLICY,
                 'config_uri': HOST + '/' + self.project + '//ci/architecture-pipeline.yml@GetBusbar/busbar:'
                               + POLICY + '@refs/heads/dev',
                 'steps': [{'name': 'root-runtime', 'status': 'pass', 'exit_code': 0,
                            'stdout_sha256': sha(b'out'), 'stderr_sha256': sha(b'err')}]}
        if host:
            value['host_revision'] = host
        return value

    def add_job(self, job_id, pipeline_id, source, *, receipt=None, members=None, host=None, listed=True):
        receipt = receipt or self.receipt(job_id, pipeline_id, source, host)
        members = members if members is not None else {
            'receipt.json': json.dumps(receipt).encode(), 'root-runtime.stdout': b'out',
            'root-runtime.stderr': b'err'}
        raw = archive(members)
        job = self.job(job_id, pipeline_id, source, size=len(raw))
        self.api.raws['projects/3/jobs/' + str(job_id) + '/artifacts'] = raw
        self.api.rows.setdefault('projects/3/pipelines/' + str(pipeline_id) + '/jobs?per_page=100', []).append(job)
        if listed:
            self.api.rows.setdefault('projects/3/jobs?scope[]=success&per_page=100&page=1', []).insert(0, job)
        return job, raw

    def env(self, source, **overrides):
        value = {'CI_PIPELINE_SOURCE': 'push', 'CI_COMMIT_BRANCH': 'dev', 'CI_COMMIT_REF_PROTECTED': 'true',
                 'CI_JOB_NAME': self.kind, 'CI_PROJECT_PATH': self.project, 'CI_PROJECT_ID': '3',
                 'CI_JOB_ID': '200', 'CI_PIPELINE_ID': '60', 'CI_COMMIT_SHA': source, 'CI_SERVER_HOST': HOST}
        value.update(overrides)
        return value

    def decide(self, source, **overrides):
        return retention.decide(self.env(source, **overrides), POLICY, retention.Git(self.root), self.api)

    def assertFresh(self, result, pattern):
        decision, reasons = result
        self.assertEqual(decision, 'fresh', reasons)
        self.assertRegex('\n'.join(reasons), pattern)

    def assertRetained(self, result, original):
        decision, receipt = result
        self.assertEqual(decision, 'retained', receipt)
        self.assertEqual(receipt['original']['job_id'], original)
        self.assertNotIn('status', receipt)
        return receipt


class Decisions(Fixture):
    def test_excluded_community_doc_change_is_retained_with_original_reference(self):
        current = self.commit({'CONTRIBUTING.md': 'changed\n', '.gitlab/issue_templates/bug.md': 'x\n'})
        receipt = self.assertRetained(self.decide(current), 100)
        self.assertEqual(receipt['schema'], retention.SCHEMA)
        self.assertEqual(receipt['original']['archive_sha256'],
                         sha(self.api.raws['projects/3/jobs/100/artifacts']))
        self.assertEqual(receipt['original']['pipeline_id'], 50)
        self.assertEqual(receipt['identity']['content_excluded'],
                         ['.gitlab/issue_templates/bug.md', 'CONTRIBUTING.md'])

    def test_identical_tree_is_retained(self):
        self.assertRetained(self.decide(self.commit()), 100)

    def test_changed_source_byte_in_consumed_path_runs_fresh(self):
        current = self.commit({'crates/a/src/lib.rs': 'pub fn a() { }\n'})
        self.assertFresh(self.decide(current), 'job 100 inputs differ: crates/a/src/lib.rs')
        self.assertFalse(any(call.endswith('/artifacts') for call in self.api.calls))

    def test_consumed_docs_and_readme_run_fresh(self):
        for name in ('docs/guide.md', 'README.md'):
            with self.subTest(name=name):
                current = self.commit({name: 'changed ' + name + '\n'})
                self.assertFresh(self.decide(current), 'inputs differ: ' + re.escape(name))

    def test_added_excluded_path_changes_identity(self):
        current = self.commit({'CODE_OF_CONDUCT.md': 'new\n'})
        self.assertFresh(self.decide(current), 'inputs differ: CODE_OF_CONDUCT.md')

    def test_named_excluded_file_stays_hashed(self):
        self.commit({'crates/a/src/lib.rs': 'const C: &str = include_str!("../../../CONTRIBUTING.md");\n'})
        base = git(self.root, 'rev-parse', 'HEAD')
        self.api = FakeApi()
        self.add_job(101, 51, base)
        current = self.commit({'CONTRIBUTING.md': 'changed\n'})
        self.assertFresh(self.decide(current), 'CONTRIBUTING.md stays hashed: named by crates/a/src/lib.rs')

    def test_unreviewed_markdown_walker_disables_exclusion(self):
        self.commit({'crates/a/build.rs': 'fn main() { glob("*.md"); }\n'})
        base = git(self.root, 'rev-parse', 'HEAD')
        self.api = FakeApi()
        self.add_job(101, 51, base)
        current = self.commit({'CONTRIBUTING.md': 'changed\n'})
        self.assertFresh(self.decide(current), 'unreviewed markdown walker in crates/a/build.rs')

    def test_wrong_project_ref_kind_status_or_tag_is_not_an_original(self):
        current = self.commit()
        mutations = {'project': lambda j: j['pipeline'].update(project_id=4),
                     'ref': lambda j: j.update(ref='feature'),
                     'pipeline ref': lambda j: j['pipeline'].update(ref='feature'),
                     'kind': lambda j: j.update(name='security-scans'),
                     'failed': lambda j: j.update(status='failed'),
                     'tag': lambda j: j.update(tag=True),
                     'optional': lambda j: j.update(allow_failure=True),
                     'merge request': lambda j: j['pipeline'].update(source='merge_request_event'),
                     'sha': lambda j: j['pipeline'].update(sha='0' * 40)}
        listing = 'projects/3/jobs?scope[]=success&per_page=100&page=1'
        pristine = copy.deepcopy(self.api.rows[listing])
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                self.api.rows[listing] = copy.deepcopy(pristine)
                mutate(self.api.rows[listing][0])
                self.assertFresh(self.decide(current), 'no authenticated successful native-qualification')

    def test_forged_or_altered_receipt_and_archive_are_rejected(self):
        current = self.commit()
        good = self.receipt(100, 50, self.original)
        cases = {
            'receipt project': ({**good, 'repository': 'GetBusbar/other'}, None),
            'receipt job id': ({**good, 'job_id': '99'}, None),
            'receipt source': ({**good, 'source': '0' * 40}, None),
            'policy revision': ({**good, 'policy_revision': 'b' * 40}, None),
            'config uri': ({**good, 'config_uri': good['config_uri'].replace('dev', 'main')}, None),
            'not passing': ({**good, 'status': 'fail'}, None),
            'failed step': ({**good, 'steps': [{**good['steps'][0], 'status': 'fail', 'exit_code': 1}]}, None),
            'altered log digest': (good, {'root-runtime.stdout': b'tampered'}),
            'missing log': (good, {'root-runtime.stdout': None}),
            'missing receipt': (None, {'receipt.json': None}),
            'malformed receipt': (None, {'receipt.json': b'{not json'}),
        }
        for label, (receipt, override) in cases.items():
            with self.subTest(label=label):
                self.api = FakeApi()
                members = {'receipt.json': json.dumps(receipt).encode(), 'root-runtime.stdout': b'out',
                           'root-runtime.stderr': b'err'}
                for name, raw in (override or {}).items():
                    if raw is None:
                        members.pop(name)
                    else:
                        members[name] = raw
                self.add_job(100, 50, self.original, members=members)
                self.assertFresh(self.decide(current), 'rejected evidence')

    def test_archive_size_differing_from_server_record_is_rejected(self):
        current = self.commit()
        self.api.raws['projects/3/jobs/100/artifacts'] += b'x'
        self.assertFresh(self.decide(current), 'archive size differs from server record')

    def test_missing_api_access_runs_fresh_with_reason(self):
        current = self.commit()
        self.api.rows.clear()
        self.assertFresh(self.decide(current), r'CI_JOB_TOKEN read of projects/3/jobs refused \(HTTP 404\)')

    def test_real_client_maps_refused_job_token_to_fresh(self):
        api = retention.Api({'CI_SERVER_URL': 'https://' + HOST, 'CI_API_V4_URL': 'https://' + HOST + '/api/v4',
                             'CI_JOB_TOKEN': 'token'})
        refused = urllib.error.HTTPError('u', 403, 'Forbidden', {}, None)
        with mock.patch('urllib.request.OpenerDirector.open', side_effect=refused):
            with self.assertRaisesRegex(retention.Fresh, r'refused \(HTTP 403\); job token needs read_jobs'):
                api.json('projects/3/jobs?scope[]=success')
        with self.assertRaisesRegex(retention.Fresh, 'non-canonical'):
            retention.Api({'CI_SERVER_URL': 'http://' + HOST, 'CI_API_V4_URL': 'http://' + HOST + '/api/v4',
                           'CI_JOB_TOKEN': 'token'})

    def test_only_ordinary_protected_dev_pushes_retain(self):
        current = self.commit()
        for overrides, pattern in (({'CI_PIPELINE_SOURCE': 'api'}, 'not an ordinary dev push'),
                                   ({'CI_PIPELINE_SOURCE': 'schedule'}, 'not an ordinary dev push'),
                                   ({'CI_PIPELINE_SOURCE': 'merge_request_event'}, 'not an ordinary dev push'),
                                   ({'CI_COMMIT_BRANCH': 'main'}, 'protected dev'),
                                   ({'CI_COMMIT_REF_PROTECTED': 'false'}, 'protected dev'),
                                   ({'CI_JOB_NAME': 'security-scans'}, 'not retainable')):
            with self.subTest(overrides=overrides):
                self.assertFresh(self.decide(current, **overrides), pattern)

    def test_retained_job_is_followed_to_its_authenticated_original(self):
        middle = self.commit({'CONTRIBUTING.md': 'one\n'})
        first = self.decide(middle)
        receipt = self.assertRetained(first, 100)
        receipt['job_id'], receipt['pipeline_id'] = 150, 55
        self.add_job(150, 55, middle, members={'retained.json': json.dumps(receipt).encode()})
        current = self.commit({'CONTRIBUTING.md': 'two\n'})
        followed = self.assertRetained(self.decide(current), 100)
        self.assertEqual(followed['original']['via_retained_job_id'], 150)
        # A retained receipt whose original digest is forged is never credited.
        receipt['original']['archive_sha256'] = '0' * 64
        self.api = FakeApi()
        self.add_job(100, 50, self.original, listed=False)
        self.add_job(150, 55, middle, members={'retained.json': json.dumps(receipt).encode()})
        self.assertFresh(self.decide(current), 'original archive digest differs')

    def test_unexpected_internal_error_is_never_success(self):
        current = self.commit()
        with mock.patch.object(retention, 'verify_original', side_effect=RuntimeError('boom')):
            self.assertFresh(self.decide(current), 'internal error: RuntimeError')


class PluginHost(Fixture):
    project = 'GetBusbar/busbar-plane-llm'

    def setUp(self):
        super().setUp()
        self.api = FakeApi()
        self.add_job(100, 50, self.original, host='c' * 40)

    def test_same_host_retains_and_changed_host_runs_fresh(self):
        current = self.commit({'CONTRIBUTING.md': 'changed\n'})
        self.assertRetained(self.decide(current, BUSBAR_ADMISSION_CORE_REVISION='c' * 40), 100)
        self.assertFresh(self.decide(current, BUSBAR_ADMISSION_CORE_REVISION='d' * 40),
                         'job 100 identity differs')

    def test_core_conformance_kind_is_core_only(self):
        current = self.commit()
        self.assertFresh(self.decide(current, CI_JOB_NAME='core-conformance'), 'not retainable')


class CommandLine(Fixture):
    def run_main(self, current, decision):
        output = self.root / 'boundary-evidence/retained.json'
        with mock.patch.object(retention, 'decide', return_value=decision), \
                mock.patch.object(retention, 'Api'), mock.patch.dict(os.environ, self.env(current)):
            code = retention.main(['--policy', POLICY, '--checkout', str(self.root), '--output', str(output)])
        return code, output

    def test_fresh_writes_nothing_and_retained_writes_receipt(self):
        current = self.commit()
        code, output = self.run_main(current, ('fresh', ['no authenticated original']))
        self.assertEqual((code, output.parent.exists()), (retention.FRESH, False))
        decision = self.decide(current)
        code, output = self.run_main(current, decision)
        self.assertEqual(code, retention.RETAINED)
        self.assertEqual(json.loads(output.read_text())['original']['job_id'], 100)

    def test_candidate_supplied_evidence_directory_runs_fresh(self):
        current = self.commit()
        (self.root / 'boundary-evidence').mkdir()
        code, output = self.run_main(current, self.decide(current))
        self.assertEqual(code, retention.FRESH)
        self.assertFalse(output.exists())


class Pipeline(unittest.TestCase):
    """The strict job graph: retention runs before bootstrap; schedules run security only."""

    def setUp(self):
        self.text = (REPO / 'ci/architecture-pipeline.yml').read_text()
        self.blocks = dict(re.findall(r'^([a-z][a-z-]*):\n((?:(?: .*)?\n)*)', self.text, re.M))

    def test_schedule_runs_security_only(self):
        self.assertIn("- if: '$CI_PIPELINE_SOURCE == \"schedule\" && $CI_COMMIT_BRANCH == \"dev\"'",
                      self.blocks['workflow'])
        never = "    - if: '$CI_PIPELINE_SOURCE == \"schedule\"'\n      when: never\n"
        for job in ('native-qualification', 'core-conformance'):
            self.assertIn(never, self.blocks[job], job)
        self.assertNotIn('"schedule"', self.blocks['security-scans'])
        self.assertIn('  rules:\n', self.blocks['security-scans'])
        website = self.blocks['website-dev']
        self.assertNotIn('"schedule"', website)
        self.assertEqual(re.findall(r'CI_PIPELINE_SOURCE == "(\w+)"', website), ['push', 'push'])

    def test_retention_decides_before_bootstrap_for_expensive_kinds_only(self):
        script = self.blocks['native-qualification']
        decision = script.index("scripts/architecture/ci_retention.py")
        self.assertLess(script.index("in ('native-qualification', 'core-conformance'):"), decision)
        self.assertLess(decision, script.index('if command is not None:\n              subprocess.run(command'))
        self.assertIn("if decision.returncode == 0 and retained.is_file() and not retained.is_symlink():\n"
                      "                  command = None", script)
        self.assertEqual(self.text.count('ci_retention.py'), 1)
        self.assertNotRegex(self.text, r'(?m)^\s*(needs|dependencies|include|default):')
        self.assertNotRegex(self.text, r'\$(BUSBAR_)?(SKIP|RETAIN)')

    def test_owner_workstation_grammar_still_accepts_the_graph(self):
        from reuse_evidence import independent_qualification_job
        for job in ('native-qualification', 'security-scans', 'core-conformance'):
            self.assertTrue(independent_qualification_job(self.text.encode(), job))


class RepositoryProof(unittest.TestCase):
    """Prove the content-excluded set on this repository's own committed tree."""

    def test_excluded_set_is_unreferenced_and_never_includes_consumed_docs(self):
        try:
            head = git(REPO, 'rev-parse', 'HEAD')
        except (subprocess.CalledProcessError, OSError):
            self.skipTest('not a Git checkout')
        objects = retention.Git(REPO)
        tree = objects.tree(head)
        excluded, notes = retention.excluded_paths(retention.CORE, tree, objects)
        for path in excluded:
            self.assertTrue(retention.excluded_candidate(path, tree[path][0]), path)
            self.assertFalse(path.startswith('docs/') or path == 'README.md', path)
        scanned = {path: oid for path, (_, oid) in tree.items()
                   if path not in excluded and not path.endswith('.md')}
        contents = objects.blobs(scanned.values())
        names = {Path(path).name.encode() for path in excluded}
        self.assertEqual([path for path, oid in scanned.items()
                          if any(name in contents[oid] for name in names)], [])
        # Consumers that make docs/** and README.md inputs (never excluded).
        for reader, needle in (('dist/default/tests/docs_examples.rs', b'read_dir(root.join("docs"))'),
                               ('crates/busbar-kernel-audit/src/bin/audit_verify/mod.rs', b'docs/audit-chain'),
                               ('dist/default/tests/product/admin_cross_plane/keys.rs', b'docs/admin-api.md')):
            if reader in tree:
                self.assertIn(needle, objects.blobs([tree[reader][1]])[tree[reader][1]], reader)
        if not any(note.startswith('content exclusion disabled') for note in notes):
            self.assertTrue(any('/' not in p and p.endswith('.md') for p in excluded), excluded)


if __name__ == '__main__':
    unittest.main()
