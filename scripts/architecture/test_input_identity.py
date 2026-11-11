"""Targeted proof and dependency-invalidation regressions; no builds or network."""
import ast
import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from input_identity import (CORE, GitObjects, component_identity, compute_identity,
                            encoded, make_proof, plan_reuse, preparation_source_identity,
                            retained_check_identity, verify_reuse, LEGACY_STANDALONE_SELECTOR,
                            OIDC_STANDALONE_SELECTOR, PREPARATION_SELECTOR,
                            default_artifact_reader_identity, product_input_source_identity)


OWNER = 'GetBusbar/busbar-secret-example'
SOURCE, POLICY, HOST, SDK = (str(index) * 40 for index in range(1, 5))
NEW = 'a' * 40
NOW = dt.datetime(2026, 11, 11, 12, tzinfo=dt.timezone.utc)
DATABASE = {'updated_at': '2026-11-11T01:00:00Z', 'sha256': 'b' * 64, 'metadata_sha256': 'c' * 64}


def artifact_reader_pair(filename):
    """Exercise real module checks with only the approved reader-plumbing delta.

    Works from either published form without historical Git objects/shallow refs.
    All statements/guards come from the actual module, never a stubbed validator.
    """
    text = Path(__file__).with_name(filename).read_text()
    module = ast.parse(text)
    names = {'blob', 'plan'} if filename == 'product_artifacts.py' else {'load_product_inputs'}
    selected = [n for n in module.body if isinstance(n, ast.FunctionDef) and n.name in names
                or filename == 'native_product_inputs.py' and isinstance(n, ast.ImportFrom)
                and n.module == 'product_artifacts']
    old = copy.deepcopy(selected)
    for node in old:
        if isinstance(node, ast.ImportFrom):
            node.names = [item for item in node.names if item.name != 'git']
            continue
        node.args.kwonlyargs, node.args.kw_defaults = [], []
        node.body = [item for item in node.body if not isinstance(item, ast.FunctionDef)
                     or item.name != 'canonical_git']
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                child.keywords = [item for item in child.keywords if item.arg != 'git_reader']
            if isinstance(child, ast.Name) and child.id == 'git_reader':
                child.id = 'git'
    new = copy.deepcopy(old)
    for node in new:
        if isinstance(node, ast.ImportFrom):
            node.names.insert(0, ast.alias(name='git'))
            continue
        if node.name in ('blob', 'plan'):
            node.args.kwonlyargs = [ast.arg(arg='git_reader')]
            node.args.kw_defaults = [ast.Name(id='git', ctx=ast.Load())]
            for child in ast.walk(node):
                if node.name == 'blob' and isinstance(child, ast.Name) and child.id == 'git':
                    child.id = 'git_reader'
                if node.name == 'plan' and isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id == 'blob':
                    child.keywords.append(ast.keyword(arg='git_reader', value=ast.Name(id='git_reader', ctx=ast.Load())))
            # The default itself must remain the generic reader.
            node.args.kw_defaults = [ast.Name(id='git', ctx=ast.Load())]
        else:
            helper = ast.parse('''def canonical_git(source, *args):
    require(Path(source).parent == work / "canonical-inputs", "unexpected canonical owner source")
    return git(source, "-c", "safe.directory=", "-c", "safe.directory=" + str(source), *args)
''').body[0]
            index = next(i for i, item in enumerate(node.body) if isinstance(item, ast.Assign)
                         and isinstance(item.value, ast.Call) and isinstance(item.value.func, ast.Name)
                         and item.value.func.id == 'plan')
            node.body[index].value.keywords.append(ast.keyword(arg='git_reader', value=ast.Name(id='canonical_git', ctx=ast.Load())))
            node.body.insert(index, helper)
    def render(nodes):
        lines = text.splitlines(keepends=True)
        for before, after in reversed(list(zip(selected, nodes))):
            lines[before.lineno - 1:before.end_lineno] = [ast.unparse(ast.fix_missing_locations(after)) + '\n']
        return ''.join(lines).encode()
    return render(old), render(new)


class Objects:
    def __init__(self):
        core = {
            'Cargo.toml': '[workspace.dependencies]\nsyn="2"\n',
            'Cargo.lock': 'version=4\n[[package]]\nname="core"\nversion="1.0.0"\n',
            'rust-toolchain.toml': '[toolchain]\nchannel="1.98.0"\n',
            'crates/core/src/lib.rs': 'pub fn runtime() {}',
            'ci/architecture.toml': '[repositories."' + OWNER + '"]\nkind="secret"\n',
            'ci/architecture-pipeline.yml': 'protected controller',
            'ci/native.json': '{"image":"sha256:abc","isolation":true}',
            'ci/security/tools.json': (Path(__file__).resolve().parents[2] / 'ci/security/tools.json').read_text(),
            'scripts/architecture/native.py': 'required checks, assertions and feature flags',
            'scripts/security/scan.py': (Path(__file__).resolve().parents[1] / 'security/scan.py').read_text(),
            'conformance/ci-coverage.json': json.dumps({'schema': 'busbar.conformance.ci-coverage/1',
                'suites': {'owner': {'repo': OWNER, 'script_sha256': 'd' * 64},
                           'other': {'repo': 'GetBusbar/other', 'source_commit': SOURCE}}}),
            'scripts/ci-product-pins.json': json.dumps({'sdk': SDK, 'products': [{'commit': SOURCE}]}),
            'dist/default/Cargo.lock': 'original assembly graph',
            'testing/evidence-conformance/external-rbac/test.py': 'core-only rig',
        }
        self.files = {(CORE, rev): dict(core) for rev in (POLICY, HOST, SDK)}
        self.files[OWNER, SOURCE] = {'Cargo.lock': 'locked dependencies', 'build.rs': 'embed Git revision',
                                     'testing/fixture.py': 'owner fixture', '.busbar-ref': SDK}

    def tree(self, repository, revision):
        return {path: {'mode': '100644', 'blob': hashlib.sha1(data.encode()).hexdigest()}
                for path, data in self.files[repository, revision].items()}

    def blob(self, repository, revision, path):
        return self.files[repository, revision][path].encode()

    def changed(self, repository, revision, path=None, value=None):
        self.files[repository, NEW] = dict(self.files[repository, revision])
        if path:
            self.files[repository, NEW][path] = value


class Reuse(unittest.TestCase):
    def setUp(self):
        self.objects = Objects()
        self.original = dict(repository=OWNER, source=SOURCE, policy=POLICY, host=HOST, sdk=SDK,
                             job='native-qualification')
        self.requested = dict(self.original)
        self.artifact = b'original protected job archive bytes'
        self.calls = []

    def receipt(self, job='native-qualification'):
        receipt = dict(repository=OWNER, source=SOURCE, policy_revision=POLICY,
                       pipeline_id='10', job_id='11', status='pass')
        if job == 'security-scans':
            receipt['database'] = dict(DATABASE)
        else:
            receipt.update(host_revision=HOST, sdk_revision=SDK)
        return encoded(receipt)

    def auth(self, original, receipt, digest):
        self.calls.append('auth')
        return receipt['pipeline_id'] == '10' and receipt['job_id'] == '11' and digest == hashlib.sha256(self.artifact).hexdigest()

    def validate(self, original, receipt, artifact):
        self.calls.append('validate')
        return artifact == self.artifact and json.loads(receipt)['status'] == 'pass'

    def kwargs(self):
        return dict(receipt_bytes=self.receipt(self.original['job']), artifact_bytes=self.artifact,
                    authenticate_original=self.auth, validate_original=self.validate,
                    database=DATABASE, now=NOW)

    def proof(self, scope='execution-equivalent'):
        return make_proof(self.original, self.requested, self.objects, scope=scope, **self.kwargs())

    def test_identical_inputs_reuse_requires_authentication_and_validation_each_time(self):
        proof = self.proof()
        before = self.kwargs()['receipt_bytes']
        result = verify_reuse(proof, self.requested, self.objects, **self.kwargs())
        self.assertEqual(self.calls, ['auth', 'validate', 'auth', 'validate'])
        self.assertEqual(result['scope'], 'execution-equivalent')
        self.assertEqual(before, self.kwargs()['receipt_bytes'])
        self.assertEqual(result['original'], self.original)

    def test_native_same_tree_different_source_revision_refuses_git_semantic_alias(self):
        self.objects.changed(OWNER, SOURCE)
        self.requested['source'] = NEW
        for scope in ('execution-equivalent', 'retained-component'):
            with self.subTest(scope=scope), self.assertRaisesRegex(ValueError, 'inputs changed'):
                self.proof(scope)

    def test_unrelated_plugin_fixture_repin_retains_component_but_not_current_host_protocol(self):
        self.objects.changed(CORE, HOST, 'scripts/ci-product-pins.json', json.dumps(
            {'sdk': SDK, 'products': [{'commit': NEW}]}))
        self.objects.files[CORE, NEW]['dist/default/Cargo.lock'] = 'new assembly lock'
        self.requested['host'] = NEW
        before = self.kwargs()['receipt_bytes']
        proof = self.proof('retained-component')
        result = verify_reuse(proof, self.requested, self.objects, **self.kwargs())
        self.assertEqual(result['original']['host'], HOST)
        self.assertEqual(result['requested']['host'], NEW)
        self.assertEqual(result['requires_fresh_assembly'], NEW)
        self.assertFalse(result['current_host_protocol_credit'])
        self.assertFalse(result['current_host_binary_credit'])
        self.assertEqual(before, self.kwargs()['receipt_bytes'])
        self.assertEqual(plan_reuse(self.original, self.requested, self.objects)['action'],
                         'verify-component-retention')
        with self.assertRaisesRegex(ValueError, 'inputs changed'):
            self.proof()

    def test_component_owner_fixture_lock_build_script_features_and_sdk_changes_invalidate(self):
        for path in ('testing/fixture.py', 'Cargo.lock', 'build.rs', 'Cargo.toml'):
            with self.subTest(path=path):
                self.objects.changed(OWNER, SOURCE, path, 'changed')
                requested = dict(self.original, source=NEW)
                self.assertEqual(plan_reuse(self.original, requested, self.objects)['action'], 'run')
        self.objects.changed(CORE, SDK)
        requested = dict(self.original, sdk=NEW)
        self.assertEqual(plan_reuse(self.original, requested, self.objects)['action'], 'run')

    def test_runtime_api_lock_toolchain_and_profile_changes_invalidate_components(self):
        changes = {'crates/core/src/lib.rs': 'changed ABI/runtime',
                   'scripts/runtime.sh': 'changed host runtime independent of policy revision',
                   'Cargo.lock': 'version=4\n[[package]]\nname="core"\nversion="2.0.0"\n',
                   'Cargo.toml': '[workspace.dependencies]\nsyn="2"\n[profile.test]\nopt-level=3\n',
                   'rust-toolchain.toml': '[toolchain]\nchannel="nightly"\n'}
        for path, value in changes.items():
            with self.subTest(path=path):
                self.objects.changed(CORE, HOST, path, value)
                self.requested['host'] = NEW
                with self.assertRaisesRegex(ValueError, 'inputs changed'):
                    self.proof('retained-component')

    def test_checker_assertions_image_confinement_security_policy_changes_refuse(self):
        for path in ('scripts/architecture/native.py', 'ci/native.json',
                     'ci/security/tools.json', 'scripts/architecture/new_controller.py'):
            with self.subTest(path=path):
                self.objects.changed(CORE, POLICY, path, 'changed required input')
                self.requested['policy'] = NEW
                with self.assertRaisesRegex(ValueError, 'inputs changed'):
                    self.proof('retained-component')

    def test_coverage_only_other_owner_change_does_not_invalidate_component(self):
        coverage = json.loads(self.objects.blob(CORE, POLICY, 'conformance/ci-coverage.json'))
        coverage['suites']['other']['source_commit'] = NEW
        self.objects.changed(CORE, POLICY, 'conformance/ci-coverage.json', json.dumps(coverage))
        self.requested['policy'] = NEW
        self.proof('retained-component')
        coverage['suites']['owner']['script_sha256'] = 'e' * 64
        self.objects.files[CORE, NEW]['conformance/ci-coverage.json'] = json.dumps(coverage)
        with self.assertRaisesRegex(ValueError, 'inputs changed'):
            self.proof('retained-component')

    def test_5381_core_controller_regression_fixture_fix_retains_unrelated_components(self):
        self.objects.changed(CORE, HOST, 'scripts/architecture/test_native_process_cleanup.py',
                             'three updated standalone stub lines')
        self.requested.update(host=NEW, policy=NEW)
        self.proof('retained-component')
        old_core = dict(self.original, repository=CORE, source=HOST)
        new_core = dict(self.requested, repository=CORE, source=NEW)
        self.assertEqual(plan_reuse(old_core, new_core, self.objects)['action'], 'run')
        # The equivalent-execution predicate still accounts for the complete
        # visible trusted tree, so this is NOT new-host conformance credit.
        with self.assertRaisesRegex(ValueError, 'inputs changed'):
            self.proof()

    def test_5381_retained_check_keeps_origin_and_allows_no_new_host_execution_claim(self):
        self.objects.changed(CORE, HOST, 'scripts/architecture/test_native_process_cleanup.py',
                             'three updated standalone stub lines')
        self.requested.update(host=NEW, policy=NEW)
        proof = self.proof('retained-check')
        result = verify_reuse(proof, self.requested, self.objects, **self.kwargs())
        self.assertEqual(result['original']['host'], HOST)
        self.assertTrue(result['retained_check_credit'])
        self.assertFalse(result['current_host_protocol_credit'])
        self.assertFalse(result['current_host_binary_credit'])
        self.assertEqual(result['requires_fresh_assembly'], NEW)
        self.assertEqual(plan_reuse(self.original, self.requested, self.objects)['action'],
                         'verify-retained-check')
        for job in ('core-conformance', 'external-conformance'):
            repository = CORE if job == 'core-conformance' else OWNER
            old = dict(self.original, repository=repository, job=job)
            new = dict(self.requested, repository=repository, job=job)
            if repository == CORE:
                old['source'], new['source'] = HOST, NEW
            with self.subTest(job=job):
                self.assertEqual(retained_check_identity(old, self.objects),
                                 retained_check_identity(new, self.objects))
                self.assertEqual(plan_reuse(old, new, self.objects)['action'], 'verify-retained-check')

    def test_retained_check_refuses_any_other_runtime_assertion_entrypoint_sdk_vector_or_path_change(self):
        changes = {
            'crates/core/src/lib.rs': 'changed runtime',
            'testing/conformance/assert.py': 'changed required assertion',
            'scripts/architecture/native.py': 'changed entrypoint',
            'scripts/ci-product-pins.json': json.dumps({'sdk': SDK, 'products': [{'commit': NEW}]}),
            'dist/default/Cargo.lock': 'changed dynamic graph',
            'ci/native.json': 'changed image or isolation',
            'testing/evidence-conformance/external-rbac/test.py': 'changed actual core conformance rig',
            'README.md': 'unclassified path also conservatively significant',
            'scripts/architecture/nested/test_input.py': 'not an approved immediate core test',
        }
        for path, value in changes.items():
            with self.subTest(path=path):
                self.objects.changed(CORE, HOST, path, value)
                self.requested.update(host=NEW, policy=NEW)
                with self.assertRaisesRegex(ValueError, 'inputs changed'):
                    self.proof('retained-check')
        self.objects.changed(CORE, SDK)
        self.requested = dict(self.original, sdk=NEW)
        with self.assertRaises(ValueError):
            self.proof('retained-check')

    def test_retained_check_reuse_helpers_are_explicit_and_core_native_is_never_excluded(self):
        for path in ('scripts/architecture/input_identity.py', 'scripts/architecture/reuse_evidence.py',
                     'scripts/architecture/qualification_selection.py',
                     'scripts/architecture/test_input_identity.py', 'scripts/architecture/test_reuse_evidence.py'):
            with self.subTest(path=path):
                self.objects.changed(CORE, HOST, path, 'new controller reuse support')
                self.requested.update(host=NEW, policy=NEW)
                self.proof('retained-check')
        with self.assertRaisesRegex(ValueError, 'core-native'):
            retained_check_identity(dict(self.original, repository=CORE, source=HOST), self.objects)

    def test_preparation_only_other_owner_branch_changes_retain_unchanged_owner_checks(self):
        for revision in (POLICY, HOST):
            self.objects.files[CORE, revision][PREPARATION_SELECTOR] = LEGACY_STANDALONE_SELECTOR
        self.objects.changed(CORE, HOST, PREPARATION_SELECTOR, OIDC_STANDALONE_SELECTOR)
        self.requested.update(host=NEW, policy=NEW)
        self.proof('retained-check')
        self.proof('retained-component')
        self.assertEqual(plan_reuse(self.original, self.requested, self.objects)['action'], 'verify-retained-check')
        with self.assertRaisesRegex(ValueError, 'inputs changed'):
            self.proof()  # Still not strict execution equivalence.

    def test_preparation_selected_graph_changes_invalidate_actual_consumers(self):
        vector = json.dumps({'sdk': SDK, 'products': [dict(repo='busbar-auth-oidc', commit='d' * 40,
                                                         lock_sha256='f' * 64)]})
        for revision in (POLICY, HOST):
            self.objects.files[CORE, revision][PREPARATION_SELECTOR] = LEGACY_STANDALONE_SELECTOR
            self.objects.files[CORE, revision]['scripts/ci-product-pins.json'] = vector
        self.objects.changed(CORE, HOST, PREPARATION_SELECTOR, OIDC_STANDALONE_SELECTOR)
        release = 'GetBusbar/busbar-release'
        self.objects.files[release, SOURCE] = dict(self.objects.files[OWNER, SOURCE])
        for repository, job in ((CORE, 'core-conformance'), (release, 'native-qualification')):
            old = dict(self.original, repository=repository, job=job)
            new = dict(old, policy=NEW, host=NEW)
            if repository == CORE:
                old['source'], new['source'] = HOST, NEW
            with self.subTest(repository=repository):
                self.assertNotEqual(retained_check_identity(old, self.objects),
                                    retained_check_identity(new, self.objects))
                self.assertEqual(plan_reuse(old, new, self.objects)['action'], 'run')

    def test_preparation_common_controller_seed_or_unknown_selector_changes_refuse(self):
        for revision in (POLICY, HOST):
            self.objects.files[CORE, revision][PREPARATION_SELECTOR] = LEGACY_STANDALONE_SELECTOR
        for path, contents in (
            (PREPARATION_SELECTOR, OIDC_STANDALONE_SELECTOR + '\ndef required_check():\n    assert False\n'),
            (PREPARATION_SELECTOR, OIDC_STANDALONE_SELECTOR.replace('return []', 'return vector["products"]')),
            (PREPARATION_SELECTOR, OIDC_STANDALONE_SELECTOR.replace('return []', 'print("side effect")\n    return []')),
            ('scripts/architecture/native_seed.py', 'changed collector controls'),
        ):
            with self.subTest(path=path, contents=contents):
                self.objects.changed(CORE, HOST, path, contents)
                self.requested.update(host=NEW, policy=NEW)
                with self.assertRaises(ValueError):
                    self.proof('retained-check')
                with self.assertRaises(ValueError):
                    self.proof('retained-component')

    def test_preparation_outputs_bind_selected_immutable_lock_and_git_closure(self):
        vector = {'products': [dict(repo='busbar-auth-oidc', commit='d' * 40, lock_sha256='f' * 64)]}
        source = OIDC_STANDALONE_SELECTOR.encode()
        original = preparation_source_identity(source, CORE, 'core-conformance', vector)
        for field, value in (('commit', 'e' * 40), ('lock_sha256', '0' * 64)):
            changed = copy.deepcopy(vector)
            changed['products'][0][field] = value
            with self.subTest(field=field):
                self.assertNotEqual(original, preparation_source_identity(source, CORE, 'core-conformance', changed))
        for products in ([], vector['products'] * 2):
            with self.subTest(products=products), self.assertRaisesRegex(ValueError, 'absent or ambiguous'):
                preparation_source_identity(source, CORE, 'core-conformance', {'products': products})

    def test_core_and_conformance_jobs_cannot_be_retained_components(self):
        for request in (dict(self.original, repository=CORE), dict(self.original, job='external-conformance')):
            with self.subTest(request=request), self.assertRaisesRegex(ValueError, 'non-core native'):
                component_identity(request, self.objects)

    def test_security_same_bytes_different_commit_reuses_with_current_database(self):
        self.original['job'] = self.requested['job'] = 'security-scans'
        self.objects.changed(OWNER, SOURCE)
        self.requested['source'] = NEW
        result = self.proof()
        self.assertEqual(result['original']['source'], SOURCE)
        self.assertEqual(result['requested']['source'], NEW)

    def test_security_same_scanned_database_preserves_distinct_original_metadata_provenance(self):
        self.original['job'] = self.requested['job'] = 'security-scans'
        original_bytes = self.receipt('security-scans')
        witness = dict(DATABASE, metadata_sha256='e' * 64)
        args = self.kwargs() | {'database': witness}
        proof = make_proof(self.original, self.requested, self.objects, **args)
        verify_reuse(proof, self.requested, self.objects, **args)
        self.assertEqual(self.receipt('security-scans'), original_bytes)
        self.assertEqual(json.loads(original_bytes)['database']['metadata_sha256'], DATABASE['metadata_sha256'])
        self.assertNotIn('metadata_sha256', proof['identity']['database'])
        self.assertEqual(proof['identity']['database']['sha256'], DATABASE['sha256'])

    def test_security_metadata_projection_refuses_unknown_scanner_or_wrapper_contract(self):
        self.original['job'] = self.requested['job'] = 'security-scans'
        for path, value in (
            ('scripts/security/scan.py', '# unknown wrapper semantics'),
            ('ci/security/tools.json', json.dumps(dict(database_max_age_hours=72,
                                                      trivy='unknown@sha256:' + 'f' * 64))),
        ):
            with self.subTest(path=path):
                objects = Objects()
                objects.files[CORE, POLICY][path] = value
                with self.assertRaisesRegex(ValueError, 'scanner.*contract'):
                    compute_identity(self.requested, objects, database=DATABASE, now=NOW)

    def test_security_changed_database_stale_database_or_changed_source_refuses(self):
        self.original['job'] = self.requested['job'] = 'security-scans'
        proof = self.proof()
        for database in (dict(DATABASE, sha256='d' * 64), dict(DATABASE, updated_at='2026-01-01T00:00:00Z')):
            with self.subTest(database=database), self.assertRaises(ValueError):
                verify_reuse(proof, self.requested, self.objects, **(self.kwargs() | {'database': database}))
        with self.assertRaisesRegex(ValueError, 'stale'):
            verify_reuse(proof, self.requested, self.objects, **(self.kwargs() | {'now': NOW + dt.timedelta(days=4)}))
        self.objects.changed(OWNER, SOURCE, 'testing/fixture.py', 'new secret')
        self.requested['source'] = NEW
        with self.assertRaisesRegex(ValueError, 'inputs changed'):
            self.proof()

    def test_forged_receipt_archive_wrong_source_and_changed_policy_proof_refuse(self):
        proof = self.proof()
        for name, change in (
            ('receipt bytes', {'receipt_bytes': self.receipt() + b' '}),
            ('artifact bytes', {'artifact_bytes': b'forged'}),
            ('job authentication', {'authenticate_original': lambda *args: False}),
            ('immutable validation', {'validate_original': lambda *args: False}),
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                verify_reuse(proof, self.requested, self.objects, **(self.kwargs() | change))
        for field in ('source', 'policy', 'host', 'sdk'):
            forged = copy.deepcopy(proof)
            forged['requested'][field] = NEW
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'requested context'):
                verify_reuse(forged, self.requested, self.objects, **self.kwargs())
        forged = copy.deepcopy(proof)
        forged['identity']['source_tree_sha256'] = '0' * 64
        forged['identity_sha256'] = hashlib.sha256(encoded(forged['identity'])).hexdigest()
        with self.assertRaisesRegex(ValueError, 'claimed identity'):
            verify_reuse(forged, self.requested, self.objects, **self.kwargs())

    def test_unknown_paths_and_missing_inputs_plan_fresh_instead_of_passing(self):
        self.requested['host'] = NEW
        result = plan_reuse(self.original, self.requested, self.objects)
        self.assertEqual(result['action'], 'run')
        self.assertTrue(result['requires_evidence_verification'])
        self.requested['exclude'] = ['ci/native.json']
        with self.assertRaisesRegex(ValueError, 'request fields'):
            compute_identity(self.requested, self.objects)


class ImmutableGitObjects(unittest.TestCase):
    def test_reads_commit_objects_ignoring_mutable_checkout_and_export_ignore(self):
        # Local callers set TMPDIR to their task scratch directory; CI owns its
        # disposable test workspace. No build or network is used.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args, data=None):
                return subprocess.check_output(['git', '-C', directory, *args], input=data)
            git('init', '-q')
            (root / 'source').write_text('committed bytes')
            (root / '.gitattributes').write_text('source export-ignore\n')
            git('add', '.')
            tree = git('write-tree').decode().strip()
            env = dict(os.environ, GIT_AUTHOR_NAME='Fixture', GIT_AUTHOR_EMAIL='fixture@example.test',
                       GIT_COMMITTER_NAME='Fixture', GIT_COMMITTER_EMAIL='fixture@example.test')
            revision = subprocess.check_output(['git', '-C', directory, 'commit-tree', tree],
                                               input=b'fixture\n', env=env).decode().strip()
            objects = GitObjects({CORE: root})
            before = objects.tree(CORE, revision)
            (root / 'source').write_text('untrusted worktree replacement')
            self.assertEqual(objects.tree(CORE, revision), before)
            self.assertEqual(objects.blob(CORE, revision, 'source'), b'committed bytes')
            self.assertIn('source', before)


class ArtifactReaderRetention(unittest.TestCase):
    def test_exact_optional_default_reader_and_noncore_class_contract_are_equal(self):
        old, new = artifact_reader_pair('product_artifacts.py')
        self.assertEqual(default_artifact_reader_identity(old), default_artifact_reader_identity(new))
        old, new = artifact_reader_pair('native_product_inputs.py')
        for repository, job in ((OWNER, 'native-qualification'), (CORE, 'core-conformance'),
                                ('GetBusbar/busbar-release', 'native-qualification')):
            with self.subTest(repository=repository):
                self.assertEqual(product_input_source_identity(old, repository, job),
                                 product_input_source_identity(new, repository, job))
        self.assertNotEqual(product_input_source_identity(old, CORE, 'native-qualification'),
                            product_input_source_identity(new, CORE, 'native-qualification'))

    def test_changed_default_checks_generic_reader_or_shared_class_are_not_hidden(self):
        old, new = artifact_reader_pair('product_artifacts.py')
        old_text, new_text = old.decode(), new.decode()
        old_blob = next(node for node in ast.parse(old_text).body if isinstance(node, ast.FunctionDef) and node.name == 'blob')
        new_blob = next(node for node in ast.parse(new_text).body if isinstance(node, ast.FunctionDef) and node.name == 'blob')
        mixed = new_text.replace(ast.get_source_segment(new_text, new_blob), ast.get_source_segment(old_text, old_blob), 1)
        with self.assertRaisesRegex(ValueError, 'mixed artifact reader'):
            default_artifact_reader_identity(mixed.encode())
        for changed in (new.replace(b'git_reader=git', b'git_reader=unsafe_git'),
                        new.replace(b'len(data) <= limit', b'len(data) <= limit + 1'),
                        new.replace(b'owner metadata must be a regular Git blob', b'weakened type check')):
            with self.assertRaisesRegex(ValueError, 'unknown artifact reader'):
                default_artifact_reader_identity(changed)
        changed = new.replace(b'core.fsmonitor=false', b'core.fsmonitor=true')
        self.assertNotEqual(default_artifact_reader_identity(old), default_artifact_reader_identity(changed))
        old, new = artifact_reader_pair('native_product_inputs.py')
        with self.assertRaisesRegex(ValueError, 'unknown product input'):
            product_input_source_identity(new.replace(b'canonical-inputs', b'arbitrary-inputs'), OWNER, 'native-qualification')
        self.assertNotEqual(product_input_source_identity(old, OWNER, 'native-qualification'),
                            product_input_source_identity(new.replace(b'class ProductInputs(dict)', b'class ProductInputs(list)'),
                                                          OWNER, 'native-qualification'))

    def test_whole_retained_check_keeps_core_native_fresh_and_other_workloads_retained(self):
        objects = Objects()
        changed = {}
        for name in ('product_artifacts.py', 'native_product_inputs.py'):
            old, new = artifact_reader_pair(name)
            path = 'scripts/architecture/' + name
            for revision in (POLICY, HOST):
                objects.files[CORE, revision][path] = old.decode()
            changed[path] = new.decode()
        objects.changed(CORE, HOST)
        objects.files[CORE, NEW].update(changed)
        release = 'GetBusbar/busbar-release'
        objects.files[release, SOURCE] = dict(objects.files[OWNER, SOURCE])
        for repository, job in ((OWNER, 'native-qualification'), (CORE, 'core-conformance'),
                                (release, 'native-qualification'), (CORE, 'native-qualification')):
            original = dict(repository=repository, job=job, source=HOST if repository == CORE else SOURCE,
                            host=HOST, policy=POLICY, sdk=SDK)
            requested = dict(original, host=NEW, policy=NEW)
            if repository == CORE:
                requested['source'] = NEW
            with self.subTest(repository=repository, job=job):
                expected = 'run' if repository == CORE and job == 'native-qualification' else 'verify-retained-check'
                self.assertEqual(plan_reuse(original, requested, objects)['action'], expected)


if __name__ == '__main__':
    unittest.main()
