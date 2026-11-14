"""Plugin host identity: exactly the core inputs a plugin qualification reads."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import plugin_host_identity as phi  # noqa: E402

REPO = 'GetBusbar/busbar-plane-mcp'
PLAN = {'schema': 'busbar.native-judge-inputs/1',
        'owners': {'core': {'archive_sha256': '1' * 64}, 'mcp': {'archive_sha256': '2' * 64},
                   'otlp': {'archive_sha256': '3' * 64}},
        'repositories': {'GetBusbar/busbar': ['core'], REPO: ['mcp'], 'GetBusbar/busbar-export-otlp': ['otlp']}}
NATIVE = '''class Qualification:
    def core_regressions(self):
        self.run_controller('architecture-regressions', [sys.executable, '-m', 'unittest', 'discover',
            '-s', str(self.trusted / 'scripts/architecture'), '-p', 'test_*.py'], cwd=self.trusted)

    def plugin(self):
        return 'plugin'
'''


def git(root, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@example.test', GIT_COMMITTER_NAME='t',
               GIT_COMMITTER_EMAIL='t@example.test', GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1')
    return subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True,
                          text=True, env=env).stdout.strip()


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.root = Path(self.tmp.name) / 'core'
        self.root.mkdir()
        git(self.root, 'init', '-q', '-b', 'dev')
        self.base = self.commit({
            'Cargo.toml': '[workspace]\n', 'crates/busbar/src/lib.rs': 'pub fn run() {}\n',
            'crates/busbar/tests/boot.rs': '#[test] fn boots() {}\n',
            'dist/default/Cargo.toml': '[profile.release]\nlto = true\n',
            'scripts/ci-product-pins.json': json.dumps({'sdk': 'c' * 40}) + '\n',
            'plugins.yaml': 'plugins: []\n', '.gitlab/issue_templates/bug.md': 'bug\n',
            'ci/architecture.toml': 'version = 1\n', 'ci/native-judge-inputs.json': json.dumps(PLAN),
            'scripts/architecture/native.py': NATIVE,
            'scripts/architecture/native_ci_bootstrap.py':
                "run(['python3', '-m', 'unittest', 'test_native_confinement.ExistingRuntime'])\n",
            'scripts/architecture/test_check.py': 'import unittest\n',
            'scripts/architecture/test_native_confinement.py': 'import unittest\n',
            'scripts/architecture/toolchain/test_toolchain.py': 'import unittest\n',
            'scripts/architecture/README.md': 'Run test_check and test_* via discover.\n'})

    def tearDown(self):
        self.tmp.cleanup()

    def commit(self, files=None, remove=()):
        for name, text in (files or {}).items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        for name in remove:
            (self.root / name).unlink()
        git(self.root, 'add', '-A')
        git(self.root, 'commit', '-q', '--allow-empty', '-m', 'c')
        return git(self.root, 'rev-parse', 'HEAD')

    def identity(self, policy, host=None, repository=REPO):
        trees = phi.GitTrees(self.root)
        return phi.compute(repository, trees, policy, trees, host or policy)

    def assertSame(self, before, after):
        self.assertEqual(before['sha256'], after['sha256'])

    def assertDiffers(self, before, after):
        self.assertNotEqual(before['sha256'], after['sha256'])


class Definition(Fixture):
    def test_controller_unit_test_change_keeps_identity(self):
        before = self.identity(self.base)
        after = self.identity(self.commit({'scripts/architecture/test_check.py': 'import unittest  # more\n',
                                           'scripts/architecture/toolchain/test_toolchain.py': 'pass\n'}))
        self.assertSame(before, after)
        self.assertIn('scripts/architecture/test_check.py', after['content_excluded'])

    def test_other_repository_judge_rows_keep_identity_and_own_rows_change_it(self):
        before = self.identity(self.base)
        plan = json.loads(json.dumps(PLAN))
        plan['owners']['core']['archive_sha256'] = '4' * 64
        plan['repositories']['GetBusbar/busbar'] = ['core', 'otlp']
        other = self.commit({'ci/native-judge-inputs.json': json.dumps(plan)})
        self.assertSame(before, self.identity(other))
        otlp = 'GetBusbar/busbar-export-otlp'
        self.assertSame(self.identity(self.base, repository=otlp), self.identity(other, repository=otlp))
        plan['owners']['mcp']['archive_sha256'] = '5' * 64
        self.assertDiffers(before, self.identity(self.commit({'ci/native-judge-inputs.json': json.dumps(plan)})))

    def test_identity_is_repository_specific(self):
        self.assertDiffers(self.identity(self.base), self.identity(self.base, repository='GetBusbar/busbar-export-otlp'))

    def test_host_copy_of_controller_paths_is_unread(self):
        # The host checkout never exposes ci/, scripts/architecture/ or .gitlab/:
        # plugin jobs execute the trusted policy checkout's copy instead.
        moved = self.commit({'ci/architecture.toml': 'version = 2\n', 'scripts/architecture/native.py': NATIVE + '#\n',
                             '.gitlab/issue_templates/bug.md': 'other\n'})
        self.assertSame(self.identity(self.base, self.base), self.identity(self.base, moved))
        # ... while the policy checkout's copy is judged.
        self.assertDiffers(self.identity(self.base, self.base), self.identity(moved, self.base))

    def test_runtime_sources_tests_profiles_and_pins_change_identity(self):
        before = self.identity(self.base)
        for files in ({'crates/busbar/src/lib.rs': 'pub fn run() { }\n'},
                      {'crates/busbar/tests/boot.rs': '#[test] fn boots() { }\n'},
                      {'dist/default/Cargo.toml': '[profile.release]\nlto = false\n'},
                      {'scripts/ci-product-pins.json': json.dumps({'sdk': 'd' * 40}) + '\n'},
                      {'plugins.yaml': 'plugins: [x]\n'},
                      {'scripts/architecture/native.py': NATIVE.replace("'plugin'", "'other'")},
                      {'scripts/architecture/README.md': 'changed prose\n'},
                      {'ci/architecture.toml': 'version = 2\n'}):
            with self.subTest(files=sorted(files)):
                git(self.root, 'checkout', '-q', self.base)
                self.assertDiffers(before, self.identity(self.commit(files)))

    def test_test_module_named_by_controller_code_stays_hashed(self):
        before = self.identity(self.base)
        self.assertNotIn('scripts/architecture/test_native_confinement.py', before['content_excluded'])
        self.assertDiffers(before, self.identity(self.commit(
            {'scripts/architecture/test_native_confinement.py': 'import unittest  # changed\n'})))

    def test_test_module_imported_by_a_named_test_module_stays_hashed(self):
        named = self.commit({'scripts/architecture/test_native_confinement.py': 'import test_check\n'})
        before = self.identity(named)
        self.assertNotIn('scripts/architecture/test_check.py', before['content_excluded'])
        self.assertDiffers(before, self.identity(self.commit({'scripts/architecture/test_check.py': '# x\n'})))

    def test_unreviewed_test_walker_disables_content_exclusion(self):
        walker = self.commit({'scripts/architecture/native_plugins.py':
                              "run([sys.executable, '-m', 'unittest', 'discover', '-p', 'test_*.py'])\n"})
        before = self.identity(walker)
        self.assertEqual(before['content_excluded'], [])
        self.assertTrue(any('unreviewed test walker' in note for note in before['notes']), before['notes'])
        self.assertDiffers(before, self.identity(self.commit({'scripts/architecture/test_check.py': '# x\n'})))

    def test_reviewed_walker_moved_outside_its_core_only_function_is_unreviewed(self):
        moved = NATIVE.replace('    def plugin(self):\n',
                               "    def plugin(self):\n        run('-m', 'unittest', 'discover', '-p', 'test_*.py')\n")
        before = self.identity(self.commit({'scripts/architecture/native.py': moved}))
        self.assertEqual(before['content_excluded'], [])

    def test_added_or_removed_test_module_changes_identity(self):
        before = self.identity(self.base)
        added = self.commit({'scripts/architecture/test_new.py': 'import unittest\n'})
        self.assertDiffers(before, self.identity(added))
        git(self.root, 'checkout', '-q', self.base)
        self.assertDiffers(before, self.identity(self.commit(remove=['scripts/architecture/test_check.py'])))

    def test_record_binds_its_revisions_and_is_self_consistent(self):
        record = self.identity(self.base)
        self.assertEqual(phi.verify_record(record, repository=REPO, policy=self.base, host=self.base),
                         record['sha256'])
        for key, value in (('repository', 'GetBusbar/other'), ('policy_revision', 'a' * 40),
                           ('host_revision', 'a' * 40), ('schema', 'busbar.plugin-host-identity/0'),
                           ('host_tree_sha256', '0' * 64), ('sha256', '0' * 64)):
            with self.subTest(key=key):
                forged = dict(record, **{key: value})
                with self.assertRaises(phi.Unavailable):
                    phi.verify_record(forged, repository=REPO, policy=self.base, host=self.base)
        with self.assertRaises(phi.Unavailable):
            phi.verify_record(dict(record, extra=1), repository=REPO, policy=self.base, host=self.base)
        with self.assertRaises(phi.Unavailable):
            phi.verify_record({'unavailable': 'x'}, repository=REPO, policy=self.base, host=self.base)
        with self.assertRaises(phi.Unavailable):
            phi.verify_record(None, repository=REPO, policy=self.base, host=self.base)

    def test_unsupported_tree_or_invalid_judge_plan_has_no_identity(self):
        broken = self.commit({'ci/native-judge-inputs.json': json.dumps(dict(PLAN, extra=1))})
        with self.assertRaisesRegex(phi.Unavailable, 'judge'):
            self.identity(broken)
        plan = json.loads(json.dumps(PLAN))
        plan['repositories'][REPO] = ['unknown']
        with self.assertRaisesRegex(phi.Unavailable, 'judge'):
            self.identity(self.commit({'ci/native-judge-inputs.json': json.dumps(plan)}))
        with self.assertRaisesRegex(phi.Unavailable, 'core'):
            self.identity(self.base, repository=phi.CORE)


class Acceptance(Fixture):
    def test_accepts_only_an_equal_bound_identity_with_explicit_refusals(self):
        record = self.identity(self.base)
        receipt = {'repository': REPO, 'policy_revision': self.base, 'host_revision': self.base,
                   'plugin_host_identity': record}
        self.assertEqual(phi.accept(receipt, record['sha256']), record['sha256'])
        with self.assertRaisesRegex(phi.Unavailable, 'differs from the current'):
            phi.accept(receipt, '0' * 64)
        with self.assertRaisesRegex(phi.Unavailable, 'records no plugin host identity'):
            phi.accept(dict(receipt, plugin_host_identity=None), record['sha256'])
        with self.assertRaisesRegex(phi.Unavailable, 'unavailable at qualification'):
            phi.accept(dict(receipt, plugin_host_identity={'schema': phi.SCHEMA, 'unavailable': 'x'}),
                       record['sha256'])
        with self.assertRaisesRegex(phi.Unavailable, 'host_revision'):
            phi.accept(dict(receipt, host_revision='a' * 40), record['sha256'])
        with self.assertRaisesRegex(phi.Unavailable, 'no current'):
            phi.accept(receipt, None)


class HostView(Fixture):
    def test_restricted_host_view_hides_unread_paths_and_stays_clean_at_head(self):
        clone = Path(self.tmp.name) / 'host'
        git(Path(self.tmp.name), 'clone', '-q', str(self.root), str(clone))
        phi.restrict_host_view(clone)
        for prefix in phi.HOST_UNREAD:
            self.assertFalse((clone / prefix).exists(), prefix)
        self.assertTrue((clone / 'scripts/ci-product-pins.json').is_file())
        self.assertTrue((clone / 'crates/busbar/tests/boot.rs').is_file())
        self.assertEqual(git(clone, 'status', '--porcelain', '--untracked-files=no'), '')
        self.assertEqual(git(clone, 'rev-parse', 'HEAD'), self.base)
        phi.verify_host_view(clone)
        (clone / 'ci').mkdir()
        with self.assertRaisesRegex(phi.Unavailable, 'host view exposes'):
            phi.verify_host_view(clone)


class NativeHost(Fixture):
    def qualification(self):
        import native
        from unittest import mock
        plugin = Path(self.tmp.name) / 'plugin'
        plugin.mkdir()
        (plugin / '.busbar-ref').write_text('c' * 40 + '\n')
        q = object.__new__(native.Qualification)
        q.repository, q.root, q.trusted = REPO, plugin, self.root
        q.work = Path(self.tmp.name) / 'work'
        q.work.mkdir()
        q.receipt, q.env, q.save = {}, {}, lambda: None

        def checkout(repository, revision, destination):
            self.assertEqual((repository, revision), ('GetBusbar/busbar', 'dev'))
            git(Path(self.tmp.name), 'clone', '-q', str(self.root), str(destination))
            return destination
        patch = mock.patch.object(native, 'checkout', checkout)
        patch.start()
        self.addCleanup(patch.stop)
        environment = mock.patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop('BUSBAR_ADMISSION_CORE_REVISION', None)
        return q

    def test_plugin_host_is_restricted_and_its_identity_recorded(self):
        import contextlib
        import io
        q = self.qualification()
        with contextlib.redirect_stdout(io.StringIO()) as log:
            host = q.host()
        self.assertEqual(q.receipt['host_revision'], self.base)
        self.assertEqual(q.receipt['plugin_host_identity'], self.identity(self.base))
        self.assertIn('busbar-host-identity: ' + q.receipt['plugin_host_identity']['sha256'], log.getvalue())
        self.assertEqual(q.env['BUSBAR_CHECKOUT'], str(host))
        for prefix in phi.HOST_UNREAD:
            self.assertFalse((host / prefix).exists(), prefix)

    def test_unavailable_identity_is_recorded_without_failing_qualification(self):
        import contextlib
        import io
        self.commit({'ci/native-judge-inputs.json': '{}'})
        q = self.qualification()
        with contextlib.redirect_stdout(io.StringIO()):
            q.host()
        self.assertEqual(set(q.receipt['plugin_host_identity']), {'schema', 'unavailable'})
        self.assertRegex(q.receipt['plugin_host_identity']['unavailable'], 'judge')


class CommandLine(Fixture):
    def test_compare_reports_unchanged_and_changed_without_launching(self):
        changed = self.commit({'crates/busbar/src/lib.rs': '// changed\n'})
        same = self.commit({'scripts/architecture/test_check.py': '# test only\n'})
        import contextlib
        import io
        args = ['compare', '--git-dir', str(self.root), '--repository', REPO]
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(phi.main(args + ['--policy', changed, '--host', changed, '--to', same]), 0)
            self.assertEqual(phi.main(args + ['--policy', self.base, '--host', self.base, '--to', same]), 1)
        first, second = (json.loads(line) for line in out.getvalue().splitlines())
        self.assertEqual((first['unchanged'], second['unchanged']), (True, False))


class RepositoryDefinition(unittest.TestCase):
    """The reviewed walker lines exist where the definition says they are."""

    def test_reviewed_walkers_are_present_in_the_current_tree(self):
        root = Path(__file__).resolve().parents[2]
        for path, (scope, lines) in phi.REVIEWED_TEST_WALKERS.items():
            raw = (root / path).read_bytes()
            for line in lines:
                with self.subTest(path=path, line=line):
                    self.assertIn(line, [row.strip() for row in raw.splitlines()])
            if scope:
                self.assertIn(scope, raw)


if __name__ == '__main__':
    unittest.main()
