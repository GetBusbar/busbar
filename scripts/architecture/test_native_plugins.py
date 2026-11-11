"""C qualification preserves sanitizer checks while bounding Linux startup layout."""
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from native_plugins import qualify_plugin, prepare_runtime
from check import Violation


class CQualification(unittest.TestCase):
    def qualification(self, directory):
        recipe = {'sources': ['owner/plugin.c'], 'test-root': 'owner',
                  'unit': {'sources': ['owner/tests/unit.c'], 'defines': ['BUSBAR_FIXTURE_UNIT']},
                  'schema': {'source': 'owner/tests/schema.c', 'driver': 'owner/tests/schema.py'}}
        patcher = patch('check.load_c_recipe', return_value=recipe)
        patcher.start()
        self.addCleanup(patcher.stop)
        sanitizer = patch('native_sanitizer.run_c_unit_tsan', side_effect=lambda q:
            q.run('c-unit-tsan', ['setarch', '--addr-no-randomize', str(q.work / 'unit-tsan')]))
        self.sanitizer = sanitizer.start()
        self.addCleanup(sanitizer.stop)
        root = Path(directory)
        work, evidence = root / 'work', root / 'evidence'
        (work / 'architecture').mkdir(parents=True)
        evidence.mkdir()
        library = work / 'architecture/plugin.so'
        library.write_bytes(b'actual library supplied by architecture check')
        return SimpleNamespace(
            root=root / 'candidate', work=work, evidence=evidence,
            repository='GetBusbar/busbar-secret-c',
            policy=SimpleNamespace(data={'repositories': {
                'GetBusbar/busbar-secret-c': {'language': 'c'},
            }}), env={}, receipt={}, run=Mock(),
        )

    def test_linux_only_tsan_process_has_fixed_layout_and_instrumentation(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            q = self.qualification(directory)
            with patch('native_plugins.sys.platform', 'linux'):
                qualify_plugin(q, Path(directory) / 'host', Path(directory) / 'sdk')
            calls = {call.args[0]: call.args[1] for call in q.run.call_args_list}
            self.assertEqual(calls['c-unit'], [str(q.work / 'unit')])
            self.assertEqual(calls['c-unit-tsan'], [
                'setarch', '--addr-no-randomize', str(q.work / 'unit-tsan'),
            ])
            self.assertIn('-fsanitize=thread', calls['c-build-unit-tsan'])
            self.assertIn('-pthread', calls['c-build-unit-tsan'])
            self.assertEqual(q.env['TSAN_OPTIONS'], 'halt_on_error=1')
            self.assertIn('c-native-loader', calls)
            self.assertIn('c-schema', calls)
            self.sanitizer.assert_called_once_with(q)

    def test_other_platform_retains_direct_sanitizer_execution(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            q = self.qualification(directory)
            (q.work / 'architecture/plugin.so').rename(q.work / 'architecture/plugin.dylib')
            with patch('native_plugins.sys.platform', 'darwin'):
                qualify_plugin(q, Path(directory) / 'host', Path(directory) / 'sdk')
            q.run.assert_any_call('c-unit-tsan', [str(q.work / 'unit-tsan')])
            self.sanitizer.assert_not_called()

    def test_sanitizer_or_setarch_failure_stops_qualification(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            q = self.qualification(directory)

            def run(name, argv, **_kwargs):
                if name == 'c-unit-tsan':
                    raise subprocess.CalledProcessError(66, argv)

            q.run.side_effect = run
            with patch('native_plugins.sys.platform', 'linux'):
                with self.assertRaises(subprocess.CalledProcessError) as caught:
                    qualify_plugin(q, Path(directory) / 'host', Path(directory) / 'sdk')
            self.assertEqual(caught.exception.returncode, 66)
            self.assertNotIn('c-schema', [call.args[0] for call in q.run.call_args_list])
            self.assertEqual(q.receipt, {})


class RuntimePreparation(unittest.TestCase):
    def qualification(self, root, declared=True):
        repository = 'GetBusbar/busbar-fixture-owner'
        settings = {'prepare_runtime': 'testing/native/prepare.sh'} if declared else {}
        return SimpleNamespace(root=root, repository=repository,
            policy={'repositories': {repository: {'native': settings}}}, run=Mock())

    def test_only_trusted_selection_runs_the_owner_script(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory)
            script = root / 'testing/native/prepare.sh'
            script.parent.mkdir(parents=True)
            script.write_text('exit 0\n')
            q = self.qualification(root, declared=False)
            prepare_runtime(q)
            q.run.assert_not_called()
            q = self.qualification(root)
            prepare_runtime(q)
            q.run.assert_called_once_with('plugin-runtime-prepare',
                ['bash', '-euo', 'pipefail', str(script)])

    def test_missing_or_indirect_preparation_fails_before_execution(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory)
            q = self.qualification(root)
            with self.assertRaises(Violation):
                prepare_runtime(q)
            script = root / 'testing/native/prepare.sh'
            script.parent.mkdir(parents=True)
            target = root / 'unselected.sh'
            target.write_text('exit 0\n')
            script.symlink_to(target)
            with self.assertRaises(Violation):
                prepare_runtime(q)
            q.run.assert_not_called()

    def test_preparation_failure_is_not_ignored(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory)
            script = root / 'testing/native/prepare.sh'
            script.parent.mkdir(parents=True)
            script.write_text('exit 17\n')
            q = self.qualification(root)
            q.run.side_effect = Violation('subject build failed')
            with self.assertRaisesRegex(Violation, 'subject build failed'):
                prepare_runtime(q)


if __name__ == '__main__':
    unittest.main()
