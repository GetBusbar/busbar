"""Exact-source witnesses for requalifying an already published development cohort."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from check import Violation
from native import published_dev_target


class PublishedDevTests(unittest.TestCase):
    def invoke(self, output):
        with patch.dict('os.environ', {'CI_SERVER_URL': 'https://forge.example'}), \
             patch('native.fetch_environment', return_value={}), \
             patch('native.subprocess.check_output', return_value=output) as read:
            result = published_dev_target('GetBusbar/busbar', 'a' * 40)
            self.assertEqual(read.call_args.args[0], ['git', 'ls-remote',
                'https://forge.example/GetBusbar/busbar.git', 'refs/heads/dev'])
            return result

    def test_remote_head_check_survives_removed_inherited_working_directory(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            root = Path(directory).resolve()
            repository = root / 'candidate.git'
            subprocess.run(['git', 'init', '--bare', '-q', str(repository)], check=True)
            tree = subprocess.check_output(['git', '--git-dir', str(repository),
                'hash-object', '-w', '-t', 'tree', '--stdin'], input=b'').decode().strip()
            commit = (f'tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\n'
                      'committer Fixture <fixture@example.invalid> 1 +0000\n\nfixed fixture\n').encode()
            source = subprocess.check_output(['git', '--git-dir', str(repository),
                'hash-object', '-w', '-t', 'commit', '--stdin'], input=commit).decode().strip()
            subprocess.run(['git', '--git-dir', str(repository), 'update-ref', 'refs/heads/dev', source], check=True)
            inherited = root / 'removed-cwd'
            inherited.mkdir()
            code = ('import os,sys; sys.path.insert(0,sys.argv[1]); '
                    'from native import published_dev_target; '
                    'os.chdir(sys.argv[2]); os.rmdir(sys.argv[2]); '
                    'print(published_dev_target("candidate",sys.argv[3]))')
            env = dict(os.environ, CI_SERVER_URL=root.as_uri(), CI_JOB_TOKEN='local-fixture-only',
                       GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')
            result = subprocess.run([sys.executable, '-I', '-B', '-c', code,
                str(Path(__file__).resolve().parent), str(inherited), source],
                env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), source)

    def test_exact_published_source_is_bound(self):
        self.assertEqual(self.invoke('a' * 40 + '\trefs/heads/dev\n'), 'a' * 40)

    def test_moved_dev_requires_new_qualification(self):
        with self.assertRaisesRegex(Violation, 'published dev moved'):
            self.invoke('b' * 40 + '\trefs/heads/dev\n')

    def test_missing_ambiguous_or_wrong_ref_is_refused(self):
        for output in ['', 'a' * 40 + '\trefs/heads/main\n',
                       ('a' * 40 + '\trefs/heads/dev\n') * 2]:
            with self.subTest(output=output), self.assertRaises(Violation):
                self.invoke(output)
