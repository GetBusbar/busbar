"""Pinned cache/mirror retrieval; no actual network or image pulls."""
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import scan


class RetrievalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.scanner = scan.Scanner(Path(__file__).resolve().parents[2], Path(self.temp.name))
        self.image = self.scanner.tools['trivy']
        self.digest = self.image.split('@')[1]
        self.present = SimpleNamespace(returncode=0, stdout=json.dumps([self.image]).encode())
        self.absent = SimpleNamespace(returncode=1, stdout=b'')

    def test_cache_hit_never_contacts_registry(self):
        with patch.object(subprocess, 'run', return_value=self.present) as run:
            self.scanner.prepare_image('trivy')
        self.assertEqual(run.call_count, 1)
        self.assertIn('inspect', run.call_args.args[0])
        self.assertNotIn('pull', run.call_args.args[0])

    def test_cache_miss_pulls_mirror_once_and_verifies_exact_digest(self):
        with patch.object(subprocess, 'run', side_effect=[self.absent, self.present, self.present]) as run:
            self.scanner.prepare_image('trivy')
        commands = [call.args[0] for call in run.call_args_list]
        pulls = [command for command in commands if 'pull' in command]
        self.assertEqual(len(pulls), 1)
        self.assertTrue(pulls[0][-1].startswith('mirror.gcr.io/'))
        self.assertTrue(pulls[0][-1].endswith('@' + self.digest))

    def test_wrong_cached_digest_and_failed_mirror_have_no_fallback(self):
        wrong = SimpleNamespace(returncode=0, stdout=b'["mirror.gcr.io/a@sha256:bad"]')
        with patch.object(subprocess, 'run', return_value=wrong) as run, self.assertRaises(ValueError):
            self.scanner.prepare_image('trivy')
        self.assertEqual(run.call_count, 1)
        with patch.object(subprocess, 'run', side_effect=[self.absent, subprocess.CalledProcessError(1, 'pull')]) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                self.scanner.prepare_image('trivy')
        self.assertEqual(run.call_count, 2)


if __name__ == '__main__':
    unittest.main()
