"""Targeted source/receipt/sandbox regressions; no repository-wide scans."""
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import scan
from artifacts import candidate_inventory


class SecurityScans(unittest.TestCase):
    def test_zero_exit_is_not_enough(self):
        for report in ({}, {'results': [], 'errors': []},
                       {'results': [], 'errors': [{'type': 'timeout'}], 'paths': {'scanned': ['x.py']}}):
            with self.subTest(report=report), self.assertRaises(ValueError):
                scan.inspect_report('sast', report)
        self.assertEqual(scan.inspect_report('sast', {
            'results': [], 'errors': [], 'paths': {'scanned': ['x.py']}}), 0)
        self.assertEqual(scan.inspect_report('secrets', {'SchemaVersion': 2,
            'Results': [{'Secrets': [{'Match': 'never retained'}]}]}), 1)
        with self.assertRaises(ValueError):
            scan.inspect_report('dependencies', {'Results': []})

    def test_stale_and_future_databases_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'db').mkdir()
            (root / 'db/trivy.db').write_bytes(b'fixture database')
            now = dt.datetime(2026, 11, 10, tzinfo=dt.timezone.utc)
            for hours in (-1, 73):
                (root / 'db/metadata.json').write_text(json.dumps({'UpdatedAt': (now - dt.timedelta(hours=hours)).isoformat()}))
                with self.assertRaises(ValueError):
                    scan.database_identity(root, 72, now)
            (root / 'db/metadata.json').write_text(json.dumps({'UpdatedAt': now.isoformat()}))
            self.assertEqual(scan.database_identity(root, 72, now)['sha256'], scan.digest(root / 'db/trivy.db'))

    def test_snapshot_ignores_candidate_filters_worktree_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / 'repo'
            repo.mkdir()
            def git(*args):
                return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.DEVNULL)
            git('init', '-q')
            (repo / '.gitattributes').write_text('hidden.py export-ignore\n')
            (repo / 'hidden.py').write_text('print("committed")\n')
            (repo / 'link').symlink_to('/etc/passwd')
            git('add', '.')
            git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', 'commit', '-qm', 'fixture')
            revision = git('rev-parse', 'HEAD').decode().strip()
            (repo / 'hidden.py').write_text('print("modified")\n')
            rows = scan.export_source(repo, revision, root / 'snapshot')
            self.assertEqual((root / 'snapshot/hidden.py').read_text(), 'print("committed")\n')
            self.assertFalse((root / 'snapshot/link').is_symlink())
            self.assertEqual((root / 'snapshot/link').read_text(), '/etc/passwd')
            self.assertEqual(len(rows), 3)

    def test_container_cannot_write_policy_source_or_receipt_or_use_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            scanner = scan.Scanner(Path(__file__).resolve().parents[2], work)
            calls = []
            def run(argv, **kwargs):
                calls.append((argv, kwargs))
                return subprocess.CompletedProcess(argv, 0)
            with patch.object(scan.subprocess, 'run', side_effect=run):
                scanner.container('trivy', ['--version'], [(work, '/input', False), (scanner.policy, '/policy', False)])
            command, kw = calls[0]
            for option in ('--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges'):
                self.assertIn(option, command)
            self.assertTrue(all(command[i + 1].endswith(',readonly') for i, value in enumerate(command) if value == '--mount'))
            self.assertNotIn('CI_JOB_TOKEN', kw['env'])
            self.assertNotIn('DOCKER_HOST', kw['env'])
            self.assertFalse(any('docker.sock' in arg for arg in command[command.index('run'):]))

    def test_report_findings_override_zero_exit_and_do_not_leak(self):
        with tempfile.TemporaryDirectory() as temporary:
            scanner = scan.Scanner(Path(__file__).resolve().parents[2], Path(temporary))
            payload = json.dumps({'SchemaVersion': 2, 'Results': [{'Secrets': [{'Match': 'private-value'}]}]}).encode()
            with patch.object(scanner, 'container', return_value=(0, payload, '0' * 64)):
                with self.assertRaises(ValueError):
                    scanner.scan('secrets', 'secrets', Path(temporary), [])
            self.assertEqual(scanner.steps[0]['status'], 'fail')
            self.assertNotIn('private-value', json.dumps(scanner.steps))
            private = Path(temporary) / 'private-scanner-reports'
            reports = list(private.iterdir())
            self.assertEqual(len(reports), 1)
            self.assertEqual(private.stat().st_mode & 0o777, 0o700)
            self.assertEqual(reports[0].stat().st_mode & 0o777, 0o600)
            self.assertEqual(reports[0].read_bytes(), payload)

    def test_candidate_symlink_refuses_before_mount(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for directory in ('artifacts', 'sboms', 'internal', 'plugins', 'oci'):
                (root / directory).mkdir()
            (root / 'sboms/escaped.json').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):
                candidate_inventory(root)


if __name__ == '__main__':
    unittest.main()
