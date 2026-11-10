"""Targeted source/receipt/sandbox regressions; no repository-wide scans."""
import datetime as dt
import hashlib
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
            self.assertNotIn('diagnostics', scanner.steps[0])

    def test_failed_scans_retain_only_actionable_metadata(self):
        canary = 'CANARY-private-source-token'
        reports = {
            'dependencies': ({'SchemaVersion': 2, 'Results': [{
                'Target': 'Cargo.lock', 'Vulnerabilities': [{
                    'VulnerabilityID': 'RUSTSEC-2026-0001', 'PkgName': 'example-crate',
                    'InstalledVersion': '1.2.3', 'FixedVersion': '1.2.4, 2.0.1',
                    'Severity': 'HIGH', 'Title': canary, 'Description': canary,
                    'References': [canary], 'PkgIdentifier': {'PURL': canary},
                    'CauseMetadata': {'Source': canary}, 'Secret': canary}]}]},
                {'vulnerability_id': 'RUSTSEC-2026-0001', 'package': 'example-crate',
                 'installed_version': '1.2.3', 'fixed_versions': ['1.2.4', '2.0.1'],
                 'severity': 'HIGH', 'path': 'Cargo.lock'}),
            'sast': ({'results': [{
                'check_id': 'policy.busbar.python-dynamic-shell', 'path': '/input/src/tool.py',
                'start': {'line': 17, 'col': 3}, 'end': {'line': 18},
                'extra': {'severity': 'ERROR', 'message': canary, 'lines': canary,
                          'metavars': {'$CMD': {'abstract_content': canary}},
                          'metadata': {'secret': canary}, 'fix': canary}}],
                'errors': [], 'paths': {'scanned': ['src/tool.py']}},
                {'rule_id': 'busbar.python-dynamic-shell', 'path': 'src/tool.py',
                 'line': 17, 'severity': 'ERROR'}),
        }
        for kind, (report, expected) in reports.items():
            for code in (0, 1, 2):
                with self.subTest(kind=kind, code=code), tempfile.TemporaryDirectory() as temporary:
                    scanner = scan.Scanner(Path(__file__).resolve().parents[2], Path(temporary))
                    scanner.source_rows = [{'path': 'Cargo.lock'}, {'path': 'src/tool.py'}]
                    payload = json.dumps(report).encode()
                    with patch.object(scanner, 'container', return_value=(code, payload, '0' * 64)):
                        with self.assertRaisesRegex(ValueError, '^security scan refused: ' + kind + '$'):
                            scanner.scan(kind, kind, Path(temporary), [])
                    row = scanner.steps[0]
                    self.assertEqual(row['status'], 'fail')
                    self.assertEqual(row['findings'], 1)
                    self.assertEqual(row['diagnostics'], [expected])
                    self.assertEqual(row['diagnostics_omitted'], 0)
                    self.assertEqual(row['report_sha256'], hashlib.sha256(payload).hexdigest())
                    self.assertEqual(row['stderr_sha256'], '0' * 64)
                    self.assertNotIn(canary.encode(), scan.encoded(scanner.steps))
                    self.assertFalse((Path(temporary) / 'private-scanner-reports').exists())

    def test_diagnostics_omit_untrusted_or_oversized_metadata(self):
        canary = 'CANARY-private-source-token'
        result = {'check_id': canary, 'path': '/etc/' + canary,
                  'start': {'line': True}, 'extra': {'severity': canary, 'message': canary}}
        diagnostic = scan.finding_diagnostics('sast', {'results': [result]},
            source_paths={'src/tool.py'}, rule_ids=['busbar.python-dynamic-shell'])
        self.assertEqual(diagnostic, [{}])
        for path in ('/etc/passwd', '/input/../src/tool.py', './src/tool.py',
                     'src//tool.py', 'src\\tool.py', 'https://user:password@host/tool.py',
                     'a' * 513, 'src/line\nbreak.py'):
            with self.subTest(path=path):
                result['path'] = path
                self.assertEqual(scan.finding_diagnostics('sast', {'results': [result]},
                    source_paths={path}, rule_ids=[]), [{}])
        finding = {'VulnerabilityID': canary, 'PkgName': 'https://user:password@example.test/pkg',
                   'InstalledVersion': {'value': canary}, 'FixedVersion': ['1.2.3', canary],
                   'Severity': canary}
        report = {'Results': [{'Target': canary, 'Vulnerabilities': [finding]}]}
        self.assertEqual(scan.finding_diagnostics('dependencies', report,
            source_paths=set(), rule_ids=[]), [{}])
        for key, value in [('VulnerabilityID', 'CVE-2026-' + '1' * 100),
                           ('PkgName', 'a' * 129), ('InstalledVersion', '1' * 65),
                           ('FixedVersion', '1' * 257), ('FixedVersion', ', '.join(['1.0'] * 9)),
                           ('FixedVersion', '1.0, token=secret')]:
            with self.subTest(key=key, value=value):
                mutated = {**finding, key: value}
                self.assertEqual(scan.finding_diagnostics('dependencies',
                    {'Results': [{'Vulnerabilities': [mutated]}]},
                    source_paths=set(), rule_ids=[]), [{}])

    def test_diagnostics_cap_does_not_change_failure_or_raw_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            scanner = scan.Scanner(Path(__file__).resolve().parents[2], Path(temporary))
            findings = [{'VulnerabilityID': 'CVE-2026-12345', 'Severity': 'HIGH'}] * (
                scan.DIAGNOSTIC_LIMIT + 3)
            payload = json.dumps({'SchemaVersion': 2, 'Results': [
                {'Vulnerabilities': findings[:50]}, {'Vulnerabilities': findings[50:]}]}).encode()
            with patch.object(scanner, 'container', return_value=(0, payload, '0' * 64)):
                with self.assertRaises(ValueError):
                    scanner.scan('dependencies', 'dependencies', Path(temporary), [])
            row = scanner.steps[0]
            self.assertEqual(row['findings'], scan.DIAGNOSTIC_LIMIT + 3)
            self.assertEqual(len(row['diagnostics']), scan.DIAGNOSTIC_LIMIT)
            self.assertEqual(row['diagnostics_omitted'], 3)
            self.assertEqual(row['status'], 'fail')

    def test_clean_scans_and_malformed_reports_keep_fail_closed_behavior(self):
        reports = [
            ('sast', {'results': [], 'errors': [], 'paths': {'scanned': ['src/tool.py']}}, True),
            ('dependencies', {'SchemaVersion': 2, 'Results': []}, True),
            ('sast', {'results': [], 'errors': [{'message': 'CANARY-private-token'}],
                      'paths': {'scanned': ['src/tool.py']}}, False),
            ('sast', {'results': [None], 'errors': [], 'paths': {'scanned': ['src/tool.py']}}, False),
            ('dependencies', {'SchemaVersion': 2, 'Results': [{'Vulnerabilities': [None]}]}, False),
        ]
        for kind, report, clean in reports:
            with self.subTest(kind=kind, report=report), tempfile.TemporaryDirectory() as temporary:
                scanner = scan.Scanner(Path(__file__).resolve().parents[2], Path(temporary))
                with patch.object(scanner, 'container', return_value=(0, json.dumps(report).encode(), '0' * 64)):
                    if clean:
                        scanner.scan(kind, kind, Path(temporary), [])
                        self.assertEqual(scanner.steps[0]['diagnostics'], [])
                        self.assertEqual(scanner.steps[0]['diagnostics_omitted'], 0)
                    else:
                        with self.assertRaises(ValueError):
                            scanner.scan(kind, kind, Path(temporary), [])
                    self.assertEqual(scanner.steps[0]['status'], 'pass' if clean else 'fail')
                    self.assertNotIn('CANARY-private-token', json.dumps(scanner.steps))

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
