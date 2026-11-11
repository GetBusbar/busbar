"""A missing, substituted or candidate-writable judge cannot qualify LLM traffic."""
import base64
import hashlib
import json
import io
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from check import Violation
from native_oracle import prepare, root_owned, verify
import native_oracle


class Oracle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.judge = self.root / 'busbar-oracle'
        self.judge.write_bytes(b'bounded test judge')
        self.judge.chmod(0o755)
        digest = hashlib.sha256(self.judge.read_bytes()).hexdigest()
        key, public = self.root / 'private.pem', self.root / 'public.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'ed25519', '-out', str(key)],
                       check=True, capture_output=True)
        subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-out', str(public)],
                       check=True, capture_output=True)
        message, signature = self.root / 'message', self.root / 'signature'
        message.write_text('test-artifact\n' + digest + '\n')
        subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', str(key), '-rawin',
                        '-in', str(message), '-out', str(signature)], check=True, capture_output=True)
        row = dict(filename='test-artifact', sha256=digest,
                   signature=base64.b64encode(signature.read_bytes()).decode(), canonical_asset='signed-origin')
        self.pin = dict(repository='GetBusbar/busbar-release', source='a' * 40,
                        crate='busbar-oracle', bin='busbar-oracle', release_key_pem=public.read_text(),
                        platforms={'x86_64': row, 'aarch64': dict(row)})

    def test_signed_bytes_pass_and_changed_bytes_refuse(self):
        expected = self.pin['platforms']['x86_64']['sha256']
        self.assertEqual(verify(self.judge, self.pin, 'x86_64', self.root / 'good'), expected)
        self.judge.write_bytes(b'substituted candidate judge')
        with self.assertRaisesRegex(Violation, 'digest differs'):
            verify(self.judge, self.pin, 'x86_64', self.root / 'bad')

    def test_signature_binds_artifact_identity(self):
        self.pin['platforms']['x86_64']['filename'] = 'another-release'
        with self.assertRaisesRegex(Violation, 'signature'):
            verify(self.judge, self.pin, 'x86_64', self.root / 'wrong-identity')

    def test_missing_judge_has_no_fallback(self):
        self.judge.unlink()
        with self.assertRaises(FileNotFoundError):
            verify(self.judge, self.pin, 'x86_64', self.root / 'missing')

    def test_cache_rejects_writable_foreign_owned_or_symlink_components(self):
        safe = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o755)
        with patch.object(Path, 'lstat', return_value=safe):
            root_owned(self.judge)
        for info in (SimpleNamespace(st_uid=1, st_mode=safe.st_mode),
                     SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o775),
                     SimpleNamespace(st_uid=0, st_mode=stat.S_IFLNK | 0o755)):
            with patch.object(Path, 'lstat', return_value=info), self.assertRaises(Violation):
                root_owned(self.judge)
        with patch.object(Path, 'lstat', side_effect=[safe, info]), self.assertRaises(Violation):
            root_owned(self.judge)

    def test_only_protected_pin_supplies_runtime_judge_environment(self):
        (self.root / 'ci').mkdir()
        (self.root / 'ci/native-oracle.json').write_text(json.dumps(self.pin))
        digest = self.pin['platforms']['x86_64']['sha256']
        cache = self.root / 'cache' / digest
        cache.mkdir(parents=True)
        installed = cache / 'busbar-oracle'
        installed.write_bytes(self.judge.read_bytes())
        installed.chmod(0o755)
        calls = []
        q = SimpleNamespace(trusted=self.root, evidence=self.root / 'evidence', env={}, receipt={},
                            save=lambda: None, run=lambda *args, **kw: calls.append((args, kw)))
        with patch('native_oracle.TOOLS', self.root / 'cache'), \
             patch('native_oracle.root_owned') as ownership, \
             patch('native_oracle.platform.system', return_value='Linux'), \
             patch('native_oracle.platform.machine', return_value='x86_64'), \
             patch.dict('os.environ', {'BUSBAR_ORACLE_RELEASE_REF': 'candidate-chosen'}):
            prepare(q)
        ownership.assert_called_once_with(installed)
        self.assertEqual(q.env['BUSBAR_ORACLE_RELEASE_REF'], self.pin['source'])
        self.assertEqual(q.env['BUSBAR_ORACLE_JUDGE_PATH'], str(installed))
        self.assertEqual(q.receipt['oracle_judge']['sha256'], digest)
        self.assertTrue(q.receipt['oracle_judge']['signature_verified'])
        self.assertEqual(calls[0][0], ('oracle-judge-available', [str(installed), '--help']))

    def test_staging_uses_same_origin_api_and_verifies_signed_bytes(self):
        row = self.pin['platforms']['x86_64']
        row['canonical_asset'] = 'https://github.com/GetBusbar/busbar-release/-/releases/dev-bin/downloads/' + row['filename']
        calls = []
        class Opener:
            def open(_, request, timeout):
                calls.append(request)
                return io.BytesIO(self.judge.read_bytes())
        release = {'assets': {'links': [{'name': row['filename'], 'direct_asset_url': row['canonical_asset'],
                    'url': 'https://github.com/-/project/29/uploads/' + 'a' * 32 + '/' + row['filename']}]}}
        api = SimpleNamespace(server='https://github.com', token='test-only',
                              request=lambda path: release if path.endswith('/dev-bin') else {'id': 29})
        with patch.object(native_oracle.urllib.request, 'build_opener', return_value=Opener()):
            result = native_oracle.stage(self.pin, 'x86_64', self.root / 'staged', api)
        self.assertTrue(result['signature_verified'])
        self.assertEqual(result['sha256'], row['sha256'])
        self.assertIn('/api/v4/projects/29/uploads/', calls[0].full_url)
        self.assertNotIn('test-only', json.dumps(result))
        self.assertEqual(Path(result['artifact']).stat().st_mode & 0o777, 0o555)

    def test_staging_redirect_cannot_forward_credential_to_another_origin(self):
        request = native_oracle.urllib.request.Request('https://github.com/download', headers={'PRIVATE-TOKEN': 'test-only'})
        with self.assertRaisesRegex(Violation, 'credential origin'):
            native_oracle.SameOriginRedirect().redirect_request(request, None, 302, '', {}, 'https://other.invalid/file')

    def test_cache_installation_never_escalates_a_build_identity(self):
        with patch.object(native_oracle.os, 'geteuid', return_value=1000):
            with self.assertRaisesRegex(Violation, 'administrator identity'):
                native_oracle.install(self.pin, 'x86_64', self.judge, self.root / 'installation')
        self.assertFalse((self.root / 'installation').exists())


if __name__ == '__main__':
    unittest.main()
