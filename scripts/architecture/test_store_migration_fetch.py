"""Pinned migration artifacts retain byte verification through public API fallback."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'store-migration-fixture.sh'
URL = 'https://github.com/GetBusbar/busbar/releases/download/v1.5.5/busbar-x86_64.tar.gz'
API = 'https://api.github.com/repos/GetBusbar/busbar/releases/assets/123'
DATA = b'pinned archive bytes\x00\xff'


class Fetch(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        curl = self.bin / 'curl'
        curl.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
root = pathlib.Path(os.environ['FETCH_TEST_ROOT'])
with (root / 'calls').open('a') as out:
    out.write(json.dumps(args) + '\\n')
config = json.loads((root / 'config').read_text())
url = args[-1]
if '/releases/download/' in url:
    pathlib.Path(args[args.index('-o') + 1]).write_bytes(
        b'pinned archive bytes\\x00\\xff' if config['primary'] else b'partial response')
    sys.exit(0 if config['primary'] else 22)
if '/releases/tags/' in url:
    print(json.dumps(config['metadata']))
    sys.exit(0)
if url == config['api']:
    pathlib.Path(args[args.index('-o') + 1]).write_bytes(bytes(config['payload']))
    sys.exit(config.get('api_exit', 0))
sys.exit(99)
''')
        curl.chmod(0o755)

    def fetch(self, *, primary=False, endpoint=API, matches=True, payload=DATA,
              api_exit=0, url=URL, pin=None, assets=None):
        metadata = {'assets': [{'name': 'busbar-x86_64.tar.gz', 'id': 123,
                               'browser_download_url': URL, 'url': endpoint}] if matches else []}
        if assets is not None:
            metadata['assets'] = assets
        (self.root / 'config').write_text(json.dumps(dict(
            primary=primary, metadata=metadata, api=API,
            payload=list(payload), api_exit=api_exit,
        )))
        result = subprocess.run([
            'bash', '-c', 'source "$1"; fetch "$2" "$3" "$4"',
            'fetch-test', str(SCRIPT), url, str(self.root / 'artifact'),
            pin if pin is not None else hashlib.sha256(DATA).hexdigest(),
        ], env=dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                    FETCH_TEST_ROOT=str(self.root)), capture_output=True, text=True)
        calls = [json.loads(line) for line in (self.root / 'calls').read_text().splitlines()]
        return result, calls

    def test_primary_success_never_uses_api(self):
        result, calls = self.fetch(primary=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 1)
        self.assertEqual((self.root / 'artifact').read_bytes(), DATA)

    def test_api_fallback_replaces_partial_primary_and_keeps_exact_pin(self):
        result, calls = self.fetch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[1][-1],
                         'https://api.github.com/repos/GetBusbar/busbar/releases/tags/v1.5.5')
        self.assertEqual(calls[2][-1], API)
        self.assertIn('Accept: application/octet-stream', calls[2])
        self.assertTrue(all(not any('Authorization' in arg for arg in call) for call in calls))
        self.assertEqual((self.root / 'artifact').read_bytes(), DATA)

    def test_primary_digest_mismatch_is_fatal_without_fallback(self):
        result, calls = self.fetch(primary=True, pin='0' * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('digest mismatch', result.stderr)
        self.assertEqual(len(calls), 1)

    def test_api_digest_mismatch_is_fatal(self):
        result, calls = self.fetch(payload=b'changed archive')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('digest mismatch', result.stderr)
        self.assertEqual(len(calls), 3)

    def test_foreign_or_malformed_api_endpoint_is_never_fetched(self):
        for endpoint in ['https://example.com/repos/GetBusbar/busbar/releases/assets/123',
                         API.replace('/busbar/', '/another/'), API + '?redirect=1',
                         API.replace('/123', '/not-a-number')]:
            with self.subTest(endpoint=endpoint):
                (self.root / 'calls').unlink(missing_ok=True)
                result, calls = self.fetch(endpoint=endpoint)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(calls), 2)
                self.assertIn('could not resolve the exact public release asset', result.stderr)

    def test_no_matching_asset_is_fatal(self):
        result, calls = self.fetch(matches=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 2)

    def test_same_name_with_different_original_url_is_not_a_match(self):
        result, calls = self.fetch(assets=[{
            'name': 'busbar-x86_64.tar.gz', 'id': 123, 'url': API,
            'browser_download_url': URL.replace('v1.5.5', 'v1.5.4'),
        }])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 2)

    def test_duplicate_matching_assets_are_refused(self):
        asset = dict(name='busbar-x86_64.tar.gz', id=123, url=API,
                     browser_download_url=URL)
        result, calls = self.fetch(assets=[asset, asset])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 2)

    def test_api_download_failure_is_fatal(self):
        result, calls = self.fetch(api_exit=22)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('release asset API download failed', result.stderr)
        self.assertEqual(len(calls), 3)

    def test_untrusted_original_has_no_api_fallback(self):
        result, calls = self.fetch(url=URL.replace('GetBusbar', 'another-owner'))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)


if __name__ == '__main__':
    unittest.main()
