"""Opt-in tiny real-tool tests, never a repository-wide scan.

Set BUSBAR_SECURITY_TEST_DOCKER_HOST to an existing local Unix Docker endpoint.
Images must already be present at the policy digests. No image pull or DB download.
"""
import json
import os
from pathlib import Path
import tempfile
import unittest

import scan


@unittest.skipUnless(os.environ.get('BUSBAR_SECURITY_TEST_DOCKER_HOST'), 'explicit fixture Docker endpoint required')
class ScannerTools(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.scanner = scan.Scanner(Path(__file__).resolve().parents[2], self.work)
        endpoint = os.environ['BUSBAR_SECURITY_TEST_DOCKER_HOST']
        self.assertTrue(endpoint.startswith('unix:///'))
        self.scanner.docker = ['docker', '--host', endpoint]
        self.source = self.work / 'fixture'
        self.source.mkdir()

    def sast(self):
        self.scanner.scan('sast', 'sast', self.source,
            ['scan', '--config', '/policy/semgrep.yaml', '--json', '--error', '--strict',
             '--metrics=off', '--disable-version-check', '--disable-nosem', '--no-git-ignore',
             '--max-target-bytes=0', '--optimizations=none', '--oss-only', '--jobs=2', '/input'], tool='semgrep')

    def test_semgrep_clean_finding_and_parse_error(self):
        path = self.source / 'fixture.py'
        path.write_text('print("fixture")\n')
        self.sast()
        path.write_text('import subprocess\nsubprocess.run("echo fixture", shell=True) # nosemgrep\n')
        with self.assertRaises(ValueError):
            self.sast()
        self.assertGreater(self.scanner.steps[-1]['findings'], 0)
        path.write_text('import subprocess\nsubprocess.run("fixture", shell=True\n')
        with self.assertRaises(ValueError):
            self.sast()
        self.assertEqual(self.scanner.steps[-1]['status'], 'fail')
        self.assertEqual(self.scanner.steps[-1]['exit_code'], 3)
        self.assertNotIn('findings', self.scanner.steps[-1])
        self.assertNotIn('echo fixture', json.dumps(self.scanner.steps))

    def test_trivy_clean_and_secret(self):
        path = self.source / 'fixture.txt'
        path.write_text('harmless fixture\n')
        self.scanner.scan('secrets', 'secrets', self.source,
                          self.scanner.trivy('filesystem', 'secret', ['/input']))
        # Trivy's private-key rule; synthetic text, not an actual credential.
        path.write_text('-----BEGIN RSA PRIVATE KEY-----\n' + 'fixture' * 20 + '\n-----END RSA PRIVATE KEY-----\n')
        with self.assertRaises(ValueError):
            self.scanner.scan('secrets', 'secrets', self.source,
                              self.scanner.trivy('filesystem', 'secret', ['/input']))
        self.assertGreater(self.scanner.steps[-1]['findings'], 0)

    def test_runtime_no_egress_credentials_or_source_write(self):
        self.scanner.tools['python3'] = self.scanner.tools['semgrep']
        (self.source / 'fixture.txt').write_text('private fixture')
        code, data, _ = self.scanner.container('python3', ['-c', '''
import errno, json, os, pathlib, socket
result = {}
s = socket.socket(); s.settimeout(2)
try:
    s.connect(('192.0.2.1', 443))
    result['network_blocked'] = False
except OSError as e:
    result['network_blocked'] = e.errno == errno.ENETUNREACH
try:
    pathlib.Path('/input/fixture.txt').write_text('changed')
    result['write_blocked'] = False
except OSError:
    result['write_blocked'] = True
result['no_token'] = 'CI_JOB_TOKEN' not in os.environ
result['no_socket'] = not pathlib.Path('/var/run/docker.sock').exists()
print(json.dumps(result))
'''], [(self.source, '/input', False)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(data), dict(network_blocked=True, write_blocked=True,
                                              no_token=True, no_socket=True))

    def test_sbom_flags_are_accepted_before_missing_database_refusal(self):
        # The prior draft used --secret-config here, an unsupported SBOM option.
        args = self.scanner.trivy('sbom', 'vuln', ['--help'])
        code, data, _ = self.scanner.container('trivy', args)
        self.assertEqual(code, 0)
        self.assertIn(b'Scan SBOM', data)

    @unittest.skipUnless(os.environ.get('BUSBAR_SECURITY_TEST_DB'), 'pre-fetched fixture database required')
    def test_sbom_known_vulnerability(self):
        self.scanner.cache = Path(os.environ['BUSBAR_SECURITY_TEST_DB'])
        scan.database_identity(self.scanner.cache, 72)
        (self.source / 'fixture.cdx.json').write_text(json.dumps({
            'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
            'components': [{'type': 'library', 'name': 'requests', 'version': '2.19.1',
                            'purl': 'pkg:pypi/requests@2.19.1'}]}))
        with self.assertRaises(ValueError):
            self.scanner.scan('fixture-sbom', 'dependencies', self.source,
                              self.scanner.trivy('sbom', 'vuln', ['/input/fixture.cdx.json']))
        self.assertGreater(self.scanner.steps[-1]['findings'], 0)
