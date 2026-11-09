"""Fixture readiness excludes the LDAP image's temporary bootstrap daemon."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from native_fixtures import Services, ldap_readiness_command


class Readiness(unittest.TestCase):
    def test_ldap_does_not_probe_until_bootstrap_daemon_has_stopped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker, called = root / 'first-start-done', root / 'called'
            search = root / 'ldapsearch'
            search.write_text('#!/bin/sh\nprintf ready > "$CALLED"\n')
            search.chmod(0o755)
            command = ldap_readiness_command('fixture')[3:]
            command[4] = str(marker)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'], CALLED=str(called))
            # Even a responsive bootstrap daemon must not satisfy readiness.
            self.assertNotEqual(subprocess.run(command, env=env).returncode, 0)
            self.assertFalse(called.exists())
            marker.touch()
            self.assertEqual(subprocess.run(command, env=env).returncode, 0)
            self.assertEqual(called.read_text(), 'ready')


class StoreEnvironment(unittest.TestCase):
    def qualification(self, root, repository):
        trusted, work = root / 'trusted', root / 'work'
        table = trusted / 'testing/fleet-fixtures/service-images.tsv'
        table.parent.mkdir(parents=True)
        table.write_text('valkey\tvalkey/valkey:8\tsha256:pinned\tvalkey-cli ping\t6379\t16379\t60\n')
        work.mkdir()
        return SimpleNamespace(repository=repository, trusted=trusted, work=work,
                               env={}, receipt={'job_id': '589'}, run=Mock(), save=Mock())

    def test_valkey_supplies_live_transport_and_isolated_server_witnesses(self):
        with tempfile.TemporaryDirectory() as directory:
            q = self.qualification(Path(directory), 'GetBusbar/busbar-store-valkey')
            services = Services(q, None)
            url = 'redis://127.0.0.1:34987/0'
            with patch.object(services, 'store', return_value=url):
                services.__enter__()
            for key in ('BUSBAR_TEST_VALKEY_URL', 'BUSBAR_TEST_VALKEY_V4_URL',
                        'VALKEY_URL', 'BUSBAR_V4_TRANSPORT_URL'):
                self.assertEqual(q.env[key], url)
            fixture = q.work / 'valkey-native'
            server = fixture / 'valkey-server'
            self.assertTrue(fixture.is_dir())
            self.assertEqual(q.env['BUSBAR_V4_TEST_TMP'], str(fixture))
            self.assertEqual(q.env['BUSBAR_VALKEY_SERVER'], str(server))
            q.run.assert_any_call('fixture-valkey-server', ['docker', 'cp',
                'busbar-store-qa-valkey-boundary-589:/usr/local/bin/valkey-server', str(server)], timeout=60)
            q.run.assert_any_call('fixture-valkey-server-check', [str(server), '--version'], timeout=30)

    def test_missing_isolated_server_executable_refuses_fixture_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as directory:
            q = self.qualification(Path(directory), 'GetBusbar/busbar-store-valkey')
            services = Services(q, None)

            def run(name, *_args, **_kwargs):
                if name == 'fixture-valkey-server-check':
                    raise RuntimeError('executable cannot run')

            q.run.side_effect = run
            with patch.object(services, 'store', return_value='redis://127.0.0.1:34987/0'), \
                    patch.object(services, 'close') as close:
                with self.assertRaisesRegex(RuntimeError, 'executable cannot run'):
                    services.__enter__()
            close.assert_called_once()
            self.assertNotIn('BUSBAR_VALKEY_SERVER', q.env)


if __name__ == '__main__':
    unittest.main()
