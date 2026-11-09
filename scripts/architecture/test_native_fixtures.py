"""Fixture readiness excludes the LDAP image's temporary bootstrap daemon."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from native_fixtures import ldap_readiness_command


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


if __name__ == '__main__':
    unittest.main()
