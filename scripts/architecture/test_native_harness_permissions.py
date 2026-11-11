"""Controller-generated harness sources must be readable, never candidate writable."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import native


class HarnessPermissions(unittest.TestCase):
    def prepare(self, root):
        checkout, trusted, control = (root / name for name in ('checkout', 'trusted', 'control'))
        for path in (checkout, trusted, control):
            path.mkdir(mode=0o700)
        config = root / 'runtime.json'
        config.write_text('{}')
        args = SimpleNamespace(conformance_only=False, checkout=checkout, trusted=trusted,
            work=control, confinement=config, confinement_sha256=native.digest(config))
        # Stop immediately after the real production constructor prepares its
        # filesystem roots. No controller policy or runtime substitutes are run.
        with patch('native_confinement.Execution', side_effect=RuntimeError('roots prepared')):
            with self.assertRaisesRegex(RuntimeError, 'roots prepared'):
                native.Qualification(args)
        harness = control / 'harness'
        (harness / 'architecture').mkdir(mode=0o755)
        (harness / 'architecture/Cargo.toml').write_text('[workspace]\n')
        (control / 'private-receipt').write_text('not a candidate input')
        return harness, control

    def test_published_harness_root_is_traversable_but_private_siblings_stay_closed(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            harness, control = self.prepare(Path(directory))
            self.assertEqual(harness.stat().st_mode & 0o777, 0o755)
            self.assertEqual(control.stat().st_mode & 0o777, 0o700)
            self.assertEqual((control / 'candidate').stat().st_mode & 0o777, 0o700)

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0,
                         'requires the Linux root controller for real mapped-UID access')
    def test_mapped_candidate_can_read_harness_but_cannot_modify_it_or_read_receipts(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            harness, _ = self.prepare(Path(directory))
            code = '''import os
os.setgroups([])
os.setgid(525290)
os.setuid(525289)
os.chdir('architecture')
assert open('Cargo.toml').read() == '[workspace]\\n'
for name, mode in [('Cargo.toml','a'),('../../private-receipt','r')]:
 try:
  with open(name,mode): pass
 except PermissionError:
  continue
 raise AssertionError('candidate accessed protected path: '+name)
print('mapped UID can read harness; writes and controller receipts denied')
'''
            result = subprocess.run([sys.executable, '-I', '-B', '-c', code], cwd=harness,
                                    capture_output=True, text=True, env={'PATH':'/usr/bin:/bin'})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('receipts denied', result.stdout)


if __name__ == '__main__':
    unittest.main()
