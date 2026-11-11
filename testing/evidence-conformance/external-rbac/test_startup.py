"""Startup diagnostics survive private-work cleanup without fixture credentials."""

import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

import zap


class StartupFailure(unittest.TestCase):
    def runner(self, root, code):
        runtime = root / "runtime"
        runtime.mkdir()
        java = root / "java"
        java.write_text(
            "#!" + sys.executable + "\n"
            "import sys, time\n"
            "if '-version' in sys.argv: sys.exit(0)\n" + code
        )
        java.chmod(0o700)
        runner = zap.ExternalRBAC(root / "private", root / "reports")

        def bootstrap(work):
            work.mkdir(parents=True)
            return runtime, java

        return runner, bootstrap

    def test_exited_process_diagnostic_survives_cleanup_and_redacts_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner, bootstrap = self.runner(
                root,
                "key=next(a.split('=',1)[1] for a in sys.argv if a.startswith('api.key='))\n"
                "print('api.key=' + key, file=sys.stderr)\n"
                "print('echo ' + key, file=sys.stderr)\n"
                "print('Authorization: Bearer credential', file=sys.stderr)\n"
                "print('java.nio.file.AccessDeniedException: /fixture/path', file=sys.stderr)\n"
                "sys.exit(23)\n",
            )
            captured = io.StringIO()
            with mock.patch.object(zap, "bootstrap", bootstrap), \
                    mock.patch.object(zap, "Credentials") as credentials, \
                    contextlib.redirect_stderr(captured):
                with self.assertRaisesRegex(zap.Refused, "exited during startup"):
                    runner.__enter__()
                credentials.assert_not_called()
            diagnostic = json.loads((runner.output / "startup-failure.json").read_text())
            self.assertEqual(diagnostic["exit_code"], 23)
            self.assertIn("AccessDeniedException", diagnostic["tail"])
            self.assertNotIn(runner.key, captured.getvalue())
            self.assertNotIn("Bearer credential", captured.getvalue())
            self.assertIn("ZAP_STARTUP_FAILURE ", captured.getvalue())
            self.assertFalse(runner.work.exists())
            self.assertEqual(runner.proc.returncode, 23)

    def test_deadline_diagnostic_is_bounded_and_child_is_reaped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner, bootstrap = self.runner(root, "time.sleep(30)\n")

            def api(*args):
                # A large, unterminated first line must not escape the tail cap.
                runner.stream.write(b"sensitive-prefix" + b"x" * 100000 + b"\n")
                runner.stream.write(b"startup waiting for fixture\n")
                runner.stream.flush()
                runner.deadline = time.monotonic() - 1
                raise zap.Refused("not ready")

            runner.deadline = time.monotonic() - 1
            captured = io.StringIO()
            with mock.patch.object(zap, "bootstrap", bootstrap), \
                    mock.patch.object(runner, "api", api), \
                    contextlib.redirect_stderr(captured):
                with self.assertRaisesRegex(zap.Refused, "startup deadline exceeded"):
                    runner.__enter__()
            diagnostic = json.loads((runner.output / "startup-failure.json").read_text())
            self.assertEqual(diagnostic["reason"], "startup-deadline-exceeded")
            self.assertIsNone(diagnostic["exit_code"])
            self.assertGreater(diagnostic["log_bytes"], 100000)
            self.assertEqual(diagnostic["tail"], "startup waiting for fixture")
            self.assertLess(len(captured.getvalue()), 20000)
            self.assertIsNotNone(runner.proc.returncode)
            self.assertFalse(runner.work.exists())


if __name__ == "__main__":
    unittest.main()
