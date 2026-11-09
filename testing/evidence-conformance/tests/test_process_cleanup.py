"""The evidence fixture must reap an owned subject that ignores graceful shutdown."""
import importlib.util
from pathlib import Path
import os
import signal
import subprocess
import sys
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('evidence_cleanup', Path(__file__).parents[1] / 'evidence.py')
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class ProcessCleanup(unittest.TestCase):
    def test_forced_shutdown_reaps_the_actual_child(self):
        process = subprocess.Popen([sys.executable, '-u', '-c',
            'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); '
            'print("ready", flush=True); time.sleep(60)'],
            stdout=subprocess.PIPE, text=True, start_new_session=True)
        original_wait = process.wait
        try:
            self.assertEqual(process.stdout.readline().strip(), 'ready')
            subject = evidence.Busbar.__new__(evidence.Busbar)
            subject.proc = process
            # Exercise the real timeout and SIGKILL without spending the full grace interval.
            def bounded_wait(timeout=None):
                return original_wait(timeout=0.1 if timeout == 15 else timeout)
            with mock.patch.object(process, 'wait', side_effect=bounded_wait):
                subject.stop()
            self.assertEqual(process.returncode, -signal.SIGKILL)
            with self.assertRaises(ChildProcessError):
                os.waitpid(process.pid, os.WNOHANG)
        finally:
            if process.poll() is None:
                process.kill()
            original_wait(timeout=5)
            process.stdout.close()


if __name__ == '__main__':
    unittest.main()
