"""Real child processes exercise native cancellation, nested cleanup and escalation."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import native


class Processes(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def qualification(self):
        q = native.Qualification.__new__(native.Qualification)
        q.root = self.root
        q.work = self.root / 'work'
        q.evidence = q.work / 'evidence'
        q.evidence.mkdir(parents=True)
        q.env = dict(os.environ)
        q.receipt = {'steps': []}
        return q

    def wait_file(self, path, process, log=None):
        deadline = time.monotonic() + 5
        while not path.exists():
            if process.poll() is not None or time.monotonic() > deadline:
                detail = log.read_text() if log is not None else ''
                self.fail(f'child did not become ready (exit={process.poll()}): {detail}')
            time.sleep(0.01)

    def assert_dead(self, pid):
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_term_and_int_allow_nested_session_cleanup_and_failed_receipt(self):
        supervisor = self.root / 'supervisor.py'
        supervisor.write_text('''import json, os, pathlib, signal, subprocess, sys, time
root = pathlib.Path(sys.argv[1])
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)
def stop(signum, frame):
    raise SystemExit(128 + signum)
signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
(root / 'pids').write_text(json.dumps([os.getpid(), child.pid]))
try:
    child.wait()
finally:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    time.sleep(0.15)
    os.killpg(child.pid, signal.SIGTERM)
    child.wait(timeout=1)
    (root / 'nested-cleaned').touch()
''')
        driver = self.root / 'driver.py'
        driver.write_text('''import os, pathlib, sys, types
sys.path.insert(0, sys.argv[1])
import native
root = pathlib.Path(sys.argv[2])
q = native.Qualification.__new__(native.Qualification)
q.repository = 'GetBusbar/busbar'
q.evaluation_only = False
q.policy = types.SimpleNamespace(data={'repositories': {'GetBusbar/busbar': {'native': {}}}})
q.execution = None
q.root = root / 'checkout'
q.root.mkdir()
q.work = root / 'boundary-1-2'
q.evidence = q.work / 'evidence'
q.evidence.mkdir(parents=True)
q.env = dict(os.environ)
q.receipt = {'steps': []}
q.host = lambda: q.root
# This fixture exercises cancellation, not recursive controller regressions.
q.core_regressions = lambda: None
supervisor = sys.argv[3]
q.core = lambda: q.run('nested', [sys.executable, supervisor, str(root)])
native.Qualification = lambda args: q
sys.modules['native_sources'] = types.SimpleNamespace(prepare=lambda *args: None)
os.environ.update(CI_JOB_ID='2', CI_PROJECT_ID='1', CI_PIPELINE_ID='1',
                  CI_PROJECT_PATH='GetBusbar/busbar', CI_CONFIG_REF_URI='test')
sys.argv = ['native.py', '--trusted', str(root), '--checkout', str(q.root), '--work', str(q.work)]
native.main()
''')
        for sig in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=sig):
                directory = self.root / str(sig)
                directory.mkdir()
                log = directory / 'driver.log'
                with log.open('wb') as output:
                    process = subprocess.Popen([
                        sys.executable, str(driver), str(Path(native.__file__).parent),
                        str(directory), str(supervisor),
                    ], stdout=output, stderr=output, start_new_session=True)
                    try:
                        self.wait_file(directory / 'pids', process, log)
                        pids = json.loads((directory / 'pids').read_text())
                        os.kill(process.pid, sig)
                        self.assertNotEqual(process.wait(timeout=5), 0)
                        self.assertTrue((directory / 'nested-cleaned').exists(), log.read_text())
                        for pid in pids:
                            self.assert_dead(pid)
                        receipt = json.loads((directory / 'checkout/boundary-evidence/receipt.json').read_text())
                        self.assertEqual(receipt['status'], 'fail')
                        self.assertEqual(receipt['steps'][0]['status'], 'interrupted')
                        self.assertEqual(receipt['steps'][0]['signal'], sig)
                        self.assertFalse((directory / 'boundary-1-2').exists())
                    finally:
                        if process.poll() is None:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait()
                        if (directory / 'pids').exists():
                            for pid in json.loads((directory / 'pids').read_text()):
                                try:
                                    os.killpg(pid, signal.SIGKILL)
                                except ProcessLookupError:
                                    pass

    def test_unresponsive_group_is_killed_within_grace_bound(self):
        ready = self.root / 'ready'
        code = 'import pathlib,signal,time,sys; signal.signal(signal.SIGTERM,signal.SIG_IGN); pathlib.Path(sys.argv[1]).touch(); time.sleep(60)'
        process = subprocess.Popen([sys.executable, '-c', code, str(ready)], start_new_session=True)
        try:
            self.wait_file(ready, process)
            start = time.monotonic()
            native.stop_process_group(process, grace=0.2)
            self.assertLess(time.monotonic() - start, 2)
            self.assertEqual(process.returncode, -signal.SIGKILL)
            self.assert_dead(process.pid)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()

    def test_signal_during_launch_still_cleans_the_spawned_group(self):
        q = self.qualification()
        real_popen = subprocess.Popen
        children = []
        ready = self.root / 'launch-ready'

        def launch(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            children.append(process)
            self.wait_file(ready, process)
            native.INTERRUPTIONS.handle(signal.SIGTERM, None)
            return process

        with native.interruption_signals(), patch('native.subprocess.Popen', side_effect=launch):
            with self.assertRaises(native.Interrupted):
                q.run('launch', [sys.executable, '-c',
                       'import pathlib,sys,time; pathlib.Path(sys.argv[1]).touch(); time.sleep(60)', str(ready)])
        self.assert_dead(children[0].pid)
        self.assertEqual(q.receipt['steps'][0]['status'], 'interrupted')

    def test_timeout_and_nonzero_exit_keep_their_original_failure_categories(self):
        q = self.qualification()
        with self.assertRaises(subprocess.TimeoutExpired):
            q.run('timeout', [sys.executable, '-c', 'import time; time.sleep(60)'], timeout=0.1)
        self.assertEqual(q.receipt['steps'][-1]['status'], 'timeout')
        with self.assertRaises(native.Violation):
            q.run('failed', [sys.executable, '-c', 'raise SystemExit(7)'])
        self.assertEqual(q.receipt['steps'][-1]['status'], 'fail')
        self.assertEqual(q.receipt['steps'][-1]['exit_code'], 7)


if __name__ == '__main__':
    unittest.main()
