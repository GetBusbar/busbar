#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import native_resources as nr

CID = 'a' * 64


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class FakeProcess:
    """Finishes after `polls` timed-out waits; advances the shared clock per wait."""

    def __init__(self, clock, polls, code=0):
        self.clock, self.polls, self.code, self.args = clock, polls, code, ['cmd']
        self.waits = []

    def poll(self):
        return self.code if self.polls <= 0 else None

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if self.polls <= 0:
            return self.code
        self.polls -= 1
        self.clock.t += timeout
        raise subprocess.TimeoutExpired(self.args, timeout)


def cgroup(root, current, peak, usec):
    path = root / 'system.slice' / ('docker-' + CID + '.scope')
    path.mkdir(parents=True)
    (path / 'memory.current').write_text(f'{current}\n')
    (path / 'memory.peak').write_text(f'{peak}\n')
    (path / 'cpu.stat').write_text(f'usage_usec {usec}\nuser_usec 1\n')
    return path


class Resources(unittest.TestCase):
    def test_finds_the_container_cgroup_and_records_peak_cpu_and_heartbeat(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = cgroup(root, 100, 4096, 2_500_000)
            clock, lines = Clock(), []
            observer = nr.StepObserver('root-clippy', CID, clock=clock, root=root, emit=lines.append)
            process = FakeProcess(clock, polls=25)
            self.assertEqual(nr.wait_observed(process, 3600, observer, interval=15, clock=clock), 0)
            summary = observer.summary()
            self.assertEqual(observer.cgroup, path)
            self.assertTrue(summary['cgroup_observed'])
            self.assertEqual(summary['samples'], 25)
            self.assertEqual(summary['memory_peak_bytes'], 4096)
            self.assertEqual(summary['cpu_seconds'], 2.5)
            beats = [json.loads(line)['heartbeat'] for line in lines]
            self.assertEqual([b['step'] for b in beats], ['root-clippy'])
            self.assertGreaterEqual(beats[0]['elapsed_seconds'], 300)

    def test_preserves_the_original_timeout(self):
        clock = Clock()
        observer = nr.StepObserver('slow', None, clock=clock, root=Path('/nonexistent'), emit=lambda _: None)
        process = FakeProcess(clock, polls=10**6)
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            nr.wait_observed(process, 60, observer, interval=15, clock=clock)
        self.assertEqual(raised.exception.timeout, 60)
        self.assertLessEqual(clock.t, 60)

    def test_preserves_failing_exit_and_tolerates_missing_cgroup(self):
        clock = Clock()
        observer = nr.StepObserver('x', CID, clock=clock, root=Path('/nonexistent'), emit=lambda _: None)
        self.assertEqual(nr.wait_observed(FakeProcess(clock, polls=2, code=101), 3600, observer, clock=clock), 101)
        summary = observer.summary()
        self.assertFalse(summary['cgroup_observed'])
        self.assertIsNone(summary['memory_peak_bytes'])

    def test_observation_errors_never_change_the_outcome(self):
        clock = Clock()
        observer = nr.StepObserver('x', None, clock=clock, emit=lambda _: None)
        observer.sample = lambda: (_ for _ in ()).throw(RuntimeError('boom'))
        self.assertEqual(nr.wait_observed(FakeProcess(clock, polls=3, code=0), 3600, observer, clock=clock), 0)

    def test_ignores_short_or_absent_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            cgroup(Path(directory), 1, 1, 1)
            self.assertIsNone(nr.find_cgroup(None, Path(directory)))
            self.assertIsNone(nr.find_cgroup('aaa', Path(directory)))


if __name__ == '__main__':
    unittest.main()
