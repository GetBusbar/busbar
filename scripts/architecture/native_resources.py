"""Observe a running candidate step's cgroup and emit a credential-free heartbeat.

Observation only: nothing here decides a verdict. Docker removes a container's
cgroup when it exits, so peak memory has to be sampled while the step runs.
The numbers let build parallelism be chosen from measured peaks instead of a
fixed per-slot guess, and the heartbeat distinguishes a healthy long compile
from a stall in otherwise quiet logs.
"""

import json
import os
import time
from pathlib import Path

CGROUP_ROOT = Path('/sys/fs/cgroup')
SAMPLE_SECONDS = 15
HEARTBEAT_SECONDS = 300


def find_cgroup(container_id, root=CGROUP_ROOT, depth=6):
    """Return the cgroup v2 directory whose name contains the full container id."""
    if not container_id or len(container_id) < 12 or not root.is_dir():
        return None
    base = len(root.parts)
    for current, directories, _ in os.walk(root):
        path = Path(current)
        if len(path.parts) - base >= depth:
            directories[:] = []
        for name in directories:
            if container_id in name and (path / name / 'memory.current').is_file():
                return path / name
    return None


def _read_int(path):
    try:
        return int(path.read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return None


def _cpu_seconds(cgroup):
    try:
        for line in (cgroup / 'cpu.stat').read_text().splitlines():
            key, _, value = line.partition(' ')
            if key == 'usage_usec':
                return round(int(value) / 1e6, 3)
    except (OSError, ValueError):
        return None
    return None


class StepObserver:
    """Samples one step. `container_id` may be None for controller steps."""

    def __init__(self, name, container_id=None, clock=time.monotonic, root=CGROUP_ROOT,
                 emit=lambda line: print(line, flush=True)):
        self.name, self.container_id, self.clock, self.root, self.emit = name, container_id, clock, root, emit
        self.started = clock()
        self.last_heartbeat = self.started
        self.cgroup = None
        self.samples = 0
        self.memory_peak = None
        self.cpu_seconds = None

    def sample(self):
        if self.cgroup is None and self.container_id:
            self.cgroup = find_cgroup(self.container_id, self.root)
        current = None
        if self.cgroup is not None:
            current = _read_int(self.cgroup / 'memory.current')
            peak = _read_int(self.cgroup / 'memory.peak')
            observed = max(v for v in (peak, current, self.memory_peak or 0) if v is not None)
            self.memory_peak = observed
            cpu = _cpu_seconds(self.cgroup)
            if cpu is not None:
                self.cpu_seconds = cpu
            self.samples += 1
        now = self.clock()
        if now - self.last_heartbeat >= HEARTBEAT_SECONDS:
            self.last_heartbeat = now
            self.emit(json.dumps({'heartbeat': {
                'step': self.name, 'elapsed_seconds': round(now - self.started, 1),
                'memory_current_bytes': current, 'memory_peak_bytes': self.memory_peak,
                'cpu_seconds': self.cpu_seconds}}))

    def summary(self):
        return {'elapsed_seconds': round(self.clock() - self.started, 3),
                'cgroup_observed': self.cgroup is not None, 'samples': self.samples,
                'memory_peak_bytes': self.memory_peak, 'cpu_seconds': self.cpu_seconds,
                'sample_seconds': SAMPLE_SECONDS}


def wait_observed(process, timeout, observer, interval=SAMPLE_SECONDS, clock=time.monotonic):
    """`process.wait(timeout)` with periodic sampling; raises TimeoutExpired unchanged."""
    import subprocess
    deadline = clock() + timeout
    while True:
        remaining = deadline - clock()
        if remaining <= 0:
            # Let Popen raise its own TimeoutExpired with the original timeout.
            return process.wait(timeout=0) if process.poll() is not None else _expire(process, timeout)
        try:
            return process.wait(timeout=min(interval, remaining))
        except subprocess.TimeoutExpired:
            try:
                observer.sample()
            except Exception:  # observation must never change the step outcome
                pass


def _expire(process, timeout):
    import subprocess
    raise subprocess.TimeoutExpired(process.args, timeout)
