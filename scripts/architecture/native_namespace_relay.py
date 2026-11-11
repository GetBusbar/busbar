"""Fixed-port stream relay in a pinned fixture network namespace.

Only the protected controller invokes this helper. Arguments are inherited open
FDs and controller-selected integers, never a request supplied by the candidate.
The helper enters only the peer network namespace, drops its host identity, and
copies opaque bytes; it cannot resolve a candidate-selected destination.
"""
import ctypes
import os
import socket
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from confinement_entry import relay


def run(namespace, stream, port, uid, gid):
    if not (0 < port < 65536 and uid >= 65536 and gid >= 65536):
        raise ValueError('invalid protected relay endpoint')
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.setns(namespace, 0x40000000):  # CLONE_NEWNET only
        raise OSError(ctypes.get_errno(), 'cannot enter pinned fixture network namespace')
    os.close(namespace)
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    if libc.prctl(38, 1, 0, 0, 0):  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), 'cannot restrict relay privileges')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if any(int(status[key].strip(), 16) for key in ('CapEff', 'CapPrm', 'CapAmb')):
        raise RuntimeError('relay retained host capabilities after identity drop')
    with socket.socket(fileno=stream) as downstream:
        with socket.create_connection(('127.0.0.1', port), timeout=10) as upstream:
            downstream.settimeout(60)
            upstream.settimeout(60)
            thread = threading.Thread(target=relay, args=(downstream, upstream), daemon=True)
            thread.start()
            relay(upstream, downstream)
            thread.join(timeout=5)


if __name__ == '__main__':
    run(*map(int, sys.argv[1:]))
