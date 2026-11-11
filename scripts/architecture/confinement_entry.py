"""Pinned-image entry: loopback fixture adapters, then the candidate command.

No host address is accepted here. Each Unix socket is a controller-created,
single-destination fixture capability. Network-none remains in force.
"""

import json
import os
from pathlib import Path
import socket
import shutil
import tempfile
import socketserver
import sys
import threading


def relay(left, right):
    try:
        # Either relay leg may write to TCP. Preserve the native client's prompt
        # small writes across the Unix capability instead of adding Nagle/delayed
        # ACK stalls to every database protocol exchange.
        if right.family in (socket.AF_INET, socket.AF_INET6):
            right.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        while data := left.recv(65536):
            right.sendall(data)
    except OSError:
        pass
    finally:
        try:
            right.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def ignore_cargo_seed_entries(seed_root, directory, names):
    """Ignore only Cargo's root tools and cache markers when cloning its seed."""
    if Path(directory) != Path(seed_root):
        return set()
    return {
        name for name in names
        if name == "bin" or name.startswith((".package-cache", ".global-cache"))
    }


def readonly_format_command(argv):
    """The controller's finite formatting commands need no writable Cargo cache."""
    return list(argv) in (
        ["cargo", "fmt", "--all"],
        ["cargo", "fmt", "--all", "--check"],
        ["cargo", "fmt", "--manifest-path", "dist/default/Cargo.toml", "--all", "--check"],
    )


def prepare_cargo_home(argv):
    seed = os.environ.get("CARGO_HOME")
    if not seed:
        return
    # Keep the prepared directory and its normal controller disposal even when
    # formatting can read the immutable seed directly. All compilation and
    # candidate test commands still get independent writable source copies.
    fresh = Path(os.environ.pop('BUSBAR_INVOCATION_CARGO_HOME'))
    if (fresh.parent != Path(os.environ['HOME']).parent or fresh.name != 'cargo-home-invocation'
            or fresh.is_symlink() or not fresh.is_dir() or any(fresh.iterdir())):
        raise RuntimeError('private Cargo cache was not prepared by the controller')
    if readonly_format_command(argv):
        # The image root and controller-mounted job seed are both read-only.
        # Check the actual filesystem, not permissions a candidate could chmod.
        if not os.statvfs(seed).f_flag & os.ST_RDONLY:
            raise RuntimeError('formatting requires a read-only Cargo seed')
        return
    shutil.copytree(
        seed,
        fresh,
        dirs_exist_ok=True,
        ignore=lambda directory, names: ignore_cargo_seed_entries(seed, directory, names),
    )
    os.environ["CARGO_HOME"] = str(fresh)


def start(port, path):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            with socket.socket(socket.AF_UNIX) as upstream:
                upstream.connect(path)
                thread = threading.Thread(
                    target=relay, args=(self.request, upstream), daemon=True
                )
                thread.start()
                relay(upstream, self.request)
                thread.join(timeout=5)

    server = Server(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def verify_boundary():
    for kind in ("uid", "gid"):
        expected = json.loads(os.environ.pop("BUSBAR_EXPECTED_" + kind.upper() + "_MAP"))
        actual = [list(map(int, row.split())) for row in
                  Path("/proc/self/" + kind + "_map").read_text().splitlines()]
        if (not isinstance(expected, list) or len(expected) != 3
                or not all(type(value) is int for value in expected)
                or expected[0] != 0 or expected[1] < 65536
                or actual != [expected]):
            raise RuntimeError("candidate user namespace differs from protected mapping")
    status = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    if os.geteuid() == 0 or any(
        int(status[name].strip(), 16) for name in ("CapEff", "CapPrm", "CapBnd")
    ):
        raise RuntimeError("candidate has elevated identity or capabilities")
    if status["NoNewPrivs"].strip() != "1" or status["Seccomp"].strip() != "2":
        raise RuntimeError("candidate lacks no-new-privileges or seccomp filtering")
    if set(os.listdir("/sys/class/net")) != {"lo"}:
        raise RuntimeError("candidate has an external network interface")


def main():
    import subprocess

    verify_boundary()
    if sys.argv[1:2] != ["--"] or len(sys.argv) < 3:
        raise ValueError("missing candidate command")
    prepare_cargo_home(sys.argv[2:])
    rows = json.loads(Path("/__busbar_fixture_map.json").read_text())
    servers = []
    for row in rows:
        if (
            set(row) != {"port", "socket"}
            or type(row["port"]) is not int
            or not 1024 <= row["port"] <= 65535
        ):
            raise ValueError("invalid fixture mapping")
        if row["socket"] != str(row["port"]) + ".sock":
            raise ValueError("invalid fixture capability")
        servers.append(start(row["port"], "/__busbar_fixtures/" + row["socket"]))
    # Keep the proxy supervisor alive; Docker's init reaps descendant processes.
    try:
        return subprocess.call(sys.argv[2:], env=os.environ)
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    sys.exit(main())
