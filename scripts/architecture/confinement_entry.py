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
    seed = os.environ.get("CARGO_HOME")
    if seed:
        # Each invocation starts from the immutable image cache. Cargo can acquire
        # its locks without letting an earlier candidate poison a trusted harness.
        fresh = Path(
            tempfile.mkdtemp(prefix="cargo-home-", dir=Path(os.environ["HOME"]).parent)
        )
        shutil.copytree(
            seed,
            fresh,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("bin", ".package-cache*", ".global-cache*"),
        )
        os.environ["CARGO_HOME"] = str(fresh)
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
    if sys.argv[1:2] != ["--"] or len(sys.argv) < 3:
        raise ValueError("missing candidate command")
    try:
        return subprocess.call(sys.argv[2:], env=os.environ)
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    sys.exit(main())
