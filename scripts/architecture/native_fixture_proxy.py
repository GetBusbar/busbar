"""Controller-only fixture capabilities. No protocol accepts destination addresses."""

import json
import os
import socket
import socketserver
import subprocess
import sys
from pathlib import Path
import threading

from confinement_entry import relay


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = False
    block_on_close = True

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self.active_lock:
            self.active.add(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self.active_lock:
                self.active.discard(request)
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.active_lock:
                self.active.discard(request)
            self.slots.release()


class Fixtures:
    def __init__(self, execution):
        self.execution = execution
        self.servers = []
        self.ports = set()
        self.slots = threading.BoundedSemaphore(64)

    def add(self, port, *, namespace=None, peer_port=None):
        if type(port) is not int or not 1024 <= port <= 65535:
            raise ValueError("invalid fixed fixture port")
        if port in self.ports:
            return
        if len(self.ports) >= 32:
            raise ValueError("too many fixed fixture capabilities")
        if namespace is not None and (type(namespace) is not int or type(peer_port) is not int
                                      or not 1 <= peer_port <= 65535):
            raise ValueError("invalid pinned namespace endpoint")
        execution = self.execution
        path = self.execution.fixture_directory / (str(port) + ".sock")

        if len(os.fsencode(path)) > 100:
            raise ValueError("fixture socket path exceeds portable Unix path limit")

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                process = None
                if namespace is None:
                    upstream = socket.create_connection(("127.0.0.1", port), timeout=10)
                else:
                    upstream, child = socket.socketpair()
                    try:
                        process = subprocess.Popen([sys.executable, '-I', '-B',
                            str(Path(__file__).with_name('native_namespace_relay.py')),
                            str(namespace), str(child.fileno()), str(peer_port),
                            str(execution.config['collector']['uid']),
                            str(execution.config['collector']['gid'])],
                            pass_fds=(namespace, child.fileno()), stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
                    except BaseException:
                        upstream.close()
                        raise
                    finally:
                        child.close()
                try:
                    with upstream:
                        upstream.settimeout(60)
                        self.request.settimeout(60)
                        thread = threading.Thread(target=relay, args=(self.request, upstream), daemon=True)
                        thread.start()
                        relay(upstream, self.request)
                        thread.join(timeout=5)
                finally:
                    if process is not None:
                        try:
                            process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=2)

        server = Server(str(path), Handler)
        server.slots = self.slots
        server.active = set()
        server.active_lock = threading.Lock()
        try:
            os.chmod(path, 0o666)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        except BaseException:
            server.server_close()
            path.unlink(missing_ok=True)
            raise
        self.servers.append((server, path))
        self.ports.add(port)
        self.execution.fixture_map.write_text(
            json.dumps(
                [{"port": p, "socket": str(p) + ".sock"} for p in sorted(self.ports)]
            )
            + "\n"
        )

    def close(self):
        for server, path in self.servers:
            server.shutdown()
            with server.active_lock:
                for stream in server.active:
                    try:
                        stream.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
            server.server_close()
            path.unlink(missing_ok=True)
        self.servers.clear()
        self.ports.clear()
        self.execution.fixture_map.write_text("[]\n")
