"""Controller-only fixture capabilities. No protocol accepts destination addresses."""

import json
import os
import socket
import socketserver
import threading

from confinement_entry import relay


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class Fixtures:
    def __init__(self, execution):
        self.execution = execution
        self.servers = []
        self.ports = set()
        self.slots = threading.BoundedSemaphore(64)

    def add(self, port):
        if type(port) is not int or not 1024 <= port <= 65535:
            raise ValueError("invalid fixed fixture port")
        if port in self.ports:
            return
        if len(self.ports) >= 32:
            raise ValueError("too many fixed fixture capabilities")
        path = self.execution.fixture_directory / (str(port) + ".sock")

        if len(os.fsencode(path)) > 100:
            raise ValueError("fixture socket path exceeds portable Unix path limit")

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                # This tuple is fixed by the controller before the candidate runs.
                with socket.create_connection(
                    ("127.0.0.1", port), timeout=10
                ) as upstream:
                    upstream.settimeout(60)
                    self.request.settimeout(60)
                    thread = threading.Thread(
                        target=relay, args=(self.request, upstream), daemon=True
                    )
                    thread.start()
                    relay(upstream, self.request)
                    thread.join(timeout=5)

        server = Server(str(path), Handler)
        server.slots = self.slots
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
            server.server_close()
            path.unlink(missing_ok=True)
        self.servers.clear()
        self.ports.clear()
        self.execution.fixture_map.write_text("[]\n")
