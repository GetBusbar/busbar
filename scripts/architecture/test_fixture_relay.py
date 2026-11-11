"""Fixed-destination fixture relays preserve byte streams without TCP batching stalls."""
import socket
import threading
import unittest

from confinement_entry import relay


class FixtureRelay(unittest.TestCase):
    def exercise(self, outgoing, receiver):
        source, incoming = socket.socketpair()
        self.addCleanup(source.close)
        self.addCleanup(incoming.close)
        receiver.settimeout(5)
        worker = threading.Thread(target=relay, args=(incoming, outgoing), daemon=True)
        worker.start()
        payload = b'CONNECT 169.254.169.254:80\r\n\x00opaque fixture bytes'
        source.sendall(payload[:7])
        source.sendall(payload[7:])
        source.shutdown(socket.SHUT_WR)
        result = bytearray()
        while chunk := receiver.recv(4096):
            result.extend(chunk)
        worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(bytes(result), payload)

    def test_tcp_destination_disables_nagle_and_preserves_bytes_and_eof(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            with socket.create_connection(listener.getsockname()) as outgoing:
                receiver, _ = listener.accept()
                with receiver:
                    self.assertEqual(outgoing.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY), 0)
                    self.exercise(outgoing, receiver)
                    # Boolean socket options may return the kernel's nonzero flag bit.
                    self.assertNotEqual(outgoing.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY), 0)

    def test_unix_capability_preserves_bytes_and_eof_without_tcp_options(self):
        outgoing, receiver = socket.socketpair()
        with outgoing, receiver:
            self.exercise(outgoing, receiver)


if __name__ == '__main__':
    unittest.main()
