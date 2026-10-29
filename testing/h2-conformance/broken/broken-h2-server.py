#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# THE NEGATIVE CONTROL: a deliberately broken HTTP/2 server (TLS, ALPN h2) that h2spec MUST grade red.
#
#   broken-h2-server.py <port> <cert.pem> <key.pem>     prints BROKEN_H2_PORT=<port> once listening
#
# Its faults, each a MUST of RFC 9113 it breaks:
#   * it never acknowledges the client's SETTINGS (RFC 9113 6.5.3);
#   * it never answers PING (6.7), never sends WINDOW_UPDATE and never validates a frame: a frame of
#     the wrong size, on the wrong stream, in the wrong state, or an oversized/illegal one gets no
#     connection error or stream error (4.2, 5.4, 6.x);
#   * every HEADERS frame, however malformed (a pseudo-header after a regular field, a missing
#     :method, an uppercase field name), is answered `200` with a body: no request is ever refused
#     (8.1.2);
#   * it never sends GOAWAY or RST_STREAM.
# It speaks just enough HTTP/2 to look alive (preface, an empty SETTINGS, a static-table `:status 200`),
# so a grader that only checked "the connection opened" would pass it.
import socket
import ssl
import struct
import sys
import threading

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
HEADERS, DATA, SETTINGS = 0x1, 0x0, 0x4


def frame(kind, flags, stream, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([kind, flags]) + struct.pack(">I", stream) + payload


def read_n(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def serve(sock):
    try:
        sock.settimeout(30)
        if read_n(sock, len(PREFACE)) != PREFACE:
            return
        sock.sendall(frame(SETTINGS, 0, 0))
        while True:
            head = read_n(sock, 9)
            length = int.from_bytes(head[:3], "big")
            kind, flags = head[3], head[4]
            stream = int.from_bytes(head[5:], "big") & 0x7FFFFFFF
            if length:
                read_n(sock, min(length, 1 << 20))
            if kind == HEADERS and stream:
                # :status 200 (static index 8), END_HEADERS; then a body and END_STREAM.
                sock.sendall(frame(HEADERS, 0x4, stream, b"\x88") + frame(DATA, 0x1, stream, b"ok\n"))
    except (OSError, EOFError):
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


def main():
    port, cert, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["h2"])
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    print("BROKEN_H2_PORT=%d" % srv.getsockname()[1], flush=True)
    while True:
        raw, _ = srv.accept()
        try:
            tls = ctx.wrap_socket(raw, server_side=True)
        except (OSError, ssl.SSLError):
            raw.close()
            continue
        threading.Thread(target=serve, args=(tls,), daemon=True).start()


if __name__ == "__main__":
    main()
