"""HTTP transport for the A2A bindings, plus raw-socket escape hatches.

Two layers on purpose:

  Client      well-behaved calls over the JSONRPC and HTTP+JSON bindings,
              used by the conformance tests.

  raw_*       deliberately ill-behaved byte-level operations (truncated
              bodies, connect-then-stall, disconnect mid-stream) that no
              polite HTTP library will let you perform.

gRPC is not implemented. That is a stated gap, not an oversight: doing it
properly needs generated stubs from a2a.proto and a protobuf runtime, which
would put a build step in front of every CI run. The harness reports GRPC
interfaces as untested rather than pretending.
"""

import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_TIMEOUT = 20.0


class HttpResponse:
    def __init__(self, status, headers, body, elapsed):
        self.status = status
        self.headers = {k.lower(): v for k, v in headers}
        self.raw_headers = headers
        self.body = body
        self.elapsed = elapsed

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.body.decode("utf-8"))

    def json_or_none(self):
        try:
            return self.json()
        except Exception:
            return None

    def content_type(self):
        return self.headers.get("content-type", "").split(";")[0].strip()


def _opener():
    ctx = ssl.create_default_context()
    # Test targets are routinely on self-signed certs in CI. Verification is
    # controlled by the caller through A2AHT_INSECURE_TLS; default is secure.
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))


def request(method, url, body=None, headers=None, timeout=DEFAULT_TIMEOUT,
            insecure=False):
    hdrs = dict(headers or {})
    data = body
    if isinstance(data, (dict, list)):
        data = json.dumps(data).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    elif isinstance(data, str):
        data = data.encode("utf-8")

    req = urllib.request.Request(url, data=data, method=method)
    for k, v in hdrs.items():
        req.add_header(k, v)

    if insecure:
        ctx = ssl._create_unverified_context()
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    else:
        opener = _opener()

    started = time.time()
    try:
        with opener.open(req, timeout=timeout) as resp:
            return HttpResponse(resp.status, list(resp.headers.items()),
                                resp.read(), time.time() - started)
    except urllib.error.HTTPError as exc:
        return HttpResponse(exc.code, list(exc.headers.items()),
                            exc.read(), time.time() - started)
    except Exception as exc:
        # A peer that drops the connection rather than answering is a RESULT,
        # not a harness crash. Synthesising 599 lets the test report it as a
        # clean failure with a legible message instead of a traceback: an
        # agent that hangs up on bad input is indistinguishable, to its peer,
        # from an agent that has died.
        return HttpResponse(
            599,
            [("Content-Type", "application/x-harness-connection-error")],
            ("connection failed without an HTTP response: %s: %s"
             % (type(exc).__name__, exc)).encode("utf-8"),
            time.time() - started)


def sse_events(url, body=None, headers=None, method="POST",
               max_events=200, timeout=DEFAULT_TIMEOUT, insecure=False,
               stop_after=None, abort_after_events=None):
    """Read a Server-Sent Events stream and yield decoded `data:` payloads.

    Returns (events, closed_cleanly, error). `abort_after_events` closes the
    connection from our side after N events, which is how the mid-stream
    client disconnect test is driven.
    """
    hdrs = dict(headers or {})
    hdrs.setdefault("Accept", "text/event-stream")
    data = body
    if isinstance(data, (dict, list)):
        data = json.dumps(data).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url, data=data, method=method)
    for k, v in hdrs.items():
        req.add_header(k, v)

    if insecure:
        ctx = ssl._create_unverified_context()
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    else:
        opener = _opener()

    events = []
    status = None
    ctype = None
    closed_cleanly = False
    error = None
    started = time.time()
    try:
        resp = opener.open(req, timeout=timeout)
        status = resp.status
        ctype = resp.headers.get("Content-Type", "")
        buf = b""
        while True:
            if time.time() - started > timeout:
                error = "timeout"
                break
            chunk = resp.read(1)
            if not chunk:
                closed_cleanly = True
                # A final frame not followed by a blank line would otherwise
                # be dropped on the floor at EOF.
                tail = _sse_data(buf.replace(b"\r\n", b"\n").replace(b"\r", b"\n"))
                if tail is not None:
                    events.append(tail)
                break
            buf += chunk
            # The SSE grammar (WHATWG HTML, server-sent events) allows CRLF,
            # LF or a bare CR as the line terminator, and real A2A servers use
            # different ones: a2a-go emits LF, a2a-python emits CRLF. A reader
            # that handles only LF silently sees zero events against half the
            # ecosystem, which looks exactly like a broken server.
            buf = buf.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            while b"\n\n" in buf:
                frame, buf = buf.split(b"\n\n", 1)
                payload = _sse_data(frame)
                if payload is None:
                    continue
                events.append(payload)
                if abort_after_events and len(events) >= abort_after_events:
                    resp.close()
                    return _SseResult(events, False, "aborted-by-harness",
                                      status, ctype)
                if stop_after and stop_after(payload):
                    resp.close()
                    return _SseResult(events, True, None, status, ctype)
                if len(events) >= max_events:
                    resp.close()
                    return _SseResult(events, False, "max-events", status, ctype)
        resp.close()
    except urllib.error.HTTPError as exc:
        status = exc.code
        ctype = exc.headers.get("Content-Type", "")
        error = "http-error"
        try:
            events.append(json.loads(exc.read().decode("utf-8")))
        except Exception:
            pass
    except Exception as exc:
        error = "%s: %s" % (type(exc).__name__, exc)
    return _SseResult(events, closed_cleanly, error, status, ctype)


class _SseResult:
    def __init__(self, events, closed_cleanly, error, status, content_type):
        self.events = events
        self.closed_cleanly = closed_cleanly
        self.error = error
        self.status = status
        self.content_type = (content_type or "").split(";")[0].strip()

    def __iter__(self):
        return iter(self.events)

    def __len__(self):
        return len(self.events)


def _sse_data(frame):
    lines = frame.decode("utf-8", "replace").splitlines()
    data_lines = [ln[5:].lstrip() for ln in lines if ln.startswith("data:")]
    if not data_lines:
        return None
    raw = "\n".join(data_lines)
    try:
        return json.loads(raw)
    except Exception:
        return {"_unparsed": raw}


# ---------------------------------------------------------------------------
# Raw socket operations. These exist to produce byte sequences a well-behaved
# HTTP client refuses to emit.
# ---------------------------------------------------------------------------

def _connect(url, timeout=DEFAULT_TIMEOUT, insecure=False):
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    sock = socket.create_connection((host, port), timeout=timeout)
    if parts.scheme == "https":
        ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=host)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return sock, host, path


def raw_send(url, method, body_bytes, headers=None, declared_length=None,
             send_bytes=None, timeout=DEFAULT_TIMEOUT, insecure=False,
             read_reply=True):
    """Send a hand-built request.

    `declared_length` lets you lie in Content-Length; `send_bytes` lets you
    send fewer bytes than you declared. Together they produce a truncated
    request body, which is the classic way to wedge a naive parser.
    """
    sock, host, path = _connect(url, timeout, insecure)
    payload = body_bytes or b""
    length = declared_length if declared_length is not None else len(payload)
    to_send = payload if send_bytes is None else payload[:send_bytes]

    lines = ["%s %s HTTP/1.1" % (method, path), "Host: %s" % host,
             "Content-Length: %d" % length, "Connection: close"]
    for k, v in (headers or {}).items():
        lines.append("%s: %s" % (k, v))
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
    try:
        sock.sendall(head + to_send)
        if not read_reply:
            return None
        sock.settimeout(timeout)
        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
        return data
    finally:
        try:
            sock.close()
        except Exception:
            pass


def raw_connect_and_stall(url, seconds, timeout=DEFAULT_TIMEOUT, insecure=False):
    """Open a connection, send a partial request, then go silent.

    Returns the number of seconds until the peer closed on us, or None if it
    was still holding the connection when we gave up. This measures whether
    the target has any idle timeout at all.
    """
    sock, host, path = _connect(url, timeout, insecure)
    try:
        head = ("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 1000\r\n\r\n"
                % (path, host)).encode("ascii")
        sock.sendall(head)
        sock.sendall(b"{")
        sock.settimeout(seconds)
        started = time.time()
        try:
            chunk = sock.recv(4096)
            if not chunk:
                return time.time() - started
            return time.time() - started
        except socket.timeout:
            return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def port_open(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def wait_for_port(host, port, deadline_seconds=30.0, interval=0.1):
    """Deterministic readiness wait.

    This is the ONE place a wall clock is allowed, and only as a deadline for
    giving up. No test asserts on how long this took.
    """
    end = time.time() + deadline_seconds
    while time.time() < end:
        if port_open(host, port):
            return True
        time.sleep(interval)
    return False
