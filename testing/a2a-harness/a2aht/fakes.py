"""Fake peers: a spec-correct A2A server, a configurable hostile one, and a
webhook sink.

These exist so the harness can test the target's CLIENT role. To test whether
a subject behaves correctly as a client you must control what it talks to, and
that means running a server whose misbehaviour you can dial in precisely.

The honest server here is also load-bearing in another way: it is a second
opinion on the spec. If the honest fake and the control disagree, one of the
two is wrong and the harness author needs to know before trusting either.
"""

import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import spec


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".000Z"


def honest_card(base_url, name="Harness Honest Peer", streaming=True,
                push=False, extended=False, skills=None, binding="HTTP+JSON",
                version="1.0"):
    """A card that satisfies every REQUIRED field in PROTO AgentCard."""
    return {
        "name": name,
        "description": "A deliberately correct A2A peer, used by the "
                       "independent harness to test client behaviour.",
        "supportedInterfaces": [
            {"url": base_url, "protocolBinding": binding,
             "protocolVersion": version},
        ],
        "version": "1.0.0",
        "capabilities": {
            "streaming": streaming,
            "pushNotifications": push,
            "extendedAgentCard": extended,
        },
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": skills if skills is not None else [{
            "id": "echo",
            "name": "Echo",
            "description": "Returns the text it was given, unchanged.",
            "tags": ["echo", "test"],
        }],
    }


class Behaviour:
    """Every way the fake peer can misbehave, all off by default.

    Each switch corresponds to a named test. Adding a switch without a test
    that uses it is dead weight; adding a test without a switch means the test
    is not actually exercising the condition it claims to.
    """

    def __init__(self, **kw):
        # Card level
        self.card_missing_fields = kw.get("card_missing_fields") or []
        self.card_mutate_after_n_fetches = kw.get("card_mutate_after_n_fetches")
        self.card_mutation = kw.get("card_mutation") or {}
        self.card_status = kw.get("card_status", 200)
        self.card_body_override = kw.get("card_body_override")
        self.card_declares_streaming = kw.get("card_declares_streaming", True)
        self.card_declares_push = kw.get("card_declares_push", False)
        self.card_protocol_version = kw.get("card_protocol_version", "1.0")
        self.card_content_type = kw.get("card_content_type", "application/json")
        self.card_delay_seconds = kw.get("card_delay_seconds", 0)
        # Authentication. Neither public control declares any security
        # scheme, so this is the only way the battery can exercise the auth
        # surface at all.
        self.card_security_schemes = kw.get("card_security_schemes")
        self.card_security_requirements = kw.get("card_security_requirements")
        self.require_auth = kw.get("require_auth")  # e.g. "Bearer s3cret"
        self.card_signatures = kw.get("card_signatures")

        # Capability lying
        self.streaming_actually_works = kw.get("streaming_actually_works", True)

        # Response level
        self.emit_unknown_task_state = kw.get("emit_unknown_task_state")
        self.emit_duplicate_task_ids = kw.get("emit_duplicate_task_ids", False)
        self.emit_response_to_nothing = kw.get("emit_response_to_nothing", False)
        self.never_resolve = kw.get("never_resolve", False)
        self.oversized_artifact_bytes = kw.get("oversized_artifact_bytes", 0)
        self.nesting_depth = kw.get("nesting_depth", 0)
        self.truncate_stream_after = kw.get("truncate_stream_after")
        self.stall_seconds = kw.get("stall_seconds", 0)
        self.prompt_injection_text = kw.get("prompt_injection_text")
        self.artifact_media_type_lie = kw.get("artifact_media_type_lie")
        self.echo_wrong_task_id = kw.get("echo_wrong_task_id", False)
        self.reject_all = kw.get("reject_all", False)
        self.malformed_json_response = kw.get("malformed_json_response", False)
        self.wrong_jsonrpc_id = kw.get("wrong_jsonrpc_id", False)


class FakePeer:
    """An A2A server the harness fully controls."""

    def __init__(self, behaviour=None, host="127.0.0.1", port=0,
                 binding="HTTP+JSON"):
        self.behaviour = behaviour or Behaviour()
        self.host = host
        self.binding = binding
        self.tasks = {}
        self.requests = []  # everything the peer under test sent us
        self.card_fetches = 0
        self._lock = threading.Lock()
        self._server = ThreadingHTTPServer((host, port), _make_handler(self))
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self._thread = None

    @property
    def base_url(self):
        return "http://%s:%d" % (self.host, self.port)

    def card(self):
        b = self.behaviour
        if b.card_body_override is not None:
            return b.card_body_override
        card = honest_card(self.base_url, streaming=b.card_declares_streaming,
                           push=b.card_declares_push, binding=self.binding,
                           version=b.card_protocol_version)
        if b.card_security_schemes is not None:
            card["securitySchemes"] = b.card_security_schemes
        if b.card_security_requirements is not None:
            card["securityRequirements"] = b.card_security_requirements
        if b.card_signatures is not None:
            card["signatures"] = b.card_signatures
        for field in b.card_missing_fields:
            card.pop(field, None)
        if (b.card_mutate_after_n_fetches is not None
                and self.card_fetches > b.card_mutate_after_n_fetches):
            card = _deep_merge(card, b.card_mutation)
        return card

    def start(self):
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()
        return self

    def stop(self):
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception:
            pass

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False

    def record(self, method, path, headers, body):
        with self._lock:
            self.requests.append({
                "method": method, "path": path,
                "headers": {k.lower(): v for k, v in headers.items()},
                "body": body,
                "at": time.time(),
            })

    def saw_header(self, name):
        name = name.lower()
        return [r["headers"].get(name) for r in self.requests
                if name in r["headers"]]

    def a2a_requests(self):
        return [r for r in self.requests
                if not r["path"].endswith("agent-card.json")]


def _deep_merge(base, patch):
    out = dict(base)
    for k, v in (patch or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _nested(depth):
    node = {"leaf": True}
    for _ in range(depth):
        node = {"n": node}
    return node


def _make_handler(peer):

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        # -- plumbing ----------------------------------------------------

        def _read_body(self):
            length = int(self.headers.get("Content-Length") or 0)
            if not length:
                return None
            raw = self.rfile.read(length)
            try:
                return json.loads(raw.decode("utf-8"))
            except Exception:
                return {"_unparsed": raw.decode("utf-8", "replace")}

        def _json(self, obj, status=200, content_type=None):
            b = peer.behaviour
            if b.malformed_json_response:
                raw = b'{"task": {"id": "truncated"'
            else:
                raw = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type",
                             content_type or spec.MEDIA_TYPE_A2A_JSON)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _error(self, http_status, error_name, message):
            self._json({"error": {
                "code": http_status,
                "status": spec.ERROR_MAP.get(error_name, (0, "UNKNOWN", 0))[1],
                "message": message,
                "details": [{
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": spec.error_reason(error_name),
                    "domain": spec.ERROR_INFO_DOMAIN,
                    "metadata": {"timestamp": _now()},
                }],
            }}, status=http_status)

        # -- routes ------------------------------------------------------

        def do_GET(self):
            body = None
            peer.record("GET", self.path, self.headers, body)
            b = peer.behaviour
            if self.path.endswith("/.well-known/agent-card.json"):
                peer.card_fetches += 1
                if b.card_delay_seconds:
                    time.sleep(b.card_delay_seconds)
                if b.card_status != 200:
                    self.send_response(b.card_status)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                return self._json(peer.card(),
                                  content_type=b.card_content_type)
            if self.path.startswith("/tasks/"):
                task_id = self.path.split("/tasks/", 1)[1].split("?")[0]
                task = peer.tasks.get(task_id)
                if task is None:
                    return self._error(404, "TaskNotFoundError",
                                       "task not found")
                return self._json({"task": task})
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            body = self._read_body()
            peer.record("POST", self.path, self.headers, body)
            b = peer.behaviour

            # SPEC 3.3.2 Authentication Errors: servers MUST reject requests
            # with invalid or missing credentials, and SHOULD include a
            # challenge naming the required scheme.
            if b.require_auth:
                presented = self.headers.get("Authorization")
                if presented != b.require_auth:
                    raw = json.dumps({"error": {
                        "code": 401, "status": "UNAUTHENTICATED",
                        "message": "missing or invalid credentials",
                        "details": [{
                            "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                            "reason": "UNAUTHENTICATED",
                            "domain": spec.ERROR_INFO_DOMAIN,
                            "metadata": {"timestamp": _now()}}]}}).encode()
                    self.send_response(401)
                    self.send_header("WWW-Authenticate",
                                     'Bearer realm="harness"')
                    self.send_header("Content-Type", spec.MEDIA_TYPE_A2A_JSON)
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return

            if b.reject_all:
                return self._error(400, "UnsupportedOperationError",
                                   "this peer refuses everything by design")
            if b.stall_seconds:
                time.sleep(b.stall_seconds)

            if self.path.endswith("/message:stream") or _is_rpc(body, "SendStreamingMessage"):
                return self._stream(body)
            if self.path.endswith("/message:send") or _is_rpc(body, "SendMessage"):
                return self._send(body)
            if ":cancel" in self.path or _is_rpc(body, "CancelTask"):
                return self._cancel(body)
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        # -- operations --------------------------------------------------

        def _make_task(self, body):
            b = peer.behaviour
            params = _params(body)
            message = (params or {}).get("message") or {}
            text = "".join(p.get("text", "") for p in message.get("parts") or [])

            task_id = ("duplicate-task-id" if b.emit_duplicate_task_ids
                       else str(uuid.uuid4()))
            state = (b.emit_unknown_task_state or
                     ("TASK_STATE_WORKING" if b.never_resolve
                      else "TASK_STATE_COMPLETED"))

            part = {"text": b.prompt_injection_text or text or "ok"}
            if b.oversized_artifact_bytes:
                part = {"text": "A" * b.oversized_artifact_bytes}
            if b.nesting_depth:
                part = {"data": _nested(b.nesting_depth)}
            if b.artifact_media_type_lie:
                part = {"text": "this is plain text, honestly",
                        "mediaType": b.artifact_media_type_lie}

            task = {
                "id": task_id,
                "contextId": str(uuid.uuid4()),
                "status": {"state": state, "timestamp": _now()},
                "artifacts": [{
                    "artifactId": str(uuid.uuid4()),
                    "parts": [part],
                }],
            }
            peer.tasks[task_id] = task
            return task

        def _send(self, body):
            b = peer.behaviour
            task = self._make_task(body)
            if b.echo_wrong_task_id:
                task = dict(task, id="a-task-id-you-never-asked-about")
            payload = {"task": task}
            if _is_jsonrpc(body):
                rid = body.get("id")
                if b.wrong_jsonrpc_id:
                    rid = 999999
                return self._json({"jsonrpc": "2.0", "id": rid,
                                   "result": payload},
                                  content_type=spec.MEDIA_TYPE_JSON)
            return self._json(payload)

        def _cancel(self, body):
            params = _params(body)
            task_id = (params or {}).get("id")
            task = peer.tasks.get(task_id)
            if task is None:
                return self._error(404, "TaskNotFoundError", "task not found")
            if task["status"]["state"] in spec.TERMINAL_STATES:
                return self._error(400, "TaskNotCancelableError",
                                   "task already in a terminal state")
            task["status"] = {"state": "TASK_STATE_CANCELED",
                              "timestamp": _now()}
            return self._json({"task": task})

        def _stream(self, body):
            b = peer.behaviour
            if not b.streaming_actually_works:
                return self._error(400, "UnsupportedOperationError",
                                   "the card said streaming; this peer lies")
            task = self._make_task(body)
            frames = [
                {"task": dict(task, status={"state": "TASK_STATE_SUBMITTED",
                                            "timestamp": _now()})},
                {"statusUpdate": {"taskId": task["id"],
                                  "contextId": task["contextId"],
                                  "status": {"state": "TASK_STATE_WORKING",
                                             "timestamp": _now()}}},
                {"artifactUpdate": {"taskId": task["id"],
                                    "contextId": task["contextId"],
                                    "artifact": task["artifacts"][0],
                                    "lastChunk": True}},
                {"statusUpdate": {"taskId": task["id"],
                                  "contextId": task["contextId"],
                                  "status": {"state": task["status"]["state"],
                                             "timestamp": _now()}}},
            ]
            if b.emit_response_to_nothing:
                frames.insert(0, {"statusUpdate": {
                    "taskId": "a-task-that-was-never-created",
                    "contextId": "nor-this-context",
                    "status": {"state": "TASK_STATE_WORKING",
                               "timestamp": _now()}}})
            if b.never_resolve:
                frames = frames[:2]

            self.send_response(200)
            self.send_header("Content-Type", spec.MEDIA_TYPE_SSE)
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            for i, frame in enumerate(frames):
                if (b.truncate_stream_after is not None
                        and i >= b.truncate_stream_after):
                    # Cut the connection mid-stream, without a terminal event.
                    try:
                        self.wfile.flush()
                        self.connection.close()
                    except Exception:
                        pass
                    return
                try:
                    self.wfile.write(
                        ("data: %s\n\n" % json.dumps(frame)).encode("utf-8"))
                    self.wfile.flush()
                except Exception:
                    return
            if b.never_resolve:
                # Hold the connection open with no further events.
                time.sleep(min(b.stall_seconds or 30, 30))

    return Handler


def _is_jsonrpc(body):
    return isinstance(body, dict) and body.get("jsonrpc") == "2.0"


def _is_rpc(body, method):
    return isinstance(body, dict) and body.get("method") == method


def _params(body):
    if _is_jsonrpc(body):
        return body.get("params") or {}
    return body or {}


# ---------------------------------------------------------------------------
# Webhook sink for push notification tests
# ---------------------------------------------------------------------------

class WebhookSink:
    def __init__(self, host="127.0.0.1", port=0, respond=200):
        self.received = []
        self.respond = respond
        self._lock = threading.Lock()
        sink = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    payload = json.loads(raw.decode("utf-8"))
                except Exception:
                    payload = {"_unparsed": raw.decode("utf-8", "replace")}
                with sink._lock:
                    sink.received.append({
                        "headers": {k.lower(): v
                                    for k, v in self.headers.items()},
                        "body": payload,
                        "at": time.time(),
                    })
                self.send_response(sink.respond)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self._server = ThreadingHTTPServer((host, port), Handler)
        self._server.daemon_threads = True
        self.host = host
        self.port = self._server.server_address[1]

    @property
    def url(self):
        return "http://%s:%d/webhook" % (self.host, self.port)

    def start(self):
        threading.Thread(target=self._server.serve_forever,
                         daemon=True).start()
        return self

    def stop(self):
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception:
            pass

    def wait_for(self, count=1, deadline_seconds=15.0, interval=0.05):
        """Deterministic wait on a condition, not a fixed sleep."""
        end = time.time() + deadline_seconds
        while time.time() < end:
            with self._lock:
                if len(self.received) >= count:
                    return True
            time.sleep(interval)
        return False

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False
