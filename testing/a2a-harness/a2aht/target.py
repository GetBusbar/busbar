"""The thing under test.

A Target is described entirely by configuration. There are no per-implementation
branches anywhere in this harness, and there must never be one. If a subject
needs special handling to be testable, that is a finding about the protocol
being underspecified, and it belongs in the report, not in an if-statement.

A target is given as either:

  --endpoint URL          an already-running agent
  --launch "CMD"          a command the harness starts and stops, plus
                          --port to know when it is up

Everything else the harness needs, it learns from the agent card, exactly as
any other client would.
"""

import json
import os
import shlex
import signal
import subprocess
import time
import urllib.parse

from . import spec, transport


class TargetError(Exception):
    pass


class Target:
    def __init__(self, endpoint=None, launch=None, port=None, host="127.0.0.1",
                 card_url=None, auth_header=None, insecure=False,
                 launch_ready_seconds=45.0, label="target", cwd=None,
                 env=None):
        self.label = label
        self.endpoint = endpoint.rstrip("/") if endpoint else None
        self.launch = launch
        self.port = port
        self.host = host
        self.card_url_override = card_url
        self.auth_header = auth_header
        self.insecure = insecure
        self.launch_ready_seconds = launch_ready_seconds
        self.cwd = cwd
        self.env = env
        self._proc = None
        self._card = None
        self._card_response = None
        self._interface = None

    # -- lifecycle ---------------------------------------------------------

    def start(self):
        if not self.launch:
            if not self.endpoint:
                raise TargetError(
                    "target '%s' has neither --endpoint nor --launch" % self.label
                )
            return
        if not self.port:
            raise TargetError(
                "target '%s' uses --launch so it must also give --port, "
                "otherwise the harness cannot tell when it is ready without "
                "sleeping, and sleeping is not a synchronisation primitive"
                % self.label
            )
        env = dict(os.environ)
        env.update(self.env or {})
        self._proc = subprocess.Popen(
            self.launch if isinstance(self.launch, list) else shlex.split(self.launch),
            cwd=self.cwd, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        if not transport.wait_for_port(self.host, int(self.port),
                                       self.launch_ready_seconds):
            out = self._drain()
            self.stop()
            raise TargetError(
                "target '%s' did not open %s:%s within %.0fs.\n"
                "launch command: %s\nprocess output:\n%s"
                % (self.label, self.host, self.port, self.launch_ready_seconds,
                   self.launch, out)
            )
        if not self.endpoint:
            self.endpoint = "http://%s:%s" % (self.host, self.port)

    def _drain(self):
        if not self._proc or not self._proc.stdout:
            return "(no output captured)"
        try:
            self._proc.stdout.flush()
        except Exception:
            pass
        try:
            import fcntl
            fd = self._proc.stdout.fileno()
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            return (self._proc.stdout.read() or b"").decode("utf-8", "replace")
        except Exception:
            return "(output unavailable)"

    def stop(self):
        if self._proc and self._proc.poll() is None:
            try:
                os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
            except Exception:
                try:
                    self._proc.terminate()
                except Exception:
                    pass
            try:
                self._proc.wait(timeout=10)
            except Exception:
                try:
                    os.killpg(os.getpgid(self._proc.pid), signal.SIGKILL)
                except Exception:
                    pass
        self._proc = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()
        return False

    # -- discovery ---------------------------------------------------------

    def card_candidates(self):
        """Both readings of SPEC 8.2 for where the card lives.

        See spec.AMBIGUITIES['CARD_AT_INTERFACE_URL'].
        """
        if self.card_url_override:
            return [self.card_url_override]
        parts = urllib.parse.urlsplit(self.endpoint)
        origin = "%s://%s" % (parts.scheme, parts.netloc)
        out = [origin + spec.WELL_KNOWN_CARD_PATH]
        path = parts.path.rstrip("/")
        if path:
            out.append(origin + path + spec.WELL_KNOWN_CARD_PATH)
        return out

    def fetch_card_response(self, force=False, headers=None):
        if self._card_response is not None and not force and headers is None:
            return self._card_response
        last = None
        for url in self.card_candidates():
            resp = transport.request("GET", url, headers=self._headers(headers),
                                     insecure=self.insecure)
            last = resp
            if resp.status == 200 and resp.json_or_none() is not None:
                resp.card_url = url
                if headers is None:
                    self._card_response = resp
                return resp
        if last is not None:
            last.card_url = self.card_candidates()[0]
        return last

    def card(self, force=False):
        if self._card is not None and not force:
            return self._card
        resp = self.fetch_card_response(force=force)
        if resp is None or resp.status != 200:
            raise TargetError(
                "no agent card at any of %s (last status %s). SPEC 8.1: "
                "'A2A Servers MUST make an Agent Card available.'"
                % (self.card_candidates(), resp.status if resp else "no-response")
            )
        card = resp.json_or_none()
        if card is None:
            raise TargetError("agent card at %s is not JSON" % resp.card_url)
        self._card = card
        return card

    # -- binding selection -------------------------------------------------

    def interfaces(self):
        card = self.card()
        ifaces = card.get("supportedInterfaces")
        if not isinstance(ifaces, list):
            return []
        return [i for i in ifaces if isinstance(i, dict)]

    def pick_interface(self, binding=None):
        """SPEC 8.3.2: select the first supported transport, preferring
        earlier entries."""
        if self._interface and not binding:
            return self._interface
        for iface in self.interfaces():
            pb = iface.get("protocolBinding")
            if binding and pb != binding:
                continue
            if pb in ("JSONRPC", "HTTP+JSON"):
                if not binding:
                    self._interface = iface
                return iface
        if binding:
            return None
        # No usable interface declared. Fall back to the endpoint we were
        # given so that card-level tests can still report something useful.
        fallback = {"url": self.endpoint, "protocolBinding": "JSONRPC",
                    "protocolVersion": spec.PROTOCOL_VERSION,
                    "_synthesised_by_harness": True}
        self._interface = fallback
        return fallback

    def _headers(self, extra=None, version=spec.PROTOCOL_VERSION):
        h = {}
        if version:
            # SPEC 3.6.1: "Clients MUST send the A2A-Version header with each
            # request". The harness is a client, so the harness complies.
            h[spec.VERSION_HEADER] = version
        if self.auth_header:
            name, _, value = self.auth_header.partition(":")
            h[name.strip()] = value.strip()
        h.update(extra or {})
        return h

    def request_headers(self, extra=None, version=spec.PROTOCOL_VERSION):
        """The headers a CLIENT OF THIS TARGET sends on any request.

        Public because several tests post raw bytes past `call()` -- a
        truncated body, a request with no `jsonrpc` member -- and those are
        still requests from the same client. Built by hand they arrived
        anonymously, and a target that requires authentication answers an
        anonymous request from its auth layer, before its parser has seen a
        byte. The test then reports on the wrong component: not "the agent
        faulted on malformed input" but "the agent asked who I was", which is
        a different question and one `tests_auth` asks on purpose.

        Nothing here decides WHETHER to authenticate. It attaches the
        credential the harness was given (`--auth`) and nothing else, so a
        target that needs none is unaffected.
        """
        return self._headers(extra, version)

    # -- calling -----------------------------------------------------------

    def call(self, method, params=None, iface=None, headers=None,
             version=spec.PROTOCOL_VERSION, raw=False):
        """Invoke an A2A operation over whichever binding the card declares.

        Returns a Call with .ok, .result, .error_code, .error_name, .http.
        """
        iface = iface or self.pick_interface()
        binding = iface.get("protocolBinding")
        if binding == "JSONRPC":
            return self._call_jsonrpc(iface, method, params, headers, version)
        if binding == "HTTP+JSON":
            return self._call_rest(iface, method, params, headers, version)
        raise TargetError(
            "binding %r is not drivable by this harness (only JSONRPC and "
            "HTTP+JSON are). GRPC targets are reported as untested." % binding
        )

    def _call_jsonrpc(self, iface, method, params, headers, version):
        body = {"jsonrpc": "2.0", "id": _next_id(), "method": method}
        if params is not None:
            body["params"] = params
        resp = transport.request(
            "POST", iface["url"], body=body,
            headers=self._headers(headers, version),
            insecure=self.insecure)
        return Call.from_jsonrpc(resp, method, body)

    def _call_rest(self, iface, method, params, headers, version):
        params = params or {}
        verb, template = spec.REST_ROUTES[method]
        path = template
        query = {}
        body = None
        if method in ("SendMessage", "SendStreamingMessage"):
            body = params
        elif method == "GetTask":
            path = template.replace("{id}", urllib.parse.quote(str(params.get("id", ""))))
            if params.get("historyLength") is not None:
                query["historyLength"] = params["historyLength"]
        elif method == "CancelTask":
            path = template.replace("{id}", urllib.parse.quote(str(params.get("id", ""))))
            body = {k: v for k, v in params.items() if k != "id"}
        elif method == "ListTasks":
            query = {k: v for k, v in params.items() if v is not None}
        elif method in ("CreateTaskPushNotificationConfig",):
            path = template.replace("{id}", urllib.parse.quote(str(params.get("taskId", ""))))
            body = params
        elif method in ("GetTaskPushNotificationConfig",
                        "DeleteTaskPushNotificationConfig"):
            path = template.replace("{id}", urllib.parse.quote(str(params.get("taskId", ""))))
            path = path.replace("{configId}", urllib.parse.quote(str(params.get("id", ""))))
        elif method == "ListTaskPushNotificationConfigs":
            path = template.replace("{id}", urllib.parse.quote(str(params.get("taskId", ""))))
        url = iface["url"].rstrip("/") + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        hdrs = self._headers(headers, version)
        if body is not None:
            hdrs.setdefault("Content-Type", spec.MEDIA_TYPE_A2A_JSON)
        resp = transport.request(verb, url, body=body, headers=hdrs,
                                 insecure=self.insecure)
        return Call.from_rest(resp, method, body)

    def stream(self, method, params=None, iface=None, headers=None,
               version=spec.PROTOCOL_VERSION, **kw):
        iface = iface or self.pick_interface()
        binding = iface.get("protocolBinding")
        hdrs = self._headers(headers, version)
        if binding == "JSONRPC":
            rid = _next_id()
            body = {"jsonrpc": "2.0", "id": rid, "method": method,
                    "params": params or {}}
            # SPEC 9.4.2 shows each SSE frame under the JSON-RPC binding as a
            # full JSON-RPC envelope wrapping a StreamResponse in `result`:
            #   data: {"jsonrpc": "2.0", "id": 1, "result": {...}}
            # so `stop_after` and the tests must see the unwrapped payload.
            inner_stop = kw.pop("stop_after", None)
            if inner_stop:
                kw["stop_after"] = lambda ev: inner_stop(_unwrap_rpc(ev))
            res = transport.sse_events(iface["url"], body=body, headers=hdrs,
                                       insecure=self.insecure, **kw)
            res.envelopes = list(res.events)
            res.envelope_problems = _envelope_problems(res.envelopes, rid)
            res.events = [_unwrap_rpc(ev) for ev in res.events]
            return res
        if binding == "HTTP+JSON":
            if method == "SendStreamingMessage":
                url = iface["url"].rstrip("/") + "/message:stream"
                return transport.sse_events(url, body=params or {},
                                            headers=hdrs,
                                            insecure=self.insecure, **kw)
            if method == "SubscribeToTask":
                # Both readings of the verb. See AMBIGUITIES.
                url = (iface["url"].rstrip("/") + "/tasks/"
                       + urllib.parse.quote(str((params or {}).get("id", "")))
                       + ":subscribe")
                res = transport.sse_events(url, body=None, headers=hdrs,
                                           method="GET",
                                           insecure=self.insecure, **kw)
                if res.status in (404, 405, 501):
                    res2 = transport.sse_events(url, body={}, headers=hdrs,
                                                method="POST",
                                                insecure=self.insecure, **kw)
                    res2.verb_used = "POST"
                    return res2
                res.verb_used = "GET"
                return res
        raise TargetError("binding %r not drivable for streaming" % binding)

    def capability(self, name):
        caps = self.card().get("capabilities") or {}
        return bool(caps.get(name))


_counter = [0]


def _next_id():
    _counter[0] += 1
    return _counter[0]


def _unwrap_rpc(event):
    """Strip the JSON-RPC envelope from an SSE frame, per SPEC 9.4.2.

    An error frame is passed through untouched so tests can see it; only a
    `result` member is unwrapped.
    """
    if isinstance(event, dict) and event.get("jsonrpc") == "2.0":
        if "result" in event:
            return event["result"]
    return event


def _envelope_problems(envelopes, request_id):
    """Check the JSON-RPC framing of a stream, which SPEC 9.4.2 fixes."""
    problems = []
    for i, ev in enumerate(envelopes):
        if not isinstance(ev, dict):
            problems.append("frame %d is not a JSON object" % i)
            continue
        if ev.get("jsonrpc") != "2.0":
            problems.append(
                "frame %d has jsonrpc=%r, expected '2.0' (SPEC 9.4.2)"
                % (i, ev.get("jsonrpc")))
        if "result" not in ev and "error" not in ev:
            problems.append(
                "frame %d carries neither result nor error (SPEC 9.4.2)" % i)
        if "error" not in ev and ev.get("id") != request_id:
            problems.append(
                "frame %d has id=%r but the request id was %r; a client "
                "cannot correlate the stream (JSON-RPC 2.0)"
                % (i, ev.get("id"), request_id))
    return problems


class Call:
    def __init__(self, http, method, request_body, result=None, error=None,
                 binding=None):
        self.http = http
        self.method = method
        self.request_body = request_body
        self.result = result
        self.error = error
        self.binding = binding

    @property
    def ok(self):
        return self.error is None and self.result is not None

    @property
    def error_code(self):
        if not self.error:
            return None
        return self.error.get("code")

    @property
    def error_name(self):
        """Best-effort A2A error name, from whichever channel carries it."""
        if not self.error:
            return None
        code = self.error.get("code")
        if code in spec.JSONRPC_CODE_TO_ERROR:
            return spec.JSONRPC_CODE_TO_ERROR[code]
        if code in spec.JSONRPC_STANDARD_ERRORS:
            return spec.JSONRPC_STANDARD_ERRORS[code]
        for detail in self.error_details():
            if detail.get("@type", "").endswith("google.rpc.ErrorInfo"):
                reason = detail.get("reason")
                if reason:
                    return reason
        return None

    def error_details(self):
        if not self.error:
            return []
        for key in ("data", "details"):
            value = self.error.get(key)
            if isinstance(value, list):
                return [d for d in value if isinstance(d, dict)]
        return []

    @classmethod
    def from_jsonrpc(cls, resp, method, body):
        payload = resp.json_or_none()
        if not isinstance(payload, dict):
            return cls(resp, method, body, binding="JSONRPC")
        return cls(resp, method, body, result=payload.get("result"),
                   error=payload.get("error"), binding="JSONRPC")

    @classmethod
    def from_rest(cls, resp, method, body):
        payload = resp.json_or_none()
        if resp.status >= 400:
            err = None
            if isinstance(payload, dict):
                err = payload.get("error") if isinstance(payload.get("error"), dict) else payload
            return cls(resp, method, body, error=err or {"code": resp.status},
                       binding="HTTP+JSON")
        return cls(resp, method, body, result=payload, binding="HTTP+JSON")


def user_message(text, message_id=None, task_id=None, context_id=None):
    """A minimally valid Message per PROTO Message required fields."""
    import uuid
    msg = {
        "messageId": message_id or str(uuid.uuid4()),
        "role": "ROLE_USER",
        "parts": [{"text": text}],
    }
    if task_id:
        msg["taskId"] = task_id
    if context_id:
        msg["contextId"] = context_id
    return msg


def send_params(text=None, message=None, **config):
    params = {"message": message if message is not None else user_message(text or "ping")}
    if config:
        params["configuration"] = {k: v for k, v in config.items() if v is not None}
    return params
