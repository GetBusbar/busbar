"""Adversarial input against the target's SERVER role.

Everything here is malformed rather than malicious: bad bytes, bad shapes, bad
sequencing. The distinction from tests_hostile matters, because the defence is
different. Malformed input is a parser problem. A hostile peer is a trust
problem, and no amount of schema validation fixes it.

The bar for every test below is the same and it is deliberately low: the agent
must survive and answer legibly. An agent that returns a clean 400 passes. An
agent that returns 500, hangs, or closes the connection has a defect, because
a peer cannot tell a malformed request from a dead agent.
"""

import json
import uuid

from .model import (a2a_test, ROLE_SERVER, EVERY_COMMIT, PULL_REQUEST,
                    PRE_RELEASE, NEEDS_FAKE_PEER, Inapplicable)
from . import spec, transport
from .target import send_params, user_message


def _endpoint(ctx):
    return ctx.target.pick_interface()["url"]


def _binding(ctx):
    return ctx.target.pick_interface().get("protocolBinding")


def _post_raw(ctx, raw_body, path=None, headers=None):
    """POST arbitrary bytes to the agent's send endpoint.

    Carrying the harness's own credential, like every other request it makes:
    see `Target.request_headers`. Malformed bytes only reach a parser if the
    request gets past the door.
    """
    url = _endpoint(ctx).rstrip("/")
    if _binding(ctx) == "HTTP+JSON":
        url += path or "/message:send"
    hdrs = ctx.target.request_headers(
        {"Content-Type": spec.MEDIA_TYPE_A2A_JSON})
    hdrs.update(headers or {})
    return transport.request("POST", url, body=raw_body, headers=hdrs,
                             insecure=ctx.target.insecure)


def _survived(ctx, resp, what):
    """The universal adversarial bar: a legible client error, not a fault.

    Both channels must be checked. Under the JSON-RPC binding a server fault
    is carried as error.code -32603 inside an HTTP 200, so looking only at the
    HTTP status would let exactly the same defect through on one binding and
    catch it on the other.
    """
    ctx.assert_must(
        resp.status is not None and resp.status != 599,
        "%s produced no HTTP response at all: the peer dropped the "
        "connection. %s" % (what, resp.text[:200]),
        "SPEC 3.3.2 requires servers to return errors, which presupposes "
        "returning something.",
    )
    payload = resp.json_or_none()
    if isinstance(payload, dict) and isinstance(payload.get("error"), dict):
        code = payload["error"].get("code")
        ctx.assert_must(
            code != -32603,
            "%s produced JSON-RPC error -32603 InternalError. SPEC 3.3.2 "
            "classes malformed input as a Validation Error, which maps to "
            "-32602 Invalid params, not to an internal fault. Message: %r"
            % (what, payload["error"].get("message")),
            "SPEC 9.5: '-32603 InternalError \"Internal error\" An internal "
            "error occurred on the server'. SPEC 3.3.2 requires servers "
            "validate all input parameters before processing, so invalid "
            "input must not reach the point where it can fault the server.",
        )
    ctx.assert_must(
        resp.status < 500,
        "%s produced HTTP %d. SPEC 3.3.2 classes malformed input as a "
        "Validation Error, which servers MUST validate for and which maps to "
        "400, not to a server fault. Body: %s"
        % (what, resp.status, resp.text[:400]),
        "SPEC 3.3.2: 'Validation Errors: Invalid input parameters or message "
        "format. Servers MUST validate all input parameters before "
        "processing... Example error codes: HTTP 400 Bad Request ... JSON-RPC "
        "-32602 Invalid params'.",
    )
    return resp


@a2a_test(
    id="adv.malformed_json",
    defect="A truncated or corrupt JSON body crashes the agent or returns a "
           "500, so any peer with a flaky connection can fault the agent "
           "instead of being told its request was bad.",
    clause="SPEC 3.3.2; SPEC 9.5 (-32700 JSONParseError)",
    role=ROLE_SERVER, tier=EVERY_COMMIT,
)
def test_malformed_json(ctx):
    resp = _post_raw(ctx, '{"message": {"parts": [')
    _survived(ctx, resp, "a truncated JSON body")
    ctx.observe("malformed_json_status", resp.status)
    if _binding(ctx) == "JSONRPC":
        payload = resp.json_or_none() or {}
        code = (payload.get("error") or {}).get("code")
        ctx.observe("malformed_json_code", code,
                    "SPEC 9.5 names -32700 JSONParseError for this.")


@a2a_test(
    id="adv.empty_body",
    defect="An empty POST body faults the agent, giving any unauthenticated "
           "caller a one-byte denial of service.",
    clause="SPEC 3.3.2",
    role=ROLE_SERVER, tier=EVERY_COMMIT,
)
def test_empty_body(ctx):
    resp = _post_raw(ctx, "")
    _survived(ctx, resp, "an empty request body")
    ctx.observe("empty_body_status", resp.status)


@a2a_test(
    id="adv.wrong_types",
    defect="A field with the wrong JSON type (parts as a string, role as a "
           "number) is coerced or crashes rather than rejected, so garbage "
           "enters the task store and surfaces later as corrupt history.",
    clause="SPEC 3.3.2; PROTO Message field types",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_wrong_types(ctx):
    cases = {
        "parts_is_string": {"message": {"messageId": "x", "role": "ROLE_USER",
                                        "parts": "not an array"}},
        "role_is_number": {"message": {"messageId": "x", "role": 7,
                                       "parts": [{"text": "hi"}]}},
        "message_is_array": {"message": [1, 2, 3]},
        "part_is_null": {"message": {"messageId": "x", "role": "ROLE_USER",
                                     "parts": [None]}},
    }
    statuses = {}
    for name, body in cases.items():
        payload = body
        if _binding(ctx) == "JSONRPC":
            payload = {"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
                       "params": body}
        resp = _post_raw(ctx, json.dumps(payload))
        _survived(ctx, resp, "a request with %s" % name.replace("_", " "))
        statuses[name] = resp.status
    ctx.observe("wrong_type_statuses", statuses)


@a2a_test(
    id="adv.missing_required_fields",
    defect="A message with no parts is accepted, so an agent starts work on "
           "an empty instruction and bills or acts on nothing.",
    clause="PROTO Message.parts REQUIRED; SPEC 5.7",
    role=ROLE_SERVER, tier=EVERY_COMMIT,
)
def test_missing_required(ctx):
    call = ctx.target.call("SendMessage",
                           {"message": {"messageId": str(uuid.uuid4()),
                                        "role": "ROLE_USER"}})
    ctx.assert_must(
        call.error is not None,
        "a Message with no parts was accepted: %r" % (call.result,),
        "PROTO Message: 'repeated Part parts = 5 [(google.api.field_behavior) "
        "= REQUIRED]'. SPEC 5.7: 'Arrays marked as required MUST contain at "
        "least one element.'",
    )
    ctx.observe("missing_parts_error", call.error_name or call.error_code)

    call2 = ctx.target.call("SendMessage", {"message": {"role": "ROLE_USER",
                                                        "parts": []}})
    ctx.assert_must(
        call2.error is not None,
        "a Message with an empty parts array was accepted",
        "SPEC 5.7: 'Arrays marked as required MUST contain at least one "
        "element.'",
    )


@a2a_test(
    id="adv.unknown_fields_ignored",
    defect="Agent rejects a request carrying a field it does not recognise, "
           "breaking forward compatibility so that every future spec addition "
           "is a flag day for this agent.",
    clause="SPEC 5.7 Unrecognized Fields",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_unknown_fields(ctx):
    msg = user_message("forward compatible")
    msg["someFutureFieldFromA2A_2_0"] = {"nested": True}
    call = ctx.target.call("SendMessage", {"message": msg,
                                           "unknownTopLevel": 42})
    # SPEC 5.7 says SHOULD ignore, so rejection is not a hard violation. What
    # is asserted is that it does not fault.
    if call.error is not None and call.binding == "HTTP+JSON":
        ctx.assert_must(
            call.http.status < 500,
            "an unrecognised field caused HTTP %d" % call.http.status,
            "SPEC 5.7: 'Implementations SHOULD ignore unrecognized fields in "
            "messages, allowing for forward compatibility'. Faulting is never "
            "the right answer.",
        )
    ctx.observe("unknown_field_accepted", call.error is None,
                "SPEC 5.7 makes ignoring unknown fields a SHOULD, so "
                "rejecting them is a legal if unfriendly choice.")


@a2a_test(
    id="adv.deep_nesting",
    defect="A deeply nested data part exhausts the parser stack and takes the "
           "agent process down, which is a remote crash from a single "
           "well-formed JSON document.",
    clause="SPEC 3.3.2; PROTO Part.data is google.protobuf.Value",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_deep_nesting(ctx):
    depth = int(ctx.config.get("nesting_depth", 2000))
    node = {"leaf": True}
    for _ in range(depth):
        node = {"n": node}
    msg = {"messageId": str(uuid.uuid4()), "role": "ROLE_USER",
           "parts": [{"data": node}]}
    payload = {"message": msg}
    if _binding(ctx) == "JSONRPC":
        payload = {"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
                   "params": payload}
    resp = _post_raw(ctx, json.dumps(payload))
    _survived(ctx, resp, "a %d-deep nested data part" % depth)
    ctx.observe("deep_nesting_depth", depth)
    ctx.observe("deep_nesting_status", resp.status)
    # Prove the agent is still alive afterwards. A crash that only shows up on
    # the NEXT request is the failure mode this catches.
    after = ctx.target.call("SendMessage", send_params("still alive?"))
    ctx.assert_must(
        after.error is None or (after.http and after.http.status < 500),
        "the agent did not survive a deeply nested payload: the following "
        "request returned %s"
        % (after.http.status if after.http else after.error),
        "An agent that dies on input it should have rejected fails SPEC "
        "3.3.2's requirement to validate input before processing.",
    )


@a2a_test(
    id="adv.oversized_payload",
    defect="A very large message is accepted without limit and exhausts "
           "memory, or is rejected with a fault instead of a clear 413/400, "
           "so callers cannot tell 'too big' from 'agent broken'.",
    clause="SPEC 3.3.2 (no size limit is specified anywhere; see notes)",
    role=ROLE_SERVER, tier=PRE_RELEASE,
)
def test_oversized(ctx):
    size = int(ctx.config.get("oversize_bytes", 8 * 1024 * 1024))
    msg = {"messageId": str(uuid.uuid4()), "role": "ROLE_USER",
           "parts": [{"text": "A" * size}]}
    payload = {"message": msg}
    if _binding(ctx) == "JSONRPC":
        payload = {"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
                   "params": payload}
    resp = _post_raw(ctx, json.dumps(payload))
    ctx.observe("oversize_bytes", size)
    ctx.observe("oversize_status", resp.status)
    # THE SPEC SETS NO MAXIMUM MESSAGE SIZE ANYWHERE. Accepting an 8MB message
    # is therefore fully conformant, and so is rejecting it. Only a fault is
    # wrong.
    ctx.assert_must(
        resp.status is not None and resp.status < 500,
        "an oversized message produced HTTP %s" % resp.status,
        "SPEC 3.3.2: oversized input is a validation concern; the spec sets "
        "no size limit, so an agent may accept or reject, but a 5xx means it "
        "neither validated nor coped.",
    )
    ctx.note("The A2A specification defines NO maximum message or artifact "
             "size. Any limit an implementation applies is its own policy, so "
             "the harness records the outcome rather than judging it.")


@a2a_test(
    id="adv.truncated_request_body",
    defect="A request whose Content-Length overstates the bytes actually sent "
           "leaves a connection or worker wedged, so a peer that dies "
           "mid-send degrades the agent for everyone else.",
    clause="SPEC 3.3.2; RFC 9110 message framing",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_truncated_body(ctx):
    url = _endpoint(ctx).rstrip("/")
    if _binding(ctx) == "HTTP+JSON":
        url += "/message:send"
    body = json.dumps({"message": user_message("truncate me")}).encode("utf-8")
    try:
        reply = transport.raw_send(
            url, "POST", body, declared_length=len(body) + 500,
            send_bytes=len(body) // 2,
            headers={"Content-Type": spec.MEDIA_TYPE_A2A_JSON},
            timeout=10.0, insecure=ctx.target.insecure)
        ctx.observe("truncated_body_reply",
                    (reply or b"")[:80].decode("ascii", "replace"))
    except Exception as exc:
        ctx.observe("truncated_body_reply", "connection error: %s" % exc)
    # The real assertion: the agent still serves other callers afterwards.
    after = ctx.target.call("SendMessage", send_params("alive after truncate"))
    ctx.assert_must(
        after.error is None or (after.http and after.http.status < 500),
        "after a truncated request body, a subsequent well-formed request "
        "returned %s"
        % (after.http.status if after.http else after.error),
        "An agent wedged by a half-sent request cannot meet any of its SPEC "
        "3.1 operation obligations to other callers.",
    )


@a2a_test(
    id="adv.connect_then_stall",
    defect="A peer that connects and then goes silent holds a worker open "
           "indefinitely, so a handful of idle connections starve the agent "
           "of capacity.",
    clause="NO SPEC CLAUSE. The A2A spec sets no idle timeout. Characterised, "
           "not enforced.",
    role=ROLE_SERVER, tier=PRE_RELEASE,
)
def test_connect_and_stall(ctx):
    url = _endpoint(ctx).rstrip("/")
    if _binding(ctx) == "HTTP+JSON":
        url += "/message:send"
    budget = float(ctx.config.get("stall_seconds", 8.0))
    closed_after = transport.raw_connect_and_stall(
        url, budget, insecure=ctx.target.insecure)
    # Deliberately NOT an assertion on elapsed time. The recorded value is
    # whether the peer closed within the budget at all, which is a property of
    # the code; the exact seconds are a property of the machine.
    ctx.observe("closed_idle_connection_within_budget", closed_after is not None)
    ctx.observe("stall_budget_seconds", budget)
    # Concurrency is the thing that actually matters, so prove the agent still
    # serves someone else while we are stalling it.
    after = ctx.target.call("SendMessage", send_params("alive during stall"))
    ctx.assert_must(
        after.error is None or (after.http and after.http.status < 500),
        "while one connection was stalled, a second well-formed request "
        "returned %s" % (after.http.status if after.http else after.error),
        "An agent that cannot serve a second caller while one connection is "
        "idle cannot meet its SPEC 3.1 obligations under any real load.",
    )


@a2a_test(
    id="adv.client_disconnects_mid_stream",
    defect="When a client vanishes mid-stream the agent keeps the task or the "
           "connection alive forever, leaking a worker per abandoned "
           "delegation.",
    clause="SPEC 3.5.2 (stream lifecycle is independent of task lifecycle)",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_client_disconnect_midstream(ctx):
    if not ctx.target.capability("streaming"):
        raise Inapplicable("card does not declare capabilities.streaming")
    res = ctx.target.stream("SendStreamingMessage",
                            send_params("disconnect me"),
                            abort_after_events=1)
    ctx.observe("events_before_abort", len(res.events))
    task_id = None
    for event in res.events:
        for key in ("task",):
            if key in event:
                task_id = (event[key] or {}).get("id")
    ctx.observe("aborted_task_id_known", task_id is not None)
    # SPEC 3.5.2: "The task lifecycle is independent of any individual
    # stream's lifecycle", so the task MUST still be there after we hang up.
    if task_id:
        got = ctx.target.call("GetTask", {"id": task_id})
        ctx.assert_must(
            got.error is None,
            "after the client disconnected mid-stream, GetTask on the task "
            "failed with %s. The task should outlive the stream."
            % (got.error,),
            "SPEC 3.5.2: 'Closing one stream MUST NOT affect other active "
            "streams for the same task. The task lifecycle is independent of "
            "any individual stream's lifecycle.'",
        )
    after = ctx.target.call("SendMessage", send_params("alive after abort"))
    ctx.assert_must(
        after.error is None or (after.http and after.http.status < 500),
        "after a mid-stream client disconnect the agent returned %s to the "
        "next caller" % (after.http.status if after.http else after.error),
        "SPEC 3.5.2 requires stream lifecycles be independent.",
    )


@a2a_test(
    id="adv.duplicate_message_id",
    defect="The same messageId submitted twice silently creates two tasks and "
           "the work is done, and possibly charged, twice.",
    clause="SPEC 3.3.1 Idempotency (MAY, so recorded not enforced)",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_duplicate_message_id(ctx):
    message_id = "harness-duplicate-%s" % uuid.uuid4()
    first = ctx.target.call("SendMessage", {
        "message": user_message("do the thing", message_id=message_id)})
    second = ctx.target.call("SendMessage", {
        "message": user_message("do the thing", message_id=message_id)})

    def task_id(call):
        task = (call.result or {}).get("task") if isinstance(call.result, dict) else None
        return (task or {}).get("id")

    a, b = task_id(first), task_id(second)
    deduplicated = bool(a and b and a == b)
    ctx.observe("duplicate_message_id_deduplicated", deduplicated,
                "SPEC 3.3.1: 'Send Message operations MAY be idempotent. "
                "Agents may utilize the messageId to detect duplicate "
                "messages.' MAY, so both answers are conformant.")
    ctx.observe("duplicate_second_error",
                second.error_name or second.error_code or "ok")
    if not deduplicated:
        ctx.note("Resubmitting an identical messageId produced a second, "
                 "distinct task. SPEC 3.3.1 permits this, but it means the "
                 "agent offers no replay protection: a retried request after "
                 "a network timeout does the work twice.")


@a2a_test(
    id="adv.response_to_nothing",
    defect="Agent accepts a cancel, subscribe or push-config call naming a "
           "task it never issued, letting an unrelated caller manipulate or "
           "probe another tenant's task namespace.",
    clause="SPEC 3.1.5, 3.1.6, 3.1.7 error cases; SPEC 13.1",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_response_to_nothing(ctx):
    ghost = "harness-ghost-%s" % uuid.uuid4()
    outcomes = {}
    for method, params in (
        ("CancelTask", {"id": ghost}),
        ("GetTask", {"id": ghost}),
        ("ListTaskPushNotificationConfigs", {"taskId": ghost}),
    ):
        call = ctx.target.call(method, params)
        outcomes[method] = call.error_name or call.error_code or "ACCEPTED"
        ctx.assert_must(
            call.error is not None,
            "%s on a task id the agent never issued (%s) succeeded"
            % (method, ghost),
            "SPEC 3.3.2: 'Servers MUST return a not found error when a "
            "requested resource does not exist or is not accessible to the "
            "authenticated client.'",
        )
    ctx.observe("ghost_task_outcomes", outcomes)


@a2a_test(
    id="adv.wrong_jsonrpc_envelope",
    defect="Agent answers a request with a missing or wrong jsonrpc version, "
           "or fails to echo the request id, so a client multiplexing calls "
           "over one connection matches the wrong reply to the wrong request.",
    clause="SPEC 9.3; JSON-RPC 2.0",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_jsonrpc_envelope(ctx):
    if _binding(ctx) != "JSONRPC":
        raise Inapplicable("the selected interface is not the JSON-RPC "
                           "binding, so its envelope rules do not apply")
    url = _endpoint(ctx)
    marker = "harness-id-%s" % uuid.uuid4()
    good = {"jsonrpc": "2.0", "id": marker, "method": "SendMessage",
            "params": send_params("envelope check")}
    resp = transport.request("POST", url, body=good,
                             headers=ctx.target.request_headers(),
                             insecure=ctx.target.insecure)
    payload = resp.json_or_none() or {}
    ctx.assert_must(
        payload.get("jsonrpc") == "2.0",
        "response jsonrpc field is %r, expected '2.0'"
        % payload.get("jsonrpc"),
        "SPEC 9.3: 'All JSON-RPC requests MUST follow the standard JSON-RPC "
        "2.0 format', and JSON-RPC 2.0 requires the same of responses.",
    )
    ctx.assert_must(
        payload.get("id") == marker,
        "response id is %r but the request id was %r"
        % (payload.get("id"), marker),
        "JSON-RPC 2.0: the response id MUST be the same as the request id. "
        "Without this a client cannot correlate replies.",
    )

    missing_version = {"id": 1, "method": "SendMessage",
                       "params": send_params("no jsonrpc field")}
    # No `A2A-Version` header here on purpose -- the probe is the missing
    # `jsonrpc` member, and the version header's own absence is
    # `core.absent_version_header_defaults_to_0_3`. The credential still goes.
    resp2 = transport.request("POST", url, body=missing_version,
                              headers=ctx.target.request_headers(version=None),
                              insecure=ctx.target.insecure)
    _survived(ctx, resp2, "a request with no jsonrpc member")
    ctx.observe("missing_jsonrpc_member_status", resp2.status)

    unknown = {"jsonrpc": "2.0", "id": 2,
               "method": "ThisMethodDoesNotExist", "params": {}}
    resp3 = transport.request("POST", url, body=unknown,
                              headers=ctx.target.request_headers(),
                              insecure=ctx.target.insecure)
    body3 = resp3.json_or_none() or {}
    code = (body3.get("error") or {}).get("code")
    ctx.assert_must(
        code == -32601,
        "an unknown method returned error code %r, expected -32601 "
        "MethodNotFoundError" % code,
        "SPEC 9.5: '-32601 MethodNotFoundError \"Method not found\" The "
        "requested method does not exist or is not available'.",
    )


@a2a_test(
    id="adv.method_case_sensitivity",
    defect="Agent accepts a method name in the wrong case, so an "
           "implementation that happens to send 'sendmessage' works against "
           "this agent and fails against a conformant one, producing an "
           "interop bug nobody can reproduce.",
    clause="SPEC 9.1 (PascalCase); see AMBIGUITIES.JSONRPC_METHOD_NAMING",
    role=ROLE_SERVER, tier=PRE_RELEASE,
)
def test_method_case(ctx):
    if _binding(ctx) != "JSONRPC":
        raise Inapplicable("not the JSON-RPC binding")
    url = _endpoint(ctx)
    seen = {}
    for name in ("SendMessage", "sendMessage", "sendmessage", "message/send"):
        resp = transport.request(
            "POST", url,
            body={"jsonrpc": "2.0", "id": 1, "method": name,
                  "params": send_params("case probe")},
            headers=ctx.target.request_headers(),
            insecure=ctx.target.insecure)
        body = resp.json_or_none() or {}
        seen[name] = "ok" if "result" in body else (body.get("error") or {}).get("code")
    ctx.observe("method_name_acceptance", seen,
                "SPEC 9.1 mandates PascalCase. 'message/send' is the 0.3 "
                "name and an interface may legally still serve 0.3 (SPEC "
                "3.6.2), so its acceptance is observed, not failed.")
    ctx.assert_must(
        seen.get("SendMessage") == "ok",
        "the PascalCase method name SendMessage was not accepted (got %r)"
        % seen.get("SendMessage"),
        "SPEC 9.1: 'Method Naming: PascalCase method names matching gRPC "
        "conventions (e.g., SendMessage, GetTask)'.",
    )


@a2a_test(
    id="adv.concurrent_interleaved_tasks",
    defect="Concurrent tasks bleed into each other: one task's artifact is "
           "attached to another's id, so a caller receives another caller's "
           "output. This is the worst defect in the battery.",
    clause="SPEC 3.4.2 (unique task ids); SPEC 13.1 (access scoping)",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_concurrent_tasks(ctx):
    import concurrent.futures

    count = int(ctx.config.get("concurrency", 8))
    markers = {}

    def one(i):
        marker = "harness-marker-%d-%s" % (i, uuid.uuid4().hex[:8])
        call = ctx.target.call("SendMessage", send_params(marker))
        return marker, call

    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
        results = list(pool.map(one, range(count)))

    task_ids = []
    for marker, call in results:
        if call.error is not None:
            ctx.assert_must(
                False,
                "under %d concurrent SendMessage calls, one failed: %s"
                % (count, call.error),
                "SPEC 3.1.1 places no concurrency restriction on SendMessage.",
            )
        task = (call.result or {}).get("task")
        if task:
            task_ids.append(task["id"])
            markers[task["id"]] = marker

    ctx.observe("concurrent_tasks_created", len(task_ids))
    ctx.assert_must(
        len(set(task_ids)) == len(task_ids),
        "concurrent SendMessage calls produced duplicate task ids: %s"
        % [t for t in task_ids if task_ids.count(t) > 1],
        "SPEC 3.4.2: 'Agents MUST generate a unique taskId for each new task "
        "they create.'",
    )

    # Content isolation. Each task's own marker must appear in its own result
    # and no other task's marker may.
    crossovers = []
    for task_id, marker in markers.items():
        got = ctx.target.call("GetTask", {"id": task_id})
        if got.error is not None:
            continue
        task = got.result.get("task") if isinstance(got.result, dict) and "task" in got.result else got.result
        blob = json.dumps(task)
        for other_id, other_marker in markers.items():
            if other_id != task_id and other_marker in blob:
                crossovers.append((task_id, other_marker))
    ctx.assert_must(
        not crossovers,
        "content from one task appeared inside another: %s" % crossovers[:5],
        "SPEC 13.1 Data Access and Authorization Scoping, and SPEC 3.4.2's "
        "requirement that each task be a distinct unit of work.",
    )


@a2a_test(
    id="adv.task_survives_across_calls",
    defect="Task state is lost between calls, so any workflow longer than one "
           "request forgets itself and long-running delegation is impossible.",
    clause="SPEC 3.1.3, 3.3.3",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_state_persistence(ctx):
    first = ctx.target.call("SendMessage", send_params("remember me"))
    task = (first.result or {}).get("task")
    if not task:
        raise Inapplicable("agent answered with a Message; no task state")
    task_id = task["id"]
    seen = []
    for _ in range(3):
        got = ctx.target.call("GetTask", {"id": task_id})
        seen.append(got.error is None)
    ctx.assert_must(
        all(seen),
        "a task became unretrievable after %d GetTask calls (%s)"
        % (len(seen), seen),
        "SPEC 3.1.3: GetTask retrieves 'the current state ... of a previously "
        "initiated task'. It does not permit the task to vanish between "
        "polls.",
    )


@a2a_test(
    id="adv.subscribe_to_terminal_task",
    defect="Subscribing to an already-finished task hangs the client forever "
           "instead of erroring, so a reconnecting client waits on a stream "
           "that will never produce an event.",
    clause="SPEC 3.1.6",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_subscribe_terminal(ctx):
    if not ctx.target.capability("streaming"):
        raise Inapplicable("card does not declare capabilities.streaming")
    first = ctx.target.call("SendMessage", send_params("finish then subscribe"))
    task = (first.result or {}).get("task")
    if not task:
        raise Inapplicable("agent answered with a Message; no task")
    state = (task.get("status") or {}).get("state")
    if state not in spec.TERMINAL_STATES:
        raise Inapplicable("task is %s, not terminal; rule does not apply"
                           % state)
    res = ctx.target.stream("SubscribeToTask", {"id": task["id"]},
                            max_events=4, timeout=15.0)
    ctx.observe("subscribe_terminal_status", res.status)
    ctx.observe("subscribe_terminal_events", len(res.events))
    ctx.observe("subscribe_verb_used", getattr(res, "verb_used", None),
                spec.AMBIGUITIES["SUBSCRIBE_HTTP_METHOD"]["summary"])
    ctx.assert_must(
        res.error != "timeout",
        "subscribing to a task already in %s neither errored nor closed; the "
        "client would hang" % state,
        "SPEC 3.1.6: 'UnsupportedOperationError: The operation is attempted "
        "on a task that is in a terminal state (TASK_STATE_COMPLETED, "
        "TASK_STATE_FAILED, TASK_STATE_CANCELED, TASK_STATE_REJECTED).' "
        "PROTO SubscribeToTask repeats this.",
    )
