"""Core operation and task lifecycle conformance. Target acts as A2A server."""

import uuid

from .model import (a2a_test, ROLE_SERVER, EVERY_COMMIT, PULL_REQUEST,
                    PRE_RELEASE, NEEDS_FAKE_PEER, Inapplicable)
from . import spec, validate
from .target import send_params, user_message


def _send(ctx, text="ping", **kw):
    return ctx.target.call("SendMessage", send_params(text, **kw))


def _payload_kind(result):
    if not isinstance(result, dict):
        return None
    kinds = [k for k in spec.SEND_PAYLOAD_KINDS if k in result]
    return kinds[0] if len(kinds) == 1 else None


def _task_of(result):
    if isinstance(result, dict) and isinstance(result.get("task"), dict):
        return result["task"]
    return None


@a2a_test(
    id="core.send_message_returns_task_or_message",
    defect="SendMessage returns something that is neither a Task nor a "
           "Message, so a client cannot tell whether work was accepted and "
           "delegation silently drops on the floor.",
    clause="SPEC 3.1.1; PROTO SendMessageResponse oneof payload",
    role=ROLE_SERVER, tier=EVERY_COMMIT,
)
def test_send_message(ctx):
    call = _send(ctx, "hello from the harness")
    ctx.assert_must(
        call.error is None,
        "SendMessage returned an error: %s" % (call.error,),
        "SPEC 3.1.1: a well-formed SendMessage returns a Task or a Message.",
    )
    kind = _payload_kind(call.result)
    ctx.assert_must(
        kind is not None,
        "SendMessage response sets %s of the oneof {task, message}; exactly "
        "one is required. Body: %r"
        % (len([k for k in spec.SEND_PAYLOAD_KINDS if k in (call.result or {})]),
           call.result),
        "PROTO SendMessageResponse declares payload as a oneof over task and "
        "message.",
    )
    # Which of the two the agent chooses is entirely its business.
    ctx.observe("send_response_kind", kind,
                "SPEC 3.1.1: 'The agent MAY create a new Task ... or MAY "
                "return a direct Message response'.")
    if kind == "task":
        ok, problems = validate.validate_task(call.result["task"])
        ctx.assert_must(ok, "returned Task is malformed: %s" % problems,
                        "PROTO Task REQUIRED annotations; SPEC 5.7")
        ctx.observe("initial_task_state",
                    call.result["task"]["status"].get("state"))
    else:
        problems = validate.validate_message(call.result["message"],
                                             require_message_id=False)
        ctx.assert_must(not problems,
                        "returned Message is malformed: %s" % problems,
                        "PROTO Message REQUIRED annotations")


@a2a_test(
    id="core.task_state_is_defined_enum",
    defect="Agent reports a task state outside the proto enum, so a client's "
           "state machine falls through and the task hangs forever in a state "
           "nobody handles.",
    clause="PROTO enum TaskState; SPEC 5.5 (ProtoJSON enum serialisation)",
    role=ROLE_SERVER, tier=EVERY_COMMIT,
)
def test_task_state_enum(ctx):
    call = _send(ctx, "state check")
    task = _task_of(call.result)
    if task is None:
        raise Inapplicable("agent answered with a Message, so there is no "
                           "task state to check (SPEC 3.1.1 permits this)")
    state = (task.get("status") or {}).get("state")
    ctx.assert_must(
        state in spec.TASK_STATES,
        "task state %r is not one of the proto TaskState values %s"
        % (state, list(spec.TASK_STATES)),
        "PROTO enum TaskState, serialised per SPEC 5.5 as the proto name.",
    )


@a2a_test(
    id="core.blocking_send_reaches_settled_state",
    defect="A blocking SendMessage returns while the task is still running, "
           "so a caller that trusts the default gets an empty result and "
           "reports success with no output.",
    clause="SPEC 3.2.2 Execution Mode",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_blocking_send(ctx):
    # returnImmediately unset means blocking, per SPEC 3.2.2.
    call = _send(ctx, "blocking please")
    task = _task_of(call.result)
    if task is None:
        raise Inapplicable("agent answered with a Message; SPEC 3.2.2 says "
                           "returnImmediately has no effect in that case")
    state = (task.get("status") or {}).get("state")
    settled = spec.TERMINAL_STATES | spec.INTERRUPTED_STATES
    ctx.assert_must(
        state in settled,
        "blocking SendMessage returned in state %r; SPEC 3.2.2 requires it "
        "wait for a terminal or interrupted state" % state,
        "SPEC 3.2.2: 'Blocking (return_immediately: false or unset): The "
        "operation MUST wait until the task reaches a terminal ... or an "
        "interrupted ... state before returning. ... This is the default "
        "behavior.'",
    )
    ctx.observe("blocking_final_state", state)


@a2a_test(
    id="core.return_immediately_is_honoured",
    defect="returnImmediately is ignored, so a client that deliberately went "
           "non-blocking is blocked anyway and its own request times out.",
    clause="SPEC 3.2.2",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_return_immediately(ctx):
    call = ctx.target.call("SendMessage",
                           send_params("non blocking", returnImmediately=True))
    task = _task_of(call.result)
    if task is None:
        raise Inapplicable("agent answered with a Message; SPEC 3.2.2 says "
                           "returnImmediately has no effect in that case")
    state = (task.get("status") or {}).get("state")
    # An agent that genuinely finishes instantly is allowed to come back
    # COMPLETED, so this cannot be asserted. It is observed and compared.
    ctx.observe("return_immediately_state", state,
                "SPEC 3.2.2 requires an immediate return, but a fast agent "
                "may legitimately already be finished.")


@a2a_test(
    id="core.get_task_roundtrip",
    defect="A task id handed out by SendMessage is not retrievable by "
           "GetTask, so polling clients can never collect the result of work "
           "the agent actually did.",
    clause="SPEC 3.1.3, 3.4.2",
    role=ROLE_SERVER, tier=EVERY_COMMIT,
)
def test_get_task(ctx):
    call = _send(ctx, "roundtrip")
    task = _task_of(call.result)
    if task is None:
        raise Inapplicable("agent answered with a Message, so no task exists")
    got = ctx.target.call("GetTask", {"id": task["id"]})
    ctx.assert_must(
        got.error is None,
        "GetTask on the id just returned by SendMessage failed: %s"
        % (got.error,),
        "SPEC 3.1.3: GetTask 'Retrieves the current state ... of a previously "
        "initiated task'.",
    )
    fetched = got.result.get("task") if isinstance(got.result, dict) and "task" in got.result else got.result
    ctx.assert_must(
        isinstance(fetched, dict) and fetched.get("id") == task["id"],
        "GetTask returned a different task id (%r) than requested (%r)"
        % ((fetched or {}).get("id"), task["id"]),
        "SPEC 3.1.3 returns the requested task.",
    )
    ok, problems = validate.validate_task(fetched)
    ctx.assert_must(ok, "GetTask returned a malformed Task: %s" % problems,
                    "PROTO Task REQUIRED annotations")


@a2a_test(
    id="core.unknown_task_is_task_not_found",
    defect="Agent answers a bogus task id with success or the wrong error, so "
           "a client cannot distinguish 'never existed' from 'still working' "
           "and either retries forever or gives up on live work.",
    clause="SPEC 3.1.3 errors; SPEC 5.4 error code mapping",
    role=ROLE_SERVER, tier=EVERY_COMMIT,
)
def test_unknown_task(ctx):
    bogus = "harness-nonexistent-%s" % uuid.uuid4()
    got = ctx.target.call("GetTask", {"id": bogus})
    ctx.assert_must(
        got.error is not None,
        "GetTask on a task id that was never issued returned success: %r"
        % (got.result,),
        "SPEC 3.1.3: 'TaskNotFoundError: The task ID does not exist or is not "
        "accessible.'",
    )
    expected_json, _grpc, expected_http = spec.ERROR_MAP["TaskNotFoundError"]
    if got.binding == "JSONRPC":
        ctx.assert_must(
            got.error_code == expected_json,
            "expected JSON-RPC code %d (TaskNotFoundError), got %r"
            % (expected_json, got.error_code),
            "SPEC 5.4 Error Code Mappings: TaskNotFoundError is -32001.",
        )
    else:
        ctx.assert_must(
            got.http.status == expected_http,
            "expected HTTP %d for TaskNotFoundError, got %d"
            % (expected_http, got.http.status),
            "SPEC 5.4 Error Code Mappings: TaskNotFoundError is 404.",
        )
        reasons = [d.get("reason") for d in got.error_details()]
        ctx.assert_must(
            spec.error_reason("TaskNotFoundError") in reasons,
            "HTTP error body does not carry a google.rpc.ErrorInfo with "
            "reason %r; details were %s"
            % (spec.error_reason("TaskNotFoundError"), got.error_details()),
            "SPEC 11.6: 'implementations MUST include a google.rpc.ErrorInfo "
            "object in the details array for A2A-specific errors with ... "
            "reason: The A2A error type in UPPER_SNAKE_CASE without the Error "
            "suffix'.",
        )
        domains = [d.get("domain") for d in got.error_details()]
        ctx.assert_must(
            spec.ERROR_INFO_DOMAIN in domains,
            "ErrorInfo.domain is %s, expected %r"
            % (domains, spec.ERROR_INFO_DOMAIN),
            "SPEC 11.6: 'domain: Set to a2a-protocol.org'.",
        )


@a2a_test(
    id="core.client_supplied_task_id_rejected",
    defect="Agent accepts a client-invented task id and creates a task under "
           "it, letting one client collide with or hijack another client's "
           "task namespace.",
    clause="SPEC 3.4.2",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_client_task_id(ctx):
    invented = "harness-client-invented-%s" % uuid.uuid4()
    msg = user_message("this carries a task id that does not exist",
                       task_id=invented)
    call = ctx.target.call("SendMessage", {"message": msg})
    ctx.assert_must(
        call.error is not None,
        "SendMessage with a client-invented taskId succeeded (%r). SPEC 3.4.2 "
        "forbids client-supplied task ids for new tasks." % (call.result,),
        "SPEC 3.4.2: 'When a client includes a taskId in a Message, it MUST "
        "reference an existing task. Agents MUST return a TaskNotFoundError "
        "if the provided taskId does not correspond to an existing task. "
        "Client-provided taskId values for creating new tasks is NOT "
        "supported.'",
    )
    ctx.observe("client_task_id_error", call.error_name or call.error_code)
    # The spec names TaskNotFoundError specifically for this case.
    expected_json, _g, expected_http = spec.ERROR_MAP["TaskNotFoundError"]
    if call.binding == "JSONRPC":
        ctx.assert_must(
            call.error_code == expected_json,
            "expected TaskNotFoundError (-32001), got %r" % call.error_code,
            "SPEC 3.4.2 names TaskNotFoundError; SPEC 5.4 maps it to -32001.",
        )
    else:
        ctx.assert_must(
            call.http.status == expected_http,
            "expected HTTP 404 (TaskNotFoundError), got %d" % call.http.status,
            "SPEC 3.4.2 names TaskNotFoundError; SPEC 5.4 maps it to 404.",
        )


@a2a_test(
    id="core.context_id_present_and_stable",
    defect="Agent issues a new contextId for every turn of the same "
           "conversation, so multi-turn delegation loses all continuity and "
           "the remote agent forgets what it was asked.",
    clause="SPEC 3.4.1, 3.4.3",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_context_continuity(ctx):
    first = _send(ctx, "first turn")
    task = _task_of(first.result)
    if task is None:
        msg = (first.result or {}).get("message") or {}
        ctx.assert_must(
            bool(msg.get("contextId")),
            "agent returned a Message with no contextId",
            "SPEC 3.4.1: 'If an agent generates a new contextId, it MUST be "
            "included in the response (either Task or Message).'",
        )
        raise Inapplicable("agent answered with a Message; no task to continue")
    context_id = task.get("contextId")
    ctx.assert_must(
        bool(context_id),
        "Task has no contextId",
        "SPEC 3.4.1: a generated contextId 'MUST be included in the "
        "response'.",
    )
    second = ctx.target.call(
        "SendMessage",
        {"message": user_message("second turn", context_id=context_id)})
    if second.error is not None:
        # SPEC 3.4.1 explicitly allows an agent to refuse a client-supplied
        # contextId, so this is not a failure.
        ctx.observe("client_supplied_context_rejected", True,
                    "SPEC 3.4.1: 'If an agent cannot accept a client-provided "
                    "contextId, it MUST reject the request with an error'.")
        ctx.observe("reject_error", second.error_name or second.error_code)
        return
    ctx.observe("client_supplied_context_rejected", False)
    second_task = _task_of(second.result)
    if second_task is not None:
        ctx.assert_must(
            second_task.get("contextId") == context_id,
            "agent accepted contextId %r but answered with %r"
            % (context_id, second_task.get("contextId")),
            "SPEC 3.4.1: 'Agents MAY accept and preserve client-provided "
            "contextId values.' Having accepted it, echoing a different one "
            "makes the grouping meaningless.",
        )


@a2a_test(
    id="core.mismatched_task_and_context_rejected",
    defect="Agent accepts a message whose contextId contradicts its taskId, "
           "letting a caller splice a task into a conversation it does not "
           "belong to and leak context across sessions.",
    clause="SPEC 3.4.3",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_context_task_mismatch(ctx):
    first = _send(ctx, "establish a task")
    task = _task_of(first.result)
    if task is None:
        raise Inapplicable("agent answered with a Message; no task to mismatch")
    wrong_context = "harness-wrong-context-%s" % uuid.uuid4()
    call = ctx.target.call("SendMessage", {
        "message": user_message("mismatched", task_id=task["id"],
                                context_id=wrong_context)})
    ctx.assert_must(
        call.error is not None,
        "agent accepted a message whose contextId (%r) contradicts the "
        "contextId of the referenced task (%r)"
        % (wrong_context, task.get("contextId")),
        "SPEC 3.4.3: 'Agents MUST reject messages containing mismatching "
        "contextId and taskId (i.e., the provided contextId is different from "
        "that of the referenced Task).'",
    )
    ctx.observe("mismatch_error", call.error_name or call.error_code,
                "The spec mandates rejection but does not name which error, "
                "so the code itself is observed.")


@a2a_test(
    id="core.terminal_task_refuses_new_messages",
    defect="Agent accepts new work on an already-completed task, so a stale "
           "or replayed message silently mutates a finished result that a "
           "caller has already acted on.",
    clause="SPEC 3.1.1 errors",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_terminal_task_rejects(ctx):
    first = _send(ctx, "finish quickly")
    task = _task_of(first.result)
    if task is None:
        raise Inapplicable("agent answered with a Message; no task")
    state = (task.get("status") or {}).get("state")
    if state not in spec.TERMINAL_STATES:
        raise Inapplicable("task is in %s, not a terminal state, so the rule "
                           "under test does not apply" % state)
    call = ctx.target.call("SendMessage", {
        "message": user_message("more work please", task_id=task["id"],
                                context_id=task.get("contextId"))})
    ctx.assert_must(
        call.error is not None,
        "agent accepted a new message on a task already in %s" % state,
        "SPEC 3.1.1: 'UnsupportedOperationError: Messages sent to Tasks that "
        "are in a terminal state (TASK_STATE_COMPLETED, TASK_STATE_FAILED, "
        "TASK_STATE_CANCELED, TASK_STATE_REJECTED) cannot accept further "
        "messages.'",
    )
    ctx.observe("terminal_reject_error", call.error_name or call.error_code)


@a2a_test(
    id="core.cancel_semantics",
    defect="Cancel neither cancels nor reports why, so a caller cannot stop "
           "runaway work and has no way to know it failed to stop it.",
    clause="SPEC 3.1.5",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_cancel(ctx):
    first = ctx.target.call("SendMessage",
                            send_params("cancel me", returnImmediately=True))
    task = _task_of(first.result)
    if task is None:
        raise Inapplicable("agent answered with a Message; nothing to cancel")
    state = (task.get("status") or {}).get("state")
    call = ctx.target.call("CancelTask", {"id": task["id"]})
    if state in spec.TERMINAL_STATES:
        # SPEC 3.1.5 gives exactly two legal answers for an already-finished
        # task: TaskNotCancelableError, or TaskNotFoundError if it was purged.
        ctx.assert_must(
            call.error is not None,
            "cancelling an already-%s task returned success" % state,
            "SPEC 3.1.5: 'TaskNotCancelableError: The task is not in a "
            "cancelable state (e.g., already completed, failed, or "
            "canceled).'",
        )
        ctx.observe("cancel_terminal_error",
                    call.error_name or call.error_code)
        return
    ctx.assert_must(
        call.error is None or call.error_name in
        ("TaskNotCancelableError", "TASK_NOT_CANCELABLE"),
        "cancel of a live task failed with an unexpected error: %s"
        % (call.error,),
        "SPEC 3.1.5: cancel 'attempts to cancel the specified task and "
        "returns its updated state', or reports TaskNotCancelableError.",
    )
    if call.error is None:
        returned = call.result.get("task") if isinstance(call.result, dict) and "task" in call.result else call.result
        new_state = ((returned or {}).get("status") or {}).get("state")
        ctx.observe("state_after_cancel", new_state,
                    "SPEC 3.1.5: 'success is not guaranteed', so the state "
                    "after a cancel request is observed, not asserted.")


@a2a_test(
    id="core.cancel_is_idempotent",
    defect="A repeated cancel throws a different error the second time, so a "
           "client retrying after a network blip cannot tell a real failure "
           "from a duplicate it caused itself.",
    clause="SPEC 3.3.1",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_cancel_idempotent(ctx):
    first = ctx.target.call("SendMessage",
                            send_params("cancel twice", returnImmediately=True))
    task = _task_of(first.result)
    if task is None:
        raise Inapplicable("agent answered with a Message; nothing to cancel")
    a = ctx.target.call("CancelTask", {"id": task["id"]})
    b = ctx.target.call("CancelTask", {"id": task["id"]})
    ctx.observe("cancel_first", a.error_name or a.error_code or "ok")
    ctx.observe("cancel_second", b.error_name or b.error_code or "ok")
    # SPEC 3.3.1 permits the second call to return TaskNotFoundError if the
    # task was purged, so equality cannot be asserted. What CAN be asserted is
    # that the second call does not blow up with an internal error.
    if b.error is not None:
        ctx.assert_must(
            b.error_name not in ("InternalError",) and
            (b.error_code != -32603) and
            (b.binding != "HTTP+JSON" or b.http.status < 500),
            "a duplicate CancelTask produced a server-side internal error "
            "(%s); SPEC 3.3.1 makes cancel idempotent" % (b.error,),
            "SPEC 3.3.1: 'Cancel Task operations are idempotent - multiple "
            "cancellation requests have the same effect.'",
        )


@a2a_test(
    id="core.timestamps_are_utc_z",
    defect="Timestamps carry a local UTC offset instead of Z, so any client "
           "comparing or sorting task times across agents in different "
           "regions orders them wrongly.",
    clause="SPEC 5.6.1",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_timestamps(ctx):
    call = _send(ctx, "timestamp check")
    task = _task_of(call.result)
    if task is None:
        raise Inapplicable("agent answered with a Message; no task timestamp")
    ts = (task.get("status") or {}).get("timestamp")
    if ts is None:
        # PROTO TaskStatus.timestamp is not REQUIRED, so absence is legal.
        ctx.observe("status_timestamp_present", False)
        raise Inapplicable("TaskStatus.timestamp is absent, which is legal "
                           "because the proto does not mark it REQUIRED")
    ctx.observe("status_timestamp_present", True)
    ctx.observe("status_timestamp_sample", ts)
    problems = validate.validate_timestamp(ts, "TaskStatus.timestamp")
    ctx.assert_must(
        not problems,
        "; ".join(problems),
        "SPEC 5.6.1: 'Timezone: UTC (denoted by Z suffix)' and 'Timestamps "
        "MUST NOT include timezone offsets other than Z (all times are "
        "UTC).'",
    )


@a2a_test(
    id="core.history_length_zero_omits_history",
    defect="historyLength=0 still returns the whole conversation, so a client "
           "asking for a lightweight poll gets an unbounded payload and a "
           "long transcript is echoed back to a caller that must not see it.",
    clause="SPEC 3.2.4",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_history_length(ctx):
    first = _send(ctx, "history check")
    task = _task_of(first.result)
    if task is None:
        raise Inapplicable("agent answered with a Message; no task history")
    got = ctx.target.call("GetTask", {"id": task["id"], "historyLength": 0})
    if got.error is not None:
        raise Inapplicable("GetTask with historyLength=0 errored: %s"
                           % (got.error,))
    fetched = got.result.get("task") if isinstance(got.result, dict) and "task" in got.result else got.result
    history = (fetched or {}).get("history")
    # SPEC 3.2.4 says the history field SHOULD be omitted, so an empty list is
    # a SHOULD-level deviation, not a MUST violation. Only a NON-EMPTY history
    # is a real violation of "no history should be returned".
    ctx.assert_must(
        not history,
        "historyLength=0 returned %d history entries" % len(history or []),
        "SPEC 3.2.4: '0: No history should be returned; the history field "
        "SHOULD be omitted'.",
    )
    ctx.observe("history_field_omitted_at_zero", "history" not in (fetched or {}),
                "SPEC 3.2.4 says SHOULD omit, so present-but-empty is legal.")

    got2 = ctx.target.call("GetTask", {"id": task["id"], "historyLength": 1})
    if got2.error is None:
        f2 = got2.result.get("task") if isinstance(got2.result, dict) and "task" in got2.result else got2.result
        n = len((f2 or {}).get("history") or [])
        ctx.assert_must(
            n <= 1,
            "historyLength=1 returned %d history entries" % n,
            "SPEC 3.2.4: '> 0: Return at most this many recent messages'. "
            "PROTO GetTaskRequest.history_length: 'The server MUST NOT return "
            "more messages than the provided value'.",
        )


@a2a_test(
    id="core.unsupported_version_is_rejected",
    defect="Agent silently serves a protocol version it was not asked for, so "
           "a client pinned to a newer version gets older semantics and "
           "loses functionality with no error to alert anyone.",
    clause="SPEC 3.6.2",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_version_negotiation(ctx):
    declared = {i.get("protocolVersion") for i in ctx.target.interfaces()}
    bogus = "0.5"
    while bogus in declared:
        bogus = "%.1f" % (float(bogus) + 0.1)
    call = ctx.target.call("SendMessage", send_params("version probe"),
                           version=bogus)
    ctx.observe("declared_versions", sorted(v for v in declared if v))
    ctx.observe("unsupported_version_status",
                call.http.status if call.http else None)
    ctx.assert_must(
        call.error is not None,
        "agent accepted A2A-Version: %s, a version it does not declare "
        "support for (%s), and answered normally with HTTP %s"
        % (bogus, sorted(v for v in declared if v),
           call.http.status if call.http else "?"),
        "SPEC 3.6.2: 'Agents MUST process requests using the semantics of the "
        "requested A2A-Version (matching Major.Minor). If the version is not "
        "supported by the interface, agents MUST return a "
        "VersionNotSupportedError.'",
    )
    expected_json, _g, expected_http = spec.ERROR_MAP["VersionNotSupportedError"]
    if call.binding == "JSONRPC":
        ctx.observe("version_error_code", call.error_code,
                    "SPEC 5.4 maps VersionNotSupportedError to -32009.")
    else:
        ctx.observe("version_error_http", call.http.status)
    # The body shape is genuinely ambiguous. See
    # AMBIGUITIES.VERSION_ERROR_BODY_SHAPE, so only the fact of the error and
    # the status code family are asserted.


@a2a_test(
    id="core.absent_version_header_defaults_to_0_3",
    defect="Agent rejects requests that omit A2A-Version, breaking every 0.3 "
           "client, which the spec requires be treated as 0.3 rather than as "
           "an error.",
    clause="SPEC 3.6.2",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_absent_version_header(ctx):
    call = ctx.target.call("SendMessage", send_params("no version header"),
                           version=None)
    ctx.observe("no_version_header_error",
                call.error_name or call.error_code or "ok")
    # SPEC 3.6.2 says the agent MUST interpret an empty value as 0.3. An agent
    # that does not serve 0.3 at all may legitimately answer
    # VersionNotSupportedError, so success cannot be asserted. What must not
    # happen is an unhandled server error.
    if call.error is not None and call.binding == "HTTP+JSON":
        ctx.assert_must(
            call.http.status < 500,
            "omitting the A2A-Version header produced HTTP %d; SPEC 3.6.2 "
            "requires the agent treat an empty version as 0.3, so this is a "
            "handled case, not a server fault" % call.http.status,
            "SPEC 3.6.2: 'Agents MUST interpret empty value as 0.3 version.'",
        )


@a2a_test(
    id="core.streaming_capability_is_honest",
    defect="Card claims streaming and the stream endpoint does not work, or "
           "denies streaming and streams anyway. Either way a client's "
           "capability check is worthless and it picks the wrong call path.",
    clause="SPEC 3.3.4 Capability Validation",
    role=ROLE_SERVER, tier=EVERY_COMMIT,
)
def test_streaming_capability(ctx):
    declared = ctx.target.capability("streaming")
    ctx.observe("capability_streaming", declared)
    res = ctx.target.stream("SendStreamingMessage", send_params("stream probe"),
                            stop_after=_is_terminal_frame)
    if declared:
        ctx.assert_must(
            res.events and res.status in (200, None),
            "card declares capabilities.streaming = true but the streaming "
            "call produced no events (status %s, error %s)"
            % (res.status, res.error),
            "SPEC 3.3.4: capability declarations must match behaviour; SPEC "
            "3.1.2 defines the streaming operation.",
        )
        ctx.observe("stream_content_type", res.content_type,
                    "SPEC 9.1 / 11.1 specify text/event-stream for SSE.")
    else:
        # SPEC 3.3.4 is explicit: undeclared streaming MUST error.
        ctx.assert_must(
            not res.events or res.status not in (200,),
            "card does not declare capabilities.streaming but the streaming "
            "endpoint returned %d events with status %s"
            % (len(res.events), res.status),
            "SPEC 3.3.4: 'Streaming: If AgentCard.capabilities.streaming is "
            "false or not present, attempts to use SendStreamingMessage or "
            "SubscribeToTask operations MUST return "
            "UnsupportedOperationError.'",
        )


def _is_terminal_frame(payload):
    if not isinstance(payload, dict):
        return False
    if "statusUpdate" in payload:
        state = ((payload["statusUpdate"] or {}).get("status") or {}).get("state")
        return state in spec.TERMINAL_STATES
    if "task" in payload:
        state = ((payload["task"] or {}).get("status") or {}).get("state")
        return state in spec.TERMINAL_STATES
    if "message" in payload:
        return True
    return False


@a2a_test(
    id="core.stream_frames_are_wellformed",
    defect="A stream frame sets two payload kinds at once or none, so a "
           "client's dispatch either drops the event or double-applies it, "
           "corrupting the assembled artifact.",
    clause="SPEC 3.1.2, 3.2.3; PROTO StreamResponse oneof",
    role=ROLE_SERVER, tier=EVERY_COMMIT,
)
def test_stream_frames(ctx):
    if not ctx.target.capability("streaming"):
        raise Inapplicable("card does not declare capabilities.streaming")
    res = ctx.target.stream("SendStreamingMessage", send_params("frame check"),
                            stop_after=_is_terminal_frame)
    ctx.assert_must(
        bool(res.events),
        "streaming produced no events (status %s, error %s)"
        % (res.status, res.error),
        "SPEC 3.1.2: the operation 'MUST establish a streaming connection'.",
    )
    for i, event in enumerate(res.events):
        problems = validate.validate_stream_payload(event, "event[%d]" % i)
        ctx.assert_must(
            not problems,
            "malformed stream frame %d: %s" % (i, problems),
            "PROTO StreamResponse declares payload as a oneof; SPEC 3.1.2 "
            "requires 'exactly one' per response.",
        )
    kinds = [validate.stream_payload_kind(e) for e in res.events]
    ctx.observe("stream_frame_kinds", kinds)
    ctx.observe("stream_frame_count", len(res.events))


@a2a_test(
    id="core.jsonrpc_stream_envelope",
    defect="Under the JSON-RPC binding, stream frames omit the JSON-RPC "
           "envelope or echo the wrong request id, so a client multiplexing "
           "several streams over one connection attributes events to the "
           "wrong task.",
    clause="SPEC 9.4.2",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_jsonrpc_stream_envelope(ctx):
    if ctx.target.pick_interface().get("protocolBinding") != "JSONRPC":
        raise Inapplicable("the selected interface is not the JSON-RPC "
                           "binding, so its SSE framing does not apply")
    if not ctx.target.capability("streaming"):
        raise Inapplicable("card does not declare capabilities.streaming")
    res = ctx.target.stream("SendStreamingMessage",
                            send_params("envelope check"),
                            stop_after=_is_terminal_frame)
    problems = getattr(res, "envelope_problems", [])
    ctx.assert_must(
        not problems,
        "JSON-RPC stream framing is wrong: %s" % problems[:5],
        "SPEC 9.4.2 fixes the frame shape as "
        "data: {\"jsonrpc\": \"2.0\", \"id\": 1, \"result\": "
        "{ StreamResponse object }}.",
    )
    ctx.observe("jsonrpc_stream_frames", len(getattr(res, "envelopes", [])))


@a2a_test(
    id="core.stream_opens_with_task_or_message",
    defect="A stream begins with a status delta before any Task, so a client "
           "receives updates for a task it has never been told the id of and "
           "cannot correlate them to anything.",
    clause="SPEC 3.1.2 Behavior",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_stream_opening_frame(ctx):
    if not ctx.target.capability("streaming"):
        raise Inapplicable("card does not declare capabilities.streaming")
    res = ctx.target.stream("SendStreamingMessage", send_params("open check"),
                            stop_after=_is_terminal_frame)
    ctx.assert_must(
        bool(res.events),
        "streaming produced no events",
        "SPEC 3.1.2 requires a stream.",
    )
    first = validate.stream_payload_kind(res.events[0])
    ctx.assert_must(
        first in ("task", "message"),
        "stream opened with a %r frame; SPEC 3.1.2 requires it begin with a "
        "Task or be a single Message" % first,
        "SPEC 3.1.2: 'Message-only stream: ... the stream MUST contain "
        "exactly one Message object and then close immediately. Task "
        "lifecycle stream: ... the stream MUST begin with the Task object'.",
    )
    ctx.observe("stream_opening_kind", first)
    if first == "message":
        ctx.assert_must(
            len(res.events) == 1,
            "a message-only stream carried %d events; SPEC 3.1.2 requires "
            "exactly one" % len(res.events),
            "SPEC 3.1.2: 'the stream MUST contain exactly one Message object "
            "and then close immediately'.",
        )


@a2a_test(
    id="core.stream_closes_at_terminal_state",
    defect="Stream stays open after the task reaches a terminal state, so "
           "clients leak a connection per delegated task and eventually "
           "exhaust their socket budget under load.",
    clause="SPEC 3.1.2 Behavior",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_stream_closes(ctx):
    if not ctx.target.capability("streaming"):
        raise Inapplicable("card does not declare capabilities.streaming")
    # No wall-clock assertion here. The stream is read to natural EOF with a
    # generous ceiling; the assertion is on WHAT happened, not how fast.
    res = ctx.target.stream("SendStreamingMessage", send_params("close check"),
                            max_events=64)
    terminal_at = None
    for i, event in enumerate(res.events):
        if _is_terminal_frame(event):
            terminal_at = i
            break
    ctx.observe("terminal_frame_index", terminal_at)
    ctx.observe("events_after_terminal",
                None if terminal_at is None else len(res.events) - terminal_at - 1)
    if terminal_at is None:
        raise Inapplicable("no terminal state was reached within %d events"
                           % len(res.events))
    ctx.assert_must(
        res.closed_cleanly or res.error is None,
        "stream did not close after the task reached a terminal state "
        "(error=%s)" % res.error,
        "SPEC 3.1.2: 'The stream MUST close when the task reaches a terminal "
        "state'.",
    )
    trailing = res.events[terminal_at + 1:]
    # SPEC 11.7 permits a final Task snapshot after the terminal status.
    unexpected = [validate.stream_payload_kind(e) for e in trailing
                  if validate.stream_payload_kind(e) != "task"]
    ctx.assert_must(
        not unexpected,
        "stream emitted %s after reaching a terminal state" % unexpected,
        "SPEC 3.1.2: the stream MUST close at a terminal state. SPEC 11.7 "
        "permits only an optional trailing Task snapshot.",
    )


@a2a_test(
    id="core.push_capability_is_honest",
    defect="Card denies push notifications but the config endpoint accepts "
           "registrations, so a client believes it will be called back on a "
           "webhook that will never fire and waits forever.",
    clause="SPEC 3.3.4",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_push_capability(ctx):
    declared = ctx.target.capability("pushNotifications")
    ctx.observe("capability_pushNotifications", declared)
    first = _send(ctx, "push probe")
    task = _task_of(first.result)
    if task is None:
        raise Inapplicable("agent answered with a Message; no task to attach "
                           "a push config to")
    call = ctx.target.call("CreateTaskPushNotificationConfig", {
        "taskId": task["id"],
        "url": "http://127.0.0.1:9/harness-never-listens",
    })
    if not declared:
        ctx.assert_must(
            call.error is not None,
            "card does not declare capabilities.pushNotifications but "
            "CreateTaskPushNotificationConfig succeeded",
            "SPEC 3.3.4: 'Push Notifications: If "
            "AgentCard.capabilities.pushNotifications is false or not "
            "present, operations related to push notification configuration "
            "(Create, Get, List, Delete) MUST return "
            "PushNotificationNotSupportedError.'",
        )
        expected_json, _g, expected_http = spec.ERROR_MAP[
            "PushNotificationNotSupportedError"]
        if call.binding == "JSONRPC":
            ctx.observe("push_denied_code", call.error_code,
                        "SPEC 5.4 maps this to -32003.")
        else:
            ctx.observe("push_denied_http", call.http.status,
                        "SPEC 5.4 maps this to HTTP 400.")
    else:
        ctx.observe("push_config_create_error",
                    call.error_name or call.error_code or "ok")


@a2a_test(
    id="core.extended_card_capability_is_honest",
    defect="Card denies extendedAgentCard but the endpoint serves one, or "
           "claims it and returns the wrong error, so a client either misses "
           "authenticated capabilities or hangs on an endpoint that is not "
           "there.",
    clause="SPEC 3.1.11, 3.3.4",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_extended_card(ctx):
    declared = ctx.target.capability("extendedAgentCard")
    ctx.observe("capability_extendedAgentCard", declared)
    call = ctx.target.call("GetExtendedAgentCard", {})
    if not declared:
        ctx.assert_must(
            call.error is not None,
            "card does not declare capabilities.extendedAgentCard but "
            "GetExtendedAgentCard returned a card",
            "SPEC 3.3.4: 'Extended Agent Card: If "
            "AgentCard.capabilities.extendedAgentCard is false or not "
            "present, attempts to call the Get Extended Agent Card operation "
            "MUST return UnsupportedOperationError.'",
        )
        ctx.observe("extended_card_denied_error",
                    call.error_name or call.error_code)
    else:
        ctx.observe("extended_card_error",
                    call.error_name or call.error_code or "ok")
        if call.error is None:
            card = call.result.get("agentCard") if isinstance(call.result, dict) and "agentCard" in call.result else call.result
            ok, problems = validate.validate_agent_card(card)
            ctx.assert_must(
                ok, "extended agent card is malformed: %s" % problems,
                "SPEC 3.1.11 returns 'A complete Agent Card object'.",
            )


@a2a_test(
    id="core.list_tasks_shape",
    defect="ListTasks omits nextPageToken or returns it as null on the last "
           "page, so a paginating client either loops forever or stops early "
           "and silently misses tasks.",
    clause="SPEC 3.1.4",
    role=ROLE_SERVER, tier=PULL_REQUEST,
)
def test_list_tasks(ctx):
    call = ctx.target.call("ListTasks", {})
    if call.error is not None:
        # ListTasks requires authorisation scoping (SPEC 3.1.4, 13.1), so an
        # unauthenticated harness being refused is entirely correct.
        ctx.observe("list_tasks_error", call.error_name or call.error_code)
        raise Inapplicable(
            "ListTasks refused this caller (%s). SPEC 3.1.4 requires "
            "authorization scoping, so refusing an unauthenticated harness is "
            "conformant." % (call.error_name or call.error_code))
    result = call.result
    ctx.assert_must(
        isinstance(result, dict) and "nextPageToken" in result,
        "ListTasks response has no nextPageToken field",
        "SPEC 3.1.4: 'The nextPageToken field MUST always be present in the "
        "response. When there are no more results to retrieve ... the field "
        "MUST be set to an empty string (\"\").'",
    )
    ctx.assert_must(
        isinstance(result.get("nextPageToken"), str),
        "nextPageToken is %r, not a string" % (result.get("nextPageToken"),),
        "SPEC 3.1.4 requires an empty string, not null, on the final page.",
    )
    ctx.observe("list_tasks_fields", sorted(result.keys()))
    tasks = result.get("tasks") or []
    # SPEC 3.1.4: artifacts MUST be omitted entirely when includeArtifacts is
    # false, which is the default.
    with_artifacts = [t.get("id") for t in tasks if "artifacts" in t]
    ctx.assert_must(
        not with_artifacts,
        "ListTasks returned artifacts for %d task(s) without "
        "includeArtifacts=true" % len(with_artifacts),
        "SPEC 3.1.4: 'When includeArtifacts is false (the default), the "
        "artifacts field MUST be omitted entirely from each Task object in "
        "the response.'",
    )
    ctx.observe("list_tasks_count", len(tasks))


@a2a_test(
    id="core.artifacts_wellformed",
    defect="An artifact arrives with no parts or no artifactId, so the "
           "consuming agent has an output it cannot address, chunk, or "
           "render, and the result of the delegated work is unusable.",
    clause="PROTO Artifact REQUIRED annotations",
    role=ROLE_SERVER, tier=EVERY_COMMIT,
)
def test_artifacts(ctx):
    call = _send(ctx, "produce an artifact")
    task = _task_of(call.result)
    if task is None:
        raise Inapplicable("agent answered with a Message; no artifacts")
    artifacts = task.get("artifacts") or []
    ctx.observe("artifact_count", len(artifacts))
    if not artifacts:
        # Artifacts are not mandatory. SPEC 3.7 says results SHOULD be
        # returned as artifacts, which is a SHOULD.
        ctx.note("Task produced no artifacts. SPEC 3.7 says results SHOULD be "
                 "returned via artifacts, so this is observed, not failed.")
        return
    for i, artifact in enumerate(artifacts):
        problems = validate.validate_artifact(artifact, "artifacts[%d]" % i)
        ctx.assert_must(
            not problems, "; ".join(problems),
            "PROTO Artifact: artifact_id and parts are REQUIRED, and parts "
            "'Must contain at least one part'.",
        )
    ids = [a.get("artifactId") for a in artifacts]
    ctx.assert_must(
        len(set(ids)) == len(ids),
        "artifact ids are not unique within the task: %s" % ids,
        "PROTO Artifact.artifact_id: 'Unique identifier (e.g. UUID) for the "
        "artifact. It must be unique within a task.'",
    )
