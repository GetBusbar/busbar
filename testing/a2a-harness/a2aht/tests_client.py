"""The target's CLIENT role, and the seam between its two roles.

This is the least-tested area of any A2A implementation and the one where the
interesting defects live, because an implementation is usually written and
tested as a server and then acquires a client almost by accident.

To test a client you must control what it talks to. The harness therefore
stands up a peer it fully controls (see fakes.py) and asks the target to
delegate to it. Asking is the parameterised part:

    --client-drive 'some-command --agent {url}'

The command is invoked with {url} replaced by the fake peer's base URL and
{card_url} by its agent card URL. The harness makes NO assumption about what
the command is. If it is not supplied, these tests report NOT_CONFIGURED and
the run is red. They never skip, because a client-role gate that quietly
passes having driven nothing is exactly the false green this harness exists to
prevent.
"""

import json
import shlex
import subprocess
import time

from .model import (a2a_test, ROLE_CLIENT, ROLE_SEAM, PULL_REQUEST,
                    PRE_RELEASE, NEEDS_FAKE_PEER, NEEDS_REAL_PEER,
                    Inapplicable)
from . import spec
from .fakes import Behaviour, FakePeer


def drive(ctx, peer, extra_env=None, timeout=60.0):
    """Ask the target to act as an A2A client against `peer`."""
    template = ctx.config.get("client_drive")
    if not template:
        from .model import NotConfigured
        raise NotConfigured(
            "no --client-drive command was given, so the target's CLIENT role "
            "cannot be exercised at all. This is reported as NOT CONFIGURED "
            "and the run is RED. It is not a pass. Supply a command that "
            "makes the subject delegate to an A2A agent, using {url} for the "
            "agent base URL and {card_url} for its agent card, for example:\n"
            "  --client-drive 'my-agent delegate --to {url}'"
        )
    command = template.replace("{url}", peer.base_url).replace(
        "{card_url}", peer.base_url + spec.WELL_KNOWN_CARD_PATH)
    env = dict(ctx.config.get("env") or {})
    env.update(extra_env or {})
    import os
    full_env = dict(os.environ)
    full_env.update(env)
    started = time.time()
    try:
        proc = subprocess.run(
            shlex.split(command), capture_output=True, timeout=timeout,
            env=full_env, cwd=ctx.config.get("cwd"))
        return {
            "command": command,
            "returncode": proc.returncode,
            "stdout": proc.stdout.decode("utf-8", "replace")[-4000:],
            "stderr": proc.stderr.decode("utf-8", "replace")[-4000:],
            "timed_out": False,
            "elapsed": time.time() - started,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command,
            "returncode": None,
            "stdout": (exc.stdout or b"").decode("utf-8", "replace")[-4000:],
            "stderr": (exc.stderr or b"").decode("utf-8", "replace")[-4000:],
            "timed_out": True,
            "elapsed": time.time() - started,
        }


def _summary(run):
    """What the harness records about a drive, minus machine-specific noise."""
    return {
        "returncode": run["returncode"],
        "timed_out": run["timed_out"],
        "stdout_bytes": len(run["stdout"]),
        "stderr_bytes": len(run["stderr"]),
    }


@a2a_test(
    id="client.fetches_card_before_calling",
    defect="Client calls an agent's operations without ever fetching its "
           "card, so it has not checked capabilities, security schemes or "
           "protocol version and will call operations the peer does not "
           "support.",
    clause="SPEC 3.3.4, 8.3.2",
    role=ROLE_CLIENT, tier=PULL_REQUEST,
)
def test_client_fetches_card(ctx):
    with FakePeer() as peer:
        run = drive(ctx, peer)
        ctx.observe("drive", _summary(run))
        ctx.assert_must(
            peer.card_fetches > 0,
            "the target made %d A2A request(s) but never fetched the agent "
            "card at %s. Command was: %s"
            % (len(peer.a2a_requests()), spec.WELL_KNOWN_CARD_PATH,
               run["command"]),
            "SPEC 3.3.4: 'Clients SHOULD validate capability support by "
            "examining the Agent Card before attempting operations that "
            "require optional capabilities.' SPEC 8.3.2 requires the client "
            "parse supportedInterfaces to choose a transport at all.",
        )
        ctx.observe("card_fetches", peer.card_fetches)
        ctx.observe("a2a_request_count", len(peer.a2a_requests()))


@a2a_test(
    id="client.sends_version_header",
    defect="Client omits the A2A-Version header, so every agent it talks to "
           "silently serves it 0.3 semantics and it loses 1.0 features with "
           "no error anywhere.",
    clause="SPEC 3.6.1",
    role=ROLE_CLIENT, tier=PULL_REQUEST,
)
def test_client_version_header(ctx):
    with FakePeer() as peer:
        run = drive(ctx, peer)
        ctx.observe("drive", _summary(run))
        requests = peer.a2a_requests()
        if not requests:
            ctx.assert_must(
                False,
                "the target made no A2A requests to the fake peer, so its "
                "client role could not be observed. stdout: %r stderr: %r"
                % (run["stdout"][-500:], run["stderr"][-500:]),
                "The test cannot run without traffic; reported as a failure "
                "rather than a skip so it is never a silent pass.",
            )
        versions = peer.saw_header(spec.VERSION_HEADER)
        ctx.observe("version_headers_seen", sorted(set(versions)))
        # SPEC 3.6.1 also permits the version as a request parameter.
        param_versions = [r["path"] for r in requests
                          if "A2A-Version=" in r["path"]]
        ctx.observe("version_as_query_param", bool(param_versions))
        ctx.assert_must(
            bool(versions) or bool(param_versions),
            "the target sent %d A2A request(s) and none carried the "
            "A2A-Version header or query parameter"
            % len(requests),
            "SPEC 3.6.1: 'Clients MUST send the A2A-Version header with each "
            "request'. SPEC 3.6.1 also allows it 'as a request parameter "
            "instead of a header'.",
        )


@a2a_test(
    id="client.sends_wellformed_messages",
    defect="Client emits a Message missing messageId, role or parts, so "
           "strict agents reject every delegation it attempts and the "
           "failure looks like the remote agent's fault.",
    clause="PROTO Message REQUIRED annotations; SPEC 5.7",
    role=ROLE_CLIENT, tier=PULL_REQUEST,
)
def test_client_message_shape(ctx):
    from .validate import validate_message
    with FakePeer() as peer:
        run = drive(ctx, peer)
        ctx.observe("drive", _summary(run))
        problems = []
        checked = 0
        for req in peer.a2a_requests():
            body = req["body"]
            if not isinstance(body, dict):
                continue
            params = body.get("params") if body.get("jsonrpc") else body
            message = (params or {}).get("message")
            if not isinstance(message, dict):
                continue
            checked += 1
            problems += validate_message(message, "request[%d].message" % checked)
        ctx.observe("client_messages_checked", checked)
        if not checked:
            ctx.assert_must(
                False,
                "the target sent no A2A message the harness could inspect "
                "(%d request(s) total)" % len(peer.a2a_requests()),
                "Reported as a failure rather than a skip: a client-role test "
                "that inspects nothing must never be green.",
            )
        ctx.assert_must(
            not problems,
            "the target sent malformed A2A messages: %s" % problems[:6],
            "PROTO Message: message_id, role and parts are all REQUIRED.",
        )


@a2a_test(
    id="client.honours_declared_binding",
    defect="Client ignores the binding the card declares and guesses a "
           "transport, so it works against agents that happen to serve both "
           "and fails against conformant single-binding agents.",
    clause="SPEC 8.3.2",
    role=ROLE_CLIENT, tier=PULL_REQUEST,
)
def test_client_honours_binding(ctx):
    with FakePeer(binding="HTTP+JSON") as peer:
        run = drive(ctx, peer)
        ctx.observe("drive", _summary(run))
        paths = [r["path"] for r in peer.a2a_requests()]
        ctx.observe("paths_used", sorted(set(paths)))
        rpc_style = [r for r in peer.a2a_requests()
                     if isinstance(r["body"], dict)
                     and r["body"].get("jsonrpc") == "2.0"]
        ctx.observe("used_jsonrpc_envelope_against_rest_card", bool(rpc_style))
        if rpc_style:
            ctx.note(
                "The peer's card declared only HTTP+JSON, but the target sent "
                "a JSON-RPC envelope. SPEC 8.3.2 requires the client select a "
                "transport from supportedInterfaces and 'Use the correct URL "
                "for the selected transport'."
            )


@a2a_test(
    id="client.rejects_card_missing_required_fields",
    defect="Client accepts a card with no supportedInterfaces or no name and "
           "proceeds anyway, meaning it will talk to anything at all and its "
           "card validation provides no protection.",
    clause="PROTO AgentCard REQUIRED; SPEC 5.7",
    role=ROLE_CLIENT, tier=PULL_REQUEST,
)
def test_client_rejects_bad_card(ctx):
    outcomes = {}
    for field in ("supportedInterfaces", "name", "capabilities"):
        with FakePeer(Behaviour(card_missing_fields=[field])) as peer:
            run = drive(ctx, peer)
            outcomes[field] = {
                "returncode": run["returncode"],
                "made_a2a_calls": len(peer.a2a_requests()),
                "timed_out": run["timed_out"],
            }
    ctx.observe("bad_card_outcomes", outcomes)
    # A client that cannot even find a URL has nothing to call, so the
    # supportedInterfaces case is the one that can be asserted.
    ctx.assert_must(
        outcomes["supportedInterfaces"]["made_a2a_calls"] == 0,
        "the target made %d A2A call(s) against a card with no "
        "supportedInterfaces, so it invented an endpoint rather than reading "
        "one" % outcomes["supportedInterfaces"]["made_a2a_calls"],
        "SPEC 8.3.2: 'Parse supportedInterfaces if present, and select the "
        "first supported transport ... Use the correct URL for the selected "
        "transport.' There is no URL to use here.",
    )


@a2a_test(
    id="client.handles_unreachable_card",
    defect="When the card endpoint is down or 500s, the client hangs or dies "
           "with a stack trace instead of reporting a legible failure, so an "
           "operator cannot tell a down peer from a broken client.",
    clause="NO SPEC CLAUSE for the message. Characterises the failure mode.",
    role=ROLE_CLIENT, tier=PULL_REQUEST,
)
def test_client_unreachable_card(ctx):
    outcomes = {}
    for status in (404, 500, 503):
        with FakePeer(Behaviour(card_status=status)) as peer:
            run = drive(ctx, peer, timeout=45.0)
            outcomes[status] = {"returncode": run["returncode"],
                                "timed_out": run["timed_out"]}
            ctx.assert_must(
                not run["timed_out"],
                "with the agent card returning HTTP %d, the target hung and "
                "had to be killed after %.0fs. A client must fail, not hang, "
                "when discovery fails." % (status, run["elapsed"]),
                "No spec clause mandates a timeout, but SPEC 8.1 makes the "
                "card the entry point to everything; a client that blocks "
                "forever on a missing one cannot be operated.",
            )
    ctx.observe("unreachable_card_outcomes", outcomes)


@a2a_test(
    id="client.handles_truncated_stream",
    defect="When a peer cuts a stream off before any terminal event, the "
           "client reports success on a half-finished task, so a partial "
           "result is treated as a complete one.",
    clause="SPEC 3.1.2 (streams close at a terminal state)",
    role=ROLE_CLIENT, tier=PULL_REQUEST,
)
def test_client_truncated_stream(ctx):
    with FakePeer(Behaviour(truncate_stream_after=2)) as peer:
        run = drive(ctx, peer, timeout=45.0)
        ctx.observe("drive", _summary(run))
        ctx.assert_must(
            not run["timed_out"],
            "the target hung when the peer truncated the stream mid-task",
            "SPEC 3.1.2 requires the stream close at a terminal state; a "
            "client must cope with a peer that closes early instead.",
        )
        ctx.observe("truncated_stream_returncode", run["returncode"])
        if run["returncode"] == 0:
            ctx.note(
                "The target exited 0 after a stream that was cut off before "
                "any terminal state. SPEC 3.1.2 says a conformant stream "
                "closes only at a terminal state, so this stream was "
                "incomplete. Reporting success on it means a partial result "
                "is indistinguishable from a complete one. No clause "
                "mandates the exit code, so this is a finding, not a failure."
            )


@a2a_test(
    id="client.handles_never_resolving_task",
    defect="A task that never leaves WORKING blocks the client forever, so "
           "one unresponsive peer wedges the whole delegating agent.",
    clause="NO SPEC CLAUSE: A2A sets no task deadline. Characterised.",
    role=ROLE_CLIENT, tier=PRE_RELEASE,
)
def test_client_never_resolving(ctx):
    budget = float(ctx.config.get("never_resolve_budget", 30.0))
    with FakePeer(Behaviour(never_resolve=True)) as peer:
        run = drive(ctx, peer, timeout=budget)
        ctx.observe("never_resolve_timed_out", run["timed_out"])
        ctx.observe("never_resolve_budget_seconds", budget)
        if run["timed_out"]:
            ctx.note(
                "The target did not give up on a task that never left "
                "TASK_STATE_WORKING within %.0fs. The A2A specification sets "
                "no deadline for task completion, so this is NOT a "
                "conformance failure. It is, however, the mechanism by which "
                "a single slow peer stalls a delegating agent, and a client "
                "should have its own deadline. That is MY RECOMMENDATION, "
                "not a spec requirement." % budget
            )


@a2a_test(
    id="client.handles_unknown_task_state",
    defect="A peer emitting a task state the client has never heard of causes "
           "a crash or an infinite poll, rather than a clean unknown-state "
           "error.",
    clause="SPEC 5.7 (ignore unrecognised); PROTO enum TaskState",
    role=ROLE_CLIENT, tier=PULL_REQUEST,
)
def test_client_unknown_state(ctx):
    with FakePeer(Behaviour(
            emit_unknown_task_state="TASK_STATE_FROM_THE_FUTURE")) as peer:
        run = drive(ctx, peer, timeout=45.0)
        ctx.observe("drive", _summary(run))
        ctx.assert_must(
            not run["timed_out"],
            "the target hung on an unrecognised TaskState value",
            "SPEC 5.7: 'Implementations SHOULD ignore unrecognized fields ... "
            "allowing for forward compatibility'. Hanging is never forward "
            "compatible.",
        )
        ctx.observe("unknown_state_returncode", run["returncode"])


@a2a_test(
    id="client.handles_malformed_response",
    defect="A peer returning truncated JSON crashes the client with an "
           "unhandled parse error, so a flaky remote agent takes down the "
           "delegating one.",
    clause="SPEC 3.3.2 InvalidAgentResponseError",
    role=ROLE_CLIENT, tier=PULL_REQUEST,
)
def test_client_malformed_response(ctx):
    with FakePeer(Behaviour(malformed_json_response=True)) as peer:
        run = drive(ctx, peer, timeout=45.0)
        ctx.observe("drive", _summary(run))
        ctx.assert_must(
            not run["timed_out"],
            "the target hung on a malformed response body",
            "SPEC 3.3.2 defines InvalidAgentResponseError precisely for 'An "
            "agent returned a response that does not conform to the "
            "specification for the current method', so this case is "
            "anticipated and must be handled.",
        )
        ctx.observe("malformed_response_returncode", run["returncode"])


@a2a_test(
    id="seam.relays_without_leaking_context",
    defect="An agent acting as both server and client relays a caller's task "
           "outward while leaking its own internal identifiers, or attaches "
           "the downstream peer's task id to the upstream caller's task, "
           "breaking correlation at the seam between the two roles.",
    clause="SPEC 3.4.2 (task ids are server-generated per agent)",
    role=ROLE_SEAM, tier=PRE_RELEASE, needs=NEEDS_REAL_PEER,
)
def test_seam_relay(ctx):
    with FakePeer() as peer:
        run = drive(ctx, peer, timeout=60.0)
        ctx.observe("drive", _summary(run))
        downstream_task_ids = [t for t in peer.tasks]
        ctx.observe("downstream_tasks_created", len(downstream_task_ids))
        if not downstream_task_ids:
            raise Inapplicable(
                "the drive command created no task on the downstream peer, so "
                "there is no seam to inspect")
        # The upstream caller here is the harness itself. If the target is
        # also serving, its own task ids must not be the downstream ones.
        try:
            upstream = ctx.target.call("SendMessage",
                                       {"message": {"messageId": "seam-probe",
                                                    "role": "ROLE_USER",
                                                    "parts": [{"text": "relay"}]}})
        except Exception:
            raise Inapplicable("target does not also serve, so there is no "
                               "seam between roles to test")
        upstream_task = (upstream.result or {}).get("task") or {}
        ctx.assert_must(
            upstream_task.get("id") not in downstream_task_ids,
            "the target handed its caller a task id (%s) that was generated "
            "by the downstream peer. Task ids are per-agent, so this "
            "conflates two different agents' namespaces."
            % upstream_task.get("id"),
            "SPEC 3.4.2: 'Task IDs are server-generated when a new task is "
            "created ... Agents MUST generate a unique taskId for each new "
            "task they create.'",
        )
