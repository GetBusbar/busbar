# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""AUTH-*: section 7 authentication, section 13.1 authorization scoping.

Nine requirements, none of which the official TCK executes against any implementation. Each check
below states the specification sentence it encodes at the top of its docstring, and the reading it
takes where the sentence admits more than one; `spec.py` carries the same text in full.
"""

from __future__ import annotations

import uuid

from a2asup.model import Result, Verdict, short
from a2asup.spec import REQUIREMENTS
from a2asup.target import Target

# Every operation in the SPEC 5.3 method mapping table that can be driven with no prior state.
# `send_message` creates; the rest address an id that will not exist, which is fine and is the
# point: an authorization check must fire BEFORE the resource is looked up (SPEC 13.1, "Authorization
# checks MUST occur before any database queries or operations that could leak information about the
# existence of resources outside the caller's authorization scope"), so a well-behaved server
# refuses these unauthenticated regardless of whether the id exists.
UNAUTHENTICATED_PROBES: list[tuple[str, dict]] = [
    ("send_message", {"message": {"role": "ROLE_USER", "parts": [{"text": "probe"}]}}),
    ("get_task", {"id": "a2asup-nonexistent"}),
    ("list_tasks", {}),
    ("cancel_task", {"id": "a2asup-nonexistent"}),
    ("list_push_configs", {"id": "a2asup-nonexistent"}),
    ("get_extended_card", {}),
]

# A syntactically well-formed bearer that no honest issuer produced. Three dots, base64url-ish
# segments: it is refused for being unverifiable, not for being unparseable, which is the
# distinction that makes the probe about the signature check rather than about the parser.
FORGED_BEARER = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJhMmFzdXAtZm9yZ2VkIiwiYXVkIjoiYTJhc3VwIn0"
    ".ZmFrZS1zaWduYXR1cmUtdGhhdC1uZXZlci12ZXJpZmllcw"
)


def _declared_schemes(card: dict) -> dict:
    """The card's declared authentication schemes.

    SPEC 8.5 spells the member `securitySchemes` and the requirement list `security`; the strict
    ProtoJSON schema generated alongside spells them `security_schemes` and `security_requirements`.
    That divergence is the subject of an existing busbar waiver (`testing/a2a-tck/WAIVERS.md`,
    CARD-EXT-001) and is NOT what these checks are about, so both spellings are accepted here.
    Refusing one spelling would make this check report on the naming dispute instead of on whether
    the agent authenticates anything.
    """
    for key in ("securitySchemes", "security_schemes"):
        value = card.get(key)
        if isinstance(value, dict) and value:
            return value
    return {}


def _security_requirements(card: dict) -> list:
    for key in ("security", "security_requirements"):
        value = card.get(key)
        if isinstance(value, list) and value:
            return value
    return []


def _admitted(reply) -> bool:
    """Was this call ADMITTED past the authentication boundary?

    Deliberately not `reply.ok`. An operation that authenticates the caller and then fails for a
    protocol reason -- an unknown task id, an unimplemented verb -- HAS admitted the caller, and
    counting that as a refusal would let an agent that authenticates nothing pass by answering
    every probe with an error. So a reply counts as refused ONLY when the binding's own code says
    unauthenticated or permission-denied.
    """
    code = reply.code
    if reply.ok:
        return True
    if code in {"UNAUTHENTICATED", "PERMISSION_DENIED"}:
        return False
    if code in {401, 403, "http-401", "http-403"}:
        return False
    if reply.http_status in {401, 403}:
        return False
    return True


def check_auth_server_002(target: Target) -> Result:
    """SPEC 7.4: 'The A2A Server ... MUST authenticate every incoming request based on the
    provided credentials and its declared authentication requirements.'"""
    req = REQUIREMENTS["AUTH-SERVER-002"]
    evidence: list[str] = []
    schemes = _declared_schemes(target.card)
    reqs = _security_requirements(target.card)
    evidence.append(f"card declares securitySchemes={short(sorted(schemes))} security={short(reqs)}")

    if not schemes:
        return Result(
            req.id,
            Verdict.FAIL,
            "the card declares NO authentication scheme, so no incoming request is authenticated "
            "against anything. See the reading in spec.py: the alternative interpretation makes "
            "this MUST unfailable.",
            evidence,
        )

    bindings = target.bindings()
    admitted_anon: list[str] = []
    admitted_forged: list[str] = []
    for name, binding in bindings.items():
        for op, params in UNAUTHENTICATED_PROBES:
            try:
                anon = binding.call(op, dict(params), token=None)
            except Exception as exc:  # noqa: BLE001
                # A PROBE THAT RAISED IS NOT A PROBE THAT PASSED. An earlier draft appended the
                # exception to the evidence and continued, and the check then reported PASS having
                # driven nothing -- the precise false green this suite exists to refuse. A raise is
                # now counted as an un-refused operation, which is the conservative direction.
                evidence.append(f"{name}/{op} anonymous RAISED {type(exc).__name__}: {exc}")
                admitted_anon.append(f"{name}/{op} (probe raised, so nothing was established)")
                continue
            evidence.append(f"{name}/{op} anonymous -> {anon!r}")
            if _admitted(anon):
                admitted_anon.append(f"{name}/{op}")
            try:
                forged = binding.call(op, dict(params), token=FORGED_BEARER)
            except Exception as exc:  # noqa: BLE001
                evidence.append(f"{name}/{op} forged RAISED {type(exc).__name__}: {exc}")
                admitted_forged.append(f"{name}/{op} (probe raised, so nothing was established)")
                continue
            evidence.append(f"{name}/{op} forged -> {forged!r}")
            if _admitted(forged):
                admitted_forged.append(f"{name}/{op}")

    if admitted_forged:
        return Result(
            req.id,
            Verdict.FAIL,
            f"a FORGED bearer was admitted on {len(admitted_forged)} operation(s): "
            f"{', '.join(admitted_forged)}. This half of the requirement is unambiguous under "
            f"either reading.",
            evidence,
        )
    if admitted_anon:
        return Result(
            req.id,
            Verdict.FAIL,
            f"an ANONYMOUS request was admitted on {len(admitted_anon)} operation(s): "
            f"{', '.join(admitted_anon)}, while the card declares "
            f"{sorted(schemes)}.",
            evidence,
        )
    return Result(
        req.id,
        Verdict.PASS,
        f"every one of {len(bindings) * len(UNAUTHENTICATED_PROBES)} probes "
        f"({len(bindings)} binding(s) x {len(UNAUTHENTICATED_PROBES)} operations) was refused "
        f"unauthenticated and refused again with a forged bearer, against a card declaring "
        f"{sorted(schemes)}.",
        evidence,
    )


def check_auth_scope_001(target: Target) -> Result:
    """SPEC 13.1: 'Servers MUST implement authorization checks on every A2A Protocol Operations
    request'."""
    req = REQUIREMENTS["AUTH-SCOPE-001"]
    evidence: list[str] = []
    if not target.token:
        return Result(
            req.id,
            Verdict.FAIL,
            "this target takes no credential at all, so there is no authenticated identity for an "
            "authorization check to be made against, on any operation.",
            evidence,
        )

    bindings = target.bindings()
    unchecked: list[str] = []
    for name, binding in bindings.items():
        for op, params in UNAUTHENTICATED_PROBES:
            try:
                anon = binding.call(op, dict(params), token=None)
            except Exception as exc:  # noqa: BLE001
                evidence.append(f"{name}/{op} raised {type(exc).__name__}: {exc}")
                unchecked.append(f"{name}/{op} (raised)")
                continue
            evidence.append(f"{name}/{op} anonymous -> {anon!r}")
            if _admitted(anon):
                unchecked.append(f"{name}/{op}")
    if unchecked:
        return Result(
            req.id,
            Verdict.FAIL,
            f"{len(unchecked)} operation(s) answered a request carrying no identity without "
            f"refusing it: {', '.join(unchecked)}. 'Every' in SPEC 13.1 is per-operation.",
            evidence,
        )
    return Result(
        req.id,
        Verdict.PASS,
        f"all {len(UNAUTHENTICATED_PROBES)} operations, on all {len(bindings)} declared "
        f"binding(s), applied an authorization check before answering.",
        evidence,
    )


def _open_a_task(binding, token: str, marker: str) -> tuple[str | None, object]:
    """Send one message and return whatever task id came back."""
    reply = binding.call(
        "send_message",
        {
            "message": {
                "role": "ROLE_USER",
                "parts": [{"text": f"a2a-supplement scope probe {marker}"}],
                "messageId": f"a2asup-scope-{marker}-{uuid.uuid4().hex[:12]}",
            }
        },
        token=token,
    )
    if not reply.ok:
        return None, reply
    payload = reply.payload if isinstance(reply.payload, dict) else {}
    task = payload.get("task") if isinstance(payload.get("task"), dict) else payload
    return (task or {}).get("id"), reply


def _task_ids_visible(binding, token: str) -> tuple[set[str], object]:
    reply = binding.call("list_tasks", {}, token=token)
    if not reply.ok:
        return set(), reply
    payload = reply.payload if isinstance(reply.payload, dict) else {}
    tasks = payload.get("tasks") or payload.get("items") or []
    ids = {t.get("id") for t in tasks if isinstance(t, dict) and t.get("id")}
    return ids, reply


def check_auth_scope_002(target: Target) -> Result:
    """SPEC 13.1: 'Implementations MUST scope results to the caller's authorized access boundaries
    ... List Tasks MUST only return tasks visible to the authenticated client'."""
    req = REQUIREMENTS["AUTH-SCOPE-002"]
    evidence: list[str] = []
    if not (target.token and target.token_b):
        return Result(
            req.id,
            Verdict.FAIL,
            "two distinct authenticated principals are required to decide this and this target "
            "supplied "
            f"{'one' if target.token else 'none'}. With a single identity an implementation that "
            "scopes perfectly and one that does not scope at all are observationally identical, "
            "so a one-identity run would be a test that cannot fail.",
            evidence,
        )
    bindings = target.bindings()
    binding = bindings.get("jsonrpc") or next(iter(bindings.values()))
    name = getattr(binding, "name", "?")

    task_a, reply_a = _open_a_task(binding, target.token, "a")
    evidence.append(f"{name} principal A send_message -> {reply_a!r} task={task_a}")
    if not task_a:
        return Result(
            req.id,
            Verdict.FAIL,
            "principal A could not open a task, so there is nothing whose visibility to principal "
            "B could be decided. Reported as a failure of the check's premise rather than "
            "skipped.",
            evidence,
        )

    visible_to_b, reply_b = _task_ids_visible(binding, target.token_b)
    evidence.append(f"{name} principal B list_tasks -> {reply_b!r}")
    evidence.append(f"{name} principal B sees task ids {short(sorted(visible_to_b))}")
    visible_to_a, reply_aa = _task_ids_visible(binding, target.token)
    evidence.append(f"{name} principal A sees task ids {short(sorted(visible_to_a))}")

    if not reply_b.ok and reply_b.code in {-32004, "UNIMPLEMENTED", 400, 404}:
        return Result(
            req.id,
            Verdict.NOT_APPLICABLE,
            f"the agent does not implement List Tasks ({reply_b!r}), which is the operation SPEC "
            f"13.1 names for this requirement. Nothing here is asserted about an operation the "
            f"agent does not have.",
            evidence,
        )
    if task_a in visible_to_b:
        return Result(
            req.id,
            Verdict.FAIL,
            f"principal B's unfiltered List Tasks returned principal A's task {task_a!r}. Under "
            f"every authorization model SPEC 13.1 lists, two distinct principals that no operator "
            f"placed in a shared boundary do not share task visibility.",
            evidence,
        )
    if task_a not in visible_to_a:
        return Result(
            req.id,
            Verdict.FAIL,
            f"principal A's own List Tasks did NOT return A's task {task_a!r}, so B's not seeing "
            f"it is not evidence of scoping -- an agent whose List Tasks returns nothing to "
            f"anybody would pass otherwise. The control half of this check failed.",
            evidence,
        )
    return Result(
        req.id,
        Verdict.PASS,
        f"principal A's task {task_a!r} is returned to A by an unfiltered List Tasks and is NOT "
        f"returned to a second, distinct authenticated principal B.",
        evidence,
    )


def check_auth_scope_003(target: Target) -> Result:
    """SPEC 3.3.2: 'Servers MUST NOT reveal the existence of resources the client is not authorized
    to access'."""
    req = REQUIREMENTS["AUTH-SCOPE-003"]
    evidence: list[str] = []
    if not (target.token and target.token_b):
        return Result(
            req.id,
            Verdict.FAIL,
            "deciding this needs a resource that exists for one principal and an id that exists "
            "for nobody, fetched by a second principal; this target supplied "
            f"{'one credential' if target.token else 'no credential'}.",
            evidence,
        )
    bindings = target.bindings()
    binding = bindings.get("jsonrpc") or next(iter(bindings.values()))
    name = getattr(binding, "name", "?")

    task_a, reply_a = _open_a_task(binding, target.token, "b")
    evidence.append(f"{name} principal A send_message -> {reply_a!r} task={task_a}")
    if not task_a:
        return Result(
            req.id,
            Verdict.FAIL,
            "principal A could not open a task, so there is no existing-but-unauthorized resource "
            "to ask about.",
            evidence,
        )

    absent_id = f"a2asup-absent-{uuid.uuid4().hex}"
    others = binding.call("get_task", {"id": task_a}, token=target.token_b)
    absent = binding.call("get_task", {"id": absent_id}, token=target.token_b)
    evidence.append(f"B get_task(A's task {task_a}) -> {others!r}")
    evidence.append(f"B get_task(absent id)        -> {absent!r}")

    if others.ok:
        return Result(
            req.id,
            Verdict.FAIL,
            f"principal B successfully READ principal A's task {task_a!r}. That is not merely "
            f"revealing its existence, it is disclosing its contents.",
            evidence,
        )
    if (others.code, others.http_status) != (absent.code, absent.http_status):
        return Result(
            req.id,
            Verdict.FAIL,
            f"a task that exists but belongs to another principal is answered "
            f"{others.code!r}/http {others.http_status} while an id that exists for nobody is "
            f"answered {absent.code!r}/http {absent.http_status}. The difference is exactly the "
            f"disclosure SPEC 3.3.2 forbids: a caller can distinguish 'not yours' from 'not "
            f"there'.",
            evidence,
        )
    if others.message != absent.message:
        return Result(
            req.id,
            Verdict.FAIL,
            f"the codes match but the messages differ -- {others.message!r} for the existing task "
            f"vs {absent.message!r} for the absent id -- which is the same disclosure by a "
            f"narrower channel.",
            evidence,
        )
    return Result(
        req.id,
        Verdict.PASS,
        f"principal B's read of an existing-but-unauthorized task is INDISTINGUISHABLE from its "
        f"read of an id that exists for nobody: both {others.code!r}, both {others.message!r}.",
        evidence,
    )


def check_auth_tls_001(target: Target) -> Result:
    """SPEC 7.1: 'Production deployments MUST use encrypted communication'."""
    req = REQUIREMENTS["AUTH-TLS-001"]
    scheme = target.card_url.split("://", 1)[0]
    return Result(
        req.id,
        Verdict.UNTESTABLE,
        "the requirement's subject is a PRODUCTION DEPLOYMENT, not a build or a running process. "
        "MECHANISM: what a conformance run can observe is the scheme of the endpoint it was "
        "pointed at, and that is a fact about the rig -- this run was pointed at a "
        f"`{scheme}://` loopback endpoint, as is every hermetic conformance rig including the "
        "official TCK's. Observing plaintext here says nothing about the operator's deployment, "
        "and observing TLS here would say nothing either. Deciding it needs an attestation about "
        "a deployed system (a TLS scan of the published endpoint, or an infrastructure policy "
        "check), which is a different instrument from a protocol conformance suite.",
        [f"card_url scheme = {scheme}", f"interfaces = {[i.url for i in target.interfaces]}"],
    )


def check_auth_intask_004(target: Target) -> Result:
    """SPEC 7.6.1: 'Agents MUST arrange to receive credentials via an out-of-band means'."""
    req = REQUIREMENTS["AUTH-INTASK-004"]
    return Result(
        req.id,
        Verdict.UNTESTABLE,
        "the requirement is about a channel that is BY DEFINITION not the A2A connection. "
        "MECHANISM: an observer of the A2A wire can establish that credentials did not arrive in "
        "band, but that observation does not distinguish a conformant agent (which received them "
        "elsewhere) from a broken one (which never received them at all) -- the distinguishing "
        "evidence lives on a channel the suite cannot see and whose shape the specification "
        "deliberately leaves open. Deciding it would require the agent to disclose its "
        "out-of-band arrangement over a protocol surface that does not exist.",
        [],
    )


# ── SPEC 7.6.1, in-task authorization ───────────────────────────────────────────────────────────
#
# THE FIXTURE, AND WHY THESE THREE NEED ONE. The other checks in this file provoke their own
# stimulus: an anonymous request, a forged bearer, a second principal. These three are about what
# an agent does when IT needs authorization, and no request a client can send makes that happen --
# the agent has to be the kind of agent that asks. So the subject rig's upstream agent
# (`testing/a2a-tck/scenario-agent`) grows one branch that parks a task in
# `TASK_STATE_AUTH_REQUIRED` with an explanation, and what these checks measure is whether the A2A
# SERVER UNDER TEST preserves the three observable consequences end to end.
#
# THAT IS A NARROWER CLAIM THAN THE REQUIREMENT, AND IT IS STATED RATHER THAN IMPLIED. For a
# gateway, "the agent" in SPEC 7.6.1 is the composition of the gateway and its upstream, and this
# establishes that the composition behaves correctly when the upstream asks. It does NOT establish
# that a gateway which itself needs authorization would ask correctly, because this gateway has no
# such path to drive.

AUTH_REQUIRED_PREFIX = "a2asup-auth-required"
# The states an implementation might spell `auth_required` as. The proto name is
# `TASK_STATE_AUTH_REQUIRED` (SPEC 4.1.4); the 0.3 JSON spelling is `auth-required`. Both are
# accepted because the requirement is about the STATE, not about which of the specification's own
# two spellings an implementation emits.
AUTH_REQUIRED_STATES = {
    "TASK_STATE_AUTH_REQUIRED",
    "auth-required",
    "AUTH_REQUIRED",
    "auth_required",
}


def _ask_for_authorization(target: Target) -> tuple[object, dict, str]:
    """One Send Message that makes the upstream agent require authorization."""
    bindings = target.bindings()
    binding = bindings.get("jsonrpc") or next(iter(bindings.values()))
    reply = binding.call(
        "send_message",
        {
            "message": {
                "role": "ROLE_USER",
                "parts": [{"text": "a2a-supplement in-task authorization probe"}],
                "messageId": f"{AUTH_REQUIRED_PREFIX}-{uuid.uuid4().hex[:12]}",
            }
        },
        token=target.token,
    )
    payload = reply.payload if isinstance(reply.payload, dict) else {}
    task = payload.get("task") if isinstance(payload.get("task"), dict) else None
    return reply, (task or {}), getattr(binding, "name", "?")


def _no_fixture(req, reply, name: str) -> Result:
    return Result(
        req.id,
        Verdict.NOT_APPLICABLE,
        "the upstream agent behind this target did not enter an authorization-required state when "
        "asked to, so there is no in-task authorization to observe. This check needs a subject "
        f"whose upstream implements the `{AUTH_REQUIRED_PREFIX}` fixture; a target without one is "
        "reported here rather than passed or failed, because neither verdict would be about the "
        "requirement.",
        [f"{name} send_message -> {reply!r}"],
    )


def check_auth_intask_001(target: Target) -> Result:
    """SPEC 7.6.1: 'the agent ... MUST use a Task to track the operation it is performing'."""
    req = REQUIREMENTS["AUTH-INTASK-001"]
    reply, task, name = _ask_for_authorization(target)
    evidence = [f"{name} send_message -> {reply!r}", f"task = {short(task, 700)}"]
    if not reply.ok:
        return _no_fixture(req, reply, name)
    if not task:
        return Result(
            req.id,
            Verdict.FAIL,
            "the agent answered a request that requires authorization with something that is not "
            "a Task -- a bare Message, or a document with no `task` member. SPEC 7.6.1 makes a "
            "Task mandatory for exactly this case, because a bare Message gives the client nothing "
            "to address a credential or a rejection to.",
            evidence,
        )
    if not task.get("id"):
        return Result(
            req.id,
            Verdict.FAIL,
            "a Task was returned but it carries no `id`, so nothing can be tracked by it and the "
            "client cannot address the authorization it is being asked for.",
            evidence,
        )
    return Result(
        req.id,
        Verdict.PASS,
        f"the operation requiring authorization is tracked by a Task, id {task['id']!r}, returned "
        f"through the {name} binding.",
        evidence,
    )


def check_auth_intask_002(target: Target) -> Result:
    """SPEC 7.6.1: 'the agent ... MUST transition the TaskState to TASK_STATE_AUTH_REQUIRED'."""
    req = REQUIREMENTS["AUTH-INTASK-002"]
    reply, task, name = _ask_for_authorization(target)
    evidence = [f"{name} send_message -> {reply!r}", f"task = {short(task, 700)}"]
    if not reply.ok or not task:
        return _no_fixture(req, reply, name)
    state = str((task.get("status") or {}).get("state") or task.get("state") or "")
    evidence.append(f"observed state = {state!r}")
    if state not in AUTH_REQUIRED_STATES:
        return Result(
            req.id,
            Verdict.FAIL,
            f"the upstream agent set the task to auth-required and the subject reported it as "
            f"{state!r}. A client cannot know it is being asked for a credential, so the "
            f"authorization request is lost.",
            evidence,
        )
    return Result(
        req.id,
        Verdict.PASS,
        f"the task requiring authorization is reported in state {state!r}, which is the state "
        f"SPEC 7.6.1 names.",
        evidence,
    )


def check_auth_intask_003(target: Target) -> Result:
    """SPEC 7.6.1: 'MUST include a TaskStatus message explaining the required authorization,
    unless the details ... have been negotiated out-of-band or via an extension'."""
    req = REQUIREMENTS["AUTH-INTASK-003"]
    reply, task, name = _ask_for_authorization(target)
    evidence = [f"{name} send_message -> {reply!r}", f"task = {short(task, 700)}"]
    if not reply.ok or not task:
        return _no_fixture(req, reply, name)
    status = task.get("status") or {}
    message = status.get("message") or {}
    parts = message.get("parts") or []
    text = " ".join(str(p.get("text", "")) for p in parts if isinstance(p, dict)).strip()
    evidence.append(f"status.message = {short(message, 500)}")
    # THE `unless` CLAUSE DOES NOT APPLY HERE and that is why this is a FAIL rather than a skip:
    # this suite negotiated nothing out of band and declared no extension, so the escape the
    # sentence offers is not available to the subject on this connection.
    if not message:
        return Result(
            req.id,
            Verdict.FAIL,
            "the task is in the authorization-required state and carries NO TaskStatus message. "
            "The client is told a credential is wanted and not told which one. The `unless` clause "
            "does not apply: this suite negotiated nothing out of band and declared no extension.",
            evidence,
        )
    if not text:
        return Result(
            req.id,
            Verdict.FAIL,
            f"a TaskStatus message is present but carries no text explaining the required "
            f"authorization: {short(message, 300)}",
            evidence,
        )
    return Result(
        req.id,
        Verdict.PASS,
        f"the authorization-required task carries a TaskStatus message explaining what is wanted "
        f"({len(text)} characters, first 80: {text[:80]!r}). The check asserts only that a "
        f"non-empty explanation survived end to end -- matching the fixture's exact wording would "
        f"be testing the fixture.",
        evidence,
    )
