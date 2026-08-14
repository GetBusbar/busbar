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
