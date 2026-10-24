# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""BIND-EQUIV-*: SPEC 5.1 functional equivalence across bindings.

A DIFFERENTIAL, not a checklist. The four requirements in section 5.1 are all of the form "the
same X across every binding", so the check drives one stimulus on every binding the card declares
and compares the answers to each other. Nothing here has an expected value baked in: the test has
no opinion about WHICH operations an agent implements or WHICH error text it uses, only that the
bindings agree. That is what keeps it from being a mirror -- there is nothing about busbar it could
have been copied from, because the assertion is a relation between the subject's own answers.

WHEN THE CARD DECLARES ONE BINDING the requirements are vacuous by their own first clause ("when
an agent supports multiple protocols"), and the verdict is NOT_APPLICABLE with the declared set
named. That is reported in its own column and is never counted as a pass.
"""

from __future__ import annotations

import uuid

from a2asup.model import Result, Verdict, short
from a2asup.spec import REQUIREMENTS
from a2asup.target import Target

# The eleven operations of the SPEC 5.3 method mapping table, minus the two streaming ones. The
# streaming pair is excluded DELIBERATELY and out loud: SSE and gRPC server-streaming answer with a
# sequence rather than a document, so "the same result" needs a different comparison, and the
# subject rig's SSE relay is a known-stalling component (see scripts/a2a-subject/binding-shim.mjs).
# Including them would measure the rig. What is lost is stated here rather than left implicit.
EQUIV_OPS: list[tuple[str, dict]] = [
    ("get_task", {"id": "PLACEHOLDER"}),
    ("list_tasks", {}),
    ("cancel_task", {"id": "PLACEHOLDER"}),
    ("create_push_config", {"id": "PLACEHOLDER"}),
    ("get_push_config", {"id": "PLACEHOLDER", "config_id": "a2asup-cfg"}),
    ("list_push_configs", {"id": "PLACEHOLDER"}),
    ("delete_push_config", {"id": "PLACEHOLDER", "config_id": "a2asup-cfg"}),
    ("get_extended_card", {}),
    ("send_message", {"message": {"role": "ROLE_USER", "parts": [{"text": "equiv"}]}}),
]

# EVERY PROBE IS WELL FORMED ON PURPOSE, and this note is here because the first draft was not.
#
# SPEC 5.4 maps UnsupportedOperationError to HTTP `400` for the REST binding, so a `400` is how a
# REST agent says "I do not have this operation" -- and it is ALSO how it says "your request was
# malformed". Those two are indistinguishable from outside. The first version of this check sent a
# Send Message with no `messageId`; the agent refused it as malformed on all three bindings, which
# JSON-RPC reported as `-32602` and gRPC as `INVALID_ARGUMENT` (both unambiguous) and REST as `400`
# (ambiguous). The check read the REST `400` as "not implemented", reported a divergence between
# the bindings, and the divergence was ENTIRELY ITS OWN -- all three bindings had in fact behaved
# identically.
#
# The fix is not to loosen the classification, which would let a genuinely missing REST operation
# through. It is to make every probe a request no correct agent can reject as malformed, so that an
# implemented operation answers either success or a resource error and the `400` is left meaning
# what SPEC 5.4 says it means.

# SPEC 5.4's canonical mapping for UnsupportedOperationError, per binding. An operation the agent
# does not implement answers with THIS; anything else means the operation exists.
#
# NOTE WHAT IS NOT IN THE REST SET, because an earlier draft got it wrong in a way that inverted
# the verdict: `404` is NOT here. SPEC 5.4 maps UnsupportedOperationError to `400 Bad Request` for
# HTTP and TaskNotFoundError to `404`, so counting 404 as "not implemented" made every REST
# operation that correctly reported an absent task look absent ITSELF -- and the check then
# reported a divergence that was entirely its own. `405` and `501` are retained because an
# unrouted verb and an explicit not-implemented are both unambiguous.
NOT_IMPLEMENTED = {
    "jsonrpc": {-32004, -32601},
    "http_json": {400, 405, 501},
    "grpc": {"UNIMPLEMENTED"},
}

# SPEC 5.4, the TaskNotFoundError row: JSON-RPC -32001 / gRPC NOT_FOUND / HTTP 404.
TASK_NOT_FOUND = {"jsonrpc": -32001, "http_json": 404, "grpc": "NOT_FOUND"}


def _multi(target: Target) -> tuple[dict, list[str]]:
    bindings = target.bindings()
    return bindings, sorted(bindings)


def _not_applicable(req_id: str, names: list[str]) -> Result:
    return Result(
        req_id,
        Verdict.NOT_APPLICABLE,
        f"SPEC 5.1 is conditioned on 'when an agent supports multiple protocols'; this card "
        f"declares {names or 'none'}. Reported in its own column and NOT counted as a pass.",
        [f"declared bindings = {names}"],
    )


def check_bind_equiv_001(target: Target) -> Result:
    """SPEC 5.1: 'Identical Functionality: Provide the same set of operations and capabilities'."""
    req = REQUIREMENTS["BIND-EQUIV-001"]
    bindings, names = _multi(target)
    if len(bindings) < 2:
        return _not_applicable(req.id, names)

    evidence: list[str] = []
    implemented: dict[str, set[str]] = {}
    raised: list[str] = []
    for name, binding in bindings.items():
        found: set[str] = set()
        for op, params in EQUIV_OPS:
            probe = dict(params)
            if probe.get("id") == "PLACEHOLDER":
                probe["id"] = f"a2asup-{uuid.uuid4().hex[:10]}"
            if op == "create_push_config":
                probe["config"] = {
                    "pushNotificationConfig": {"url": "https://a2asup.invalid/hook"}
                }
            if op == "send_message":
                probe = {
                    "message": {
                        "role": "ROLE_USER",
                        "parts": [{"text": "a2a-supplement operation-set probe"}],
                        "messageId": f"a2asup-opset-{uuid.uuid4().hex[:12]}",
                    }
                }
            try:
                reply = binding.call(op, probe, token=target.token)
            except Exception as exc:  # noqa: BLE001
                # NOT a `continue` that quietly shrinks the comparison. A probe that raised
                # established nothing, and an operation silently dropped from one binding's set is
                # exactly how a divergence disappears from a differential.
                evidence.append(f"{name}/{op} RAISED {type(exc).__name__}: {exc}")
                raised.append(f"{name}/{op}: {type(exc).__name__}: {exc}")
                continue
            evidence.append(f"{name}/{op} -> {reply!r}")
            if reply.ok or reply.code not in NOT_IMPLEMENTED[name]:
                found.add(op)
        implemented[name] = found

    if raised:
        return Result(
            req.id,
            Verdict.ERROR,
            f"{len(raised)} probe(s) raised, so the sets being compared are incomplete and any "
            f"verdict from them would be about the suite rather than the subject: "
            + "; ".join(raised[:6]),
            evidence,
        )
    baseline_name = names[0]
    baseline = implemented[baseline_name]
    divergent = {n: s for n, s in implemented.items() if s != baseline}
    if divergent:
        lines = [f"{n}: {sorted(s)}" for n, s in sorted(implemented.items())]
        return Result(
            req.id,
            Verdict.FAIL,
            "the set of implemented operations is not identical across the declared bindings: "
            + "; ".join(lines),
            evidence,
        )
    return Result(
        req.id,
        Verdict.PASS,
        f"all {len(bindings)} declared bindings ({', '.join(names)}) implement the identical set "
        f"of {len(baseline)} operations out of the {len(EQUIV_OPS)} probed: {sorted(baseline)}.",
        evidence,
    )


def _normalise_task(doc: object) -> object:
    """Strip the members that MUST differ between two calls, and nothing else.

    Server-assigned identifiers and timestamps are necessarily different for two separate
    submissions, so comparing them would make the check fail for every conformant agent. Everything
    else is retained -- including the state, the role, the part kinds and the text -- because that
    is the semantic content SPEC 5.1 requires to be equivalent.
    """
    volatile = {
        "id",
        "taskId",
        "task_id",
        "contextId",
        "context_id",
        "messageId",
        "message_id",
        "artifactId",
        "artifact_id",
        "timestamp",
        "createTime",
        "create_time",
        "updateTime",
        "update_time",
        "lastUpdated",
        "name",
    }
    if isinstance(doc, dict):
        return {k: _normalise_task(v) for k, v in sorted(doc.items()) if k not in volatile}
    if isinstance(doc, list):
        return [_normalise_task(v) for v in doc]
    return doc


def _mask(doc: object, message_id: str) -> object:
    """Replace one caller-chosen identifier wherever it appears in a string value.

    Not a general scrubber: it masks exactly the id THIS suite sent on THIS binding, and nothing
    else. An agent that echoes the caller's message id in its reply is behaving identically on
    every binding; the difference in the echoed text is one the suite introduced by having to send
    three distinct ids, and masking it is how the comparison stays about the agent.
    """
    if isinstance(doc, dict):
        return {k: _mask(v, message_id) for k, v in doc.items()}
    if isinstance(doc, list):
        return [_mask(v, message_id) for v in doc]
    if isinstance(doc, str) and message_id in doc:
        return doc.replace(message_id, "<the message id this suite sent>")
    return doc


def _shape(doc: object, depth: int = 0) -> object:
    """The structure alone: keys and value KINDS, no values. Used when the values legitimately
    differ (two different messages produce two different texts) but the shape must not."""
    if isinstance(doc, dict):
        return {k: _shape(v, depth + 1) for k, v in sorted(doc.items())}
    if isinstance(doc, list):
        return [_shape(doc[0], depth + 1)] if doc else []
    return type(doc).__name__


def check_bind_equiv_002(target: Target) -> Result:
    """SPEC 5.1: 'Consistent Behavior: Return semantically equivalent results for the same
    requests'."""
    req = REQUIREMENTS["BIND-EQUIV-002"]
    bindings, names = _multi(target)
    if len(bindings) < 2:
        return _not_applicable(req.id, names)

    evidence: list[str] = []
    sent_ids: dict[str, str] = {}
    # ONE request document, sent verbatim on every binding. SPEC 11.4 makes the REST body
    # structurally equivalent to the JSON-RPC `params`, which is what makes "the same request"
    # a meaningful phrase across these bindings at all.
    text = f"a2a-supplement equivalence probe {uuid.uuid4().hex[:8]}"
    normalised: dict[str, object] = {}
    shapes: dict[str, object] = {}
    for name, binding in bindings.items():
        # A DISTINCT messageId PER BINDING, because SPEC 4.2 makes it the message's identity and
        # reusing one across three submissions would be three different requests wearing one id.
        # The consequence is handled rather than ignored: an agent may legitimately ECHO the id
        # back in its own text, so `_mask` below replaces it with a fixed token before the
        # comparison. Comparing the raw text would report a divergence this suite created.
        message_id = f"a2asup-equiv-{uuid.uuid4().hex[:12]}"
        sent_ids[name] = message_id
        params = {
            "message": {
                "role": "ROLE_USER",
                "parts": [{"text": text}],
                "messageId": message_id,
            }
        }
        try:
            reply = binding.call("send_message", params, token=target.token)
        except Exception as exc:  # noqa: BLE001
            return Result(
                req.id,
                Verdict.FAIL,
                f"the {name} binding raised {type(exc).__name__} on a Send Message that the other "
                f"bindings answered: {exc}",
                evidence,
            )
        evidence.append(f"{name} send_message -> {short(reply.payload, 700)}")
        if not reply.ok:
            evidence.append(f"{name} send_message error {reply!r}")
        normalised[name] = _normalise_task(_mask(reply.payload, sent_ids[name]))
        shapes[name] = _shape(reply.payload)

    baseline = names[0]
    differing_shape = [n for n in names if shapes[n] != shapes[baseline]]
    if differing_shape:
        lines = [f"{n}: {short(shapes[n], 500)}" for n in names]
        return Result(
            req.id,
            Verdict.FAIL,
            f"the same Send Message produced structurally different results on "
            f"{', '.join(differing_shape)} than on {baseline}: " + " || ".join(lines),
            evidence,
        )
    differing_value = [n for n in names if normalised[n] != normalised[baseline]]
    if differing_value:
        lines = [f"{n}: {short(normalised[n], 500)}" for n in names]
        return Result(
            req.id,
            Verdict.FAIL,
            f"the same Send Message produced the same structure but different semantic content on "
            f"{', '.join(differing_value)} than on {baseline}: " + " || ".join(lines),
            evidence,
        )
    return Result(
        req.id,
        Verdict.PASS,
        f"one Send Message document, sent verbatim on {len(bindings)} bindings "
        f"({', '.join(names)}), produced results that agree on structure AND on every member "
        f"except the server-assigned ids and timestamps that necessarily differ.",
        evidence,
    )


def check_bind_equiv_003(target: Target) -> Result:
    """SPEC 5.1: 'Same Error Handling: Map errors consistently using appropriate protocol-specific
    codes', read against the canonical mapping table of SPEC 5.4."""
    req = REQUIREMENTS["BIND-EQUIV-003"]
    bindings, names = _multi(target)
    if len(bindings) < 2:
        return _not_applicable(req.id, names)

    evidence: list[str] = []
    absent = f"a2asup-absent-{uuid.uuid4().hex}"
    wrong: list[str] = []
    for name, binding in bindings.items():
        try:
            reply = binding.call("get_task", {"id": absent}, token=target.token)
        except Exception as exc:  # noqa: BLE001
            return Result(
                req.id,
                Verdict.FAIL,
                f"the {name} binding raised {type(exc).__name__} on Get Task for an absent id: "
                f"{exc}",
                evidence,
            )
        evidence.append(f"{name} get_task(absent) -> {reply!r}")
        expected = TASK_NOT_FOUND[name]
        if reply.ok:
            wrong.append(f"{name} SUCCEEDED for an id that does not exist")
        elif reply.code != expected:
            wrong.append(f"{name} answered {reply.code!r}, SPEC 5.4 maps TaskNotFoundError to {expected!r}")
    if wrong:
        return Result(
            req.id,
            Verdict.FAIL,
            "one provoked TaskNotFoundError is not mapped per the SPEC 5.4 table on every "
            "binding: " + "; ".join(wrong),
            evidence,
        )
    return Result(
        req.id,
        Verdict.PASS,
        f"one provoked TaskNotFoundError maps to the SPEC 5.4 canonical code on every declared "
        f"binding: " + ", ".join(f"{n}={TASK_NOT_FOUND[n]!r}" for n in names),
        evidence,
    )


def check_bind_equiv_004(target: Target) -> Result:
    """SPEC 5.1: 'Equivalent Authentication: Support the same authentication schemes declared in
    the AgentCard'."""
    req = REQUIREMENTS["BIND-EQUIV-004"]
    bindings, names = _multi(target)
    if len(bindings) < 2:
        return _not_applicable(req.id, names)

    evidence: list[str] = []
    # (a) The DECLARATION. SPEC 4.4 puts securitySchemes on the card, once, for the agent -- so a
    # per-interface security declaration that differs between interfaces is a divergence on its
    # face, before any request is made.
    per_interface = {
        f"{i.binding}@{i.version} {i.url}": sorted(i.__dict__.get("securitySchemes") or {})
        for i in target.interfaces
    }
    evidence.append(f"per-interface security declarations = {short(per_interface)}")

    # (b) The ENFORCEMENT, which is what makes (a) more than a documentation check. The same three
    # credentials on every binding must be sorted the same way.
    from a2asup.checks_auth import FORGED_BEARER, _admitted  # noqa: PLC0415

    verdicts: dict[str, tuple[bool, bool, bool]] = {}
    for name, binding in bindings.items():
        probe = {"message": {"role": "ROLE_USER", "parts": [{"text": "auth equivalence"}]}}
        try:
            anon = _admitted(binding.call("send_message", dict(probe), token=None))
            forged = _admitted(binding.call("send_message", dict(probe), token=FORGED_BEARER))
            good = (
                _admitted(binding.call("send_message", dict(probe), token=target.token))
                if target.token
                else None
            )
        except Exception as exc:  # noqa: BLE001
            return Result(
                req.id,
                Verdict.FAIL,
                f"the {name} binding raised {type(exc).__name__} while being probed with three "
                f"credentials the other bindings answered: {exc}",
                evidence,
            )
        verdicts[name] = (anon, forged, good)
        evidence.append(
            f"{name}: anonymous admitted={anon}, forged admitted={forged}, real admitted={good}"
        )

    baseline = names[0]
    divergent = [n for n in names if verdicts[n] != verdicts[baseline]]
    if divergent:
        return Result(
            req.id,
            Verdict.FAIL,
            f"the same three credentials are sorted differently by different bindings "
            f"({', '.join(divergent)} disagree with {baseline}): "
            + "; ".join(f"{n}={verdicts[n]}" for n in names),
            evidence,
        )
    if target.token and verdicts[baseline][2] is False:
        return Result(
            req.id,
            Verdict.FAIL,
            "every binding agrees, but they agree by refusing the REAL credential too -- so the "
            "agreement is not evidence that the declared scheme is supported anywhere.",
            evidence,
        )
    return Result(
        req.id,
        Verdict.PASS,
        f"all {len(bindings)} declared bindings ({', '.join(names)}) sort the same three "
        f"credentials identically: anonymous refused, forged refused, the real credential "
        f"admitted.",
        evidence,
    )
