#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""PROVE EVERY CHECK BITES, by making it fail on purpose.

WHY THIS FILE IS NOT OPTIONAL, and it is the honest answer to a gap rather than a decoration.

The controls in `run-supplement.sh` establish that a check has a failure mode by pointing it at an
implementation nobody here wrote. That works for the `AUTH-*` and `VER-SERVER-*` families, where
`a2a-go` and `a2a-python` fail checks busbar passes. It does NOT work for three families, and
saying so is more useful than pretending otherwise:

    BIND-EQUIV-*    every available control serves exactly ONE binding, so the requirement is
                    vacuous against them by its own first clause and the checks report
                    NOT_APPLICABLE. A third-party agent serving three bindings would be the right
                    control; there isn't one to hand.
    CARD-SIGN-*     no available control signs its agent card at all, so the checks report
                    NOT_APPLICABLE. Signing is MAY in SPEC 8.4 and almost nobody does it.
    VER-CLIENT-001  a requirement on the CLIENT role. No control here is a gateway, so no control
                    originates an upstream A2A request to observe.

For those, a control run says nothing, and a check that has never been observed to fail is a check
nobody should believe. So this file supplies the missing evidence the only other way there is:
MUTATION. It builds a subject that is deliberately wrong in exactly the way each requirement
forbids, runs the real check against it, and FAILS THE SELFTEST IF THE CHECK PASSES.

A green here means every mutation was caught. A red here means a check is asleep, and no verdict
from the suite should be believed until it is fixed.

    python3 selftest.py          (needs the pinned TCK's interpreter only for `cryptography`;
                                  run it the way run-supplement.sh runs the suite)
"""

from __future__ import annotations

import base64
import copy
import json
import sys

from a2asup import checks_auth, checks_bind, checks_card, checks_ver
from a2asup.model import Verdict
from a2asup.target import Interface, Target
from a2asup.transport import Reply

FAILURES: list[str] = []
# How many expectations HELD. Counted rather than inferred, so `main`'s floor can tell a green run
# from a run in which the cases were deleted -- a selftest that discovered nothing is not a pass.
PASSES_SEEN = [0]


def expect(label: str, result, allowed: set[Verdict]) -> None:
    ok = result.verdict in allowed
    mark = "ok " if ok else "MISS"
    print(f"  {mark}  {label}")
    print(f"        -> {result.verdict.value}: {result.summary[:150]}")
    if ok:
        PASSES_SEEN[0] += 1
    if not ok:
        FAILURES.append(
            f"{label}: the check answered {result.verdict.value}, but this subject is "
            f"deliberately wrong and one of {sorted(v.value for v in allowed)} was required. "
            f"The check did not bite."
        )


# ── card signing ────────────────────────────────────────────────────────────────────────────────


def _sign(payload_text: str, header: dict, private_key) -> dict:
    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    protected = b64(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    signing_input = (protected + "." + b64(payload_text.encode())).encode("ascii")
    return {"protected": protected, "signature": b64(private_key.sign(signing_input))}


def card_signing_mutations() -> None:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from a2asup.checks_card import canonicalize

    private = ed25519.Ed25519PrivateKey.generate()
    issuer_key = base64.b64encode(
        private.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    ).decode("ascii")

    base_card = {
        "name": "selftest agent",
        "description": "",
        "version": "1.0.0",
        "zzz_last_key_by_sort_order": {"b": 2, "a": 1},
        "supportedInterfaces": [
            {"url": "http://127.0.0.1:1/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}
        ],
        "skills": [],
    }

    def target_with(card: dict) -> Target:
        t = Target(label="selftest", card_url="http://selftest.invalid/card")
        t.card = card
        t.interfaces = Target._read_interfaces(card)
        return t

    print("\nCARD-SIGN-001 -- a card signed over a NON-canonical serialisation")
    bad = copy.deepcopy(base_card)
    # json.dumps with keys in INSERTION order is a perfectly good JSON document and is not RFC 8785.
    noncanonical = json.dumps(bad, separators=(",", ":"))
    bad["signatures"] = [_sign(noncanonical, {"alg": "EdDSA", "kid": "k"}, private)]
    expect(
        "a signature over a non-canonical payload must NOT be read as canonicalized",
        checks_card.check_card_sign_001(target_with(bad), issuer_key),
        {Verdict.FAIL},
    )

    print("\nCARD-SIGN-001 -- the honest case, so the mutation above is not passed by a check that")
    print("                 fails everything")
    good = copy.deepcopy(base_card)
    good["signatures"] = [_sign(canonicalize(base_card), {"alg": "EdDSA", "kid": "k"}, private)]
    expect(
        "POSITIVE CONTROL: a correctly canonicalized signature must PASS",
        checks_card.check_card_sign_001(target_with(good), issuer_key),
        {Verdict.PASS},
    )

    print("\nCARD-SIGN-002 -- a card whose signature covers the `signatures` member itself")
    circular = copy.deepcopy(base_card)
    placeholder = _sign(canonicalize(base_card), {"alg": "EdDSA", "kid": "k"}, private)
    circular["signatures"] = [placeholder]
    # Re-sign over the document WITH `signatures` present, which is the circular dependency
    # SPEC 8.4.1 forbids.
    circular["signatures"] = [_sign(canonicalize(circular), {"alg": "EdDSA", "kid": "k"}, private)]
    expect(
        "a signature that covers `signatures` must NOT be read as excluding it",
        checks_card.check_card_sign_002(target_with(circular), issuer_key),
        {Verdict.FAIL},
    )
    expect(
        "POSITIVE CONTROL: an exclusion-correct signature must PASS",
        checks_card.check_card_sign_002(target_with(good), issuer_key),
        {Verdict.PASS},
    )

    print("\nCARD-SIGN-003 -- protected headers missing a REQUIRED member")
    for missing, header in (
        ("kid", {"alg": "EdDSA"}),
        ("alg", {"kid": "k"}),
        ("alg is 'none'", {"alg": "none", "kid": "k"}),
    ):
        mutated = copy.deepcopy(base_card)
        mutated["signatures"] = [_sign(canonicalize(base_card), header, private)]
        expect(
            f"a protected header with {missing} must FAIL",
            checks_card.check_card_sign_003(target_with(mutated)),
            {Verdict.FAIL},
        )
    expect(
        "POSITIVE CONTROL: alg + kid present must PASS",
        checks_card.check_card_sign_003(target_with(good)),
        {Verdict.PASS},
    )


# ── binding equivalence ─────────────────────────────────────────────────────────────────────────


class FakeBinding:
    """A binding whose every answer is dictated by the selftest.

    Not a mock of busbar: it has no busbar behaviour in it at all. It exists so that a DIVERGENCE
    between two bindings can be constructed, which is the only condition the BIND-EQUIV checks are
    written to detect and the one no available control can produce.
    """

    def __init__(self, name: str, answers: dict) -> None:
        self.name = name
        self.answers = answers

    def call(self, op, params=None, *, token=None, version="1.0", extra_headers=None, **_):
        key = (op, "anon" if token is None else "token")
        if key in self.answers:
            return self.answers[key]
        return self.answers.get(op, Reply(ok=True, payload={"task": {"id": "x"}}, http_status=200))


def _two_binding_target(bindings: dict) -> Target:
    card = {
        "securitySchemes": {"s": {"type": "http"}},
        "supportedInterfaces": [
            {"url": "http://a/", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"},
            {"url": "http://b/", "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"},
        ],
    }
    t = Target(label="selftest", card_url="http://selftest.invalid/card", token="tok")
    t.card = card
    t.interfaces = [
        Interface("http://a/", "jsonrpc", "1.0"),
        Interface("http://b/", "http_json", "1.0"),
    ]
    t.bindings = lambda: bindings  # type: ignore[method-assign]
    return t


def binding_equivalence_mutations() -> None:
    ok_task = Reply(ok=True, payload={"task": {"status": {"state": "COMPLETED"}}}, http_status=200)

    print("\nBIND-EQUIV-001 -- one binding implements an operation the other does not")
    unequal = _two_binding_target(
        {
            "jsonrpc": FakeBinding("jsonrpc", {"cancel_task": ok_task}),
            "http_json": FakeBinding(
                "http_json", {"cancel_task": Reply(ok=False, code=400, http_status=400)}
            ),
        }
    )
    expect(
        "an operation present on one binding and absent on another must FAIL",
        checks_bind.check_bind_equiv_001(unequal),
        {Verdict.FAIL},
    )
    equal = _two_binding_target(
        {"jsonrpc": FakeBinding("jsonrpc", {}), "http_json": FakeBinding("http_json", {})}
    )
    expect(
        "POSITIVE CONTROL: identical operation sets must PASS",
        checks_bind.check_bind_equiv_001(equal),
        {Verdict.PASS},
    )

    print("\nBIND-EQUIV-002 -- the same request answered with different semantic content")
    diverging = _two_binding_target(
        {
            "jsonrpc": FakeBinding(
                "jsonrpc",
                {"send_message": Reply(ok=True, payload={"task": {"state": "COMPLETED"}})},
            ),
            "http_json": FakeBinding(
                "http_json",
                {"send_message": Reply(ok=True, payload={"task": {"state": "FAILED"}})},
            ),
        }
    )
    expect(
        "the same request answered COMPLETED on one binding and FAILED on another must FAIL",
        checks_bind.check_bind_equiv_002(diverging),
        {Verdict.FAIL},
    )

    print("\nBIND-EQUIV-003 -- an error mapped outside the SPEC 5.4 table")
    miscoded = _two_binding_target(
        {
            "jsonrpc": FakeBinding(
                "jsonrpc", {"get_task": Reply(ok=False, code=-32001, http_status=404)}
            ),
            "http_json": FakeBinding(
                "http_json", {"get_task": Reply(ok=False, code=500, http_status=500)}
            ),
        }
    )
    expect(
        "TaskNotFoundError answered 500 on the REST binding must FAIL",
        checks_bind.check_bind_equiv_003(miscoded),
        {Verdict.FAIL},
    )
    correct = _two_binding_target(
        {
            "jsonrpc": FakeBinding(
                "jsonrpc", {"get_task": Reply(ok=False, code=-32001, http_status=404)}
            ),
            "http_json": FakeBinding(
                "http_json", {"get_task": Reply(ok=False, code=404, http_status=404)}
            ),
        }
    )
    expect(
        "POSITIVE CONTROL: the SPEC 5.4 codes on both bindings must PASS",
        checks_bind.check_bind_equiv_003(correct),
        {Verdict.PASS},
    )

    print("\nBIND-EQUIV-004 -- one binding enforces the declared scheme and the other does not")
    refused = Reply(ok=False, code=401, http_status=401)
    lopsided = _two_binding_target(
        {
            "jsonrpc": FakeBinding(
                "jsonrpc",
                {
                    ("send_message", "anon"): refused,
                    ("send_message", "token"): ok_task,
                },
            ),
            "http_json": FakeBinding(
                "http_json",
                {
                    ("send_message", "anon"): ok_task,  # admits anonymous. The bug.
                    ("send_message", "token"): ok_task,
                },
            ),
        }
    )
    expect(
        "a binding that admits anonymous where its sibling refuses must FAIL",
        checks_bind.check_bind_equiv_004(lopsided),
        {Verdict.FAIL},
    )


# ── versioning ──────────────────────────────────────────────────────────────────────────────────


def versioning_mutations() -> None:
    print("\nVER-SERVER-001 -- an agent that answers every method name regardless of version")
    ok = Reply(ok=True, payload={"task": {"id": "x"}}, http_status=200)
    ignores = Target(label="selftest", card_url="http://selftest.invalid/card", token="t")
    ignores.card = {}
    ignores.interfaces = [Interface("http://a/", "jsonrpc", "1.0")]
    ignores.bindings = lambda: {"jsonrpc": FakeBinding("jsonrpc", {})}  # type: ignore[method-assign]
    expect(
        "an agent that answers 0.3's method names while 1.0 was requested must FAIL",
        checks_ver.check_ver_server_001(ignores),
        {Verdict.FAIL},
    )

    print("\nVER-CLIENT-002 -- an agent that refuses a patch-numbered version")
    picky = Target(label="selftest", card_url="http://selftest.invalid/card", token="t")
    picky.card = {}
    picky.interfaces = [Interface("http://a/", "jsonrpc", "1.0")]
    picky.bindings = lambda: {  # type: ignore[method-assign]
        "jsonrpc": _PatchRefusing()
    }
    expect(
        "VersionNotSupportedError for `1.0.7` where `1.0` is accepted must FAIL",
        checks_ver.check_ver_client_002(picky),
        {Verdict.FAIL},
    )

    print("\nVER-CLIENT-001 -- an upstream recording in which a request carries no version")
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as handle:
        handle.write(json.dumps({"method": "POST", "path": "/a2a", "headers": {"host": "x"}}) + "\n")
        path = handle.name
    silent = Target(
        label="selftest", card_url="http://selftest.invalid/card", upstream_record=path
    )
    silent.card = {}
    silent.interfaces = [Interface("http://a/", "jsonrpc", "1.0")]
    expect(
        "an originated request with no A2A-Version header or parameter must FAIL",
        checks_ver.check_ver_client_001(silent),
        {Verdict.FAIL},
    )

    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as handle:
        handle.write(
            json.dumps({"method": "POST", "path": "/a2a", "headers": {"A2A-Version": "1.0"}}) + "\n"
        )
        path = handle.name
    speaking = Target(
        label="selftest", card_url="http://selftest.invalid/card", upstream_record=path
    )
    speaking.card = {}
    speaking.interfaces = [Interface("http://a/", "jsonrpc", "1.0")]
    expect(
        "POSITIVE CONTROL: a recording in which every request carries it must PASS",
        checks_ver.check_ver_client_001(speaking),
        {Verdict.PASS},
    )

    print("\nVER-CLIENT-001 -- an EMPTY recording must not be read as compliance")
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as handle:
        path = handle.name
    empty = Target(label="selftest", card_url="http://selftest.invalid/card", upstream_record=path)
    empty.card = {}
    empty.interfaces = [Interface("http://a/", "jsonrpc", "1.0")]
    expect(
        "no observed request at all must FAIL, not pass vacuously",
        checks_ver.check_ver_client_001(empty),
        {Verdict.FAIL},
    )


class _PatchRefusing:
    """Accepts `1.0`, answers VersionNotSupportedError for `1.0.7`."""

    name = "jsonrpc"

    def call(self, op, params=None, *, token=None, version="1.0", **_):
        if version and version.count(".") > 1:
            return Reply(ok=False, code=-32009, message="VersionNotSupportedError", http_status=400)
        return Reply(ok=True, payload={"task": {"id": "x"}}, http_status=200)


def in_task_authorization_mutations() -> None:
    """The three SPEC 7.6.1 checks, made to fail.

    A control DOES decide these -- `run-supplement.sh control-scenario` drives the fixture
    directly, with no gateway in the path -- but a control that passes only shows the checks accept
    a correct subject. These mutations show they reject an incorrect one, which is the half a
    passing control never establishes.
    """
    def target_answering(payload) -> Target:
        t = Target(label="selftest", card_url="http://selftest.invalid/card", token="tok")
        t.card = {}
        t.interfaces = [Interface("http://a/", "jsonrpc", "1.0")]
        t.bindings = lambda: {  # type: ignore[method-assign]
            "jsonrpc": FakeBinding(
                "jsonrpc", {"send_message": Reply(ok=True, payload=payload, http_status=200)}
            )
        }
        return t

    print("\nAUTH-INTASK-001 -- an authorization request answered with a bare Message")
    expect(
        "no Task where SPEC 7.6.1 requires one must FAIL",
        checks_auth.check_auth_intask_001(
            target_answering({"message": {"role": "ROLE_AGENT", "parts": [{"text": "auth?"}]}})
        ),
        {Verdict.FAIL},
    )

    print("\nAUTH-INTASK-002 -- the task is returned in the wrong state")
    expect(
        "a task reported COMPLETED rather than auth-required must FAIL",
        checks_auth.check_auth_intask_002(
            target_answering(
                {"task": {"id": "t1", "status": {"state": "TASK_STATE_COMPLETED"}}}
            )
        ),
        {Verdict.FAIL},
    )
    expect(
        "POSITIVE CONTROL: the auth-required state must PASS",
        checks_auth.check_auth_intask_002(
            target_answering(
                {"task": {"id": "t1", "status": {"state": "TASK_STATE_AUTH_REQUIRED"}}}
            )
        ),
        {Verdict.PASS},
    )

    print("\nAUTH-INTASK-003 -- auth-required with no explanation")
    expect(
        "no TaskStatus message at all must FAIL",
        checks_auth.check_auth_intask_003(
            target_answering(
                {"task": {"id": "t1", "status": {"state": "TASK_STATE_AUTH_REQUIRED"}}}
            )
        ),
        {Verdict.FAIL},
    )
    expect(
        "a TaskStatus message with empty text must FAIL",
        checks_auth.check_auth_intask_003(
            target_answering(
                {
                    "task": {
                        "id": "t1",
                        "status": {
                            "state": "TASK_STATE_AUTH_REQUIRED",
                            "message": {"role": "ROLE_AGENT", "parts": [{"text": "  "}]},
                        },
                    }
                }
            )
        ),
        {Verdict.FAIL},
    )
    expect(
        "POSITIVE CONTROL: an explanation must PASS",
        checks_auth.check_auth_intask_003(
            target_answering(
                {
                    "task": {
                        "id": "t1",
                        "status": {
                            "state": "TASK_STATE_AUTH_REQUIRED",
                            "message": {
                                "role": "ROLE_AGENT",
                                "parts": [{"text": "an OAuth token for the downstream API"}],
                            },
                        },
                    }
                }
            )
        ),
        {Verdict.PASS},
    )


# ── the runner's own floors ─────────────────────────────────────────────────────────────────────


def expect_code(label: str, got: int, want: int, why: str) -> None:
    ok = got == want
    print(f"  {'ok ' if ok else 'MISS'}  {label}")
    print(f"        -> exit {got} (wanted {want})")
    if ok:
        PASSES_SEEN[0] += 1
    if not ok:
        FAILURES.append(f"{label}: report() exited {got}, wanted {want}. {why}")


def runner_floor_mutations() -> None:
    """The two ways a run can establish NOTHING and still exit 0.

    `report()` used to end `return 1 if bad else 0`, where `bad` is FAIL|ERROR only. Neither of the
    mutations below produces a FAIL or an ERROR, so both were green. They are the supplement's own
    version of the vacuous pass the rest of this file exists to refuse, one level up: not a check
    that failed to bite, but a SUITE that reported on fewer requirements than it declares, or on
    none at all.
    """
    import io  # noqa: PLC0415
    import contextlib  # noqa: PLC0415

    from a2asup.model import Result  # noqa: PLC0415
    from a2asup.runner import report  # noqa: PLC0415
    from a2asup.spec import REQUIREMENTS  # noqa: PLC0415

    target = Target(label="selftest", card_url="http://selftest.invalid/card")
    target.card = {}
    target.interfaces = [Interface("http://a/", "jsonrpc", "1.0")]

    def run_report(results) -> int:
        with contextlib.redirect_stdout(io.StringIO()):
            return report(target, results, None)

    all_ids = sorted(REQUIREMENTS)

    print("\nRUNNER -- every declared requirement decided, at least one DEMONSTRATED")
    full_pass = [Result(i, Verdict.PASS, "selftest") for i in all_ids]
    expect_code(
        "POSITIVE CONTROL: a complete run with passes must exit 0",
        run_report(full_pass), 0,
        "None of the floors may refuse a run that actually decided everything.",
    )

    print("\nRUNNER -- a requirement silently dropped from the plan")
    short = [Result(i, Verdict.PASS, "selftest") for i in all_ids[1:]]
    expect_code(
        f"a run that never ran {all_ids[0]} must NOT exit 0",
        run_report(short), 1,
        "A requirement that leaves the denominator instead of failing turns '21 of 21' into "
        "'20 of 20' with nothing anywhere going red.",
    )

    print("\nRUNNER -- nothing demonstrated, and nothing failed either")
    nothing = [Result(i, Verdict.UNTESTABLE, "selftest") for i in all_ids]
    expect_code(
        "a run demonstrating ZERO MUSTs must NOT exit 0",
        run_report(nothing), 1,
        "UNTESTABLE, PARTIAL and NOT_APPLICABLE are not passes and are not `bad`, so '0 of 21 "
        "DEMONSTRATED' exited 0 and read as a clean run.",
    )

    print("\nRUNNER -- a real failure is still a failure (the floors did not replace it)")
    one_bad = [Result(i, Verdict.PASS, "selftest") for i in all_ids[1:]]
    one_bad.append(Result(all_ids[0], Verdict.FAIL, "selftest"))
    expect_code(
        "a FAIL must still exit 1",
        run_report(one_bad), 1,
        "The floors are added to the FAIL/ERROR rule, never in place of it.",
    )


def main() -> int:
    print("a2a-supplement SELFTEST -- every check is made to fail on purpose")
    print("A check that does not bite here is a check that reports green over nothing.")
    in_task_authorization_mutations()
    card_signing_mutations()
    binding_equivalence_mutations()
    versioning_mutations()
    runner_floor_mutations()
    print()
    # A SELFTEST THAT DISCOVERED NO CASES IS NOT A PASS. Same discipline as
    # testing/a2a-tck/check-baseline-selftest.py: without a floor, deleting a mutation family
    # leaves this file printing SELFTEST PASSED over the checks it stopped exercising.
    total = len(FAILURES) + PASSES_SEEN[0]
    if total < 24:
        print(f"SELFTEST DISCOVERED ONLY {total} CASES. Mutations were deleted or never ran.")
        return 2
    if FAILURES:
        print(f"SELFTEST FAILED: {len(FAILURES)} check(s) did not bite")
        for line in FAILURES:
            print(f"  - {line}")
        return 1
    print("SELFTEST PASSED: every mutation was caught and every positive control still passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
