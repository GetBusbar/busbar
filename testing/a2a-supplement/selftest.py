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

from a2asup import checks_bind, checks_card, checks_ver
from a2asup.model import Verdict
from a2asup.target import Interface, Target
from a2asup.transport import Reply

FAILURES: list[str] = []


def expect(label: str, result, allowed: set[Verdict]) -> None:
    ok = result.verdict in allowed
    mark = "ok " if ok else "MISS"
    print(f"  {mark}  {label}")
    print(f"        -> {result.verdict.value}: {result.summary[:150]}")
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


def main() -> int:
    print("a2a-supplement SELFTEST -- every check is made to fail on purpose")
    print("A check that does not bite here is a check that reports green over nothing.")
    card_signing_mutations()
    binding_equivalence_mutations()
    versioning_mutations()
    print()
    if FAILURES:
        print(f"SELFTEST FAILED: {len(FAILURES)} check(s) did not bite")
        for line in FAILURES:
            print(f"  - {line}")
        return 1
    print("SELFTEST PASSED: every mutation was caught and every positive control still passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
