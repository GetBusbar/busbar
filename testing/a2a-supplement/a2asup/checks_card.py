# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""CARD-SIGN-*: SPEC 8.4 agent card signing.

THE TCK MARKS ALL FOUR OF THESE `NOT_AUTOMATABLE` AND THREE OF THEM ARE NOT.

A digital signature is a proof of which bytes were signed, so a verifier standing outside the
implementation can decide questions that look internal:

  * CARD-SIGN-001 asks whether the card was canonicalized with RFC 8785 before signing. Canonicalise
    the SERVED card independently, verify the published signature over exactly those bytes, and the
    answer follows: no other serialisation produces bytes that verify.
  * CARD-SIGN-002 asks whether `signatures` was excluded. A MATCHED PAIR decides it -- the signature
    must verify with the member removed and must NOT verify with it retained. Either half alone is
    consistent with the wrong implementation.
  * CARD-SIGN-003 is a structural fact about a base64url-encoded header and needs no key at all.

CARD-SIGN-004 is different in kind: it constrains the VERIFYING party, so it can only be decided
against a subject that verifies somebody else's card. See its check.

THE VERIFIER USED HERE IS INDEPENDENT OF THE SUBJECT'S, and that is the only reason any of this is
evidence. The canonicalizer is `testing/a2a-harness/a2aht/jcs.py` -- a clean-room Python reading of
RFC 8785 that predates this suite and has its own tests -- rather than a call into whatever the
subject uses. A check that asked the subject to canonicalise the card and then agreed with itself
would be the exact mirror this directory exists to refuse.
"""

from __future__ import annotations

import base64
import json
import os
import sys

from a2asup.model import Result, Verdict, short
from a2asup.spec import REQUIREMENTS
from a2asup.target import Target

# The sibling battery's RFC 8785 implementation, imported rather than copied. A second
# canonicalizer in this tree would be a second set of bytes we call canonical, and the first
# divergence between them would be silent.
_HARNESS = os.path.join(os.path.dirname(__file__), "..", "..", "a2a-harness")
if os.path.isdir(_HARNESS) and _HARNESS not in sys.path:
    sys.path.insert(0, os.path.abspath(_HARNESS))


def canonicalize(obj):
    from a2aht.jcs import canonicalize as _c  # noqa: PLC0415

    return _c(obj)


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _load_public_key(issuer_key: str):
    """The operator's out-of-band copy of the signer's public key: base64 of a DER SubjectPublicKeyInfo.

    That is the shape SPEC 8.4 leaves to the deployment -- an `AgentCardSignature` carries `kid`
    and optionally `jku`, not the key itself -- so a verifier is always given the key by some
    channel outside the card. This suite takes it as an argument for exactly that reason.
    """
    from cryptography.hazmat.primitives.serialization import load_der_public_key  # noqa: PLC0415

    return load_der_public_key(base64.b64decode(issuer_key))


def _verify(public_key, alg: str, signing_input: bytes, signature: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa  # noqa: PLC0415

    try:
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, signing_input)
            return True
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            from cryptography.hazmat.primitives.asymmetric.utils import (  # noqa: PLC0415
                encode_dss_signature,
            )

            half = len(signature) // 2
            der = encode_dss_signature(
                int.from_bytes(signature[:half], "big"),
                int.from_bytes(signature[half:], "big"),
            )
            digest = {"ES256": hashes.SHA256(), "ES384": hashes.SHA384(), "ES512": hashes.SHA512()}[
                alg
            ]
            public_key.verify(der, signing_input, ec.ECDSA(digest))
            return True
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
            return True
    except InvalidSignature:
        return False
    raise TypeError(f"unsupported key type {type(public_key).__name__} for alg {alg!r}")


def _signatures(card: dict) -> list:
    sigs = card.get("signatures")
    return sigs if isinstance(sigs, list) else []


def _signing_input(protected_b64: str, payload_text: str) -> bytes:
    """RFC 7515 section 5.1: ASCII(BASE64URL(protected) || '.' || BASE64URL(payload))."""
    return (protected_b64 + "." + b64url_encode(payload_text.encode("utf-8"))).encode("ascii")


def _no_signature(req_id: str, card: dict) -> Result:
    return Result(
        req_id,
        Verdict.NOT_APPLICABLE,
        "SPEC 8.4 makes signing OPTIONAL ('Agent Cards MAY be digitally signed'), and this card "
        "carries no `signatures` member. The requirement constrains how a card IS signed, so there "
        "is nothing to decide. Reported in its own column, never as a pass.",
        [f"card members = {short(sorted(card))}"],
    )


def check_card_sign_001(target: Target, issuer_key: str | None) -> Result:
    """SPEC 8.4.1: 'Before signing, the Agent Card content MUST be canonicalized using the JSON
    Canonicalization Scheme (JCS) as defined in RFC 8785.'"""
    req = REQUIREMENTS["CARD-SIGN-001"]
    sigs = _signatures(target.card)
    if not sigs:
        return _no_signature(req.id, target.card)
    if not issuer_key:
        return Result(
            req.id,
            Verdict.FAIL,
            "the card IS signed but this run was given no public key, so the signature could not "
            "be verified and the canonicalization could not be decided. An unverified signature is "
            "reported as unverified, never as valid -- and a signed card the operator cannot "
            "supply a key for is itself worth reporting.",
            [f"signature count = {len(sigs)}"],
        )

    payload_card = {k: v for k, v in target.card.items() if k != "signatures"}
    canonical = canonicalize(payload_card)
    evidence = [f"independently canonicalized payload ({len(canonical)} bytes): {short(canonical, 300)}"]
    public_key = _load_public_key(issuer_key)

    for index, sig in enumerate(sigs):
        try:
            protected_b64 = sig["protected"]
            header = json.loads(b64url_decode(protected_b64))
        except Exception as exc:  # noqa: BLE001
            evidence.append(f"signatures[{index}] protected is not base64url JSON: {exc}")
            continue
        try:
            verified = _verify(
                public_key,
                str(header.get("alg")),
                _signing_input(protected_b64, canonical),
                b64url_decode(sig["signature"]),
            )
        except Exception as exc:  # noqa: BLE001
            evidence.append(f"signatures[{index}] verification raised {type(exc).__name__}: {exc}")
            continue
        evidence.append(f"signatures[{index}] alg={header.get('alg')!r} verified={verified}")
        if verified:
            return Result(
                req.id,
                Verdict.PASS,
                f"the published signature verifies over the card canonicalized by an INDEPENDENT "
                f"RFC 8785 implementation. Any other serialisation of the same document would "
                f"produce different bytes and would not verify, so JCS is what the signer used.",
                evidence,
            )

    # A JSON round-trip that is NOT canonical, to say which failure this is. If the signature
    # verifies over a non-canonical serialisation then the signer signed something else.
    naive = json.dumps(payload_card, separators=(",", ":"))
    naive_ok = False
    for sig in sigs:
        try:
            naive_ok = naive_ok or _verify(
                public_key,
                str(json.loads(b64url_decode(sig["protected"])).get("alg")),
                _signing_input(sig["protected"], naive),
                b64url_decode(sig["signature"]),
            )
        except Exception:  # noqa: BLE001, S110
            pass
    evidence.append(f"verifies over a NON-canonical json.dumps of the same document: {naive_ok}")
    return Result(
        req.id,
        Verdict.FAIL,
        "no published signature verifies over the RFC 8785 canonical form of the served card"
        + (
            " -- but one DOES verify over a plain, non-canonical serialisation, so the signer did "
            "not canonicalize."
            if naive_ok
            else " and none verifies over a non-canonical serialisation either, so the signed "
            "bytes are not this document at all."
        ),
        evidence,
    )


def check_card_sign_002(target: Target, issuer_key: str | None) -> Result:
    """SPEC 8.4.1: 'The signatures field itself MUST be excluded from the content being signed to
    avoid circular dependencies.'"""
    req = REQUIREMENTS["CARD-SIGN-002"]
    sigs = _signatures(target.card)
    if not sigs:
        return _no_signature(req.id, target.card)
    if not issuer_key:
        return Result(
            req.id,
            Verdict.FAIL,
            "the card is signed and no public key was supplied, so neither half of the matched "
            "pair this requirement needs could be evaluated.",
            [],
        )
    public_key = _load_public_key(issuer_key)
    without = canonicalize({k: v for k, v in target.card.items() if k != "signatures"})
    with_sigs = canonicalize(target.card)
    evidence: list[str] = []

    excluded_ok = False
    included_ok = False
    for index, sig in enumerate(sigs):
        alg = str(json.loads(b64url_decode(sig["protected"])).get("alg"))
        raw = b64url_decode(sig["signature"])
        a = _verify(public_key, alg, _signing_input(sig["protected"], without), raw)
        b = _verify(public_key, alg, _signing_input(sig["protected"], with_sigs), raw)
        evidence.append(
            f"signatures[{index}]: verifies with `signatures` EXCLUDED={a}, INCLUDED={b}"
        )
        excluded_ok = excluded_ok or a
        included_ok = included_ok or b

    if included_ok:
        return Result(
            req.id,
            Verdict.FAIL,
            "a signature verifies over a payload that RETAINS the `signatures` member, which is "
            "the circular dependency SPEC 8.4.1 forbids in as many words.",
            evidence,
        )
    if not excluded_ok:
        return Result(
            req.id,
            Verdict.FAIL,
            "no signature verifies over the payload with `signatures` excluded, so exclusion "
            "cannot be established -- and the negative half alone would be passed by a card whose "
            "signature is simply wrong.",
            evidence,
        )
    return Result(
        req.id,
        Verdict.PASS,
        "the matched pair holds: the signature verifies over the card with `signatures` excluded "
        "and does NOT verify over the card with `signatures` retained.",
        evidence,
    )


def check_card_sign_003(target: Target) -> Result:
    """SPEC 8.4.2: 'The protected header MUST include: alg ... kid ...' (typ is SHOULD)."""
    req = REQUIREMENTS["CARD-SIGN-003"]
    sigs = _signatures(target.card)
    if not sigs:
        return _no_signature(req.id, target.card)
    evidence: list[str] = []
    failures: list[str] = []
    should_notes: list[str] = []
    for index, sig in enumerate(sigs):
        if not isinstance(sig, dict) or "protected" not in sig or "signature" not in sig:
            failures.append(
                f"signatures[{index}] is missing a REQUIRED member of AgentCardSignature "
                f"(SPEC 4.4.7: `protected` and `signature` are required): {short(sig)}"
            )
            continue
        try:
            header = json.loads(b64url_decode(sig["protected"]))
        except Exception as exc:  # noqa: BLE001
            failures.append(
                f"signatures[{index}].protected does not base64url-decode to JSON: {exc}"
            )
            continue
        if not isinstance(header, dict):
            failures.append(f"signatures[{index}].protected decodes to {type(header).__name__}")
            continue
        evidence.append(f"signatures[{index}] protected header = {short(header)}")
        missing = [m for m in ("alg", "kid") if not header.get(m)]
        if missing:
            failures.append(f"signatures[{index}] protected header lacks {missing}")
        if header.get("alg") == "none":
            failures.append(
                f"signatures[{index}] declares alg 'none', which is an unsigned JWS wearing the "
                f"shape of a signed one"
            )
        if header.get("typ") != "JOSE":
            should_notes.append(f"signatures[{index}].typ={header.get('typ')!r}")

    if failures:
        return Result(req.id, Verdict.FAIL, "; ".join(failures), evidence)
    note = (
        f" (SHOULD, reported separately and NOT part of this MUST verdict: SPEC 8.4.2 says `typ` "
        f"SHOULD be \"JOSE\"; observed {should_notes}.)"
        if should_notes
        else ""
    )
    return Result(
        req.id,
        Verdict.PASS,
        f"every one of {len(sigs)} signature(s) carries a base64url-encoded JSON protected header "
        f"containing both `alg` and `kid`." + note,
        evidence,
    )


def check_card_sign_004(target: Target, verifier_probe) -> Result:
    """SPEC 8.4.3: 'Expired or revoked keys MUST NOT be used for verification'."""
    req = REQUIREMENTS["CARD-SIGN-004"]
    if verifier_probe is None:
        return Result(
            req.id,
            Verdict.NOT_APPLICABLE,
            "this requirement constrains the party that VERIFIES a card, so it is only decidable "
            "against a subject that fetches and verifies somebody else's card -- an A2A client, or "
            "a gateway. This target was run with no verifier probe configured, so the run "
            "observed no verification and asserts nothing about it.",
            [],
        )
    return verifier_probe(req)
