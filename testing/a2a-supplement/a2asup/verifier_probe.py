# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""CARD-SIGN-004, the one requirement in section 8.4 that constrains the VERIFIER.

    SPEC 8.4.3: "Expired or revoked keys MUST NOT be used for verification"

WHY IT NEEDS A DIFFERENT SHAPE FROM EVERY OTHER CHECK HERE. The other three signing requirements
are decidable by looking at a document the subject SERVES. This one is about what the subject does
when it RECEIVES somebody else's signed card, so no amount of reading the subject's own card can
settle it. The subject has to be asked to verify something, and the only party that can ask is an
operator.

WHAT 'REVOKED' MEANS OVER THE WIRE, and the reading is stated because the specification does not
give one. A bare `AgentCardSignature` carries `protected`, `signature` and an optional `header`; it
carries no validity window, no revocation list and no chain. So there is nothing in the signature
itself that an implementation could consult to decide 'expired'. What IS reachable is the operational
half of the same sentence: a key the verifier has been told to trust versus one it has not. A
verifier that accepts a signature from a key outside its trust anchor cannot possibly be honouring
revocation, because revocation is precisely the act of removing a key from that set.

SO THE PROBE IS A MATCHED PAIR, and the pair is the whole point:

    positive control   the RIGHT key is configured  -> the card must VERIFY
    the assertion      a DIFFERENT key is configured -> the card must be REFUSED

Without the positive control, a subject that refuses every card for any reason passes. Without the
assertion, a subject that accepts every card passes. Neither half is evidence alone.

WHAT THIS DOES NOT ESTABLISH, said out loud: temporal expiry. Deciding `notAfter` needs a signature
format that carries one -- an X.509 chain or a JWKS entry with a validity window -- and the card
signature shape in SPEC 4.4.7 has no such member. That half is reported as a limit on the verdict
rather than quietly folded into a pass.
"""

from __future__ import annotations

import base64
import os
import uuid

import httpx

from a2asup.model import Result, Verdict, short

CONNECT_TIMEOUT = 60.0


def build_verifier_probe(admin_base: str | None, admin_token: str | None, agent_url: str | None):
    """Return a callable probe, or None when this target exposes no verifying role to drive."""
    if not (admin_base and admin_token and agent_url):
        return None

    def probe(req) -> Result:
        return _run(req, admin_base.rstrip("/"), admin_token, agent_url)

    return probe


def _wrong_key() -> str:
    """A syntactically valid Ed25519 SPKI that no signer in this rig holds.

    Generated fresh, not a constant: a hard-coded 'wrong key' is a value somebody eventually adds
    to a trust store to make a test pass.
    """
    from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: PLC0415
    from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
        Encoding,
        PublicFormat,
    )

    key = ed25519.Ed25519PrivateKey.generate().public_key()
    return base64.b64encode(key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).decode(
        "ascii"
    )


def _put_agent(base: str, token: str, name: str, body: dict) -> httpx.Response:
    return httpx.put(
        f"{base}/api/v1/admin/agents/{name}",
        json=body,
        headers={"authorization": f"Bearer {token}", "content-type": "application/json"},
        timeout=CONNECT_TIMEOUT,
    )


def _connect(base: str, token: str, name: str) -> httpx.Response:
    return httpx.post(
        f"{base}/api/v1/admin/agents/{name}/connect",
        headers={"authorization": f"Bearer {token}"},
        timeout=CONNECT_TIMEOUT,
    )


def _delete_agent(base: str, token: str, name: str) -> None:
    try:
        httpx.delete(
            f"{base}/api/v1/admin/agents/{name}",
            headers={"authorization": f"Bearer {token}"},
            timeout=CONNECT_TIMEOUT,
        )
    except Exception:  # noqa: BLE001, S110 - cleanup, never a verdict
        pass


def _verified(response: httpx.Response) -> tuple[bool, str]:
    """Did the subject actually VERIFY the card, or merely answer the request?

    THIS FUNCTION EXISTS BECAUSE THE FIRST VERSION OF IT WAS WRONG IN THE DANGEROUS DIRECTION. It
    tested `"fingerprint" in response.text`, and the operator API answers a REFUSED verification
    with HTTP 200 carrying `{"state":"error","fingerprint":null,"failure":"the agent card is
    signed, but not by the pinned issuer key"}` -- a body in which the string `fingerprint`
    appears. The check therefore read a correct refusal as an acceptance and was one report away
    from accusing the subject of a signature-verification defect it does not have.

    A verification counts as having SUCCEEDED only when the response carries a non-empty
    fingerprint AND names no failure. Any other shape is a refusal, and an unparseable body is a
    refusal too -- the conservative direction for a check whose FAIL is an accusation.
    """
    if response.status_code >= 400:
        return False, f"http {response.status_code}"
    try:
        doc = response.json()
    except Exception:  # noqa: BLE001
        return False, "the response body did not parse as JSON"
    if not isinstance(doc, dict):
        return False, f"the response body is a {type(doc).__name__}, not an object"
    failure = doc.get("failure")
    fingerprint = doc.get("fingerprint")
    if failure:
        return False, f"refused, naming: {failure}"
    if not fingerprint:
        return False, "no fingerprint was produced, so no card was verified"
    return True, f"fingerprint {fingerprint}"


def _run(req, base: str, token: str, agent_url: str) -> Result:
    evidence: list[str] = []
    right_key = os.environ.get("A2ASUP_RIGHT_ISSUER_KEY", "")
    if not right_key:
        return Result(
            req.id,
            Verdict.NOT_APPLICABLE,
            "no known-good issuer key was supplied for the upstream agent, so the POSITIVE CONTROL "
            "half of this probe cannot be run. Without it, a refusal proves nothing -- a subject "
            "that refuses every card would pass. Reported rather than half-run.",
            [],
        )

    suffix = uuid.uuid4().hex[:8]
    good_name = f"a2asup-cardsign-good-{suffix}"
    bad_name = f"a2asup-cardsign-wrong-{suffix}"
    wrong_key = _wrong_key()
    evidence.append(f"upstream agent under test: {agent_url}")
    evidence.append(f"trusted key (positive control) = {right_key[:24]}...")
    evidence.append(f"untrusted key (the assertion)  = {wrong_key[:24]}...")

    try:
        # ── POSITIVE CONTROL ──
        put_good = _put_agent(
            base,
            token,
            good_name,
            {
                "url": agent_url,
                "allow_private": True,
                "pin": {"mechanism": "jws_issuer_key", "key": right_key},
            },
        )
        evidence.append(f"PUT {good_name} -> {put_good.status_code} {short(put_good.text, 200)}")
        if put_good.status_code >= 400:
            return Result(
                req.id,
                Verdict.ERROR,
                f"the operator API refused to register the positive-control agent "
                f"({put_good.status_code}), so neither half of the probe could run: "
                f"{short(put_good.text, 300)}",
                evidence,
            )
        good = _connect(base, token, good_name)
        evidence.append(f"connect {good_name} (TRUSTED key) -> {good.status_code} {short(good.text, 300)}")

        # ── THE ASSERTION ──
        put_bad = _put_agent(
            base,
            token,
            bad_name,
            {
                "url": agent_url,
                "allow_private": True,
                "pin": {"mechanism": "jws_issuer_key", "key": wrong_key},
            },
        )
        evidence.append(f"PUT {bad_name} -> {put_bad.status_code} {short(put_bad.text, 200)}")
        bad = _connect(base, token, bad_name)
        evidence.append(f"connect {bad_name} (UNTRUSTED key) -> {bad.status_code} {short(bad.text, 300)}")
    finally:
        _delete_agent(base, token, good_name)
        _delete_agent(base, token, bad_name)

    good_ok, good_why = _verified(good)
    bad_ok, bad_why = _verified(bad)
    evidence.append(f"verdict on the trusted key:   verified={good_ok} ({good_why})")
    evidence.append(f"verdict on the untrusted key: verified={bad_ok} ({bad_why})")

    if not good_ok:
        return Result(
            req.id,
            Verdict.FAIL,
            "the POSITIVE CONTROL failed: the subject would not verify a card signed by the key it "
            "was told to trust. A refusal of the untrusted key would then be evidence of nothing, "
            "so this is reported as a failure of the pair rather than as a pass on one half.",
            evidence,
        )
    if bad_ok:
        return Result(
            req.id,
            Verdict.FAIL,
            "the subject VERIFIED a card signed by a key it was never given -- it accepted a "
            "signature under a key outside its trust anchor. A verifier that does this cannot be "
            "honouring revocation, because revocation is removal from exactly that set.",
            evidence,
        )
    return Result(
        req.id,
        Verdict.PASS,
        "matched pair: the same upstream card is VERIFIED under the key the operator pinned and "
        "REFUSED under a freshly generated key the subject was never given. "
        f"({req.limits})",
        evidence,
    )
