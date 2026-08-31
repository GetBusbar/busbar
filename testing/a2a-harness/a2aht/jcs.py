"""RFC 8785 JSON Canonicalization Scheme, and JWS verification for agent cards.

SPEC 8.4.1 mandates RFC 8785 before signing. This is a compact implementation
of the parts of RFC 8785 that agent cards actually exercise: lexicographic key
ordering by UTF-16 code unit, no insignificant whitespace, and ECMAScript
number formatting.

Signature verification needs asymmetric crypto. The `cryptography` package is
used if present. If it is absent the harness reports "not verifiable" and says
so out loud; it never reports an unverified signature as verified.
"""

import base64
import json
import math
import urllib.request


def canonicalize(obj):
    """Return the RFC 8785 canonical JSON text for `obj`."""
    return _ser(obj)


def _ser(obj):
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    if isinstance(obj, (int,)) and not isinstance(obj, bool):
        return _number(float(obj)) if abs(obj) > 2 ** 53 else str(obj)
    if isinstance(obj, float):
        return _number(obj)
    if isinstance(obj, list):
        return "[" + ",".join(_ser(v) for v in obj) + "]"
    if isinstance(obj, dict):
        # RFC 8785 section 3.2.3: sort by UTF-16 code units.
        items = sorted(obj.items(), key=lambda kv: _utf16_key(kv[0]))
        return "{" + ",".join(
            _ser(k) + ":" + _ser(v) for k, v in items) + "}"
    raise TypeError("cannot canonicalize %r" % type(obj))


def _utf16_key(text):
    return tuple(text.encode("utf-16-be"))


def _number(value):
    """RFC 8785 section 3.2.2.3: ECMAScript Number::toString."""
    if math.isnan(value) or math.isinf(value):
        raise ValueError("RFC 8785 forbids NaN and Infinity")
    if value == 0:
        return "0"
    if value == int(value) and abs(value) < 1e21:
        return str(int(value))
    return repr(value)


def b64url_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def verify_jws(signature_obj, canonical_payload, jwks=None, timeout=10.0):
    """Verify one AgentCardSignature over the canonical payload.

    Returns a dict with `verified` set to True, False, or None when the
    signature could not be checked at all. None is never treated as success.
    """
    out = {"verified": None, "reason": None, "alg": None, "kid": None}
    try:
        header = json.loads(b64url_decode(signature_obj["protected"]))
    except Exception as exc:
        out["reason"] = "protected header is not base64url JSON: %s" % exc
        out["verified"] = False
        return out
    out["alg"] = header.get("alg")
    out["kid"] = header.get("kid")

    if header.get("alg") == "none":
        out["verified"] = False
        out["reason"] = ("alg is 'none'. An unsigned JWS must never be "
                         "accepted; this is the classic JWS downgrade.")
        return out

    keys = list(jwks or [])
    jku = header.get("jku")
    if not keys and jku:
        try:
            with urllib.request.urlopen(jku, timeout=timeout) as resp:
                keys = json.loads(resp.read()).get("keys", [])
        except Exception as exc:
            out["reason"] = "could not fetch jku %s: %s" % (jku, exc)
            return out
    if not keys:
        out["reason"] = ("no public key available: the protected header has "
                         "no jku and no --jwks was supplied")
        return out

    key = None
    for candidate in keys:
        if not header.get("kid") or candidate.get("kid") == header.get("kid"):
            key = candidate
            break
    if key is None:
        out["reason"] = "no key in the key set matches kid %r" % header.get("kid")
        return out

    signing_input = (signature_obj["protected"].encode("ascii") + b"."
                     + b64url_encode(canonical_payload.encode("utf-8")).encode("ascii"))
    sig = b64url_decode(signature_obj["signature"])

    try:
        out["verified"] = _verify(key, header.get("alg"), signing_input, sig)
        if not out["verified"]:
            out["reason"] = "signature did not verify over the canonical form"
    except ImportError:
        out["verified"] = None
        out["reason"] = ("the 'cryptography' package is not installed, so the "
                         "signature could not be checked. Reported as "
                         "unverified, never as verified.")
    except Exception as exc:
        out["verified"] = False
        out["reason"] = "verification error: %s: %s" % (type(exc).__name__, exc)
    return out


def _verify(jwk, alg, signing_input, sig):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import (
        encode_dss_signature)
    from cryptography.exceptions import InvalidSignature

    kty = jwk.get("kty")
    if kty == "EC":
        curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(),
                 "P-521": ec.SECP521R1()}[jwk["crv"]]
        numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(b64url_decode(jwk["x"]), "big"),
            int.from_bytes(b64url_decode(jwk["y"]), "big"), curve)
        pub = numbers.public_key()
        half = len(sig) // 2
        der = encode_dss_signature(int.from_bytes(sig[:half], "big"),
                                   int.from_bytes(sig[half:], "big"))
        digest = {"ES256": hashes.SHA256(), "ES384": hashes.SHA384(),
                  "ES512": hashes.SHA512()}[alg]
        try:
            pub.verify(der, signing_input, ec.ECDSA(digest))
            return True
        except InvalidSignature:
            return False
    if kty == "RSA":
        numbers = rsa.RSAPublicNumbers(
            int.from_bytes(b64url_decode(jwk["e"]), "big"),
            int.from_bytes(b64url_decode(jwk["n"]), "big"))
        pub = numbers.public_key()
        digest = {"RS256": hashes.SHA256(), "RS384": hashes.SHA384(),
                  "RS512": hashes.SHA512()}[alg]
        try:
            pub.verify(sig, signing_input, padding.PKCS1v15(), digest)
            return True
        except InvalidSignature:
            return False
    raise ValueError("unsupported key type %r" % kty)


# ---------------------------------------------------------------------------
# Adversarial JWS construction, used to probe a client's card verification.
# ---------------------------------------------------------------------------

def make_signature(header, payload_canonical, raw_signature=b"\x00" * 64):
    """Build an AgentCardSignature with an arbitrary protected header.

    Deliberately does NOT sign anything real. These are attack shapes: what
    matters is whether the peer under test REFUSES them, not whether the
    bytes verify.
    """
    protected = b64url_encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8"))
    return {"protected": protected,
            "signature": b64url_encode(raw_signature)}


ADVERSARIAL_HEADERS = {
    "alg_none": {
        "header": {"alg": "none", "typ": "JOSE", "kid": "key-1"},
        "why": "The unsigned JWS. RFC 7515 Appendix F allows alg 'none' only "
               "for JWSs that are explicitly unsecured; a verifier that "
               "accepts it for a card that is supposed to be signed has no "
               "integrity protection at all.",
    },
    "alg_confusion_hmac": {
        "header": {"alg": "HS256", "typ": "JOSE", "kid": "key-1"},
        "why": "Algorithm confusion. The card was signed with an asymmetric "
               "key (ES256/RS256) and the attacker re-declares it as HMAC so "
               "that the verifier uses the PUBLIC key as the HMAC secret. The "
               "public key is public, so the attacker can forge freely. A "
               "verifier must bind the accepted algorithm to the pinned key "
               "type, not take it from the attacker-controlled header.",
    },
    "crit_unknown": {
        "header": {"alg": "ES256", "typ": "JOSE", "kid": "key-1",
                   "crit": ["urn:harness:unsupported-extension"],
                   "urn:harness:unsupported-extension": True},
        "why": "RFC 7515 section 4.1.11: 'the JWS MUST be rejected' if the "
               "crit list names an extension the recipient does not "
               "understand. A verifier that ignores crit can be fed a header "
               "whose meaning it has silently dropped.",
    },
    "kid_swap": {
        "header": {"alg": "ES256", "typ": "JOSE", "kid": "attacker-key"},
        "why": "Key selection by attacker-controlled kid. If the verifier "
               "resolves kid against anything other than a pinned trust "
               "store, the attacker chooses which key validates their card.",
    },
    "jku_offsite": {
        "header": {"alg": "ES256", "typ": "JOSE", "kid": "key-1",
                   "jku": "http://127.0.0.1:9/harness-attacker-jwks.json"},
        "why": "Key fetch from an attacker-named URL. SPEC 8.4.2 permits jku, "
               "and SPEC 8.4.3 says keys SHOULD be retrieved over secure "
               "channels, but nothing forbids trusting the jku the card "
               "itself supplies, which is circular.",
    },
}


def crit_is_understood(header, understood=()):
    """RFC 7515 4.1.11. Returns True only if every crit entry is understood."""
    crit = header.get("crit")
    if crit is None:
        return True
    if not isinstance(crit, list) or not crit:
        return False
    return all(name in understood for name in crit)
