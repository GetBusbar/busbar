#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""
An INDEPENDENT verifier for a busbar audit chain.

This script is the acceptance test for `docs/audit-chain-digest-v1.md`. It reads what the three
read-only admin verbs answer with and checks the chain from first principles:

    GET /api/v1/admin/audit/range?from=..&to=..   -> the records
    GET /api/v1/admin/audit/head                  -> the tip, and the anchors
    GET /api/v1/admin/audit/keys                  -> the public keys

and it does so using ONLY the published recipe. It does not import busbar, does not run the busbar
binary, does not shell out to openssl and does not use a third-party Python package — ed25519
verification below is the RFC 8032 reference formulation over `hashlib.sha512`, which is in the
standard library. If this script cannot reproduce a chain, the published recipe is incomplete, and
that is the thing it exists to prove.

    ./scripts/verify-audit-chain.py --range range.json --keys keys.json [--head head.json]
    curl -s "$NODE/api/v1/admin/audit/range?from=1&to=100" > range.json
    curl -s "$NODE/api/v1/admin/audit/keys"                > keys.json
    curl -s "$NODE/api/v1/admin/audit/head"                > head.json

Exit 0 means every record hashes to its own published fields, links to the one before it, and
carries a signature that verifies against a published key. Any other exit means it does not, and
the reason is printed.

WHAT A GREEN RUN DOES AND DOES NOT PROVE. It proves the records are internally consistent and that
they were signed by the key the node publishes. It does NOT prove the node did not rewrite its own
history and re-sign it — an operator holding the signing key can do that, and no amount of checking
signatures detects it. What detects it is an externally recorded head that a rewrite cannot match.
So: green here earns "signed and tamper-evident", and only a head you recorded yourself, elsewhere,
earlier, earns "tamper-evident to a counterparty who trusts neither of us".
"""

import argparse
import hashlib
import json
import sys

RECIPE = "busbar.audit.digest.v1"
SIGNATURE_DOMAIN = "busbar.audit.record.v1"

# ── THE RECIPE ───────────────────────────────────────────────────────────────────────────────────
#
# The exact field order the digest is taken over, and for each field whether it goes in as TEXT
# (length-prefixed bytes) or as a NUMBER (big-endian eight bytes). The distinction is load-bearing:
# num(7) and text("7") are different byte strings, so a verifier that guessed wrong computes a
# different digest and reports an honest chain as tampered.
#
# "lines", "hooks" and "children" are REPEATED GROUPS. Each is preceded by its own count field, and
# each element's members are fed in the order named below. The count is what stops two different
# groupings of the same values from digesting identically.
TEXT, NUM = "text", "num"

FIELDS = [
    ("prev_hash", TEXT),
    ("seq", NUM),
    ("subject_tag", TEXT),
    ("subject_value", TEXT),
    ("unit_key", NUM),
    ("op_class", TEXT),
    ("destination", TEXT),
    ("parent", NUM),
    ("pre_hook_head", TEXT),
    ("post_hook_head", TEXT),
    ("wall", NUM),
    ("mono", NUM),
    ("origin_kind", TEXT),
    ("outcome", TEXT),
    ("step", TEXT),
    ("finish", TEXT),
    ("hook_failed", NUM),
    ("emission_delta", TEXT),
    ("stale_policy", NUM),
    ("lines_count", NUM),
    ("lines", [("class", TEXT), ("quantity", NUM), ("source", TEXT), ("estimated", NUM)]),
    ("pre_tier", TEXT),
    ("priced", TEXT),
    ("tier_bp", NUM),
    ("fee_count", NUM),
    ("currency", TEXT),
    ("rate_card_version", NUM),
    ("bucket_chain_ref", TEXT),
    ("hold_ref", TEXT),
    ("settle_ref", TEXT),
    ("slice_ref", TEXT),
    ("lease_ref", TEXT),
    ("lease_epoch", NUM),
    ("policy_epoch", NUM),
    ("hooks_count", NUM),
    ("hooks", [("hook", TEXT), ("priced_delta", TEXT)]),
    ("replayed", NUM),
    ("children_count", NUM),
    ("children", NUM),
    ("correlation_hash", TEXT),
]


class Bad(Exception):
    """A chain that does not check out, or a body that is not one."""


def framed(value, kind):
    """One field, LENGTH-PREFIXED. Never separator-joined -- see the spec's section on framing."""
    if kind is NUM:
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise Bad("a numeric field is not a non-negative integer: %r" % (value,))
        body = value.to_bytes(8, "big")
    else:
        if not isinstance(value, str):
            raise Bad("a text field is not a string: %r" % (value,))
        body = value.encode("utf-8")
    return len(body).to_bytes(8, "big") + body


def preimage(record):
    """The exact bytes SHA-256 is taken over, built from the published members alone."""
    out = bytearray()
    for name, kind in FIELDS:
        if name not in record:
            raise Bad("the record is missing the published member %r" % name)
        if isinstance(kind, list):
            for element in record[name]:
                for member, member_kind in kind:
                    if member not in element:
                        raise Bad("a %s element is missing %r" % (name, member))
                    out += framed(element[member], member_kind)
        elif name in ("children",):
            for element in record[name]:
                out += framed(element, kind)
        else:
            out += framed(record[name], kind)
    return bytes(out)


def digest_of(record):
    return hashlib.sha256(preimage(record)).hexdigest()


# ── ed25519, RFC 8032, over hashlib.sha512 and nothing else ──────────────────────────────────────
#
# Reproduced here rather than imported so that "verify this without trusting busbar" does not quietly
# become "verify this with a library you also have to trust". It is the reference formulation: edwards
# curve arithmetic in extended coordinates, and `verify_strict`'s cofactor-free equation.

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _point_add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _P
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _P
    C = 2 * P[3] * Q[3] * _D % _P
    D = 2 * P[2] * Q[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _point_mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _point_add(Q, P)
        P = _point_add(P, P)
        s >>= 1
    return Q


def _point_equal(P, Q):
    if (P[0] * Q[2] - Q[0] * P[2]) % _P != 0:
        return False
    return (P[1] * Q[2] - Q[1] * P[2]) % _P == 0


_G_Y = 4 * pow(5, _P - 2, _P) % _P


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_G = (_recover_x(_G_Y, 0), _G_Y, 1, _recover_x(_G_Y, 0) * _G_Y % _P)


def _point_decompress(blob):
    if len(blob) != 32:
        raise Bad("a public key or signature half is not 32 bytes")
    y = int.from_bytes(blob, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def ed25519_verify(public_key, message, signature):
    """RFC 8032 verification. False on anything malformed -- never an exception a caller ignores."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    A = _point_decompress(public_key)
    if A is None:
        return False
    R = _point_decompress(signature[:32])
    if R is None:
        return False
    S = int.from_bytes(signature[32:], "little")
    if S >= _L:
        return False
    h = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
    ) % _L
    return _point_equal(_point_mul(S, _G), _point_add(R, _point_mul(h, A)))


def key_id_of(public_key):
    """The published derivation: the first eight bytes of the key's SHA-256, in lowercase hex."""
    return hashlib.sha256(public_key).hexdigest()[:16]


def signing_preimage(digest_hex):
    """The published preimage: the domain, one zero byte, then the digest's 64 hex characters."""
    return SIGNATURE_DOMAIN.encode("ascii") + b"\x00" + digest_hex.encode("ascii")


# ── the checks ───────────────────────────────────────────────────────────────────────────────────


def load_keys(body):
    if body.get("recipe") != RECIPE:
        raise Bad("the key set names recipe %r, not %r" % (body.get("recipe"), RECIPE))
    keys = {}
    for entry in body.get("keys", []):
        if entry.get("algorithm") != "ed25519":
            raise Bad("a published key names algorithm %r" % entry.get("algorithm"))
        raw = bytes.fromhex(entry["public_key"])
        derived = key_id_of(raw)
        if derived != entry["key_id"]:
            raise Bad(
                "published key_id %r is not the SHA-256 derivation of its own key (%r)"
                % (entry["key_id"], derived)
            )
        keys[derived] = raw
    return keys


def verify(range_body, keys, require_signature, from_genesis):
    if range_body.get("recipe") != RECIPE:
        raise Bad("the range names recipe %r, not %r" % (range_body.get("recipe"), RECIPE))
    if range_body.get("signature_domain") != SIGNATURE_DOMAIN:
        raise Bad("the range names an unexpected signature domain")
    records = range_body.get("records", [])
    if not records:
        raise Bad("the range carries no records; there is nothing to verify")

    checked = 0
    signed = 0
    expected_prev = "" if from_genesis else records[0]["prev_hash"]
    expected_seq = 1 if from_genesis else records[0]["seq"]

    for record in records:
        where = "seq %s" % record.get("seq")
        if record["prev_hash"] != expected_prev:
            raise Bad("%s does not point at its predecessor: a record was INSERTED, REMOVED or "
                      "REORDERED here" % where)
        if record["seq"] != expected_seq:
            raise Bad("%s is out of position (expected %d): the run has a hole" % (where, expected_seq))
        recomputed = digest_of(record)
        if recomputed != record["hash"]:
            raise Bad("%s does not hash to its own published fields -- it was EDITED\n"
                      "  published: %s\n  recomputed: %s" % (where, record["hash"], recomputed))
        signature = record.get("signature")
        key_id = record.get("key_id")
        if signature is None or key_id is None:
            if require_signature:
                raise Bad("%s carries no signature, and --require-signature was given" % where)
        else:
            if key_id not in keys:
                raise Bad("%s names key %r, which the published key set does not hold" % (where, key_id))
            ok = ed25519_verify(
                keys[key_id], signing_preimage(record["hash"]), bytes.fromhex(signature)
            )
            if not ok:
                raise Bad("%s carries a signature that does NOT verify against published key %r"
                          % (where, key_id))
            signed += 1
        expected_prev = record["hash"]
        expected_seq += 1
        checked += 1
    return checked, signed


def check_head(head_body, range_body):
    """The one check a run of records cannot make about itself.

    A TAIL truncation is invisible to a verifier reading only the records: the survivors link and
    number correctly among themselves, because dropping the last one leaves a perfectly good chain
    that is simply shorter. It takes the node's own published head to notice -- the range says which
    window it is answering, the head says how far the chain actually goes, and a window that stops
    short of both is a window with records missing from the end of it."""
    head = head_body.get("head")
    records = range_body["records"]
    tail = records[-1]
    if head is None:
        raise Bad("the head read carries no head, but the range carried records")
    asked_to = range_body.get("to")
    if not isinstance(asked_to, int):
        raise Bad("the range does not say which window it is answering")
    # The last position this window could honestly reach: the window's own end, or the chain's tip
    # if the chain does not go that far yet.
    expected_last = min(asked_to, head["seq"])
    if tail["seq"] < expected_last:
        raise Bad("the range answers 1..%d and the chain's head is at %d, but the last record "
                  "delivered is %d -- records are MISSING FROM THE END of this window"
                  % (asked_to, head["seq"], tail["seq"]))
    if head["seq"] == tail["seq"] and head["hash"] != tail["hash"]:
        raise Bad("the published head disagrees with the record at the same position -- the chain "
                  "was FORKED")
    return head


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--range", required=True, help="body of GET /api/v1/admin/audit/range")
    ap.add_argument("--keys", required=True, help="body of GET /api/v1/admin/audit/keys")
    ap.add_argument("--head", help="body of GET /api/v1/admin/audit/head")
    ap.add_argument("--require-signature", action="store_true",
                    help="refuse a record that carries no signature")
    ap.add_argument("--window", action="store_true",
                    help="the range is a window of a longer chain, not its genesis")
    args = ap.parse_args()

    try:
        with open(args.range) as f:
            range_body = json.load(f)
        with open(args.keys) as f:
            keys = load_keys(json.load(f))
        checked, signed = verify(range_body, keys, args.require_signature, not args.window)
        if args.head:
            with open(args.head) as f:
                head = check_head(json.load(f), range_body)
            print("head: seq %d, hash %s" % (head["seq"], head["hash"]))
    except Bad as bad:
        print("AUDIT CHAIN DOES NOT VERIFY: %s" % bad, file=sys.stderr)
        return 1
    except (KeyError, ValueError) as bad:
        print("AUDIT CHAIN DOES NOT VERIFY: malformed body: %s" % bad, file=sys.stderr)
        return 1

    print("OK: %d record(s) verified, %d of them signed, %d published key(s)"
          % (checked, signed, len(keys)))
    print("    recipe %s, framing length-prefixed, signature domain %s"
          % (RECIPE, SIGNATURE_DOMAIN))
    return 0


if __name__ == "__main__":
    sys.exit(main())
