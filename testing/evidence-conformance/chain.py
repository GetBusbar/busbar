# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""THE INDEPENDENT AUDIT-CHAIN VERIFIER of the `evidence-audit-trail` suite.

Written from the published contract alone, docs/audit-chain-digest-v4.md (sections 3 to 5), as a
third party would write it: no busbar code, no busbar library, no busbar constant. It frames and
hashes each record by the page's field table, checks each Ed25519 signature with this directory's
own RFC 8032 implementation against the key the node publishes (whose identifier it re-derives), and
checks the chain: genesis, links, contiguous positions, and the tail against the head read.

`verify(range_body, keys_body, head_body)` answers a list of findings: empty means the chain held.
`seal(records, seed)` builds a known-good chain of the rig's own (the control leg), by the same page.
"""
import hashlib
import importlib.util
import os

_spec = importlib.util.spec_from_file_location(
    "evidence_ed25519", os.path.join(os.path.dirname(os.path.abspath(__file__)), "ed25519.py"))
ed25519 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ed25519)

RECIPE = "busbar.audit.digest.v4"
DOMAIN = "busbar.audit.record.v1"

# Section 3.6, in order: (field, kind). A tuple names a repeated group: (count field, list member,
# [(element member or None for a bare number, kind), ...]).
FIELDS = [
    ("prev_hash", "text"), ("seq", "number"), ("subject_tag", "text"), ("subject_value", "text"),
    ("unit_key", "number"), ("incarnation", "number"), ("op_class", "text"), ("destination", "text"),
    ("parent", "number"), ("pre_hook_head", "text"), ("post_hook_head", "text"), ("wall", "number"),
    ("mono", "number"), ("node", "number"), ("origin_kind", "text"), ("outcome", "text"),
    ("step", "text"), ("finish", "text"), ("hook_failed", "number"), ("emission_delta", "text"),
    ("stale_policy", "number"),
    ("lines_count", "lines", [("class", "text"), ("quantity", "number"), ("source", "text"),
                              ("estimated", "number")]),
    ("tier_bp", "number"), ("fee_count", "number"), ("rate_card_version", "number"),
    ("bucket_chain_ref", "text"), ("hold_ref", "text"), ("settle_ref", "text"), ("slice_ref", "text"),
    ("lease_ref", "text"), ("lease_epoch", "number"), ("policy_epoch", "number"),
    ("hooks_count", "hooks", [("hook", "text"), ("head", "text"), ("failed", "number")]),
    ("replayed", "number"),
    ("children_count", "children", [(None, "number")]),
    ("correlation_hash", "text"),
]


class Malformed(Exception):
    pass


def _frame(value, kind, name):
    if kind == "text":
        if not isinstance(value, str):
            raise Malformed(f"`{name}` is not a JSON string")
        b = value.encode("utf-8")
        return len(b).to_bytes(8, "big") + b
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 2 ** 64:
        raise Malformed(f"`{name}` is not an unsigned 64-bit JSON number")
    return (8).to_bytes(8, "big") + value.to_bytes(8, "big")


def preimage(rec):
    out = []
    for f in FIELDS:
        if len(f) == 2:
            name, kind = f
            if name not in rec:
                raise Malformed(f"record lacks `{name}`")
            out.append(_frame(rec[name], kind, name))
            continue
        count, member, parts = f
        items = rec.get(member)
        if not isinstance(items, list):
            raise Malformed(f"`{member}` is not a list")
        if rec.get(count) != len(items):
            raise Malformed(f"`{count}` is {rec.get(count)!r} but `{member}` holds {len(items)}")
        out.append(_frame(rec[count], "number", count))
        for i, el in enumerate(items):
            for sub, kind in parts:
                if sub is None:
                    out.append(_frame(el, kind, f"{member}[{i}]"))
                else:
                    if not isinstance(el, dict) or sub not in el:
                        raise Malformed(f"`{member}[{i}]` lacks `{sub}`")
                    out.append(_frame(el[sub], kind, f"{member}[{i}].{sub}"))
    return b"".join(out)


def digest(rec):
    return hashlib.sha256(preimage(rec)).hexdigest()


def key_id(public_key):
    return hashlib.sha256(public_key).digest()[:8].hex()


def signing_input(hash_hex):
    return DOMAIN.encode() + b"\x00" + hash_hex.encode("ascii")


def _keys(keys_body):
    """key_id -> public key bytes, refusing a key set whose identifier is not its key's derivation."""
    found, keys = [], {}
    for k in (keys_body or {}).get("keys", []):
        try:
            pk = bytes.fromhex(k["public_key"])
        except (KeyError, ValueError, TypeError):
            found.append(f"a published key is not hex: {k!r}")
            continue
        if k.get("algorithm") != "ed25519":
            found.append(f"key {k.get('key_id')} is {k.get('algorithm')!r}, not ed25519")
            continue
        if key_id(pk) != k.get("key_id"):
            found.append(f"key {k.get('key_id')}: its identifier is not the derivation of its key ({key_id(pk)})")
            continue
        keys[k["key_id"]] = pk
    return keys, found


def verify(range_body, keys_body, head_body=None, *, want_from=None, want_to=None):
    """Every finding against a range read (with the key set and, for the tail, the head read)."""
    found = []
    if range_body.get("recipe") != RECIPE or range_body.get("signature_domain") != DOMAIN \
            or range_body.get("algorithm") != "ed25519":
        found.append(f"the body names recipe {range_body.get('recipe')!r}, domain "
                     f"{range_body.get('signature_domain')!r}, algorithm {range_body.get('algorithm')!r}")
    keys, kf = _keys(keys_body)
    found += kf
    recs = range_body.get("records")
    if not isinstance(recs, list):
        return found + ["the body carries no `records` list"]
    prev = None
    for i, rec in enumerate(recs):
        seq = rec.get("seq")
        where = f"record #{i} (seq {seq})"
        if rec.get("recipe") != RECIPE:
            found.append(f"{where}: sealed under {rec.get('recipe')!r}, a recipe this verifier does not know")
            continue
        try:
            h = digest(rec)
        except Malformed as e:
            found.append(f"{where}: malformed: {e}")
            prev = rec
            continue
        if h != rec.get("hash"):
            found.append(f"{where}: digest mismatch (recomputed {h[:16]}, carried {str(rec.get('hash'))[:16]}): the record was edited")
        pk = keys.get(rec.get("key_id"))
        if pk is None:
            found.append(f"{where}: signed by key {rec.get('key_id')!r}, which the key set does not publish")
        else:
            try:
                sig = bytes.fromhex(rec.get("signature", ""))
            except ValueError:
                sig = b""
            if not ed25519.verify_strict(pk, signing_input(rec.get("hash", "")), sig):
                found.append(f"{where}: the signature does not verify against key {rec.get('key_id')}")
        if prev is None:
            if seq == 1 and rec.get("prev_hash") != "":
                found.append(f"{where}: the genesis record does not have an empty prev_hash")
            if want_from is not None and seq != max(want_from, 1):
                found.append(f"{where}: the window asked from {want_from} but starts at {seq}: records are missing from its start")
        else:
            if seq != prev.get("seq", -1) + 1:
                found.append(f"{where}: follows seq {prev.get('seq')}: positions are not contiguous")
            if rec.get("prev_hash") != prev.get("hash"):
                found.append(f"{where}: prev_hash does not link to the record before it")
        prev = rec
    if head_body is not None:
        head = head_body.get("head")
        if head is None:
            if recs:
                found.append("the head read answers no head, but the range holds records")
        else:
            top = head.get("seq", 0)
            want = top if want_to is None else min(want_to, top)
            last = recs[-1].get("seq") if recs else 0
            if last != want:
                found.append(f"the window ends at seq {last}, the head says it must reach {want}: records are missing from its end")
            elif recs and want == top and recs[-1].get("hash") != head.get("hash"):
                found.append("the last record's hash is not the head's hash")
    return found


def seal(records, seed):
    """The rig's own known-good chain over `records` (dicts of the section 3.6 fields)."""
    pk = ed25519.public_key(seed)
    kid = key_id(pk)
    prev, out = "", []
    for n, r in enumerate(records, 1):
        rec = dict(r, prev_hash=prev, seq=n, recipe=RECIPE, key_id=kid)
        rec["hash"] = digest(rec)
        rec["signature"] = ed25519.sign(seed, signing_input(rec["hash"])).hex()
        out.append(rec)
        prev = rec["hash"]
    body = {"recipe": RECIPE, "signature_domain": DOMAIN, "algorithm": "ed25519",
            "from": 1, "to": len(out), "records": out}
    keys = {"recipe": RECIPE, "signature_domain": DOMAIN, "algorithm": "ed25519",
            "keys": [{"key_id": kid, "algorithm": "ed25519", "public_key": pk.hex()}]}
    last = out[-1] if out else None
    head = {"recipe": RECIPE, "next_seq": len(out) + 1,
            "head": None if last is None else {"seq": last["seq"], "hash": last["hash"],
                                               "signature": last["signature"], "key_id": kid,
                                               "wall": last["wall"]}}
    return body, keys, head
