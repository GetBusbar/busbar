# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""THE INDEPENDENT AUDIT-CHAIN VERIFIER of the `evidence-audit-trail` suite.

Written from the published contract alone, docs/audit-chain-digest-v{2,4,5,6}.md, as a
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
import re
import copy

_spec = importlib.util.spec_from_file_location(
    "evidence_ed25519", os.path.join(os.path.dirname(os.path.abspath(__file__)), "ed25519.py"))
ed25519 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ed25519)

RECIPE = "busbar.audit.digest.v5"
SUPPORTED = {f"busbar.audit.digest.v{n}" for n in (2, 4, 5, 6)}
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
    ("tier_bp", "number"), ("fee_count", "number"),
    ("rate_card_key_present", "number"), ("rate_card_version", "text"),
    ("bucket_chain_ref", "text"), ("hold_ref", "text"), ("settle_ref", "text"), ("slice_ref", "text"),
    ("lease_ref", "text"), ("lease_epoch", "number"), ("policy_epoch", "number"),
    ("hooks_count", "hooks", [("hook", "text"), ("head", "text"), ("failed", "number")]),
    ("replayed", "number"),
    ("children_count", "children", [(None, "number")]),
    ("correlation_hash", "text"),
]


class Malformed(Exception):
    pass


def number(value, name):
    """Recipe numbers are canonical decimal JSON strings, never JSON numbers."""
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,19}", value):
        raise Malformed(f"`{name}` is not a canonical unsigned decimal JSON string")
    n = int(value)
    if n >= 2 ** 64:
        raise Malformed(f"`{name}` exceeds unsigned 64-bit range")
    return n


def envelope_number(value, name):
    if type(value) is not int or not 0 <= value < 2 ** 64:
        raise Malformed(f"`{name}` is not an unsigned 64-bit JSON number")
    return value


def fields(recipe):
    if not isinstance(recipe, str) or recipe not in SUPPORTED:
        raise Malformed(f"unsupported recipe {recipe!r}")
    out = copy.deepcopy(FIELDS)
    if recipe.endswith((".v2", ".v4")):
        out = [f for f in out if f[0] != "rate_card_key_present"]
        out = [("rate_card_version", "number") if f[0] == "rate_card_version" else f for f in out]
    if recipe.endswith(".v2"):
        out = [f for f in out if f[0] not in ("incarnation", "node")]
        index = next(i for i, f in enumerate(out) if f[0] == "rate_card_version")
        out.insert(index, ("currency", "text"))
        out = [("hooks_count", "hooks", [("hook", "text")]) if f[0] == "hooks_count" else f for f in out]
    if recipe.endswith(".v6"):
        out = [("lines_count", "lines", [("class", "text"), ("quantity", "quantity"),
                                          ("source", "text"), ("estimated", "number")])
               if f[0] == "lines_count" else f for f in out]
    return out


def _frame(value, kind, name):
    if kind in ("text", "quantity"):
        if not isinstance(value, str):
            raise Malformed(f"`{name}` is not a JSON string")
        if kind == "quantity" and not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{0,5}[1-9])?", value):
            raise Malformed(f"`{name}` is not canonical scale-six quantity text")
        try:
            b = value.encode("utf-8")
        except UnicodeEncodeError as e:
            raise Malformed(f"`{name}` is not valid UTF-8 text") from e
        return len(b).to_bytes(8, "big") + b
    return (8).to_bytes(8, "big") + number(value, name).to_bytes(8, "big")


def preimage(rec):
    if not isinstance(rec, dict):
        raise Malformed("record is not an object")
    recipe = rec.get("recipe")
    table = fields(recipe)
    if recipe.endswith((".v5", ".v6")):
        present, key = rec.get("rate_card_key_present"), rec.get("rate_card_version")
        if present not in ("0", "1") or not isinstance(key, str) or (
                key != "" if present == "0" else not re.fullmatch(r"[0-9a-f]{40}", key)):
            raise Malformed("invalid rate_card_key_present/rate_card_version pair")
    out = []
    for f in table:
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
        if number(rec.get(count), count) != len(items):
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


def _hex(value, size, name):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{%d}" % (size * 2), value):
        raise Malformed(f"`{name}` is not {size} bytes of lowercase hex")
    return bytes.fromhex(value)


def _keys(keys_body):
    """key_id -> public key bytes, refusing identifiers not derived from their keys."""
    found, keys = [], {}
    if not isinstance(keys_body, dict) or not isinstance(keys_body.get("keys"), list):
        return keys, ["the key body carries no `keys` list"]
    for k in keys_body["keys"]:
        try:
            if not isinstance(k, dict):
                raise Malformed("published key is not an object")
            pk = _hex(k.get("public_key"), 32, "public_key")
            if k.get("algorithm") != "ed25519":
                raise Malformed("published key algorithm is not ed25519")
            if key_id(pk) != k.get("key_id"):
                raise Malformed("published key identifier is not the derivation of its key")
            keys[k["key_id"]] = pk
        except Malformed as e:
            found.append(str(e))
    return keys, found


def _signature(rec, keys):
    kid = rec.get("key_id")
    if not isinstance(kid, str) or kid not in keys:
        return f"signed by key {kid!r}, which the key set does not publish"
    try:
        _hex(rec.get("hash"), 32, "hash")
        sig = _hex(rec.get("signature"), 64, "signature")
    except Malformed as e:
        return f"signature does not verify: {e}"
    if not ed25519.verify_strict(keys[kid], signing_input(rec["hash"]), sig):
        return f"the signature does not verify against key {kid}"
    return None


def verify(range_body, keys_body, head_body=None, *, want_from=None, want_to=None):
    """Return findings; dispatch each record's recipe without coercing invalid wire types."""
    found = []
    if not isinstance(range_body, dict):
        return ["the range body is not an object"]
    for label, body in (("range", range_body), ("keys", keys_body), ("head", head_body)):
        if body is None and label == "head":
            continue
        if not isinstance(body, dict) or not isinstance(body.get("recipe"), str) or \
                body.get("recipe") not in SUPPORTED or \
                body.get("signature_domain") != DOMAIN or body.get("algorithm") != "ed25519":
            found.append(f"{label} body names an unsupported recipe, domain, or algorithm")
    keys, kf = _keys(keys_body)
    found += kf
    recs = range_body.get("records")
    if not isinstance(recs, list):
        return found + ["the body carries no `records` list"]
    try:
        for field in ("from", "to"):
            envelope_number(range_body.get(field), field)
        if want_from is not None:
            envelope_number(want_from, "want_from")
        if want_to is not None:
            envelope_number(want_to, "want_to")
    except Malformed as e:
        found.append(str(e))
        return found
    prev, prev_seq, last_seq = None, None, None
    for i, rec in enumerate(recs):
        where = f"record #{i}"
        try:
            h = digest(rec)
            seq = number(rec.get("seq"), "seq")
            if seq == 0:
                raise Malformed("record seq must be positive")
        except Malformed as e:
            found.append(f"{where}: malformed: {e}")
            prev, prev_seq, last_seq = None, None, None
            continue
        where += f" (seq {seq})"
        if h != rec.get("hash"):
            found.append(f"{where}: digest mismatch (recomputed {h[:16]}, carried {str(rec.get('hash'))[:16]}): the record was edited")
        error = _signature(rec, keys)
        if error:
            found.append(f"{where}: {error}")
        if i == 0:
            if seq == 1 and rec.get("prev_hash") != "":
                found.append(f"{where}: the genesis record does not have an empty prev_hash")
            if want_from is not None and seq != max(want_from, 1):
                found.append(f"{where}: the window asked from {want_from} but starts at {seq}: records are missing from its start")
        if prev is not None:
            if seq != prev_seq + 1:
                found.append(f"{where}: follows seq {prev_seq}: positions are not contiguous")
            if rec.get("prev_hash") != prev.get("hash"):
                found.append(f"{where}: prev_hash does not link to the record before it")
        prev, prev_seq, last_seq = rec, seq, seq
    if isinstance(head_body, dict):
        head = head_body.get("head")
        if head is None:
            if recs:
                found.append("the head read answers no head, but the range holds records")
        elif not isinstance(head, dict):
            found.append("the head is not an object")
        else:
            try:
                top = envelope_number(head.get("seq"), "head.seq")
                want = top if want_to is None else min(want_to, top)
                last = last_seq if recs else 0
                if last != want:
                    found.append(f"the window ends at seq {last}, the head says it must reach {want}: records are missing from its end")
                elif recs and want == top and recs[-1].get("hash") != head.get("hash"):
                    found.append("the last record's hash is not the head's hash")
                error = _signature(head, keys)
                if error:
                    found.append(f"head: {error}")
            except Malformed as e:
                found.append(str(e))
    return found


def seal(records, seed):
    """Build canonical wire records for the rig, without accepting numeric wire records in verify."""
    pk = ed25519.public_key(seed)
    kid = key_id(pk)
    prev, out = "", []
    for n, r in enumerate(records, 1):
        recipe = r.get("recipe", RECIPE)
        rec = copy.deepcopy(dict(r, prev_hash=prev, seq=n, recipe=recipe, key_id=kid))
        # Only fixture construction converts numbers. Parsing public evidence never does.
        for f in fields(recipe):
            if len(f) == 2:
                name, kind = f
                if kind == "number" and type(rec.get(name)) is int:
                    rec[name] = str(rec[name])
            else:
                count, member, parts = f
                if type(rec.get(count)) is int:
                    rec[count] = str(rec[count])
                for i, el in enumerate(rec[member]):
                    for sub, kind in parts:
                        if kind == "number":
                            if sub is None and type(el) is int:
                                rec[member][i] = str(el)
                            elif sub is not None and type(el.get(sub)) is int:
                                el[sub] = str(el[sub])
        rec["hash"] = digest(rec)
        rec["signature"] = ed25519.sign(seed, signing_input(rec["hash"])).hex()
        out.append(rec)
        prev = rec["hash"]
    common = {"recipe": RECIPE, "signature_domain": DOMAIN, "algorithm": "ed25519"}
    body = dict(common, **{"from": 1, "to": len(out), "records": out})
    keys = dict(common, keys=[{"key_id": kid, "algorithm": "ed25519", "public_key": pk.hex()}])
    last = out[-1] if out else None
    head = dict(common, next_seq=len(out) + 1,
                head=None if last is None else {"seq": number(last["seq"], "seq"), "hash": last["hash"],
                                               "signature": last["signature"], "key_id": kid,
                                               "wall": number(last["wall"], "wall")})
    return body, keys, head
