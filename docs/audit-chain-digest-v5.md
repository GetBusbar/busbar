<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 Busbar Inc and contributors -->

# The busbar audit chain, `busbar.audit.digest.v5`

V5 records the actual rate-card entry key that the sealing caller held. The audit
crate treats this as twenty opaque bytes and does not depend on a history ledger.
A missing attachment is distinct from an actual known all-zero entry key.

V2 and V4 records retain their original numeric ordinal, field order, preimage,
signature domain and journal bytes. Their original recipe pages remain unchanged.
A legacy ordinal is never interpreted as a current entry key. A mixed range names
each record's own recipe; the envelope names the current recipe.

When an old record is decoded, `Usage.rate_card_version` contains no actual key
(`None`); this does not assert that the old operation had no priced card. Its exact
ordinal stays in the V2/V4 recipe's `legacy_rate_card_version` metadata. The old
recipe's digest fields, journal encoding and range JSON still expose that same
ordinal as before (a canonical decimal string in JSON). No current history is
consulted to invent a key for it. V5 uses the presence/key representation below.

## Digest framing

The digest is SHA-256 over the following fields in order. Text is UTF-8, prefixed
by its byte length as a big-endian u64. A number is its big-endian u64 bytes,
prefixed by the big-endian u64 length 8. Repeated groups are framed once per
array element in order; their count is checked against the corresponding array.
Every published scalar is a JSON string: numbers use canonical unsigned decimal.
Signature algorithm, domain and trust/anchor limits are unchanged from V4.

| Position | Field | Kind |
| --- | --- | --- |
| 1 | `prev_hash` | text |
| 2 | `seq` | number |
| 3 | `subject_tag` | text |
| 4 | `subject_value` | text |
| 5 | `unit_key` | number |
| 6 | `incarnation` | number |
| 7 | `op_class` | text |
| 8 | `destination` | text |
| 9 | `parent` | number |
| 10 | `pre_hook_head` | text |
| 11 | `post_hook_head` | text |
| 12 | `wall` | number |
| 13 | `mono` | number |
| 14 | `node` | number |
| 15 | `origin_kind` | text |
| 16 | `outcome` | text |
| 17 | `step` | text |
| 18 | `finish` | text |
| 19 | `hook_failed` | number |
| 20 | `emission_delta` | text |
| 21 | `stale_policy` | number |
| 22 | `lines_count` | number |
| 23 | `lines[].class` | text |
| 24 | `lines[].quantity` | number |
| 25 | `lines[].source` | text |
| 26 | `lines[].estimated` | number |
| 27 | `tier_bp` | number |
| 28 | `fee_count` | number |
| 29 | `rate_card_key_present` | number |
| 30 | `rate_card_version` | text |
| 31 | `bucket_chain_ref` | text |
| 32 | `hold_ref` | text |
| 33 | `settle_ref` | text |
| 34 | `slice_ref` | text |
| 35 | `lease_ref` | text |
| 36 | `lease_epoch` | number |
| 37 | `policy_epoch` | number |
| 38 | `hooks_count` | number |
| 39 | `hooks[].hook` | text |
| 40 | `hooks[].head` | text |
| 41 | `hooks[].failed` | number |
| 42 | `replayed` | number |
| 43 | `children_count` | number |
| 44 | `children[]` | number |
| 45 | `correlation_hash` | text |

## Key representation and validation

`rate_card_key_present` is exactly the decimal string `"0"` or `"1"`.
For `"0"`, `rate_card_version` is exactly the empty string and no key is claimed.
For `"1"`, it is exactly forty lowercase ASCII hexadecimal digits, representing
all twenty original key bytes. Forty zero digits are a present key, not absence.
A verifier rejects another presence value, a mismatched presence/key pair,
uppercase or malformed spelling, an unsupported recipe or a malformed group.
Changing any key byte or the presence flag changes the preimage.

## Journal representation

New records use tag `audit.v5` and recipe `busbar.audit.digest.v5`. The old common
prefix and suffix remain, except that the ordinal slot is replaced by a presence
number 0 or 1 and, only when present, a u32-length-prefixed binary blob of exactly
twenty key bytes. It is not UTF-8 text. A reader rejects any other blob length,
truncation, bad presence flag, extra trailing bytes or mismatched tag/recipe.

Old V2/V4 records continue to encode under `audit.v4`, with the ordinal at its
original position. Decoding and re-encoding an old record does not reseal it,
change its digest/signature, or rewrite a chain. Head-only recovery reads original
head metadata without needing the historical meter vocabulary for either tag.
