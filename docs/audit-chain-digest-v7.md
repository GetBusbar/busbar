<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 Busbar Inc and contributors -->

# The busbar audit chain, `busbar.audit.digest.v7`

V7 is the recipe every new record is sealed under (ADMIN-API-1.6 section 3.2). It
keeps V6's fields, names and order, and frames EVERY quantity as V6's canonical
decimal text, whole or fractional, so a seal no longer chooses between two
recipes. After V6's last field it appends the per-unit facts the admin API's
`/records` read serves from sealed bytes only. V2, V4, V5 and V6 records remain
verify-only: each verifies by its own recipe page, and a mixed chain dispatches
each record by its explicit recipe and journal tag (`audit.v7` for this format).

The appended facts:

- `wall_ms`: the arrival in milliseconds since the epoch, the same reading `wall`
  carries in seconds.
- `attribution`: the unit's metering `group`, `pool` and `provider`, joined by
  U+001F, each empty when absent. It is never resolved from current configuration.
- `boot_nonce`: the sealing process's 16-byte boot nonce as 32 lowercase hex
  digits, all zero when the process had none. With `node` and `unit_key` it forms
  the node-qualified unit id `node_<16 hex>.<boot_nonce>.<unit_key>`.
- `status`, `ttft_us`, `total_us`: the answer's HTTP status and its timing in
  microseconds; 0 means none or not measured.
- `attempts`: at most four attempts, `attempts_count` of them, each with
  `outcome` (`ok`, `failover`, `failed` or `cancelled`), `target`, `reason` and
  `us`; `attempts_total` counts every attempt, including those beyond the four.
- `user` and `labels` (the records tail, optional): what the operator switched
  on with `records.user` and `records.labels`. `user` is the end user as kept
  (a pseudonym `u_` + 32 hex digits, or the plain value cut to 128 bytes);
  `labels` holds at most eight allow-listed request headers, each `name` (lower
  case) and `value` (verbatim, at most 128 bytes), in the allow-list's order.
  A record that keeps neither carries no tail at all, so every V7 record sealed
  before the tail existed keeps its bytes and its digest.

## Digest framing

The digest is SHA-256 over the following fields in order. Text is UTF-8, prefixed
by its byte length as a big-endian u64. A number is its big-endian u64 bytes,
prefixed by the big-endian u64 length 8. Repeated groups are framed once per
array element in order; their count is checked against the corresponding array.
Every published scalar is a JSON string: numbers use canonical unsigned decimal.
Quantities are canonical scale-six decimal text, exactly as V6 defines them;
whole quantities are text such as `27`. Signature algorithm, domain and
trust/anchor limits are unchanged from V4.

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
| 24 | `lines[].quantity` | text |
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
| 46 | `wall_ms` | number |
| 47 | `attribution` | text |
| 48 | `boot_nonce` | text |
| 49 | `status` | number |
| 50 | `ttft_us` | number |
| 51 | `total_us` | number |
| 52 | `attempts_count` | number |
| 53 | `attempts[].outcome` | text |
| 54 | `attempts[].target` | text |
| 55 | `attempts[].reason` | text |
| 56 | `attempts[].us` | number |
| 57 | `attempts_total` | number |

### The records tail

Positions 58 to 62 follow position 57 ONLY when the record keeps an end user or
a label (`user_present` is then `"1"` or `"0"`, and at least one of `user` and
`labels` is set). A record that keeps neither ends at position 57; a verifier
frames the tail exactly when the published record carries `user_present`. An
empty tail is never framed, so each record has one framing.

| Position | Field | Kind | Present |
| --- | --- | --- | --- |
| 58 | `user_present` | number | records tail |
| 59 | `user` | text | records tail |
| 60 | `labels_count` | number | records tail |
| 61 | `labels[].name` | text | records tail |
| 62 | `labels[].value` | text | records tail |

## Key representation and validation

The rate-card key is represented and validated exactly as in V5 and V6:
`rate_card_key_present` is `"0"` with an empty `rate_card_version`, or `"1"` with
forty lowercase hexadecimal digits. A verifier rejects any other spelling, a
noncanonical quantity, an unsupported recipe or a malformed group.

## Journal representation

V7 records use tag `audit.v7` and recipe `busbar.audit.digest.v7`. The body is
V6's body, every quantity as canonical decimal text, followed by the appended
facts in table order: `wall_ms` (u64), `attribution` (u32-length-prefixed UTF-8),
`boot_nonce` (a u32-length-prefixed blob of exactly 16 bytes), `status`,
`ttft_us`, `total_us` and the attempt count (u64 each; the count is at most 4),
each attempt's `outcome`, `target` and `reason` (u32-length-prefixed UTF-8) and
`us` (u64), then `attempts_total` (u64). When the record keeps a records tail,
the body goes on with `user` (u64 0 for none, or u64 1 and u32-length-prefixed
UTF-8), the label count (u64, at most 8) and each label's `name` and `value`
(u32-length-prefixed UTF-8); a body without it ends at `attempts_total`. A
reader rejects an unknown outcome, more than four attempts, a nonce of another
length, more than eight labels, an empty records tail, truncation, trailing
bytes or a mismatched tag/recipe. V5 and V6 records keep their original journal bytes.
