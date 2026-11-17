<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 Busbar Inc and contributors -->

# The busbar audit link line, `busbar.audit.link.v1`

This page is the whole contract for checking a busbar audit chain from the outside: the link
line, its fingerprint, the page stamp and the break notice that vouch for lines, and the
`notary_key` certificate line. The offline verifier, `busbar-audit-verify`
([audit-verify.md](audit-verify.md)), embeds this page and reads its field table; nothing else
is needed.

The link line (journal tag `audit.v8`) is the audit line every unit seals. It is linked to its
predecessor by a fingerprint and carries no signature of its own. Authorship is proven for a whole
page of lines at once by a page stamp (`audit.stamp.v1`) over the newest line's fingerprint: a
stamp over line M, together with the digest-and-link walk from a line up to M, vouches for every
line of the page. A line after the last stamp is not yet vouched for; a verifier reports it as
unauthenticated, never as sealed.

## Fields

The fingerprint is SHA-256 (every crypto backend, FIPS included) over the fields of the table
below, in position order. Each field is framed by its byte length as a big-endian u64, then its
bytes:

| Kind | Framing | Published as |
|---|---|---|
| `text` | the UTF-8 bytes | the text, as a JSON string |
| `number` | the length 8, then the value's eight big-endian bytes | its canonical decimal text, as a JSON string |
| `bytes32` | the length 32, then the 32 raw bytes | 64 lowercase hex digits; the empty text for 32 zero bytes |

The `kind` column is part of the contract, and the only place a field's framing is stated: the
range read publishes every field as a JSON string, so the JSON type does not say how to frame it.
`7` framed as a number and `"7"` framed as text are different bytes. Canonical decimal text is
unsigned ASCII digits with no sign, no whitespace and no leading zero other than `0` itself, and
fits in an unsigned 64-bit integer; a verifier refuses anything else, and refuses a number published
as a JSON number.

A field named `group[].member` (or `group[]`) repeats once per element of the published array
`group`, framed element by element, in order; the element count is the field `group_count` before
it, and a verifier refuses a count that differs from the array's length.

| Position | Field | Kind |
| --- | --- | --- |
| 1 | `subject_tag` | text |
| 2 | `subject_value` | text |
| 3 | `unit_key` | number |
| 4 | `incarnation` | number |
| 5 | `op_class` | text |
| 6 | `destination` | text |
| 7 | `parent` | number |
| 8 | `pre_hook_head` | text |
| 9 | `post_hook_head` | text |
| 10 | `wall` | number |
| 11 | `mono` | number |
| 12 | `node` | number |
| 13 | `origin_kind` | text |
| 14 | `outcome` | text |
| 15 | `step` | text |
| 16 | `finish` | text |
| 17 | `hook_failed` | number |
| 18 | `emission_delta` | text |
| 19 | `stale_policy` | number |
| 20 | `lines_count` | number |
| 21 | `lines[].class` | text |
| 22 | `lines[].quantity` | text |
| 23 | `lines[].source` | text |
| 24 | `lines[].estimated` | number |
| 25 | `tier_bp` | number |
| 26 | `fee_count` | number |
| 27 | `rate_card_key_present` | number |
| 28 | `rate_card_version` | text |
| 29 | `bucket_chain_ref` | text |
| 30 | `hold_ref` | text |
| 31 | `settle_ref` | text |
| 32 | `slice_ref` | text |
| 33 | `lease_ref` | text |
| 34 | `lease_epoch` | number |
| 35 | `policy_epoch` | number |
| 36 | `hooks_count` | number |
| 37 | `hooks[].hook` | text |
| 38 | `hooks[].head` | text |
| 39 | `hooks[].failed` | number |
| 40 | `replayed` | number |
| 41 | `children_count` | number |
| 42 | `children[]` | number |
| 43 | `correlation_hash` | text |
| 44 | `wall_ms` | number |
| 45 | `attribution` | text |
| 46 | `boot_nonce` | text |
| 47 | `status` | number |
| 48 | `ttft_us` | number |
| 49 | `total_us` | number |
| 50 | `attempts_count` | number |
| 51 | `attempts[].outcome` | text |
| 52 | `attempts[].target` | text |
| 53 | `attempts[].reason` | text |
| 54 | `attempts[].us` | number |
| 55 | `attempts_total` | number |

### The records tail

Positions 56 to 60 follow position 55 only when the line keeps an end user or a label
(`user_present` is then `"1"` or `"0"`, and at least one of `user` and `labels` is set). A line
that keeps neither has no tail; a verifier frames the tail exactly when the published line carries
`user_present`. An empty tail is never framed, so each line has one framing.

| Position | Field | Kind | Present |
| --- | --- | --- | --- |
| 56 | `user_present` | number | records tail |
| 57 | `user` | text | records tail |
| 58 | `labels_count` | number | records tail |
| 59 | `labels[].name` | text | records tail |
| 60 | `labels[].value` | text | records tail |

### The link

The content comes first so it can be hashed before the chain is read; these three fields are
absorbed last, in chain order:

| Position | Field | Kind |
| --- | --- | --- |
| 61 | `linked_ms` | number |
| 62 | `seq` | number |
| 63 | `prev_hash` | bytes32 |

`prev_hash` is the predecessor's fingerprint (32 zero bytes, published as the empty text, for a
chain's first line). `seq` counts from one and is contiguous. A verifier recomputes every line's
fingerprint, requires it to equal the published `hash`, and requires each `prev_hash` to equal the
previous line's `hash` and each `seq` to be the previous one plus one.

### What the fields hold

- `subject_tag` is one of `principal`, `arrival`, `node`, `aggregate`; `subject_value` is the
  principal identifier for a principal, the node's number for a node, and empty otherwise.
- `node` is the node that linked the line, whoever the subject is. It is a uniform 64-bit value,
  above 2^53 on almost every node, which is why numbers travel as decimal text.
- `outcome`, `step`, `finish`, `origin_kind` and `lines[].source` are frozen spellings the node
  publishes verbatim; a verifier frames what it was given and never derives them. An absent
  optional text (`destination`, a hook head, `hold_ref` and the other references,
  `correlation_hash`) is the empty text; an absent `parent` is 0.
- `emission_delta` is signed, so it is a text field: its decimal text, such as `-7`.
- `lines[].quantity` is canonical scale-six decimal text: no sign, no exponent, no leading zero
  except before the decimal point, and no trailing fractional zero. `27`, `27.5` and `0.000001`
  are valid; `27.50`, `27.0` and `1e3` are refused.
- `rate_card_key_present` is `0` with an empty `rate_card_version`, or `1` with forty lowercase
  hexadecimal digits (the sealed rate-card entry key). Any other spelling is refused.
- `hooks[]` are the hooks that ran, in order: `hook` is the key the deployment configured, `head`
  is `pass`, `veto` or `modify`, and `failed` is `1` when the hook could not answer.
- `wall` is the arrival in whole seconds, `mono` a monotonic reading, and `wall_ms` the arrival in
  milliseconds. `linked_ms` is the wall clock in milliseconds read when the line was linked; it is
  the date every sealing rule uses, and the arrival times are used by none.
- `attribution` is the unit's metering `group`, `pool` and `provider`, joined by U+001F, each empty
  when absent. `boot_nonce` is the sealing process's 16-byte boot nonce as 32 lowercase hex digits
  (all zero when it had none); with `node` and `unit_key` it forms the node-qualified unit id
  `node_<16 hex>.<boot_nonce>.<unit_key>`.
- `status`, `ttft_us` and `total_us` are the answer's HTTP status and timing in microseconds; 0
  means none or not measured. `attempts[]` holds at most four attempts, each with `outcome` (`ok`,
  `failover`, `failed` or `cancelled`), `target`, `reason` and `us`; `attempts_total` counts every
  attempt, including those beyond the four.
- `user` is the end user as kept (a pseudonym `u_` and 32 hex digits, or the plain value cut to
  128 bytes); `labels[]` holds at most eight allow-listed request headers, each `name` (lower case)
  and `value` (verbatim, at most 128 bytes), in the allow-list's order.

A line whose recipe a build cannot compute is refused with `AUDIT_RECIPE_UNSUPPORTED`, never
treated as verified.

## Journal body

`audit.v8`, `busbar.audit.link.v1`, `seq`, `prev_hash` (32 bytes), `hash` (32 bytes),
`linked_ms`, then the line's content fields from the subject on, as the journal encodes them. There
is no `signature` and no `key_id`.

## Page stamp, `audit.stamp.v1`

A stamp vouches for the lines `from` through `to` of one node's chain: its `fingerprint` is line
`to`'s, and the walk from any line of the page to line `to` must recompute and link. Its signature
is over `busbar.audit.stamp.v1`, a NUL byte, then these fields, each framed by its big-endian u64
length: `node`, `from`, `to`, `fingerprint` (32 bytes), `kind` (`live`, `final` or
`after_restart`), `sealer`, `host`, `every`, `stamped_ms`, `down_from_ms`, `down_to_ms` (0 unless
`after_restart`), `crypto`, `sig_alg`, `key_id`, `key_cert`. Numbers are framed as their eight
big-endian bytes.

Pages are contiguous and never overlap: each page's `from` is the previous page's `to` plus one,
unless a break notice accounts for the lines between them.

Which key may sign which page:

- An `after_restart` page is signed by the deployment (Bootstrap) key, with `key_cert` 0. Its
  `sealer` may be a successor node on the same host.
- A `live` or `final` page is signed by the Bootstrap key with `key_cert` 0, or by the per-boot
  notary key certified by the `notary_key` line whose WAL position is `key_cert`. That key must
  still be current at the page: a later certificate line, or a `final` or `after_restart` page
  between the certificate and the page, ends it.

## Break notice, `audit.break.v1`

A break notice records where a node's chain could not be vouched for. Its signature, always by the
Bootstrap key, is over `busbar.audit.break.v1`, a NUL byte, then: `node`, `sealer`, `last_good`,
`unsealed_from`, `unsealed_to`, `journal_from`, `journal_to`, `reason`, `detected_ms`, `host`,
`crypto`, `sig_alg`, `key_id`. A break notice vouches for no line; the lines it names are reported
as unsealed.

## Certificate line, `audit.notary_key.v2`

A `notary_key` line takes a chain `seq` and links like any line, but its fingerprint is SHA-256
over these fields, each framed by its big-endian u64 length: `busbar.audit.notary_key.record.v2`,
`node`, `key_id`, `sig_alg`, `public_key` (raw: 32 bytes for `ed25519`, 65 bytes uncompressed SEC 1
for `ecdsa-p256-sha256`), `signed_by`, `signature` (64 raw bytes), `linked_ms`, `seq`, `prev_hash`
(32 bytes). The range read publishes it with `recipe` set to that domain, the certificate's
fields as text (`public_key` and `signature` as lowercase hex) and the WAL `node_seq` a stamp's
`key_cert` names.

The certificate is signed by the Bootstrap key named by `signed_by`, over
`busbar.audit.notary_key.v2`, a NUL byte, then `node`, `seq`, `prev_hash` (taken from the line
itself), `key_id`, `sig_alg` and `public_key`, each framed by its big-endian u64 length. `key_id` is
the first eight bytes of the SHA-256 of `public_key`, as 16 lowercase hex digits.
