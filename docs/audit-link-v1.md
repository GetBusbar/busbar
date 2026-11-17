<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 Busbar Inc and contributors -->

# The busbar audit link line, `busbar.audit.link.v1`

The offline verifier supports direct Bootstrap-signed pages and breaks under the explicit
trust requirements in [audit-verify.md](audit-verify.md). Delegated authority proof remains
unsupported by that tool; a certificate or unsigned WAL position alone is insufficient.

The link line (journal tag `audit.v8`) is the audit line of SEALING-FIX: it is
linked to its predecessor by a fingerprint and carries no signature of its own.
Authorship is proven for a whole page of lines at once by a page stamp
(`audit.stamp.v1`) over the newest line's fingerprint: a stamp over line M,
together with the digest-and-link walk from a line up to M, vouches for every
link line of the page. Older lines (`busbar.audit.digest.v2` to `v7`) keep
verifying by their own recipe page and their own per-line signature.

## Content

The line carries every field of `busbar.audit.digest.v7`, with the same names and
the same order, plus one field:

- `linked_ms`: the wall clock in milliseconds since the epoch, read when the line
  was linked into the chain. It is the date every sealing rule uses. The arrival
  `wall` (seconds) is not used by any sealing rule.

## Fingerprint

The fingerprint is SHA-256 (every crypto backend, FIPS included) over these
fields, each framed as in `busbar.audit.digest.v7` (a big-endian u64 byte length,
then the bytes; a number is its eight big-endian bytes):

1. every `busbar.audit.digest.v7` field after `seq` (from `subject_tag` through
   `attempts_total`, then the records tail when the line keeps one), in that
   recipe's order;
2. `linked_ms` (number);
3. `seq` (number);
4. `prev_hash` (`bytes32`: the predecessor's 32 raw fingerprint bytes; 32 zero
   bytes for a chain's first line).

The content comes first so it can be hashed before the chain is read; only the
last three fields are absorbed in chain order.

The following suffix table is embedded by the offline verifier after the v7 content
fields, including the optional records tail when present:

| Position | Field | Kind |
|---|---|---|
| 1 | `linked_ms` | number |
| 2 | `seq` | number |
| 3 | `prev_hash` | bytes32 |

| Kind | Framing | Published as |
|---|---|---|
| `bytes32` | the 32 raw bytes, length-prefixed (length 32) | 64 lowercase hex digits |

A line whose recipe a build cannot compute is refused with
`AUDIT_RECIPE_UNSUPPORTED`, never treated as verified.

## Journal body

`audit.v8`, `busbar.audit.link.v1`, `seq`, `prev_hash` (32 bytes), `hash`
(32 bytes), `linked_ms`, then the `audit.v7` body's fields from the subject on.
There is no `signature` and no `key_id`.

## Page stamp, `audit.stamp.v1`

The stamp's signature is over `busbar.audit.stamp.v1`, a NUL byte, then these
fields, each length-prefixed: `node`, `from`, `to`, `fingerprint` (32 bytes),
`kind` (`live`, `final` or `after_restart`), `sealer`, `host`, `every`,
`stamped_ms`, `down_from_ms`, `down_to_ms` (0 unless `after_restart`), `crypto`,
`sig_alg`, `key_id`, `key_cert`. An `after_restart` page is signed by the
deployment (Bootstrap) key only, with `key_cert` 0.

## Break notice, `audit.break.v1`

A break notice records where a node's chain could not be vouched for. Its
signature, always by the deployment key, is over `busbar.audit.break.v1`, a NUL
byte, then: `node`, `sealer`, `last_good`, `unsealed_from`, `unsealed_to`,
`journal_from`, `journal_to`, `reason`, `detected_ms`, `host`, `crypto`,
`sig_alg`, `key_id`. A break notice vouches for no line.
