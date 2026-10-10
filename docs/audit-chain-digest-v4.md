<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 Busbar Inc and contributors -->

# The busbar audit chain, `busbar.audit.digest.v4`

**`v4` is `v3` plus `incarnation` and `node`, and `v3` is still published.** A unit's key restarts
at every boot of a node, so `unit_key` alone named two different units across two boots;
`incarnation` — which boot of the node the unit ran in — follows `unit_key` directly, and the pair is
unique. Nodes share one store, and a monotonic reading compares only against readings of the node
that took it, so `node` — which node sealed the record — follows `mono` directly (the fixed record's
WHEN is "wall + monotonic, node"). `v4` adds those two number fields and changes nothing else: no
field is renamed, reordered or re-framed, and the signature domain is unchanged. `v3` never shipped,
so no node holds a `v3` record; its page,
[`audit-chain-digest-v3.md`](audit-chain-digest-v3.md), stays published as it was (and `v2` by
[`audit-chain-digest-v2.md`](audit-chain-digest-v2.md), `v1` by
[`audit-chain-digest-v1.md`](audit-chain-digest-v1.md)). Every record in a range body names the
recipe it was sealed under in its own `recipe` member, so a window that straddles the change says
which page checks which record.

**This is a public contract, not a description of an implementation.** It is written down so that a
third party can verify a busbar node's audit chain *without the busbar binary* — without our code,
our libraries, or our word for anything. If only busbar can verify busbar's chain then the chain is
a claim, and a claim is not evidence.

**The page is checked against itself, by something that cannot see the implementation.**
`crates/busbar-kernel/src/tests/members/audit/published_recipe_tests.rs` reads the field table below and
the worked example in section 7 — the published artifacts, nothing else — frames and hashes them by
the rules stated here, and compares the result against the digest this page and this build each
claim. It is forbidden from calling the three functions that *are* the recipe, and that ban is
enforced by a test that reads the check's own source rather than by a comment: a check that asked
the code what the answer is would go green on a build whose field order had drifted from this page,
which is precisely the failure worth catching. If the table below could not reproduce a real chain,
this page would be wrong and the build would say so.

---

## 1. What a signature here does and does not prove

| It proves | It does not prove |
| --- | --- |
| The record's fields are the ones that were sealed — any edit changes the digest. | That the operator did not rewrite the whole chain and re-sign it. |
| The record was produced by a holder of the published key, at seal time, in the node's own process. | That the node's clock was honest. |
| The run of records is contiguous and unbroken between the positions you fetched. | That records before or after the window you fetched exist, unless you check the head. |

**The claim boundary is load-bearing and we will not blur it.** An operator holding the signing key
can rewrite the chain AND re-sign it, and no amount of checking signatures will detect that. What
detects it is a head recorded somewhere the operator cannot reach — an **anchor** — and a node
cannot anchor to itself.

So a self-hosted node may honestly claim *signed and tamper-evident*: "prove it to yourself and your
auditor". Only an externally anchored head earns *"prove it to a counterparty who trusts neither of
us"*. Do not let a marketing claim outrun which of the two is deployed.

The signature is nonetheless **minted at seal time, in the sealing process, and this is the half
that cannot be added later.** A signature applied after the fact by a receiver proves that the
receiver got those bytes, not that the node produced them — so every record sealed before signing
exists is permanently unprovable, whatever is built afterwards.

---

## 2. The three reads

All three are `GET`, all three are read-only, and the node only ever **answers**. It opens no
outbound connection for any of this, holds no cloud credential, and phones nobody. That is what lets
a firewalled node be audited and an airgapped operator `curl` their own evidence.

| Read | Answers with |
| --- | --- |
| `GET /api/v1/admin/audit/head` | The chain's tip: position, digest, signature, key identifier, clock — plus `next_seq`. |
| `GET /api/v1/admin/audit/range?from=&to=` | Records by position, inclusive at both ends, each carrying **every field its digest was taken over**, plus the digest, the signature and the key identifier. |
| `GET /api/v1/admin/audit/keys` | The public keys, so a verifier never has to ask us for a key out of band. |

The range read carries the records' *digest inputs*, already reduced to the exact text or number
that goes into the preimage. That is deliberate: a verifier should not have to reimplement our enum
spellings to check a signature.

A range whose window runs off either end of what the node holds is **shorter**, not an error.

---

## 3. The digest

```
hash = SHA-256( framed(field₁) ‖ framed(field₂) ‖ … ‖ framed(field₄₂) )
```

rendered as **64 lowercase hexadecimal characters**.

### 3.1 Framing: length-prefixed, never separator-joined

```
framed(text)   = be_u64(len(utf8_bytes)) ‖ utf8_bytes
framed(number) = be_u64(8)               ‖ be_u64(value)
```

`be_u64` is the unsigned 64-bit big-endian encoding. Fields are concatenated with **nothing between
them**.

**Why this and not a separator.** These fields hold arbitrary caller-named text — an operation class
a caller named, a destination, a bucket chain reference, a tool name that came in from upstream. A
separator-joined digest is only safe while no field can contain the separator, and that is a
property of today's *values*, not of the code: it stops being true the first time somebody names a
tool with a bar in it. Length prefixes make the split between fields unforgeable whatever the fields
hold, so a caller who controls one field's bytes cannot make the same byte stream read as a
different split.

The previous release's *admin mutation* chain does use a bar-joined framing, and keeps it, because
its records are already on disk. That is a different stream with a different tag; it is not this one.

### 3.2 Text and number are different framings, and getting it wrong looks like tampering

`framed(7)` and `framed("7")` are different byte strings. A verifier that treats `tier_bp` as text,
or `emission_delta` as a number, computes a different digest and will report an honest chain as tampered.
The `kind` column below is not documentation, it is part of the contract. The published body keeps
the distinction visible: recipe numbers are JSON numbers, recipe texts are JSON strings.

### 3.3 Wide numbers travel as text

`emission_delta` is signed. It is digested as its **decimal text** (`"-7"`) and published as a JSON
**string**, because
a JSON number wide enough to hold them is not safely readable by most parsers — and through an
`f64` it is not readable at all.

### 3.4 Absent optional fields digest as the empty string

`destination`, `pre_hook_head`, `post_hook_head`, `step`, `hold_ref`, `settle_ref`, `slice_ref`,
`lease_ref` and `correlation_hash` digest as `""` when absent; `parent` digests as `0`. In the
published body they appear with their digest value (the empty string), so what you read is what you
frame.

### 3.5 The repeated groups

`lines`, `hooks` and `children` are each preceded by their own **count** field, which is itself
digested. The count is what stops two different groupings of the same values from digesting
identically. Elements are framed in order, each element's members in the order below.

### 3.6 The field order

| # | Field | Kind |
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
| 29 | `rate_card_version` | number |
| 30 | `bucket_chain_ref` | text |
| 31 | `hold_ref` | text |
| 32 | `settle_ref` | text |
| 33 | `slice_ref` | text |
| 34 | `lease_ref` | text |
| 35 | `lease_epoch` | number |
| 36 | `policy_epoch` | number |
| 37 | `hooks_count` | number |
| 38 | `hooks[].hook` | text |
| 39 | `replayed` | number |
| 40 | `children_count` | number |
| 41 | `children[]` | number |
| 42 | `correlation_hash` | text |

Fields 22–25 repeat once per usage line, 37 once per hook, 40 once per child unit.

`subject_tag` is one of `principal`, `arrival`, `node`, `aggregate`; `subject_value` is the
principal identifier for a principal, the node's number for a node, and empty otherwise. `node` (field
14) is the node that SEALED the record, whoever the subject is: the node half of every store `op_id`
the sealing process mints. `outcome`, `step`,
`finish` and `lines[].source` are frozen text spellings the node publishes verbatim — you never need
to derive them, only to frame what you were given.

---

## 4. The signature

```
preimage  = "busbar.audit.record.v1" ‖ 0x00 ‖ hash_as_64_lowercase_hex_ascii
signature = Ed25519-Sign(private_key, preimage)      # published as 128 lowercase hex characters
```

Verification is **strict** Ed25519 (RFC 8032 with the cofactorless equation and the canonical-`S`
check), the same rule `ed25519-dalek`'s `verify_strict` applies. A small-order public key is
refused, because it would verify every signature.

The digest goes into the preimage as its **hex text**, not as the 32 raw bytes it spells, because
the hex text is what the record carries and what a reader actually read — one less place for two
implementations to differ over case, padding or whitespace.

The domain prefix is not decoration. Without it, a signature over a bare SHA-256 could be replayed
from any other protocol that signs a SHA-256 with the same key.

### 4.1 Key identifiers are derived, not assigned

```
key_id = first 8 bytes of SHA-256(public_key_bytes), as 16 lowercase hex characters
```

Derived so that a verifier holding the published key can **recompute** it rather than be told it.
A key set whose `key_id` is not the derivation of its own key should be refused, and
`the_published_key_set_checks_the_published_examples_signature` refuses one here.

The identifier is a name, not a fingerprint to trust: what proves a record is the **signature**
checked against the published key, never the identifier.

Keys are only ever **added** to the published set. Removing one makes every record it signed
unverifiable, which is indistinguishable from those records having been forged.

---

## 5. Checking the chain, not just the records

1. **Link and position.** Record *n*'s `prev_hash` is record *n−1*'s `hash`, and `seq` is
   contiguous. The genesis record has `prev_hash == ""` and `seq == 1`.
2. **Digest.** Recompute each `hash` from the published fields. A mismatch means that record was
   edited.
3. **Signature.** Check each `signature` against the published key named by `key_id`.
4. **The tail.** A run of records whose last record was dropped still links and numbers perfectly
   among themselves — a truncation is invisible from the records alone. Compare against the head
   read: a window that asked for `..to` and stopped short of `min(to, head.seq)` has records missing
   from its end.
5. **The window's anchor.** A range you cannot trace back to the genesis is a window. Its `anchor`
   member is the head this node published at or before `to` — and that anchor is what you compare
   against a head you recorded yourself, earlier, elsewhere.

An **empty** run verifies, deliberately: "this chain has no records" and "every record was deleted"
are indistinguishable from the records alone, and claiming otherwise would claim a guarantee nothing
can provide.

---

## 6. Head history survives a restart

A head is about a hundred bytes. Sampled hourly, that is 8 760 a year — under a megabyte. A node
that cannot afford a megabyte a year cannot afford an audit chain either, so nothing ages a head out.

The heads are rebuilt from the records at every boot: a head is a pure function of the record it was
taken after and of the sampling rule, and the node's journal keeps every record, so after a restart
the head read answers with the tip the chain really has and a window's `anchor` is the one it was
before. A chain that has sealed nothing answers `"head": null` with `"next_seq": 1`; a non-empty
chain never answers a null head.

The genesis head is always kept, whatever the sampling rate.

---

## 7. A worked example

A single-record chain, sealed by node `5` with the RFC 8032 test key
`9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60` (public half
`d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`, key id `21fe31dfa154a261`). Its
preimage is 489 bytes; the digest is
`823fc6aa2108c9a8a3490d5c27f799eee1e0678cb3928c66e53c374a50eeea1c`.

`GET /api/v1/admin/audit/range?from=1&to=1`:

```json
{
  "recipe": "busbar.audit.digest.v4",
  "signature_domain": "busbar.audit.record.v1",
  "algorithm": "ed25519",
  "from": 1,
  "to": 1,
  "anchor": {
    "seq": 1,
    "hash": "823fc6aa2108c9a8a3490d5c27f799eee1e0678cb3928c66e53c374a50eeea1c",
    "signature": "5130255432a8e50196fda054ca72bf34a1104b8eb1308e1da1e3fd82ecc1aec092229a6d9a6c017d5543a5b8dd30343f5d1f5452b075fe3bfb7117a35ce9a506",
    "key_id": "21fe31dfa154a261",
    "wall": 1700000000
  },
  "records": [
    {
      "prev_hash": "",
      "seq": 1,
      "subject_tag": "node",
      "subject_value": "7",
      "unit_key": 9,
      "incarnation": 2,
      "op_class": "chat.completion",
      "destination": "",
      "parent": 0,
      "pre_hook_head": "",
      "post_hook_head": "",
      "wall": 1700000000,
      "mono": 42,
      "node": 5,
      "origin_kind": "client",
      "outcome": "Completed",
      "step": "",
      "finish": "Error",
      "hook_failed": 1,
      "emission_delta": "-7",
      "stale_policy": 1,
      "lines_count": 0,
      "lines": [],
      "tier_bp": 9000,
      "fee_count": 1,
      "rate_card_version": 3,
      "bucket_chain_ref": "chain:free>paid",
      "hold_ref": "",
      "settle_ref": "",
      "slice_ref": "",
      "lease_ref": "",
      "lease_epoch": 4,
      "policy_epoch": 7,
      "hooks_count": 0,
      "hooks": [],
      "replayed": 1,
      "children_count": 0,
      "children": [],
      "correlation_hash": "",
      "hash": "823fc6aa2108c9a8a3490d5c27f799eee1e0678cb3928c66e53c374a50eeea1c",
      "signature": "5130255432a8e50196fda054ca72bf34a1104b8eb1308e1da1e3fd82ecc1aec092229a6d9a6c017d5543a5b8dd30343f5d1f5452b075fe3bfb7117a35ce9a506",
      "key_id": "21fe31dfa154a261",
      "recipe": "busbar.audit.digest.v4"
    }
  ]
}
```

`GET /api/v1/admin/audit/head`:

```json
{
  "recipe": "busbar.audit.digest.v4",
  "signature_domain": "busbar.audit.record.v1",
  "algorithm": "ed25519",
  "next_seq": 2,
  "head": {
    "seq": 1,
    "hash": "823fc6aa2108c9a8a3490d5c27f799eee1e0678cb3928c66e53c374a50eeea1c",
    "signature": "5130255432a8e50196fda054ca72bf34a1104b8eb1308e1da1e3fd82ecc1aec092229a6d9a6c017d5543a5b8dd30343f5d1f5452b075fe3bfb7117a35ce9a506",
    "key_id": "21fe31dfa154a261",
    "wall": 1700000000
  }
}
```

`GET /api/v1/admin/audit/keys`:

```json
{
  "recipe": "busbar.audit.digest.v4",
  "signature_domain": "busbar.audit.record.v1",
  "algorithm": "ed25519",
  "keys": [
    {
      "key_id": "21fe31dfa154a261",
      "algorithm": "ed25519",
      "public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    }
  ]
}
```

Checking it, with nothing but this page: walk the field table in section 3.6, take each member
named there out of the record above, frame it (`be_u64(len) ‖ bytes` for a text, `be_u64(8) ‖
be_u64(v)` for a number), concatenate with nothing between, and SHA-256 the result. You get
`823fc6aa2108c9a8a3490d5c27f799eee1e0678cb3928c66e53c374a50eeea1c`, which is the `hash` the record
carries. Then prepend `busbar.audit.record.v1` and one `0x00` byte to those 64 hex characters and
check the `signature` against the `public_key` above with any ed25519 implementation you already
trust.

Three tests hold this section down, in
`crates/busbar-kernel/src/tests/members/audit/published_recipe_tests.rs`:

* `the_published_table_reproduces_the_published_examples_digest` — the page checks out on its own
  terms, over committed artifacts only, with no chain sealed and no source consulted.
* `the_published_table_still_describes_what_this_build_seals` — a record sealed by this build,
  published through the range read, and re-digested **from the table above**. This is the one that
  catches a build whose field order drifted: such a build agrees with itself perfectly, so every
  other test in the crate stays green.
* `the_published_key_set_checks_the_published_examples_signature` — the derived key identifier and
  the preimage spelling are re-derived from this page, not from the code's constants.

The three bodies are also asserted to be **this build's own output** by
`the_worked_example_in_the_published_spec_is_what_this_build_answers_with` in
`crates/busbar-kernel/src/tests/members/audit/sign_tests.rs`. The page cannot drift from the code without
one of these going red.

---

## 8. Versioning

Every published body names `"recipe": "busbar.audit.digest.v4"` — the recipe this node seals under
now — and `"signature_domain": "busbar.audit.record.v1"`. Every record in a range body also names
the recipe IT was sealed under, in its own `recipe` member, which is not a digest input. A verifier
should refuse a recipe it does not know rather than guess.

`v4` lives **beside** `v2`, and the `v3` and `v1` pages stay published as the history of the field
list. A record sealed under `v2` is checked by the `v2` page, whose field order has not changed and
never will; a node does not rewrite it. The signature domain did not move, because what is signed did
not change — the digest's hex text — only which fields the digest is taken over. Moving a record
between recipes is itself caught: a `v2` record relabelled `v4` loses `currency` and gains
`incarnation` and `node` in its preimage, and no longer hashes to its sealed digest.
`crates/busbar-kernel/src/tests/members/audit/record_tests.rs` pins the `v2` and `v4` digests a fully
populated record froze and the relabelling arms; `published_recipe_tests.rs` proves off the two pages
alone that `v4` is `v3` plus exactly `incarnation` and `node`
(`the_v3_page_is_kept_and_v4_is_v3_plus_incarnation_and_node`).

`node` entered `v4` before the 1.6.0 tag, while `v4` was still being defined and before any release
sealed a `v4` record (the owner's 2026-09-28 rule for a layout's first version: it is edited in place,
with its golden regenerated in the same commit, until the tag). From the 1.6.0 tag on, a future recipe
gets a new name and lives **beside** these. The field order here then never changes: moving it would
make every chain already on disk report its own history as tampered at the next boot, which is the
one migration this contract may never make quietly.
