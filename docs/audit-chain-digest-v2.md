<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (C) 2026 Busbar Inc and contributors -->

# The busbar audit chain, `busbar.audit.digest.v2`

**`v2` is `v1` less three priced fields, and `v1` is still published.** A record stores COUNTS
and the inputs a price is computed from — the tier, the fee count, the rate card version — never a
priced figure: money is computed when it is read, from the counts and the rate card in force. So
`v2` drops `pre_tier`, `priced` and `hooks[].priced_delta` from the `v1` field order and changes
nothing else: no field is renamed, reordered or re-framed, and the signature domain is unchanged. A
body naming `"recipe": "busbar.audit.digest.v1"` is checked by
[`audit-chain-digest-v1.md`](audit-chain-digest-v1.md), which is kept exactly as it was published;
a body naming `v2` is checked by this page.

**This is a public contract, not a description of an implementation.** It is written down so that a
third party can verify a busbar node's audit chain *without the busbar binary* — without our code,
our libraries, or our word for anything. If only busbar can verify busbar's chain then the chain is
a claim, and a claim is not evidence.

**The page is checked against itself, by something that cannot see the implementation.**
`crates/busbar-kernel-audit/src/tests/published_recipe_tests.rs` reads the field table below and
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
hash = SHA-256( framed(field₁) ‖ framed(field₂) ‖ … ‖ framed(field₄₁) )
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
| 6 | `op_class` | text |
| 7 | `destination` | text |
| 8 | `parent` | number |
| 9 | `pre_hook_head` | text |
| 10 | `post_hook_head` | text |
| 11 | `wall` | number |
| 12 | `mono` | number |
| 13 | `origin_kind` | text |
| 14 | `outcome` | text |
| 15 | `step` | text |
| 16 | `finish` | text |
| 17 | `hook_failed` | number |
| 18 | `emission_delta` | text |
| 19 | `stale_policy` | number |
| 20 | `lines_count` | number |
| 21 | `lines[].class` | text |
| 22 | `lines[].quantity` | number |
| 23 | `lines[].source` | text |
| 24 | `lines[].estimated` | number |
| 25 | `tier_bp` | number |
| 26 | `fee_count` | number |
| 27 | `currency` | text |
| 28 | `rate_card_version` | number |
| 29 | `bucket_chain_ref` | text |
| 30 | `hold_ref` | text |
| 31 | `settle_ref` | text |
| 32 | `slice_ref` | text |
| 33 | `lease_ref` | text |
| 34 | `lease_epoch` | number |
| 35 | `policy_epoch` | number |
| 36 | `hooks_count` | number |
| 37 | `hooks[].hook` | text |
| 38 | `replayed` | number |
| 39 | `children_count` | number |
| 40 | `children[]` | number |
| 41 | `correlation_hash` | text |

Fields 21–24 repeat once per usage line, 37 once per hook, 40 once per child unit.

`subject_tag` is one of `principal`, `arrival`, `node`, `aggregate`; `subject_value` is the
pseudonym for a principal, the node's number for a node, and empty otherwise. `outcome`, `step`,
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

## 6. Head history outlives record retention

Records age out; an operator is entitled to a retention window. Heads do not age out at all.

A head is about a hundred bytes. Sampled hourly, that is 8 760 a year — under a megabyte. A node
that cannot afford a megabyte a year cannot afford an audit chain either.

So a puller that was offline while a window's records were pruned has lost the records, which was
the deal, and **still has the anchor for that window**, which was never on the table. The retention
pass cannot reach the head history: `AuditChain::prune_records_before` takes `&self`, so it cannot
borrow the anchors mutably at all, and that is a compile error rather than a request.

The genesis head is always kept, whatever the sampling rate.

---

## 7. A worked example

A single-record chain, sealed with the RFC 8032 test key
`9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60` (public half
`d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`, key id `21fe31dfa154a261`). Its
preimage is 468 bytes; the digest is
`4efb8ac1465c9894e4d44aca49670f040db93ed8a16e08a19225e76f499c2eb8`.

`GET /api/v1/admin/audit/range?from=1&to=1`:

```json
{
  "recipe": "busbar.audit.digest.v2",
  "signature_domain": "busbar.audit.record.v1",
  "algorithm": "ed25519",
  "from": 1,
  "to": 1,
  "anchor": {
    "seq": 1,
    "hash": "4efb8ac1465c9894e4d44aca49670f040db93ed8a16e08a19225e76f499c2eb8",
    "signature": "bb19a411d8b99124149b8c237b45ac80d701687463e44861a7938b380c38e078927ff4996a359c2ffc1f34c3ea579577366650fe2d521c2265ed6c1765e49c0f",
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
      "op_class": "chat.completion",
      "destination": "",
      "parent": 0,
      "pre_hook_head": "",
      "post_hook_head": "",
      "wall": 1700000000,
      "mono": 42,
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
      "currency": "USD",
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
      "hash": "4efb8ac1465c9894e4d44aca49670f040db93ed8a16e08a19225e76f499c2eb8",
      "signature": "bb19a411d8b99124149b8c237b45ac80d701687463e44861a7938b380c38e078927ff4996a359c2ffc1f34c3ea579577366650fe2d521c2265ed6c1765e49c0f",
      "key_id": "21fe31dfa154a261"
    }
  ]
}
```

`GET /api/v1/admin/audit/head`:

```json
{
  "recipe": "busbar.audit.digest.v2",
  "signature_domain": "busbar.audit.record.v1",
  "algorithm": "ed25519",
  "next_seq": 2,
  "head": {
    "seq": 1,
    "hash": "4efb8ac1465c9894e4d44aca49670f040db93ed8a16e08a19225e76f499c2eb8",
    "signature": "bb19a411d8b99124149b8c237b45ac80d701687463e44861a7938b380c38e078927ff4996a359c2ffc1f34c3ea579577366650fe2d521c2265ed6c1765e49c0f",
    "key_id": "21fe31dfa154a261",
    "wall": 1700000000
  }
}
```

`GET /api/v1/admin/audit/keys`:

```json
{
  "recipe": "busbar.audit.digest.v2",
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
`4efb8ac1465c9894e4d44aca49670f040db93ed8a16e08a19225e76f499c2eb8`, which is the `hash` the record
carries. Then prepend `busbar.audit.record.v1` and one `0x00` byte to those 64 hex characters and
check the `signature` against the `public_key` above with any ed25519 implementation you already
trust.

Three tests hold this section down, in
`crates/busbar-kernel-audit/src/tests/published_recipe_tests.rs`:

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
`crates/busbar-kernel-audit/src/tests/sign_tests.rs`. The page cannot drift from the code without
one of these going red.

---

## 8. Versioning

Every published body names `"recipe": "busbar.audit.digest.v2"` and
`"signature_domain": "busbar.audit.record.v1"`. A verifier should refuse a recipe it does not know
rather than guess.

`v2` lives **beside** `v1`, not in place of it: a `v1` body is checked by the `v1` page, whose field
order has not changed and never will. The signature domain did not move, because what is signed did
not change — the digest's hex text — only which fields the digest is taken over, and the body's
`recipe` member says which. The `v1` digest a fully populated record froze is still reproduced, from
a `v2` record with the three figures put back, by
`the_v1_frozen_digest_is_reproduced_by_v1_rules_from_a_v2_record` in
`crates/busbar-kernel-audit/src/tests/record_tests.rs` — which is also what proves `v2` is `v1`
less those three fields and nothing else.

A future recipe gets a new name and lives **beside** these two. The field order here never changes:
moving it would make every chain already on disk report its own history as tampered at the next
boot, which is the one migration this contract may never make quietly.
