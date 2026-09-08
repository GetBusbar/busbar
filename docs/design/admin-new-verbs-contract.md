# busbar 1.6.0 — the contract of the new admin verbs

**Status: DESIGN, for owner review. No handler is implemented against this document yet.**

> **SUPERSEDED IN PART, 2026-09-08 (owner ruling; `ARCHITECTURE.md` §4.7 is the rule).** The admin
> API is DUMB: one admin tier, and policy — roles, who may call what, whether a change wants a second
> pair of eyes — lives in the calling application. **Five of the seventeen leave 1.6.0**:
> `set_operator_key`, `set_escrow`, `set_dual_control`, `approve` and `export_keyset`; their rows
> below, and every row's dual-control, pending-202, escrow, irreducible-set and operator-signature
> clause, are void. **Twelve remain** — `verify`, `plane_facts`, `plane_record_write`, `chain_break`,
> `store_restore`, `reseal_epoch_floor`, `set_overdraft_ceiling`, `set_dispute_max_age`,
> `commit_upgrade`, `resolve_dispute`, `resolve_slice`, `adjust` — plus `amend_rate_history`, and
> each is a plain scoped verb whose authorization is the per-verb allow-list on the admin token
> (`verbs: [ … ]` or `verbs: "*"`; `read-only` and `full` remain the 1.5.5 shorthands). The replay
> cache below stays as a MECHANISM keyed `(actor, verb, idempotency-key)`, never as a control.
> What survives the amendment intact, and is why this document is kept: each remaining verb's method
> and path, scope, request and response schema with exact keys and types, every refusal as
> (status, error code, message in the 1.5.5 template style), the audit record and journal class it
> writes, the unit that executes it, the view type where a figure appears, and the cells it owes.

CG-56 is decided. `ARCHITECTURE.md` §4.7 names the HTTP binding of each verb under
**HTTP binding of the twelve**, and Appendix A ratifies the rule. The seventeen are therefore no longer "written against
a guess": every row below derives its method and path from §4.7's own list, and everything §4.7 does
not say is marked **ARCHITECTURE silent; proposed: …** so the owner rules once, in the open, rather
than an implementer deciding it in a handler.

Owner ruling, 2026-09-08 10:2x — **the admin API is dumb; policy lives in the calling app**:

> One admin tier. No operator-key ceremony, no dual control, no pending/approve, no "irreducible"
> set inside busbar. The earlier signature / 202-pending / replay-key rulings are SUPERSEDED (the
> replay cache stays as an idempotency mechanism keyed `(actor, verb, key)` — it is not a control).

Three consequences, and every line below follows from them:

1. **Five verbs leave 1.6.0.** `set_operator_key`, `set_escrow`, `set_dual_control`, `approve`,
   `export_keyset`. They are not deferred behind a flag and not implemented-then-hidden; their
   rows leave the plane's table and their vocabulary leaves the executing unit.
2. **Twelve stay as PLAIN scoped verbs**, plus `amend_rate_history` — thirteen operations in all.
   Nothing gates them except the credential's scope and the credential's verb allow-list.
3. **Admin tokens gain a per-verb allow-list.** `verbs: ["chain_break", …]` or `verbs: "*"` on the
   `admin-tokens` token definition. `read-only` and `full` remain shorthand for the two classic
   sets. The outside app mints one token per role; busbar enforces membership and nothing else.

The previous revision of this document contracted seventeen verbs against an operator-key ceremony,
a dual-control posture, a maker-checker `approve` step, an operator signature argument and an
irreducible set. **All of that is deleted here** — from the contract and from the code plan (§10).
Owner decisions D-1 (pending-vs-refusal), D-2 (signature reason codes), D-3's header-required list,
D-7 (which verbs carry a signature) and D-8 (`adjust_threshold` as a gate) are **closed by the
ruling, as "does not exist"**.

---

## 1. What this document is, and the constraints it is written under

### 1.1 Admin is a control surface, not a data plane

The thirteen are contracted as operations of a **`control` kind** (owner ruling 08:5x, which the
10:2x ruling does not touch). Five properties, and every row in §7 is written to them:

| property of a `control` surface | what it means here | evidence it already holds |
|---|---|---|
| **unmetered** | no verb draws a meter class, a `requests` slot, a `concurrent` lease or a fee. Every one posts zero | `crates/busbar/src/root/units_admin/mod.rs:1822-1839` — the loop's `meter` reports an empty usage report and says why; `qa/full-gate.toml`'s admin cell asserts zero fee/requests postings under a non-zero configured fee |
| **routes are data** | the `(method, path) -> verb` table is a declared table matched by a pure function, never a router the surface owns | `busbar_plane_admin::verbs::{all_verbs, find_verb, resolve, table}` is exactly that — a linear scan over a closed slice with no behaviour |
| **verify · admit · audit · answer**, and nothing else | no Route-to-upstream, no egress, no encode-from-facts. It checks the call, admits it, records it, hands back the bytes the unit produced | `mod.rs:1998-2002` — `encode` hands back an empty frame, "the shape that makes it impossible for a byte to be re-derived here" |
| **node state only through the verbs unit** | no verb reaches governance, the store or the journal except through `busbar-unit-verbs`. The surface holds no store handle | `crates/busbar-unit-verbs/src/verbs.rs:463-468` — `Verbs` does not hand out its bound store |
| **no money vocabulary** | the surface names no figure, no currency, no amount. Where an answer carries a figure it is a `busbar-unit-cost` view type, serialized by the unit, passed through as bytes | §5; the `plane-no-money` gate rule (`qa/full-gate.toml:89`) |

Two readings to head off:

- **"Executes in `busbar-unit-verbs`" in §7 means the control path**, not a plane's Route step:
  `decode → authenticate → scope → allow-list → rate → (idempotency) → effect through the unit →
  audit → answer`. The kernel `Route` step is where the composition root currently hangs it
  (`mod.rs:1500`) because there is no `control` kind yet; that is wiring, and no row below depends
  on it.
- **`busbar-plane-admin` becomes `busbar-control-admin` in the R7 rename.** Every
  `crates/busbar-plane-admin/...` citation below is a `crates/busbar-control-admin/...` citation
  after R7. **Do not rename now.**

### 1.2 The constraints

| constraint | consequence for every row below |
|---|---|
| the 66 legacy verbs' bytes are untouched | no row edits `generated::verb_table_1_5_5`; the 240 existing `admin.ops` cells stay green unchanged. Every cell this document asks for is additive |
| PB-75 / openapi | `crates/busbar-core/src/admin/v1/json/openapi.json` is **not touched**. The thirteen operations are described in `docs/openapi-1.6.0-additive.json` (today five ledger reads), reached by name at `GET /api/v1/admin/ledger/openapi.json`. The openapi tests may see **new paths and new schemas only** — no existing path, field, `required` list or description byte moves |
| money is untouched | `adjust`, `resolve_dispute`, `resolve_slice` and `amend_rate_history` call the units' existing money verbs. The arithmetic stays in `busbar-unit-cost` / `busbar-unit-ledger`. This document adds **view types**, not arithmetic |
| kind isolation | the control surface is a codec and a declared route table; `busbar-unit-verbs` executes; every figure is a `busbar-unit-cost` view type. `plane-no-money` stays green |
| every verb is unmetered | no row declares a meter class, a `requests` draw, a `concurrent` lease or a fee. The mutation rate limiter is not metering — it is admission bookkeeping and posts nothing |
| the sealed idempotency cache exists and is never consulted | `Store::replay_new_verb` / `Store::commit_new_verb_replay` (`crates/busbar-unit-verbs/src/store.rs:60,63`) have no non-test caller. Every mutating row states where the probe goes |
| the config grammar is frozen additive-only | the allow-list key is a **new optional field** on an existing struct, which the config-stability gate classifies `Additive` by construction (§9.3) |

Sources every row cites:

- `docs/design/ARCHITECTURE.md` — §1.4, §2.3, §3.2, §4.1–§4.9, §8.1, §8.3, Appendix A. §4.7's
  operator-key / dual-control / escrow / irreducible-set text is **rewritten by the ruling** and is
  cited below only where the cited sentence survives it.
- `crates/busbar-unit-verbs/` — `verb.rs` (`NEW_VERBS` :672, `READ_ONLY_NEW_VERBS` :702),
  `verbs.rs` (`required_scope` :142, `admit` :215, `execute` :412), `rate.rs`, `refusal.rs`,
  `store.rs`, `idempotency.rs`.
- `crates/busbar-plane-admin/` — `verbs.rs` (the table :33-136, `VerbEntry` :23-30, `VERB_COUNT`
  :183), `envelope.rs` (`AdminError::Forbidden` :63-70, `code` :123, `http_status` :140, `message`
  :163-165, `envelope` :184-186), `refusal.rs` (`envelope_of` :212-214).
- `crates/busbar/src/root/units_admin/mod.rs` — `route` :1500, `approve` :1424-1447,
  `scope_as_verb_scope` :1452-1457, `verbs_reason` :1806, `audit` :1847, `applied_answer` :1701;
  `admin_mount.rs` `scope_answer` :264-274; `crates/busbar/src/root/kernel.rs` `admin_grant`
  :591-599.
- `crates/busbar/tests/new_verbs_legacy_leg.rs`, `crates/busbar/tests/admin_verb_ownership.rs` —
  the shipped state: of the seventeen, three are loop-served and fourteen are gated and then 404.
- `crates/busbar-substrate/src/config/auth.rs` — `IdentityProviderCfg` :44 (`deny_unknown_fields`
  :43, `module` :47, `max_admin_scope` :68, `token` :72, `settings` :88), `IdentityProviders` :93,
  `RoleBindingCfg` :139 (`admin_scope` :151), `RoleBindings` :155-156.
  `crates/busbar-core/src/config/mod.rs` — `validate_token_placement` :576-593, `resolve_auth` :558.
  `crates/busbar-core/src/auth/mod.rs` — `admin_scope_for` :1180-1219.
  `crates/auth-admin-tokens/src/lib.rs`, `crates/busbar-unit-scope/src/lib.rs` (`Scope` :61,
  `Scope::parse` :78-87, `Grants` :134-135).
- `testing/shadow-oracle/cells/__init__.py` (the `admin.ops` builder :462-690, the `ledger|amend|*`
  pair :1059-1090) and `testing/shadow-oracle/cells.json`.

---

## 2. The nine drifted table rows

`crates/busbar-plane-admin/src/verbs.rs:33-136` declares its seventeen bindings as **synthetic**
("Judgment call, flagged for review … the design does not state an HTTP binding for the 17",
:11-18). Nine of those rows disagree with the binding this document fixes. Under the ruling, three
of the nine belong to departing verbs and are **deleted rather than corrected**; five are corrected;
one (`verify`) is a method change.

### 2.1 `verify` is `GET`

The rule is 1.5.5's own: a read asks `read-only` and is bound `GET`. `verify` is a member of
`READ_ONLY_NEW_VERBS` (`verb.rs:702`), so `required_scope` already answers `ReadOnly`
(`verbs.rs:147-151`) and `MutationClass::for_verb` already answers `Forbidden` (never rate-limited).
Seven doc comments in the executing unit already say `GET`
(`verb.rs:692-693`, `verbs.rs:137`, `verbs.rs:147`, `rate.rs:141`, `posture.rs:107`,
`tests/rate_tests.rs:199`, `tests/verbs_tests.rs:1464,1467`). Exactly one place says `POST`:

| file:line | says | fix |
|---|---|---|
| `crates/busbar-plane-admin/src/verbs.rs:34-39` | `method: "POST", path: "/api/v1/admin/verify"` | `method: "GET"` |
| `crates/busbar-plane-admin/src/verbs.rs:11-18` | the module doc calls all seventeen bindings "synthetic … a judgment call, flagged for review" | rewrite: thirteen rows, each `<METHOD> /api/v1/admin/<kebab-case-verb>` (the whole verb name), transcribed from this document |

`crates/busbar/tests/new_verbs_legacy_leg.rs` drives each row with the method the table declares
(its `ask()` helper panics on anything but GET/POST), so flipping the row flips what that test
asks. That coupling is intended.

### 2.2 The eight path rows

The path rule is `<kebab-case-verb>` — **the whole verb name, `set_` prefix and all**. Eight rows
drift from it. Five are corrected; three leave with their verbs.

Same cause, same fix, and they are path literals rather than methods. §4.7's rule is
`<kebab-case-verb>` — the **whole verb name**, `set_` prefix and all.

| verb | §4.7's binding list | plane table today | file:line |
|---|---|---|---|
| `set_operator_key` | `/api/v1/admin/operator-key` (:54) | — | **row deleted** |
| `set_escrow` | `/api/v1/admin/escrow` (:60) | — | **row deleted** |
| `set_dual_control` | `/api/v1/admin/dual-control` (:84) | — | **row deleted** |
| `set_overdraft_ceiling` | `/api/v1/admin/overdraft-ceiling` (:90) | `/api/v1/admin/set-overdraft-ceiling` | corrected |
| `set_dispute_max_age` | `/api/v1/admin/dispute-max-age` (:96) | `/api/v1/admin/set-dispute-max-age` | corrected |
| `resolve_dispute` | `/api/v1/admin/disputes/resolve` (:108) | `/api/v1/admin/resolve-dispute` | corrected |
| `resolve_slice` | `/api/v1/admin/slices/resolve` (:114) | `/api/v1/admin/resolve-slice` | corrected |
| `verify` | `POST /api/v1/admin/verify` (:35) | `GET /api/v1/admin/verify` | corrected (method) |

The two remaining departing rows (`export_keyset` :120, `approve` :126) already match the rule and
are deleted for the other reason: their verbs are gone.

Seven rows are already correct and stay byte-for-byte: `plane-facts` (already `GET`),
`plane-record-write`, `chain-break`, `store-restore`, `reseal-epoch-floor`, `commit-upgrade`,
`adjust`.

Dependent literals that move with the corrections:

- `crates/busbar/src/root/units_admin/tests/units_admin.rs:1251`, `:1306`, `:1332` spell
  `"/api/v1/admin/operator-key"`. That verb is gone, so those three cases are **deleted**, not
  re-pathed.
- No other test in the tree spells a drifting path. `:411` (`export-keyset`, deleted with the verb),
  `:428` (`chain-break`), `:434` (`adjust`) and `:1463-1470` (the three recovery verbs) are
  unaffected.

`amend_rate_history` is the one operation not under the `/api/v1/admin/<verb>` rule: it is a ledger
write and keeps the path already recorded against the 1.5.5 binary,
`POST /api/v1/admin/ledger/amend-rate-history` (`testing/shadow-oracle/cells/__init__.py:1062`).
Moving it would orphan two recorded oracle cells for no gain.

---

## 3. The control path — the common admission ladder

Every one of the thirteen runs the same ladder before its own effect. There is no meter step that
posts anything, no egress step, **no posture step and no approval step**. Stated once here; §7 names
only what each verb adds.

```
0.  decode            busbar-plane-admin: verbs::find_verb(method, path) -> VerbEntry
                      no row            -> 404 not_found  (a path the table does not declare)
                      row, wrong method -> 405 method_not_allowed
1.  authenticate      the admin credential; no principal -> 401 unauthorized
2.  scope             busbar-unit-verbs::required_scope(verb)   (verbs.rs:142)
                        READ_ONLY_NEW_VERBS -> ReadOnly ; every other new verb -> Full
                      short -> ReasonCode::Unauthorized -> 403 forbidden
3.  ALLOW-LIST        the verb's own name must be in the credential's verb list         [§9]
                      absent -> ReasonCode::Unauthorized -> 403 forbidden
4.  rate class        MutationClass::for_verb(verb, CONFIG_CLASS_RULES)  (rate.rs:151)
                        verify / plane_facts -> Forbidden (never limited)
                        the other 11 + amend -> Crud, 60/min per actor          [see D-C]
                      over -> ReasonCode::RateLimited -> 429 rate_limited
5.  IDEMPOTENCY       ** the step that does not exist yet **  — §4
6.  effect            Governance::execute_new_verb  (9 verbs + amend)
                      Store::{chain_break, store_restore, reseal_epoch_floor}  (3 verbs)
7.  audit             ADMIN_LOG row for every mutating verb; journal entry per §4.1's class
8.  answer            the bytes the unit produced, unchanged. Nothing is re-derived here.
                      NO METER STEP POSTS: zero usage lines, zero fee, zero requests, no lease.
```

Steps 2 and 3 are two readings of one question and are ordered **scope first**, so that a
`read-only` credential asking for `adjust` gets the 1.5.5 answer it has always got
(`insufficient scope: this endpoint requires `full``) rather than a new one. A credential that
holds the scope and lacks the verb gets the allow-list refusal (§9.2).

### 3.1 The frozen refusal envelope

Every refusal renders through `busbar_plane_admin::refusal::envelope_of` — the 1.5.5 shape,
`{"error":{"code":"…","message":"…"}}`, `code` before `message`, serialized (never hand-formatted),
no trailing byte. Codes and statuses are `AdminError`'s ten, **unchanged and not added to**
(`crates/busbar-plane-admin/src/envelope.rs:118-147`):

`not_found` 404 · `unauthorized` 401 · `method_not_allowed` 405 · `forbidden` 403 ·
`invalid_request` 400 · `version_conflict` 409 · `conflict` 409 · `rate_limited` 429 ·
`internal` 500 · `unavailable` 503.

Message wording follows the shipped 1.5.5 template style (`envelope.rs:152-175`): lower case, no
trailing period, the named thing in backticks, caller-safe. The five shared messages are the
shipped ones **verbatim** — the allow-list refusal included, which is the point of §9.2:

| condition | status | code | message (shipped literal) |
|---|---|---|---|
| no/invalid credential | 401 | `unauthorized` | `missing or invalid admin credential (Bearer or x-admin-token)` |
| wrong method on a declared path | 405 | `method_not_allowed` | `method not allowed for this resource` |
| scope short | 403 | `forbidden` | ``insufficient scope: this endpoint requires `full` `` (or `` `read-only` ``) |
| **verb not in the token's list** | 403 | `forbidden` | ``insufficient scope: this endpoint requires `<verb>` `` |
| over the mutation budget | 429 | `rate_limited` | `admin mutation rate limit exceeded; retry next minute` |

The allow-list refusal is `AdminError::Forbidden { needed: "<verb>" }` — the **existing** variant
(`envelope.rs:63-70`, `needed: &'static str`) with the verb name as the `needed` string, so
`envelope.rs:163-165`'s format string produces it with no new arm, no new code and no new status.
The verb names are already `&'static str` in `VerbEntry` (`verbs.rs:23-30`), so nothing is
allocated to say it. A dumb API refuses in the vocabulary it already has.

The reason codes that survive from `busbar_unit_verbs::ReasonCode` (`refusal.rs:40-69`):

| `ReasonCode` | status | code | message |
|---|---|---|---|
| `Unauthorized` | 403 | `forbidden` | the scope or allow-list message above |
| `RateLimited` | 429 | `rate_limited` | the shipped literal above |
| `Validation` | 400 | `invalid_request` | the per-verb message in §7 |
| `IdempotencyInFlight` | 409 | `conflict` | `this request is still in flight` |
| `StoreError` | 503 | `unavailable` | `the journal is unavailable` |
| `Internal` | 500 | `internal` | `internal error` |

`OperatorUnset`, `SelfApproval`, `PayloadMismatch`, `InsufficientApprovers` and `ApprovalPending`
**have no referent under the ruling** and are deleted with `posture.rs` (§10). The proposed
`OperatorSignatureRequired` / `OperatorSignatureInvalid` arms (old D-2) are **not added**.

---

## 4. Idempotency and replay — the cache that exists and is never consulted

`Store::replay_new_verb` / `Store::commit_new_verb_replay` are declared
(`crates/busbar-unit-verbs/src/store.rs:52-67`), implemented over the loader shim
(`crates/plugin-loader/src/store_adapter.rs:854,869`), adapted by the root
(`crates/busbar/src/root/units_admin/mod.rs:2084,2091`) — and called by **nothing outside tests**.

The ruling keeps it, explicitly, as an **idempotency mechanism and not a control**. Contract for
every mutating verb (all eleven + `amend_rate_history`):

- **The probe happens at step 5**, after scope/allow-list/rate and before the effect. Probing before
  admission would reserve a slot for a call that is refused; probing after the effect is not a probe.
- **Key shape: `(actor, "<verb>:<idempotency-key>")`.** This mirrors the shipped rotate key
  `(actor, "rotate:{id}:{k}")` (`verbs.rs:361`), which exists precisely so a create and a rotate
  sharing one header value never replay each other. The shim's test helper currently keys
  `(verb, key)` and drops the actor (`crates/plugin-loader/src/tests/store_adapter_tests.rs:414-416`)
  — two principals sharing an `Idempotency-Key` would replay each other's answer. That is a bug to
  fix in the same cut.
- **The `Idempotency-Key` header is OPTIONAL on every verb.** A request without one proceeds without
  reserving, exactly as `IdempotencyCache::probe` → `Probe::NoKey` already does for the two legacy
  replayable operations (`idempotency.rs:74-90`). The 17-verb draft made the header **required** on
  five verbs; under the ruling busbar does not require ceremony of its caller — the calling app
  decides whether it wants replay protection, and gets it by sending a key. (Owner decision **D-B**
  if the owner wants the harder rule back for `chain_break` / `store_restore`.)
- **First sighting** reserves; the effect runs; `commit_new_verb_replay(key, response_bytes)` stores
  the **exact response body the writer was about to send**, never an intermediate form
  (`idempotency.rs:21-33` gives the reason: a decode step could re-mint a `SecretOnce`).
- **A replay** returns the cached bytes verbatim, with the original status, and mints nothing. It is
  a `200`/`204`, not a `409`: 1.5.5's create/rotate replay returns the first answer, and §8.1:1207
  pins "same node: byte-identical replay".
- **A reservation still in flight** is `ReasonCode::IdempotencyInFlight` → 409 `conflict`,
  `this request is still in flight`.
- **A reservation whose caller vanished mid-effect** is `leak()`ed, never cleared
  (`idempotency.rs:129-133`) — a `chain_break` that landed must not be re-runnable by a retry.

**TTL — still a live disagreement.** `crates/plugin-loader/src/store_adapter.rs:170` pins
`REPLAY_TTL_SECS = busbar_unit_verbs::idempotency::IDEMPOTENCY_TTL_SECS` = **600 s**. ARCHITECTURE
§4.4:834 says the new verbs' cache is `min(dispute_max_age, max(600 s, longest finite cap window +
max_unit_duration))`, which on the default `dispute_max_age` of 7 d and `max_unit_duration` of 600 s
is at least 1,200 s. Owner decision **D-A**.

---

## 5. Where money is named — `busbar-unit-cost` view types

Five of the thirteen answer with a figure. Those figures are typed in `busbar-unit-cost`, whose
claim is that it is "pure functions over integers … no clock, no store, no config parser and **no
plane**" (`crates/busbar-unit-cost/src/lib.rs:9-10`), and which already owns the scale
(`NANOS_PER_CENT` :54, `NANOS_PER_MICRO` :57), the truncating projections (`project.rs:23,31`) and
the only per-line money struct (`PricedLine`, `posting.rs:20`).

**The arithmetic does not move.** These are *view* types: field names and a wire rendering over
figures the money units already computed. `adjust`, `resolve_dispute`, `resolve_slice` and
`amend_rate_history` call the units' existing money verbs; nothing in this document adds, subtracts
or rounds. The control surface passes through the bytes the unit produced and names no figure — no
money type, no currency, no amount identifier appears in `busbar-plane-admin` — so `plane-no-money`
(`qa/full-gate.toml:89`) stays green by construction.

**ARCHITECTURE silent on the type names; proposed:** a new `busbar-unit-cost::view` module, five
types, every amount in nano-units (`u128`, or `i128` where a figure can be negative), every wire
rendering a **decimal string** so no JSON consumer silently truncates at 2^53:

| type | verb | fields |
|---|---|---|
| `IdentityDeltaView` | `verify` | `bucket, dimension, scope, window_start, delta_settlements, delta_open_holds, delta_open_slice_remainders, delta_unreconciled, delta_adjustments, delta_overdraft_carried, delta_cross_window_transfers, delta_drawn, closes: bool` — §4.2:770-772's identity, term for term |
| `CeilingView` | `set_overdraft_ceiling` | `bucket, dimension, scope, ceiling_nanos, previous_ceiling_nanos, window_cap_nanos, ceiling_bp_of_cap, unbounded: bool` |
| `DisputeVerdictView` | `resolve_dispute` | `dispute_id, verdict, posted_amount_nanos, corrected_amount_nanos, delta_nanos: i128, entry: EntryRef` |
| `UnreconciledSliceView` | `resolve_slice` | `node, lease_epoch, bucket, dimension, scope, window_start, unreconciled_nanos, resolved_nanos, remaining_nanos, entry: EntryRef` |
| `AdjustmentView` | `adjust` | `bucket, dimension, scope, window_start, amount_nanos: i128, headroom_released_nanos, pure_reversal: bool, entry: EntryRef` |

`EntryRef { node, node_seq, hash }` is §4.1's `refs` triple. `above_threshold` / `threshold_nanos`
are **dropped** from `DisputeVerdictView` and `AdjustmentView`: with no irreducible set the
threshold gates nothing, and a view field that no longer decides anything is a field that will be
read as though it does (see D-D).

`amend_rate_history` reuses `busbar-unit-cost`'s existing `HistoryView` and the repricing rows
`busbar-unit-ledger` already produces (`Ledger::record_repricing`); it needs no new view type.

The eight verbs not listed here name no figure at all, and their response schemas carry none.

---

## 6. Oracle cells — the scheme, and what each verb owes

Today `admin.ops` is **240 cells over 66 operations**, all `driver: "http"`, built by
`testing/shadow-oracle/cells/__init__.py:462-690`. **Zero cells exist for any of the new verbs.**
The `ledger|amend|*` family has two, both recorded against the published 1.5.5 binary as
404 `not_found` / `resource not found` (`cells.json:18634`, `:18657`).

**Id format, unchanged:** `admin.ops|<OperationId>|<outcome-slug>`, three pipe-separated segments,
`/` stripped. The 66 use the tag's PascalCase `operationId`. **Proposed for the twelve:** the
`KernelVerb` variant name, which is the same PascalCase and is already the spelling both crates join
on (`crates/busbar/tests/admin_verb_ownership.rs:63` squashes case and separators to do exactly this
join): `Verify`, `PlaneFacts`, `PlaneRecordWrite`, `ChainBreak`, `StoreRestore`, `ResealEpochFloor`,
`SetOverdraftCeiling`, `SetDisputeMaxAge`, `CommitUpgrade`, `ResolveDispute`, `ResolveSlice`,
`Adjust`. `amend_rate_history` keeps its recorded family, `ledger|amend|<slug>`.

Outcome slugs reused from the existing 240 where the condition is the same: `ok`, `unauth`,
`bad-body`, `not-found`, `rate-limit`, `idempotent-replay`, `if-match-stale`. New slugs, in the same
hyphen-lowercase style: `noscope`, `verb-not-allowed`, `wildcard-allows`, `full-shorthand-allows`,
`already-resolved`. The ceremony slugs the 17-verb draft proposed (`operator-unset`,
`approval-pending`, `self-approval`, `payload-mismatch`, `insufficient-approvers`, `unsigned`) are
**not added** — they name conditions that no longer exist.

Drivers (the vocabulary is closed at `__init__.py:33-36`): `http` for a single request; `script`
where node state must change between requests; `exec` for the off-node CLI equivalents on a stopped
node (`chain_break`, `store_restore`, `reseal_epoch_floor`); `concurrent` for the in-flight
reservation.

**72 new `admin.ops` cells + 3 new `ledger|amend|` cells = 75**, listed per verb in §7 and totalled
in §8. The 240 legacy cells are untouched.

---

## 7. The twelve, and `amend_rate_history`

Every row: method and path · scope · request · success · refusals · idempotency · audit · executing
unit · money view · cells · citation. **Scope** below means the credential's `Scope` rung; **every**
verb additionally requires its own name in the credential's allow-list (§9), and that is not
repeated per row.

---

### 7.1 `verify` — `GET /api/v1/admin/verify`

- **Scope** `read-only` (`READ_ONLY_NEW_VERBS`, `verb.rs:702`; `required_scope` :147-151). Rate class
  `Forbidden` — never spends a mutation slot (`rate.rs:155-163`; a read that spent one would refuse
  an operator's config change because they checked the ledger first).
- **Request** query only, no body. `?since=<checkpoint-id>` — *ARCHITECTURE silent on the parameter
  name; proposed*, defaulting to §4.2:767's "last anchored checkpoint".
- **Success** `200 application/json`:
  ```json
  { "since": { "checkpoint_id": "string", "anchored_at": 0 },
    "chains": [ { "node": "string", "body_hash_ok": true, "chain_hash_ok": true,
                  "head_hash": "string", "seq_high_water": 0 } ],
    "checkpoints_resolve": true, "seq_monotonic": true, "anchored_head_matches": true,
    "identity": [ IdentityDeltaView ],
    "recompute": { "watermark": { "node": "string", "node_seq": 0 }, "divergences": 0 },
    "ok": true }
  ```
  `ok` is the conjunction of every boolean and every `identity[].closes`. A failed verify is still a
  `200` — the verb answers the question it was asked; it does not refuse because the answer is bad.
- **Refusals** 401 · 405 · 403-scope · 403-allow-list · never 429 · plus `400 invalid_request` —
  ``since `<value>` is not a checkpoint id``.
- **Idempotency** none. A read reserves nothing.
- **Audit** no `ADMIN_LOG` row (`mod.rs:1869` — "a read is not a mutation and is not appended").
  Journal class `Access`, subject `Node`. *Proposed: the verb does **not** write a `Reconciliation`
  entry; only the every-T timer run does (§4.2:782)* — D-E.
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`. **Money view**
  `IdentityDeltaView`.
- **Cells (7)** `Verify|ok` · `|unauth` · `|noscope` · `|verb-not-allowed` · `|since-malformed` ·
  `|identity-closes` · `|identity-breaks` (script: corrupt a `priced_amount` older than the last
  checkpoint, then ask — §4.2:778's cell from this side).
- **Cite** §4.2:765-782 (what `verify` is), §8.3:1276 ("drop one principal's pseudonym key: `verify`
  passes"). Binding: **silent; proposed** (CG-56's list is rewritten by the ruling).

---

### 7.2 `plane_facts` — `GET /api/v1/admin/plane-facts`

- **Scope** `read-only`. Rate class `Forbidden`.
- **Request** query only. `?plane=<plane_key>&verb=<AdminVerbId>&subject=<name>`. The `subject`
  parameter is **CG-04, still open**: `Plane::plane_facts(&self, verb, ctx)` carries no subject, so
  both JSON-RPC planes declare only their list verb and leave per-name projections undeclared. This
  document assumes CG-04's recommendation (add the subject) and marks the parameter optional so the
  binding is correct either way — D-F.
- **Success** `200 application/json`:
  `{ "plane": "string", "verb": "string", "subject": "string|null", "facts": { "<key>": <value> } }`
- **Refusals** 401 · 405 · 403-scope · 403-allow-list, plus
  `404 not_found` — ``plane `<key>` not found`` ·
  `400 invalid_request` — `plane is required` / `verb is required` ·
  `400 invalid_request` — ``plane `<key>` does not declare introspection verb `<verb>` `` ·
  `400 invalid_request` — ``verb `<verb>` requires a subject`` (only under CG-04's shape).
- **Idempotency** none. **Audit** no `ADMIN_LOG` row; journal `Access`.
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`, which reaches the plane's own
  `plane_facts`. **Money view** none.
- **Cells (6)** `PlaneFacts|ok` · `|unauth` · `|noscope` · `|wildcard-allows` (a `verbs: "*"` token
  reaches it) · `|unknown-plane` · `|missing-subject`.
- **Cite** §3.2:580 (the signature), §1.4 (the plugin-kind table's `ADMIN_VERBS` row, "plane admin
  verbs (read-only introspection)"), CG-04 and CG-57 (the `ADMIN_VERBS` → `INTROSPECTION_VERBS`
  rename this verb's existence forces — D-G).

---

### 7.3 `plane_record_write` — `POST /api/v1/admin/plane-record-write`

- **Scope** `full`. Rate class `Crud`.
- **Request** *ARCHITECTURE names the key tuple and nothing else; proposed:*
  ```json
  { "plane": "string", "schema": "string", "key": "string",
    "value": <json>, "if_match": "string|null" }
  ```
  `(plane, schema, key)` is exactly §2.3:437-438's `record_put` key.
- **Success** `200 application/json`:
  `{ "plane": "…", "schema": "…", "key": "…", "revision": "string", "written_at": 0 }`
- **Refusals** shared, plus
  `400 invalid_request` — `plane is required` / `schema is required` / `key is required` ·
  `404 not_found` — ``plane `<key>` not found`` ·
  `403 forbidden` — ``plane `<key>` may not write schema `<schema>` `` (the trust unit's verdict,
  §2.3:438 "verified by the trust unit") ·
  `409 version_conflict` — ``the record has changed since `<if_match>` `` ·
  `409 conflict` — in-flight idempotency reservation · `503 unavailable` — the journal.
- **Idempotency** MUST probe. Key `(actor, "plane_record_write:<hdr>")`. Header optional (the verb is
  naturally re-runnable and `if_match` already guards lost updates).
- **Audit** `ADMIN_LOG` row `action = plane_record_write`,
  `resource = /api/v1/admin/plane-record-write`, outcome `applied`/`rejected`, principal = the
  resolved actor (`mod.rs:1869-1873`). Journal class `Transaction` for the write plus `Access` for
  the read side of a verified write (§2.3:438 — "journaled `Access`/`Transaction`").
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`. **Money view** none.
- **Cells (8)** `PlaneRecordWrite|ok` · `|unauth` · `|noscope` · `|verb-not-allowed` · `|bad-body` ·
  `|not-found` · `|if-match-stale` · `|idempotent-replay`.
- **Cite** §2.3:437-439 (the whole contract). Binding: silent; proposed.

---

### 7.4 `chain_break` — `POST /api/v1/admin/chain-break`

- **Scope** `full`. Rate class `Crud` (**D-C** proposes `Config`, 10/min).
- **Request** *proposed:* `{ "reason": "string" }`. The `signature` field the 17-verb draft
  required is **deleted**.
- **Success** **`204 No Content`, empty body** — what the loop already answers
  (`applied_answer()`, `mod.rs:1701-1707`) and what `crates/busbar/tests/admin_verb_ownership.rs`
  measures. Keeping it means this verb's contract is already half-shipped.
- **Refusals** shared, plus `400 invalid_request` — `reason is required` · `409 conflict` —
  in-flight reservation · `503 unavailable` — the store leg's `StoreError::Failed`
  (`store.rs:30-36`).
- **Idempotency** MUST probe; header optional. When a key IS sent, the reservation is `leak()`ed
  once the store call is entered — a caller disconnect after the break landed must not free the slot.
- **Audit** `ADMIN_LOG` `action = chain_break`. Journal class `ChainBreak` (§4.1:753's class list
  names it). §4.3:813 — "a restore below the `backup_watermark` is a `ChainBreak` by definition", so
  this class is also written by `store_restore`.
- **Executes in** `busbar-unit-verbs::Verbs::chain_break` → `Store::chain_break`
  (`verbs.rs:497-517`) — **not** the governance seam; already wired at `mod.rs:1568-1571`.
  **Money view** none.
- **Cells (6)** `ChainBreak|ok` · `|noscope` · `|verb-not-allowed` · `|store-failed` ·
  `|idempotent-replay` · `|off-node-cli` (**exec** — §4.7:990's off-node CLI on a stopped node).
- **Cite** §4.1:753 (the journal class), §4.2:782 ("WAL loss is a `ChainBreak`"), §4.3:813,
  §4.7:990 (also an off-node CLI).

---

### 7.5 `store_restore` — `POST /api/v1/admin/store-restore`

- **Scope** `full`. Rate class `Crud` (D-C: `Config`).
- **Request** `{ "backup_ref": "string" }`. `backup_ref` is **mandatory** and has no default — the
  root already refuses a body without one (`mod.rs:1574-1591`), on the stated ground that restoring
  "whatever the store thinks" is the most destructive thing this surface can be asked to do by
  accident. That refusal is `DecodeFailed` today; as a client answer it is
  **`400 invalid_request` — `backup_ref is required`**.
- **Success** `204 No Content`. After it, **the node refuses to serve until `reseal_epoch_floor`**
  (§4.6:932-934) and every node re-ships from `heads(node)` (§4.3:812).
- **Refusals** shared, plus `400` `backup_ref is required` · `404 not_found` —
  ``backup `<ref>` not found`` · `409` in-flight · `503` store.
- **Idempotency** MUST probe; header optional; reservation `leak()`ed on entry when present.
- **Audit** `ADMIN_LOG` `action = store_restore`. Journal class `StoreRestore`; **plus a `ChainBreak`
  entry** when the restore lands below the `backup_watermark` (§4.3:813 — that is not a refusal, it
  is a definition, and the entry is how it becomes visible).
- **Executes in** `busbar-unit-verbs::Verbs::store_restore` → `Store::store_restore`.
  **Money view** none.
- **Cells (6)** `StoreRestore|ok` · `|missing-backup-ref` · `|not-found` · `|verb-not-allowed` ·
  `|below-watermark-is-chainbreak` (script) · `|refuses-to-serve-until-reseal` (script).
- **Cite** §4.3:812-813, §4.6:932-934, §4.1:753, §4.7:990.

---

### 7.6 `reseal_epoch_floor` — `POST /api/v1/admin/reseal-epoch-floor`

- **Scope** `full`. Rate class `Crud` (D-C: `Config`).
- **Request** *proposed:* `{}` — empty body. No epoch argument: the floor is what the node computes
  from the re-shipped heads, and letting a caller name it is letting a caller lower it. (The
  17-verb draft's `signature` field is deleted, which leaves this verb with no fields at all.)
- **Success** `204 No Content`.
- **Refusals** shared, plus `409 conflict` — `not every node has re-shipped from its head`
  (§4.3:812 makes the re-ship the precondition — *silent on the refusal; proposed*) · `409`
  in-flight · `503` store.
- **Idempotency** MUST probe; header optional (a reseal is naturally idempotent).
- **Audit** `ADMIN_LOG` `action = reseal_epoch_floor`. Journal class `Policy` (the floor is persisted
  in every WAL header and at the anchor, §4.6:932-933) — *silent on the class; proposed.*
- **Executes in** `busbar-unit-verbs::Verbs::reseal_epoch_floor` → `Store::reseal_epoch_floor`.
  **Money view** none.
- **Cells (4)** `ResealEpochFloor|ok` · `|before-reship` · `|noscope` · `|off-node-cli` (exec).
- **Cite** §4.3:812, §4.6:932-934, §4.7:990.

---

### 7.7 `set_overdraft_ceiling` — `POST /api/v1/admin/set-overdraft-ceiling`

- **Scope** `full`. Rate class `Crud`.
- **Request** *proposed:*
  `{ "bucket": "string", "dimension": "string", "scope": "string", "ceiling_nanos": "string|null" }`
  `null` restores the default — 10 % of the refusing window cap (§4.7:1036).
- **Success** `200`: a `CeilingView` (§5).
- **Refusals** shared, plus
  `404 not_found` — ``bucket `<b>` not found`` ·
  `400 invalid_request` — ``dimension `<d>` does not accrue mid-unit`` (§4.4:845-846 — `requests` and
  `concurrent` are known at Admit and have no overdraft) ·
  `400 invalid_request` — `an attribution bucket has no overdraft ceiling` (§4.4:850 — "attribution
  buckets never refuse and have none") ·
  `409 conflict` — `a Migration-sealed bucket's ceiling is unbounded` (§4.7:1036, PB-58) ·
  `400 invalid_request` — `ceiling_nanos must be a non-negative decimal` ·
  `409` in-flight · `503` store.
- **Idempotency** MUST probe; header optional.
- **Audit** `ADMIN_LOG` `action = set_overdraft_ceiling`. Journal `Policy`, and a ledger-endpoint
  line (PB-16) because it is a listed-key delta.
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`. **Money view** `CeilingView`.
- **Cells (6)** `SetOverdraftCeiling|ok` · `|not-found` · `|attribution-bucket` ·
  `|migration-sealed-bucket` · `|bad-body` · `|idempotent-replay`.
- **Cite** §4.4:848-854, §4.7:1036 (the default). §4.7:1462's "dual-controlled" wording is rewritten
  by the ruling: this verb is now scoped and allow-listed like any other.

---

### 7.8 `set_dispute_max_age` — `POST /api/v1/admin/set-dispute-max-age`

- **Scope** `full`. Rate class `Crud`.
- **Request** *proposed:* `{ "seconds": 604800 }`. Default 7 d (§4.7:1025).
- **Success** `200`: `{ "dispute_max_age_seconds": 604800, "previous_seconds": 604800,
  "policy_epoch": 0, "open_disputes": 0, "newly_overdue": 0, "newly_hidden": 0 }`.
  `newly_hidden` is the count of disputes that were overdue under the old value and are not under the
  new one — made visible in the answer rather than only in an alarm. *Silent on the response;
  proposed.*
- **Refusals** shared, plus `400 invalid_request` — `seconds must be at least 1` · `409` in-flight ·
  `503` store.
- **Idempotency** MUST probe; header optional.
- **Note that binds two rows together:** this value is the ceiling of the new-verb replay TTL
  (§4.4:834 — `min(dispute_max_age, …)`), so lowering it shortens every other verb's replay window.
  The answer should say so; see D-A.
- **Audit** `ADMIN_LOG` `action = set_dispute_max_age`. Journal `Policy` + ledger-endpoint line.
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`. **Money view** none (a
  duration is not a figure; the dispute counts are cardinalities, not amounts).
- **Cells (4)** `SetDisputeMaxAge|ok` · `|lowering-hides-overdue` (script — the alarm and
  `newly_hidden` both asserted) · `|bad-body` · `|idempotent-replay`.
- **Cite** §4.7:1025 (default), :1057-1059 (the overdue-alarm rule), §4.4:834 (the TTL coupling).

---

### 7.9 `commit_upgrade` — `POST /api/v1/admin/commit-upgrade`

- **Scope** `full`. Rate class `Crud` (D-C: `Config`).
- **Request** *proposed:* `{ "schema_version": 0, "hash_algo_version": 0 }`.
- **Success** `200`: `{ "committed": { "schema_version": 0, "hash_algo_version": 0 },
  "policy_epoch": 0, "nodes_at_or_above": 3, "committed_at": 0 }`.
- **Refusals** shared, plus
  `409 conflict` — ``node `<n>` is below the committed version`` ·
  `400 invalid_request` — `schema_version is required` · `409` in-flight · `503` store.
  The `OperatorUnset` refusal §8.1:1209's ceremony cell asserted by name, and the "no escrow is
  sealed" refusal of §4.7:994-995, are both **deleted**: there is no ceremony and no escrow.
- **Idempotency** MUST probe; header optional but strongly advised — after the commit, older nodes
  refuse to serve (§4.8:1069), so a duplicate commit is not a no-op to a fleet mid-roll.
- **Audit** `ADMIN_LOG` `action = commit_upgrade`. Journal class `Policy` (the committed version is
  sealed there; `Migration` seals the initial one, §4.8:1068).
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`. **Money view** none.
- **Cells (4)** `CommitUpgrade|ok` · `|node-below-version` · `|full-shorthand-allows` (a
  `verbs: full` token reaches it) · `|idempotent-replay`.
- **Cite** §4.8:1068-1071 (versions). §8.1:1208-1209's two-cell ceremony is **withdrawn** with the
  ceremony (D-H).

---

### 7.10 `resolve_dispute` — `POST /api/v1/admin/resolve-dispute`

- **Scope** `full`. Rate class `Crud`. **No threshold gate** — `adjust_threshold` (§4.7:1050) is
  reporting/alarm input, not admission.
- **Request** *proposed:*
  ```json
  { "dispute_id": "string", "verdict": "uphold" | "overturn" | "amend",
    "amount_nanos": "string|null", "note": "string" }
  ```
  `amount_nanos` is required iff `verdict == "amend"`.
- **Success** `200`: a `DisputeVerdictView` (§5).
- **Refusals** shared, plus
  `404 not_found` — ``dispute `<id>` not found`` ·
  `409 conflict` — ``dispute `<id>` is already resolved`` ·
  `400 invalid_request` — ``verdict must be `uphold`, `overturn` or `amend` `` ·
  `400 invalid_request` — ``amount_nanos is required for verdict `amend` `` ·
  `409` in-flight · `503` store.
- **Idempotency** MUST probe; header optional but strongly advised — the effect is a correcting
  posting.
- **Audit** `ADMIN_LOG` `action = resolve_dispute`. Journal: a correcting posting (class
  `Transaction`, or `Adjust` on an amend — §4.1:741 lists `Adjust` as a record); the counts move on
  the next `Reconciliation` entry (§4.7:1058-1059).
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`; the money is the ledger
  unit's existing dispute-resolution verb. **Money view** `DisputeVerdictView`.
- **Cells (6)** `ResolveDispute|ok` · `|amend-with-amount` · `|already-resolved` · `|not-found` ·
  `|bad-verdict` · `|idempotent-replay`.
- **Cite** §4.7:1050 (`adjust_threshold`, now reporting only), :1057-1059 (the disputes report),
  §2.2:362 (the `dispute_max_age` bound).

---

### 7.11 `resolve_slice` — `POST /api/v1/admin/resolve-slice`

- **Scope** `full`. Rate class `Crud`.
- **Request** *proposed:*
  ```json
  { "node": "string", "lease_epoch": 0, "bucket": "string", "dimension": "string",
    "scope": "string", "window_start": 0,
    "verdict": "write-off" | "post", "amount_nanos": "string|null" }
  ```
- **Success** `200`: an `UnreconciledSliceView` (§5).
- **Refusals** shared, plus
  `404 not_found` — `no unreconciled slice for that node and epoch` ·
  `409 conflict` — `that slice is not unreconciled` ·
  `400 invalid_request` — ``verdict must be `write-off` or `post` `` ·
  `400 invalid_request` — ``amount_nanos is required for verdict `post` `` ·
  `409` in-flight · `503` store.
- **Idempotency** MUST probe; header optional.
- **Audit** `ADMIN_LOG` `action = resolve_slice`. Journal class `Slice` for the release plus a
  correcting posting. §4.2:771-772's rule applies in reverse — unreconciled is a **move out of**
  settled, so resolving it moves the amount back and the identity must still close.
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`. **Money view**
  `UnreconciledSliceView`.
- **Cells (5)** `ResolveSlice|ok` · `|not-unreconciled` · `|not-found` · `|identity-still-closes`
  (script — run `verify` after and assert `closes`) · `|idempotent-replay`.
- **Cite** §4.6:935-937 ("never-replayed spend is `UnreconciledSpend` until `resolve_slice`"),
  §4.2:770-772 (the identity and the move rule), Appendix A CG-41 (:1510-1512).

---

### 7.12 `adjust` — `POST /api/v1/admin/adjust`

- **Scope** `full`. Rate class `Crud`. **No threshold gate.**
- **Request** *proposed:*
  ```json
  { "bucket": "string", "dimension": "string", "scope": "string", "window_start": 0,
    "amount_nanos": "string", "reason": "string" }
  ```
  `amount_nanos` is a **signed** decimal string (an adjustment can go either way; §4.2:777 calls a
  closed-window adjustment a "pure ledger reversal").
- **Success** `200`: an `AdjustmentView` (§5).
- **Refusals** shared, plus
  `400 invalid_request` — `amount_nanos must be a non-zero signed decimal` ·
  `404 not_found` — ``bucket `<b>` not found`` ·
  `400 invalid_request` — `reason is required` · `409` in-flight · `503` store.
- **Idempotency** MUST probe; header optional. A retried adjustment applied twice is a money bug the
  identity would then report as closing, so a caller that cares sends a key — **and the calling app
  is where that policy lives**.
- **Audit** `ADMIN_LOG` `action = adjust`. Journal class `Adjust` (§4.1:741 names the record).
  Headroom is released to the store **only inside the open window**; outside it the entry is a pure
  reversal (§4.2:776-777) — `AdjustmentView.pure_reversal` says which happened.
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`; the arithmetic is
  `busbar-unit-ledger`'s existing adjusting-entry path. **Money view** `AdjustmentView`.
- **Cells (7)** `Adjust|ok` · `|zero-amount` · `|not-found` · `|missing-reason` ·
  `|verb-not-allowed` · `|open-window-releases-headroom` (script — `verify` after) ·
  `|closed-window-pure-reversal` (script).
- **Cite** §4.1:741 (the `Adjust` record), §4.2:760 (Σ adjustments is a sealed checkpoint figure),
  :770 (Δ adjustments is a term of the identity), :776-777 (headroom rule).

---

### 7.13 `amend_rate_history` — `POST /api/v1/admin/ledger/amend-rate-history`

The one operation outside the `/api/v1/admin/<verb>` rule, and the one whose absence is currently
red: `ledger|amend|adjusting-entries` and `ledger|amend|refused-unsigned` are recorded 404s
(`cells.json:18634`, `:18657`), and block C line 3 stopped on them 404 → 503 because the root binds
no `Verbs::amend_rate_history`.

The feature was four unwritten pieces: **(1)** the wire decode (`AmendRequest` from the body, with
`card_hash` / `reason_hash` / `card_complete` digests), **(2)** the operator-signature format,
**(3)** an operator-key registry seam the root can read, **(4)** `apply_amendment`'s root half
(append `Author::Amend`, journal batch, balance deltas). **Under the ruling, (2) and (3) do not
exist**: there is no operator key and no signature. The feature reduces to **decode + apply**.

- **Scope** `full`. Rate class `Crud`.
- **Request** the shape the recorded cells already send
  (`testing/shadow-oracle/cells/__init__.py:1059`), with the signature header dropped:
  ```json
  { "effective_from": 1, "rate_card": { … }, "window": { "day": "YYYY-MM-DD" },
    "reason": "string" }
  ```
  `X-Busbar-Signature` is **not read**. A request carrying it is not refused for carrying it — an
  unread header is an unread header — but nothing about the answer depends on it.
- **Success** `200 application/json`: the appended history row and the adjusting entries it produced
  — `{ "history_seq": 0, "effective_from": 0, "card_hash": "string",
  "repricings": [ { "window_start": 0, "bucket": "string", "old_amount_nanos": "…",
  "new_amount_nanos": "…", "delta_nanos": "…", "entry": EntryRef } ] }`. One journaled repricing
  record per affected `(window, bucket)`, carrying the old and new card, the quantities, both
  amounts and the delta, so the original line and the correction are both visible forever and **no
  booked line is rewritten**.
- **Refusals** shared, plus
  `400 invalid_request` — `effective_from is required` / `rate_card is required` /
  `reason is required` ·
  `400 invalid_request` — ``effective_from `<n>` is not before the history head`` ·
  `409 conflict` — ``the rate-card history has moved since `<history_seq>` `` · `409` in-flight ·
  `503` store.
- **Idempotency** MUST probe; header optional.
- **Audit** `ADMIN_LOG` `action = amend_rate_history`. Journal: the `Author::Amend` history append
  plus one repricing record per affected `(window, bucket)` — "the only way a history amendment
  moves money".
- **Executes in** `busbar-unit-verbs` → `Verbs::amend_rate_history` → the ledger unit's existing
  `Ledger::record_repricing`. **The arithmetic does not move.** **Money view** the existing
  `busbar-unit-cost::HistoryView`.
- **Cells (2 existing, re-answered; 3 new)** `ledger|amend|adjusting-entries` (recorded 404, becomes
  the real answer — an **additive new route**: golden 404, candidate not 5xx) ·
  `ledger|amend|refused-unsigned` (**needs an owner ruling — D-D**: the recorded cell's premise is
  an operator signature that no longer exists; either it is re-pointed at the allow-list refusal or
  it is retired) · new: `ledger|amend|verb-not-allowed` · `|bad-body` · `|idempotent-replay`.
- **Cite** ARCHITECTURE is **silent** on this verb; the contract is
  `testing/shadow-oracle/accepted-differences.json:554,568` (the breaking and additive halves of the
  rate-card history) and CHANGELOG:309, :396. Binding: **recorded, not proposed** — the path is the
  one the 1.5.5 binary was asked and refused.

---

## 8. The twelve (+ amend), in one table

| # | verb | method | path | scope | executes in | money view | cells | ARCHITECTURE cite |
|---|---|---|---|---|---|---|---|---|
| 1 | `verify` | **GET** | `/api/v1/admin/verify` | read-only | `busbar-unit-verbs` → `execute_new_verb` | `IdentityDeltaView` | 7 | §4.2:765-782 (binding: silent; proposed) |
| 2 | `plane_facts` | GET | `/api/v1/admin/plane-facts` | read-only | `busbar-unit-verbs` → plane `plane_facts` | — | 6 | §3.2:580 · §1.4 (binding: silent; proposed) |
| 3 | `plane_record_write` | POST | `/api/v1/admin/plane-record-write` | full | `busbar-unit-verbs` → `execute_new_verb` | — | 8 | §2.3:437-439 |
| 4 | `chain_break` | POST | `/api/v1/admin/chain-break` | full | `busbar-unit-verbs::Verbs::chain_break` → `Store` | — | 6 | §4.1:753 · §4.2:782 · §4.3:813 · §4.7:990 |
| 5 | `store_restore` | POST | `/api/v1/admin/store-restore` | full | `busbar-unit-verbs::Verbs::store_restore` → `Store` | — | 6 | §4.3:812-813 · §4.6:932-934 |
| 6 | `reseal_epoch_floor` | POST | `/api/v1/admin/reseal-epoch-floor` | full | `busbar-unit-verbs::Verbs::reseal_epoch_floor` → `Store` | — | 4 | §4.6:932-934 · §4.3:812 |
| 7 | `set_overdraft_ceiling` | POST | `/api/v1/admin/set-overdraft-ceiling` | full | `busbar-unit-verbs` → `execute_new_verb` | `CeilingView` | 6 | §4.4:848-854 · §4.7:1036 |
| 8 | `set_dispute_max_age` | POST | `/api/v1/admin/set-dispute-max-age` | full | `busbar-unit-verbs` → `execute_new_verb` | — | 4 | §4.7:1025,:1057-1059 · §4.4:834 |
| 9 | `commit_upgrade` | POST | `/api/v1/admin/commit-upgrade` | full | `busbar-unit-verbs` → `execute_new_verb` | — | 4 | §4.8:1068-1071 |
| 10 | `resolve_dispute` | POST | `/api/v1/admin/resolve-dispute` | full | `busbar-unit-verbs` → `execute_new_verb` | `DisputeVerdictView` | 6 | §4.7:1050,:1057-1059 |
| 11 | `resolve_slice` | POST | `/api/v1/admin/resolve-slice` | full | `busbar-unit-verbs` → `execute_new_verb` | `UnreconciledSliceView` | 5 | §4.6:935-937 · §4.2:770-772 |
| 12 | `adjust` | POST | `/api/v1/admin/adjust` | full | `busbar-unit-verbs` → `execute_new_verb` | `AdjustmentView` | 7 | §4.1:741 · §4.2:770,:776-777 |
| 13 | `amend_rate_history` | POST | `/api/v1/admin/ledger/amend-rate-history` | full | `busbar-unit-verbs::Verbs::amend_rate_history` → ledger unit | `HistoryView` | 3 new + 2 re-answered | **silent; proposed** (path recorded) |

**Totals.** 2 GET · 11 POST (+ amend). 2 read-only · 11 full (+ amend). **0 irreducible, 0 posture,
0 signature, 0 approvals.** 3 execute against `Store`, 8 against `Governance::execute_new_verb`, 1
(`plane_facts`) against the named plane through it, 1 (`amend_rate_history`) against the ledger unit.
5 name a figure: 4 in new `busbar-unit-cost` view types + 1 in the existing `HistoryView`.
**72 new `admin.ops` cells + 3 new `ledger|amend|` cells**; the 240 existing `admin.ops` cells are
untouched.

**Departed.** `set_operator_key`, `set_escrow`, `set_dual_control`, `approve`, `export_keyset` — 5
rows out of `busbar-plane-admin::verbs`, 5 variants out of `NEW_VERBS`, and every mention out of the
executing unit (§10).

Every row above is **ARCHITECTURE silent on its method and path** except `amend_rate_history`, whose
path is recorded against the shipped 1.5.5 binary. §4.7:957-962's binding list and Appendix A's
CG-56 ratification are rewritten by the ruling and are no longer this document's authority; the
bindings are proposed here, per verb, for the owner to ratify once.

---

## 9. The token allow-list

### 9.1 The config key

Admin credentials are defined today as `identity-providers.<name>` entries referenced from
`auth.admin_auth:` by **bare name** (`crates/busbar-substrate/src/config/auth.rs:20-28,44,93`;
resolved by `crates/busbar-core/src/config/mod.rs`'s `resolve_auth` :558). There is **no
`admin_token:` key and no named map of many tokens** in the modern grammar; `auth.group_map:` is
1.4.x legacy handled only by the migrator (`crates/busbar-core/src/config/migrate.rs:83-85`) and
nothing is added under it. The token definition is `IdentityProviderCfg`
(`crates/busbar-substrate/src/config/auth.rs:44`), whose current shape the config-stability
snapshot records at `config-schema.snapshot.json:825-851` as:

```json
{ "deny_unknown_fields": true,
  "fields": { "browser_login": {"optional": true,  "type": "BrowserLoginCfg"},
              "max_admin_scope": {"optional": true,  "type": "String"},
              "module":          {"optional": false, "type": "String"},
              "settings":        {"optional": true,  "type": "serde_json::Map<String, serde_json::Value>"},
              "token":           {"optional": true,  "type": "SecretRef"} },
  "kind": "struct" }
```

**Proposed: one new optional field, `verbs`.**

```yaml
identity-providers:
  ops-oncall:
    module: admin-tokens
    token: ${BUSBAR_OPS_TOKEN}
    verbs: ["verify", "plane_facts", "chain_break", "store_restore", "reseal_epoch_floor"]

  billing-ops:
    module: admin-tokens
    token: ${BUSBAR_BILLING_TOKEN}
    verbs: ["adjust", "resolve_dispute", "resolve_slice", "amend_rate_history"]

  root:
    module: admin-tokens
    token: ${BUSBAR_ROOT_TOKEN}
    verbs: "*"

  auditor:
    module: admin-tokens
    token: ${BUSBAR_AUDIT_TOKEN}
    verbs: read-only          # shorthand
```

Grammar — the whole of it:

| form | means |
|---|---|
| absent | **the 1.5.5 behaviour, unchanged**: the credential's `Scope` alone decides. See §9.4 |
| `"*"` | every verb the table declares, present and future |
| `read-only` | shorthand for every verb whose `required_scope` is `ReadOnly` — today `verify`, `plane_facts`, and the five ledger views |
| `full` | shorthand for every verb, i.e. exactly `"*"`, named so an operator can write the classic pair symmetrically |
| a list of verb names | exactly those. Names are the `KernelVerb` snake_case spelling the plane's table carries (`chain_break`, not `chain-break` and not `ChainBreak`) |

`verbs:` is `Option<Vec<String>>` with `#[serde(default)]`, the three bare tokens accepted as
one-element strings (`verbs: "*"` / `verbs: read-only` / `verbs: full`), so the schema fingerprint
renders `{"verbs": {"optional": true, "type": "Vec<String>"}}` and nothing hand-impl'd is added
(a hand-written `Deserialize` would put a refusal set into the fingerprint, which the gate freezes
in **both** directions — `classify.rs:275-300`).

**One wire-visible side effect to weigh — see D-I.** `IdentityProviderCfg` is
`#[serde(deny_unknown_fields)]` (`auth.rs:43`), so adding a field lengthens serde's
`unknown field ..., expected one of ...` list — and that message is reachable through the admin
API's named-map writer for `identity-providers`. `crates/busbar-core/src/config/prepass.rs:7-17`
exists for exactly this hazard and lifts 1.6.0-additive keys off frozen structs
(`LIFTED_TOP_LEVEL_KEYS` :52-53, `LIFTED_AUTH_KEYS` :59-60). Two ways out, both dumb:
**(a)** accept the longer list (it is an *additive* widening of an error string, not a narrowing,
and no oracle cell in the 240 spells this particular list — to be verified red-first before the
cut); **(b)** put the allow-list in the free-form `settings:` bag the definition already carries
(`auth.rs:88`, `serde_json::Map<String, Value>`) as `settings: { verbs: [...] }` — **zero** config
schema delta, zero serde-message delta, at the cost of moving §9.3's validation into the plugin and
out of the typed grammar. Proposal: **(a)**, typed and validated; (b) is the fallback if the message
turns out to be pinned.

### 9.2 Enforcement, and its refusal

Step 3 of the ladder (§3). The rule is one line: **the verb's own name must be in the credential's
resolved list.** No posture, no threshold, no exception for any verb.

```
resolve(entry) -> BTreeSet<&'static str>
    None            -> every verb whose required_scope the credential's Grants allow   (§9.4)
    ["*"] / ["full"]-> every verb the table declares
    ["read-only"]   -> every verb whose required_scope is ReadOnly
    names           -> those names
```

The refusal is `AdminError::Forbidden { needed: "<verb>" }` → **403 `forbidden`**,
``insufficient scope: this endpoint requires `<verb>` `` — the shipped 1.5.5 template
(`crates/busbar-plane-admin/src/envelope.rs:163-165`) with the verb name in the `needed` slot. No
new `AdminError` variant, no new `ReasonCode`, no new status.

**Where the check goes, exactly.** The 403 an operator sees today is produced at the ROOT's scope
step, not in the executing unit: `units_admin::approve` (`mod.rs:1424-1447`) compares
`granted.allows(scope_as_verb_scope(needed))` and `admin_mount.rs:264-274`'s `scope_answer` renders
`ReasonCode::ScopeDenied` into the message above. The unit's own `admit`
(`crates/busbar-unit-verbs/src/verbs.rs:213-222`) refuses a short scope with
`ReasonCode::Unauthorized`, which is the second, defence-in-depth reading. **The allow-list check
belongs beside the first**, in `approve`, immediately after the scope comparison — one place, one
message shape, and the unit's `admit` is left byte-unchanged.

**The gap this exposes, and it is real.** `ProductionUnits::admin_grant`
(`crates/busbar/src/root/kernel.rs:591-599`) is three arms today: open front door → `Full`;
principal id == `ADMIN_PRINCIPAL_ID` → `Full`; everything else → `None`. It **never reads
`role_bindings`**, so a group-mapped `read-only` admin principal currently reaches no kernel verb at
all — while `crates/busbar-core/src/auth/mod.rs`'s `admin_scope_for` (:1180-1219) resolves exactly
that grant for the legacy surface. The allow-list is threaded through the same accessor, so
`admin_grant` must grow from "is this the root token" to "resolve this principal's grants and verb
list" in the same cut. Without it, `verbs:` on any non-root credential would be enforced against a
grant of `None` and refuse everything.

**Ordering:** scope is checked first, allow-list second. A `read-only` credential asking for `adjust`
therefore still gets ``insufficient scope: this endpoint requires `full` ``, byte-identical to
1.5.5. Only a credential that HOLDS the scope and LACKS the verb sees the new message, and no 1.5.5
config can produce one (§9.4).

**The name resolves against the same closed table the router does.** A verb name in `verbs:` that
the table does not declare is a config error, not a silent no-op (§9.3) — an allow-list whose
entries can be typos is an allow-list that fails open by spelling.

### 9.3 Validation refusals

Checked at config load, beside `validate_token_placement`
(`crates/busbar-core/src/config/mod.rs:586`), accumulated into `errors` like every other
resolve-time diagnostic — so a bad allow-list refuses boot rather than shipping a token that can do
less (or more) than the operator wrote.

| condition | message |
|---|---|
| `verbs:` on a provider whose `module:` is not `admin-tokens` | ``identity-providers.<name>: `verbs:` is the built-in `admin-tokens` per-verb allow-list and is meaningless on `module: <m>` `` — exactly the shape and reason `validate_token_placement` (`crates/busbar-core/src/config/mod.rs:576-593`) already uses for `token:`, and checked in the same place so a definition written through the admin API and not yet referenced from a chain is caught too |
| an unknown verb name | ``identity-providers.<name>.verbs: `<v>` is not an admin verb (the closed table declares <n>)`` |
| a kebab-case or PascalCase spelling | ``identity-providers.<name>.verbs: `<v>` — admin verbs are spelled `chain_break`, not `<v>` `` |
| an empty list `verbs: []` | ``identity-providers.<name>.verbs: an empty list denies every verb; write `verbs: read-only`, a non-empty list, or omit the key`` — a loud refusal rather than a token that authenticates and can do nothing |
| `"*"` mixed with names | ``identity-providers.<name>.verbs: `*` allows every verb and may not be combined with a name list`` |
| a shorthand mixed with names | ``identity-providers.<name>.verbs: `<read-only\|full>` is a shorthand for a whole set and may not be combined with a name list`` |
| duplicate names | not an error. A list is a set; duplicates are collapsed silently |

**The config-schema gate.** `verbs` is a **new optional field on an existing struct**, which
`xtask/src/gates/config_schema/classify.rs:153-155` classifies as
`IdentityProviderCfg.verbs: new OPTIONAL field added` → `Severity::Additive` → **green, and no
waiver line** (`config-schema.waivers` is comments-only today and stays that way; a stale waiver is
itself a gate failure, `classify.rs:551-584`). The only ways to make it red are to declare it
required (`:157-162`) or to retype an existing field, and this document does neither.
`config-schema.snapshot.json` is regenerated in the same commit that adds the field
(`cargo xtask gate config-schema --write`, `mod.rs:65`); regenerating does not launder anything,
because the additive check reads the committed **git baseline**, never the working tree
(`mod.rs:16-23`, `DEFAULT_BASELINE_REF` :62). Gate rows touched: `config-schema:snapshot-drift`
(green after regen) and `config-schema:additive-only` (green with one additive delta).

### 9.4 Migration — existing configs are unchanged

**`verbs:` absent is 1.5.5's behaviour, exactly.** The resolved list is then "every verb the
credential's `Grants` already allow", which is the rule that runs today: `required_scope(verb)`
against `Grants::allows` (`crates/busbar-unit-verbs/src/verbs.rs:216`,
`crates/busbar-unit-scope/src/lib.rs:160`). So:

- Every shipped config keeps working with no edit. No boot warning, no diagnostic, no deprecation.
- The built-in operator credential (`module: admin-tokens` with a `token:`, principal id `admin`)
  remains exempt from the `max_admin_scope` ceiling and full by definition — `resolve_auth`'s
  `max_admin_scope` default skips `ADMIN_TOKENS_MODULE`
  (`crates/busbar-core/src/config/mod.rs:617-623`), and `admin_scope_for` answers
  `Grants::of(Scope::Full)` for the roleless `admin` principal on that module
  (`crates/busbar-core/src/auth/mod.rs:1203-1208`). Absent `verbs:`, it reaches every verb — which
  is what it does today.
  (`crates/busbar-unit-auth/src/admin.rs`'s `admin_grants` / `kernel_verb_scope_satisfied` cover
  only the open no-chain posture and have **no production caller**; they are not on this path and
  are not changed.)
- `read-only` and `full` keep meaning what they have always meant. `verbs: read-only` on a
  credential whose scope is already `ReadOnly` is a no-op, and is allowed rather than warned about,
  because an operator writing both is being explicit and being explicit is not an error.
- Group-mapped external principals get their scope from `role_bindings.<module>.<role>.admin_scope`
  (`crates/busbar-substrate/src/config/auth.rs:139-156`), not from a token definition. **This
  document does not give them a `verbs:` key** — see D-I. Their reach stays their `admin_scope`
  rung. (`auth-admin-tokens/src/lib.rs:18`'s doc comment still says "group-mapped external
  principals get their scope from `group_map:`" — stale 1.4.x prose; the mechanism is
  `role_bindings:`, and the line is corrected in the same cut.)
- **Narrowing is opt-in and one-directional.** Adding `verbs:` to an existing token can only take
  verbs away, never add them: the allow-list is intersected with the scope check, never substituted
  for it. A `read-only` token with `verbs: ["adjust"]` still cannot `adjust`; it can do nothing, and
  §9.3's empty-list reasoning does not apply because the list is not empty — that combination is
  legal and useless, and the owner may want it warned (D-I).

---

## 10. What leaves the code

Design only; the implementation cut is Phase 2. Listed here so the deletion is a contract and not an
implementer's judgment.

| what | where |
|---|---|
| the whole posture module | `crates/busbar-unit-verbs/src/posture.rs` — `OperatorState`, `DualControl`, `PostureCtx`, `check_operator_gate`, `check_dual_control`, `check_approve`, `check_set_dual_control_required`, `check_new_verb_admission`, and its tests |
| the two closed sets | `crates/busbar-unit-verbs/src/verb.rs:738-755` — `IRREDUCIBLE_VERBS`, `ADMITTED_UNDER_UNSET` |
| the five verb variants | `KernelVerb::{SetOperatorKey, SetEscrow, SetDualControl, ExportKeyset, Approve}` and their `NEW_VERBS` rows (`verb.rs:672-690`) |
| the five plane table rows | `crates/busbar-plane-admin/src/verbs.rs:52-63` (`set_operator_key`, `set_escrow`), `:82-87` (`set_dual_control`), `:124-135` (`export_keyset`, `approve`) |
| the table's own count | `crates/busbar-plane-admin/src/verbs.rs:183` — `VERB_COUNT = 66 + 17 + 5` becomes `66 + 13 + 5` (the twelve plus `amend_rate_history`'s new row): **88 → 84** |
| the five reason codes | `crates/busbar-unit-verbs/src/refusal.rs` — `OperatorUnset`, `SelfApproval`, `PayloadMismatch`, `InsufficientApprovers`, `ApprovalPending` |
| the root's posture folding | `crates/busbar/src/root/units_admin/mod.rs:1806-1820` — the arms mapping approval reasons onto `HookVeto` and `OperatorUnset` onto `ScopeDenied` |
| the operator-key test cases | `crates/busbar/src/root/units_admin/tests/units_admin.rs:1251,:1306,:1332,:411` |
| the operator-signature design | held.txt's `X-Busbar-Signature: ed25519:<fp>:<b64>` scheme and the operator-key registry seam — **not built**, for `amend_rate_history` or anything else |

`crates/busbar/tests/new_verbs_legacy_leg.rs` and `crates/busbar/tests/admin_verb_ownership.rs` move
in the same cut: the partition over the table's 84 rows becomes **18 loop-answered** (the 13 + the 5
ledger views) **/ 66 surface-answered / 0 answered by nobody**, and `LOOP_SERVED_VERBS` grows from
three to thirteen. The 66 legacy rows and their 240 cells do not move.

**And one thing must GROW**, or `verbs:` refuses everything it is written on:
`ProductionUnits::admin_grant` (`crates/busbar/src/root/kernel.rs:591-599`) must resolve a
principal's grants from `role_bindings` — as `crates/busbar-core/src/auth/mod.rs`'s `admin_scope_for`
(:1180-1219) already does for the legacy surface — and carry the resolved verb list alongside them,
instead of answering `Full` for the root token and `None` for everyone else. See §9.2.

ARCHITECTURE §4.7's operator-key, dual-control, escrow and irreducible-set text is rewritten to the
ruling in its own commit, not this one.

---

## 11. Owner decisions still open

Ten, and the owner wants a dumb API — so eight of them are "confirm the boring answer".

| id | decision | proposed |
|---|---|---|
| **D-A** | **The replay TTL.** §4.4:834 says `min(dispute_max_age, max(600 s, longest finite cap window + max_unit_duration))`; `plugin-loader/src/store_adapter.rs:170` pins 600 s. | keep **600 s** flat — one number, no formula the caller cannot predict. §4.4:834's formula is the ceremony-era answer |
| **D-B** | **Is `Idempotency-Key` ever required?** The 17-verb draft required it on five verbs. | **never required**, on any verb. The calling app decides whether it wants replay protection |
| **D-C** | **Rate class for the eleven mutating verbs.** They fall through to `Crud` (60/min) because no `ADMIN_PREFIX`-relative rule matches (`rate.rs:164-167`). | add `chain-break`, `store-restore`, `reseal-epoch-floor`, `commit-upgrade` to `CONFIG_CLASS_RULES` (10/min); the rest stay `Crud`. CG-38 flags this table as "supplied at integration, must not ship wrong" |
| **D-D** | **`ledger\|amend\|refused-unsigned`** — a recorded cell whose premise (an operator signature) the ruling deletes. Also: `adjust_threshold` now gates nothing; is it reporting-only, or does it leave 1.6.0 too? | re-point the cell at `verb-not-allowed` (same shape: a refusal that is about authority, not about the route); keep `adjust_threshold` as **reporting/alarm input only** |
| **D-E** | **Does `verify` write a `Reconciliation` entry**, or only the every-T timer run (§4.2:782)? | only the timer — an operator polling `verify` must not rewrite the recompute watermark |
| **D-F** | **CG-04 — does `plane_facts` carry a subject?** Decides whether `?subject=` is in the binding. Two planes already decline to declare per-name projections because of it. | add the subject; the parameter is optional either way |
| **D-G** | **CG-57 — rename `PlaneMeta::ADMIN_VERBS` to `INTROSPECTION_VERBS`.** It collides with the admin surface's own table, which is what `plane_facts` reads *about*. | rename |
| **D-H** | **`§8.1:1208-1209`'s two-cell ceremony** ("1.5.5 config, no operator key: boots; `commit_upgrade` refused; `set_operator_key` then `commit_upgrade` succeeds") has no referent. | withdraw both cells with the ceremony |
| **D-I** | **Where the allow-list lives, and how far it reaches.** (i) typed `verbs:` on `IdentityProviderCfg` — additive to the config schema, but lengthens serde's `expected one of` list on a frozen `deny_unknown_fields` struct (§9.1); or the zero-delta `settings: { verbs: [...] }` bag. (ii) does `role_bindings.<module>.<role>` get one too, for group-mapped principals? (iii) should `verbs: ["adjust"]` on a `read-only` token warn (legal, useless)? | (i) **typed**, with the serde-message widening verified red-first against the 240 cells; (ii) **no** in 1.6.0 — one allow-list, on the token, is the dumb answer; (iii) **warn** |
| **D-J** | **`ProductionUnits::admin_grant` must learn `role_bindings`** (§9.2, §10). It is a real gap today, not new work the allow-list invents: a group-mapped `read-only` admin principal reaches no kernel verb at all, while the legacy surface grants it correctly. | fix it in the same cut, reusing `admin_scope_for` rather than writing a second resolver |

The money-view types' home and shape (`busbar-unit-cost::view`, five types, nano-units as decimal
strings — §5) is the owner's 2026-09-08 07:5x ruling made concrete and is not re-opened here; it
touches `busbar-unit-cost`'s "NO WORKSPACE DEPENDENCIES BEYOND THE CAPABILITY CRATE" line only in
that bucket/dimension/scope arrive as `String`.
