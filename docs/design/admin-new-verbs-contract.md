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

Owner rulings carried into this document (2026-09-08):

1. **07:5x** — implement all seventeen to their ARCHITECTURE contract; **admin views that name money
   live in `busbar-unit-cost`'s view types** — the control surface never names a figure.
2. **08:5x** — **admin is a CONTROL SURFACE**, a new plugin kind `control`. See §1.1.

---

## 1. What this document is, and the constraints it is written under

### 1.1 Admin is a control surface, not a data plane

The seventeen are contracted here as operations of a **`control` kind**, not of a plane. Five
properties follow, and every row in §7 is written to them:

| property of a `control` surface | what it means for the seventeen | evidence it already holds |
|---|---|---|
| **unmetered** | no verb draws a meter class, a `requests` slot, a `concurrent` lease or a fee. Every one posts zero | §4.7:368 — "an admin unit's set is `KernelVerb` only … `KernelVerb` units draw no dimension unless the card's `KernelVerb` section prices them"; §8.1:1196's admin cell asserts "zero fee/requests postings" under a non-zero configured fee; the loop's `meter` already reports an empty usage report and says why (`crates/busbar/src/root/units_admin/mod.rs:1822–1839`) |
| **routes are data** | the 88-row `(method, path) -> verb` table is a declared table, matched by a pure function, never a router the surface owns | `busbar-plane-admin::verbs::{all_verbs, find_verb, resolve, table}` are already exactly this — a linear scan over a closed slice with no behaviour |
| **verify · admit · audit · answer** — and nothing else | a control surface has no Route-to-upstream, no egress, no encode-from-facts. It checks the call, admits it, records it, and hands back bytes the unit produced | the loop's `encode` already "hands back an empty frame … which is the shape that makes it impossible for a byte to be re-derived here" (`mod.rs:1998–2002`) |
| **node state only through the verbs unit** | no verb reaches governance, the store, `Policy` or the journal except through `busbar-unit-verbs`, which holds `AdminToken`. The surface holds no store handle | §4.7:949 — "executed by `busbar-unit-verbs`, which holds `AdminToken` … the admin plane is the codec only"; `Verbs` does not hand out its bound store (`verbs.rs:463–468`) |
| **no money vocabulary** | the surface names no figure, no currency, no bucket amount. Where an answer carries a figure it is a `busbar-unit-cost` view type, serialized by the unit, passed through as bytes | §5; the `plane-no-money` gate rule (`qa/full-gate.toml:89`) |

Two consequences worth stating so no row is read the wrong way:

- **"Executes in `busbar-unit-verbs`" in §7 and §8 means the control path**, not a plane's Route
  step: `verify → admit → (idempotency) → effect through the unit → audit → answer`. The kernel
  `Route` step is where the composition root currently hangs it (`mod.rs:1500`) because there is no
  `control` kind yet; that is a wiring detail, and the contract below does not depend on it.
- **`busbar-plane-admin` becomes `busbar-control-admin` in the R7 rename.** This document keeps the
  current crate name in every path citation because the rename has not happened; **do not rename
  now**. Every `crates/busbar-plane-admin/...` citation below is a `crates/busbar-control-admin/...`
  citation after R7.

The `control` kind itself — its entry in §1.4's plugin-kind table, its ABI constant, its declared
route-table shape and the AST scan that keeps it unmetered — is not this document's to invent; it is
owner decision **D-15**.

### 1.2 The constraints

| constraint | consequence for every row below |
|---|---|
| the 66 legacy verbs' bytes are untouched | no row here edits `generated::verb_table_1_5_5`, and the 240 existing `admin.ops` cells stay green unchanged. Every cell this document asks for is additive |
| kind isolation | the control surface is a codec and a declared route table (`busbar-plane-admin`, `busbar-control-admin` after R7); the unit executes (`busbar-unit-verbs`); every figure is a `busbar-unit-cost` view type. `plane-no-money` stays green |
| every verb is unmetered | no row below declares a meter class, a `requests` draw, a `concurrent` lease or a fee. The mutation **rate limiter** (§3, step 3) is not metering — it is admission bookkeeping and posts nothing |
| the sealed idempotency cache exists and is never consulted | `Store::replay_new_verb` / `Store::commit_new_verb_replay` (`crates/busbar-unit-verbs/src/store.rs:60,63`) have **no non-test caller**. Every mutating row below states where the probe goes |
| the plane's table literals are stale | §4.7's binding list disagrees with `crates/busbar-plane-admin/src/verbs.rs:33–136` in nine places. §3 lists them |

Sources every row cites:

- `docs/design/ARCHITECTURE.md` — §1.4, §2.3, §3.2, §4.1–§4.9, §8.1, §8.3, Appendix A.
- `crates/busbar-unit-verbs/` — `verb.rs` (`NEW_VERBS` :672, `READ_ONLY_NEW_VERBS` :702,
  `IRREDUCIBLE_VERBS` :738, `ADMITTED_UNDER_UNSET` :753), `verbs.rs` (`required_scope` :142,
  `admit` :215, `execute` :412), `posture.rs`, `rate.rs`, `refusal.rs`, `store.rs`, `idempotency.rs`.
- `crates/busbar-plane-admin/` — `verbs.rs` (the table), `envelope.rs` (`AdminError`), `refusal.rs`
  (the frozen envelope shape).
- `crates/busbar/src/root/units_admin/mod.rs` — `route` :1500, `verbs_reason` :1806, `audit` :1847,
  `applied_answer` :1701.
- `crates/busbar/tests/new_verbs_legacy_leg.rs`, `crates/busbar/tests/admin_verb_ownership.rs` —
  the shipped state: **fourteen of the seventeen are gated and then 404**, and `set_operator_key`
  is one of them.
- `testing/shadow-oracle/cells/__init__.py` (`admin.ops` builder :462–690) and
  `testing/shadow-oracle/cells.json` — the cell id scheme and driver vocabulary.

---

## 2. The `verify` GET-vs-POST resolution

**Resolution: `verify` is `GET`.** ARCHITECTURE decides it twice, in the normative section and again
in the decisions register, and nothing overrides either:

- `docs/design/ARCHITECTURE.md:958` — "POST for every mutating verb, GET for the two read-only verbs
  (`verify`, `plane_facts`). Bindings: `GET verify` · `GET plane-facts` · …"
- `docs/design/ARCHITECTURE.md:1514` — "**CG-56 …**: POST for every mutating verb, GET for `verify`
  and `plane_facts`."

The executing unit already agrees, in five places, and its behaviour follows from it: `verify` is a
member of `READ_ONLY_NEW_VERBS`, so it asks `ReadOnly` scope, draws no mutation budget, and is not
held behind a maker-checker step.

Exactly one place in the tree declares `POST`, and it is the row that CG-56 says was a guess:

| file:line | says | fix |
|---|---|---|
| `crates/busbar-plane-admin/src/verbs.rs:34–39` | `method: "POST", path: "/api/v1/admin/verify"` | `method: "GET"` |
| `crates/busbar-plane-admin/src/verbs.rs:11–18` | the module doc calls all seventeen bindings a "judgment call, flagged for review … synthetic" | rewrite: the bindings are §4.7's, ratified by CG-56; the literals are transcribed, not invented |
| `/Users/matthew/Developer/GetBusbar/busbar-landq-state/gate/held.txt:174` | "`verify` is POST (three doc comments say GET — owner: pick)" | the pick is GET; the three doc comments were right and the table was the outlier |

The doc lines that already say GET and need **no** change, listed so a reviewer can see the count is
not two against one: `crates/busbar-unit-verbs/src/verb.rs:692–693`,
`crates/busbar-unit-verbs/src/verbs.rs:137` and `:147`, `crates/busbar-unit-verbs/src/rate.rs:141`,
`crates/busbar-unit-verbs/src/posture.rs:107`, plus the two test docs at
`crates/busbar-unit-verbs/src/tests/rate_tests.rs:199` and
`crates/busbar-unit-verbs/src/tests/verbs_tests.rs:1464,1467`.

One consequence worth naming: `crates/busbar/tests/new_verbs_legacy_leg.rs` drives each row with the
method the plane's table declares (its `ask()` helper panics on anything but GET/POST). Flipping the
table row flips what that test asks, which is the intended coupling.

### 2.1 The other eight rows that drift from §4.7

Same cause, same fix, and they are path literals rather than methods. §4.7's rule is
`<kebab-case-verb>` — the **whole verb name**, `set_` prefix and all.

| verb | §4.7's binding list | plane table today | file:line |
|---|---|---|---|
| `set_operator_key` | `POST /api/v1/admin/set-operator-key` | `/api/v1/admin/operator-key` | `verbs.rs:54` |
| `set_escrow` | `POST /api/v1/admin/set-escrow` | `/api/v1/admin/escrow` | `verbs.rs:60` |
| `set_dual_control` | `POST /api/v1/admin/set-dual-control` | `/api/v1/admin/dual-control` | `verbs.rs:84` |
| `set_overdraft_ceiling` | `POST /api/v1/admin/set-overdraft-ceiling` | `/api/v1/admin/overdraft-ceiling` | `verbs.rs:90` |
| `set_dispute_max_age` | `POST /api/v1/admin/set-dispute-max-age` | `/api/v1/admin/dispute-max-age` | `verbs.rs:96` |
| `resolve_dispute` | `POST /api/v1/admin/resolve-dispute` | `/api/v1/admin/disputes/resolve` | `verbs.rs:108` |
| `resolve_slice` | `POST /api/v1/admin/resolve-slice` | `/api/v1/admin/slices/resolve` | `verbs.rs:114` |
| `verify` | `GET /api/v1/admin/verify` | `POST /api/v1/admin/verify` | `verbs.rs:35` |

Eight rows already match and stay byte-for-byte: `plane-facts`, `plane-record-write`, `chain-break`,
`store-restore`, `reseal-epoch-floor`, `commit-upgrade`, `adjust`, `export-keyset`, `approve` (nine,
counting `approve`).

Dependent literals that move with them:

- `crates/busbar/src/root/units_admin/tests/units_admin.rs:1251`, `:1306`, `:1332` —
  `"/api/v1/admin/operator-key"` → `"/api/v1/admin/set-operator-key"`.
- No other test in the tree spells a drifting path; `:411` (`export-keyset`), `:428`
  (`chain-break`), `:434` (`adjust`) and `:1463–1470` (the three recovery verbs) already match §4.7.

---

## 3. The control path — the common admission ladder

Every one of the seventeen runs the same ladder before its own effect: **verify** (steps 0–2),
**admit** (3–6), **effect through the unit** (7), **audit** (8), **answer**. There is no meter step
that posts anything and no egress step at all — that is what makes this a control surface. Stated
once here; the per-verb sections below name only what each adds.

```
0.  decode            busbar-plane-admin: verbs::find_verb(method, path) -> VerbEntry
                      no row            -> 404 not_found  (a path the table does not declare)
                      row, wrong method -> 405 method_not_allowed
1.  authenticate      the admin credential; no principal -> 401 unauthorized
2.  scope             busbar-unit-verbs::required_scope(verb)  (verbs.rs:142)
                        READ_ONLY_NEW_VERBS -> ReadOnly ; every other new verb -> Full
                      short -> ReasonCode::Unauthorized -> 403 forbidden
3.  rate class        MutationClass::for_verb(verb, CONFIG_CLASS_RULES)  (rate.rs:151)
                        verify / plane_facts -> Forbidden (never limited)
                        the other 15         -> Crud, 60/min per actor      [see D-14]
                      over -> ReasonCode::RateLimited -> 429 rate_limited
4.  operator gate     posture::check_operator_gate  (posture.rs:80)
                        operator == Unset AND verb in IRREDUCIBLE_VERBS
                        AND verb not in ADMITTED_UNDER_UNSET -> OperatorUnset -> 403 forbidden
5.  dual control      posture::check_dual_control   (posture.rs:98)
                        `approve` and the two reads are exempt
                        Single    -> pass
                        Required  -> Approved      -> pass
                                     NotYetApproved-> ApprovalPending   [D-1: pending, not refused]
                                     SelfApproved  -> 403 forbidden
                                     PayloadMismatch -> 409 conflict
6.  IDEMPOTENCY       ** the step that does not exist yet **  — §4 below
7.  effect            Governance::execute_new_verb  (14 verbs)
                      Store::{chain_break, store_restore, reseal_epoch_floor}  (3 verbs)
8.  audit             ADMIN_LOG row for every mutating verb; journal entry per §4.1's class
9.  answer            the bytes the unit produced, unchanged. Nothing is re-derived here.
                      NO METER STEP POSTS: zero usage lines, zero fee, zero requests, no lease.
```

### 3.1 The frozen refusal envelope

Every refusal below renders through `busbar_plane_admin::refusal::envelope_of` — the 1.5.5 shape,
`{"error":{"code":"…","message":"…"}}`, `code` before `message`, serialized (never hand-formatted),
no trailing byte. Codes and statuses are `AdminError`'s ten, unchanged
(`crates/busbar-plane-admin/src/envelope.rs:120–147`):

`not_found` 404 · `unauthorized` 401 · `method_not_allowed` 405 · `forbidden` 403 ·
`invalid_request` 400 · `version_conflict` 409 · `conflict` 409 · `rate_limited` 429 ·
`internal` 500 · `unavailable` 503.

Message wording follows the 1.5.5 template style already in `envelope.rs:152–174`: lower case, no
trailing period, the named thing in backticks, caller-safe. The four shared messages are the
shipped ones verbatim:

| condition | status | code | message |
|---|---|---|---|
| no/invalid credential | 401 | `unauthorized` | `missing or invalid admin credential (Bearer or x-admin-token)` |
| wrong method on a declared path | 405 | `method_not_allowed` | `method not allowed for this resource` |
| scope short | 403 | `forbidden` | ``insufficient scope: this endpoint requires `full` `` (or `` `read-only` ``) |
| over the mutation budget | 429 | `rate_limited` | `admin mutation rate limit exceeded; retry next minute` |

The five posture refusals are new wording in the same style. **ARCHITECTURE silent on the wording;
proposed:**

| `busbar_unit_verbs::ReasonCode` | status | code | proposed message |
|---|---|---|---|
| `OperatorUnset` | 403 | `forbidden` | ``the operator-key ceremony has not run; `<verb>` is refused until `set_operator_key` seals an operator key`` |
| `SelfApproval` | 403 | `forbidden` | `an approval may not come from the principal that made the request` |
| `PayloadMismatch` | 409 | `conflict` | `the approval's payload hash does not match the pending mutation` |
| `InsufficientApprovers` | 409 | `conflict` | ``dual control `required` needs at least two distinct admin principals`` |
| `IdempotencyInFlight` | 409 | `conflict` | `this request is still in flight` |
| `StoreError` | 503 | `unavailable` | `the journal is unavailable` |
| `Internal` | 500 | `internal` | `internal error` |

`crates/busbar/src/root/units_admin/mod.rs:1806–1820` currently folds all four approval reasons onto
one kernel `ReasonCode::HookVeto` and `OperatorUnset` onto `ScopeDenied`. That mapping is
kernel-facing and may stay; the **client-facing** code must be the table above, because an operator
who cannot tell "you may not do this" from "the ceremony has not run" cannot run the ceremony.

### 3.2 The refusal ARCHITECTURE names and the vocabulary does not have

§4.7:991 — "`busbar policy sign <config>` (off-node) emits a detached signature read beside
`config.yaml`; **verbs carry the signature as an argument**." An irreducible verb whose signature is
missing, malformed, or made by a key that is not the sealed operator key must be refused — and
`busbar_unit_verbs::ReasonCode` (`refusal.rs:40–69`) has **no arm for it**. The nearest arms are
`Validation` (400, which says the caller sent a malformed body — untrue) and `Unauthorized` (403,
which says the credential is short of scope — also untrue).

**ARCHITECTURE silent; proposed:** add `ReasonCode::OperatorSignatureRequired` (403 `forbidden`,
``this verb requires an operator signature; see `busbar policy sign` ``) and
`ReasonCode::OperatorSignatureInvalid` (403 `forbidden`, `the operator signature does not verify
against the sealed operator key`). Owner decision **D-2**.

### 3.3 `set_operator_key` under `operator: unset` — the exact gate path

§4.7:986–990 makes this the one path that must never close: "absent at `Bootstrap` → sealed
`operator: unset`, every irreducible verb refused except `set_operator_key` and `export_keyset` …
so a 1.5.5 config boots unchanged and the fleet can always be brought under the key." The shipped
tree admits it through every gate and then 404s (`crates/busbar/tests/new_verbs_legacy_leg.rs:23–26`)
— a fleet cannot be brought under the key. The gate path the implementation must keep open, step by
named step:

```
POST /api/v1/admin/set-operator-key
 └─ busbar_plane_admin::verbs::find_verb("POST", "/api/v1/admin/set-operator-key")
      -> VerbEntry { verb: "set_operator_key", read_only: false }        verbs.rs:52-57 (path fixed per §2.1)
 └─ root units_admin::route                                             mod.rs:1500
      └─ mints_its_own_identity(SetOperatorKey) == false                 mod.rs:1768  -> not the mint bypass
      └─ recovery_verb(SetOperatorKey) == None                           mod.rs:1568  -> not the Store leg
      └─ Verbs::execute(SetOperatorKey, ..)                              verbs.rs:412
           ├─ admit()                                                    verbs.rs:215
           │    ├─ required_scope -> NEW_VERBS.contains -> VerbScope::Full        verbs.rs:152
           │    └─ MutationClass::for_verb -> Crud (no legacy row, no ADMIN_PREFIX-relative
           │       rule matches) -> 60/min per actor                     rate.rs:151-168
           ├─ LEDGER_VERBS.contains == false                             verbs.rs:437
           ├─ NEW_VERBS.contains == true                                 verbs.rs:443
           │    └─ posture::check_new_verb_admission                     posture.rs:170
           │         ├─ check_operator_gate(SetOperatorKey, Unset)       posture.rs:80
           │         │     operator != Set                        -> keep going
           │         │     IRREDUCIBLE_VERBS.contains(SetOperatorKey)    verb.rs:744  -> keep going
           │         │     ADMITTED_UNDER_UNSET.contains(SetOperatorKey) verb.rs:753  -> Ok(())  ◄── THE GATE
           │         └─ check_dual_control(SetOperatorKey, ..)           posture.rs:98
           │               under `unset` the posture is ALWAYS `single`  — see below  -> Ok(())
           ├─ [D-3] sealed-replay probe: Store::replay_new_verb          store.rs:60   ◄── MISSING TODAY
           └─ Governance::execute_new_verb(SetOperatorKey, ..)           governance.rs:130  ◄── 404s TODAY
```

Two properties of that path are worth stating as contract rather than leaving to be re-derived:

1. **Under `unset`, dual control can never hold `set_operator_key`.** `required` is reachable only
   through `set_dual_control` (§4.7:972 — "`required` is only ever chosen by `set_dual_control`"),
   which is irreducible and not in `ADMITTED_UNDER_UNSET`, so it is refused under `unset`. A fleet
   that has never run the ceremony is therefore always in `single`, and step 5 is a pass. The
   ceremony cannot be deadlocked by a posture.
2. **The second and later calls are ordinary irreducible verbs.** §4.7:979 says
   `set_operator_key` is irreducible "(once set)". Rotation is "a `Policy` entry signed by the
   retiring key" (§4.7:991–992), so a call with `operator == Set` requires the operator signature
   argument (§3.2), and under `required` it takes a maker-checker `approve` like anything else.

---

## 4. Idempotency and replay — the cache that exists and is never consulted

`Store::replay_new_verb` / `Store::commit_new_verb_replay` are declared
(`crates/busbar-unit-verbs/src/store.rs:52–67`), implemented over the loader shim
(`crates/plugin-loader/src/store_adapter.rs:854,869`), adapted by the root
(`crates/busbar/src/root/units_admin/mod.rs:2084,2091`) — and called by **nothing outside tests**.
That is shipped defect (e) in the admin-leg harvest.

§4.4:833–834 is the rule: "the new credential-minting verbs use the store-backed sealed cache at
`min(dispute_max_age, max(600 s, longest finite cap window + max_unit_duration))`". §4.4:828–829 is
the discipline: `claim_key` synchronously **before** the effect; a second sighting is
`Refused(Admit, Replayed { token })` or `Refused(Admit, InFlight)`.

**Contract for every mutating new verb (all 15 — not only the credential-minting ones):**

- The probe happens at **step 6**, after posture and before the effect. Ordering is load-bearing in
  both directions: probing before posture would reserve a slot for a call the gates refuse (so a
  retry after the ceremony would replay a refusal); probing after the effect is not a probe.
- A request with **no** `Idempotency-Key` header proceeds without reserving, exactly as
  `IdempotencyCache::probe` → `Probe::NoKey` does for the two legacy replayable operations
  (`idempotency.rs:74–90`). **Except** for the five irreducible verbs whose effect is not
  re-runnable (`chain_break`, `store_restore`, `commit_upgrade`, `set_operator_key`,
  `export_keyset`), where the header is **required** — see D-3.
- First sighting reserves; the effect runs; `commit_new_verb_replay(key, response_bytes)` stores the
  **exact response body the writer was about to send**, never an intermediate form
  (`idempotency.rs:21–33` states why: a decode step could re-mint a `SecretOnce`).
- A replay returns the cached bytes **verbatim**, with the original status, and mints nothing. It is
  a `200`, not a `409`: 1.5.5's create/rotate replay returns the first answer, and §8.1:1207 pins
  "same node: byte-identical replay".
- A reservation still in flight is `ReasonCode::IdempotencyInFlight` → **409 `conflict`**,
  `this request is still in flight`.
- A reservation whose caller vanished mid-effect is `leak()`ed, never cleared
  (`idempotency.rs:129–133`) — a `chain_break` that landed must not be re-runnable by a retry.

**Key shape — ARCHITECTURE silent; proposed:** `(actor, "<verb>:<idempotency-key>")`. This mirrors
rotate's `(actor, "rotate:{id}:{k}")` exactly (`verbs.rs:361`), which exists precisely so a create
and a rotate sharing one header value never replay each other (§4.4:826–828). The shim's test helper
currently keys `(verb, key)` (`crates/plugin-loader/src/tests/store_adapter_tests.rs:414–416`), which
drops the actor — two principals sharing an idempotency key would replay each other's answer, and one
of those answers may be a sealed keyset. Owner decision **D-3**.

**TTL — a live disagreement.** `crates/plugin-loader/src/store_adapter.rs:170` pins
`REPLAY_TTL_SECS = busbar_unit_verbs::idempotency::IDEMPOTENCY_TTL_SECS` = **600 s**. §4.4:834 says
the new verbs' cache is `min(dispute_max_age, max(600 s, longest finite cap window +
max_unit_duration))`, which on the default `dispute_max_age` of 7 d and `max_unit_duration` of 600 s
is at least 1,200 s and usually much more. Owner decision **D-4**.

---

## 5. Where money is named — `busbar-unit-cost` view types

Five of the seventeen answer with a figure. Under the owner's ruling those figures are typed in
`busbar-unit-cost`, whose whole claim is that it is "pure functions over integers … no clock, no
store, no config parser and **no plane**" (`crates/busbar-unit-cost/src/lib.rs:9–10`), and whose
existing surface already owns the scale (`NANOS_PER_CENT` :54, `NANOS_PER_MICRO` :57), the truncating
projections (`project.rs:23,31`) and the only per-line money struct (`PricedLine`, `posting.rs:20`).
The control surface passes through the bytes the unit produced and names no figure — no money type,
no currency, no amount identifier appears in `busbar-plane-admin` — so `plane-no-money`
(`qa/full-gate.toml:89`) stays green and the `control` kind's no-money-vocabulary rule holds by
construction.

**ARCHITECTURE silent on the type names; proposed:** a new `busbar-unit-cost::view` module, five
types, every amount nano-units (`u128`, or `i128` where a figure can be negative), every wire
rendering a **decimal string** so no JSON consumer silently truncates at 2^53:

| type | verb | fields |
|---|---|---|
| `IdentityDeltaView` | `verify` | `bucket, dimension, scope, window_start, delta_settlements, delta_open_holds, delta_open_slice_remainders, delta_unreconciled, delta_adjustments, delta_overdraft_carried, delta_cross_window_transfers, delta_drawn, closes: bool` — §4.2:770–772's identity, term for term |
| `CeilingView` | `set_overdraft_ceiling` | `bucket, dimension, scope, ceiling_nanos, previous_ceiling_nanos, window_cap_nanos, ceiling_bp_of_cap, unbounded: bool` |
| `DisputeVerdictView` | `resolve_dispute` | `dispute_id, verdict, posted_amount_nanos, corrected_amount_nanos, delta_nanos: i128, above_threshold: bool, threshold_nanos, entry: EntryRef` |
| `UnreconciledSliceView` | `resolve_slice` | `node, lease_epoch, bucket, dimension, scope, window_start, unreconciled_nanos, resolved_nanos, remaining_nanos, entry: EntryRef` |
| `AdjustmentView` | `adjust` | `bucket, dimension, scope, window_start, amount_nanos: i128, headroom_released_nanos, pure_reversal: bool, above_threshold: bool, threshold_nanos, entry: EntryRef` |

`EntryRef { node, node_seq, hash }` is §4.1's `refs` triple. The twelve verbs not listed here name no
figure at all, and their response schemas below carry none.

---

## 6. Oracle cells — the scheme, and what each verb owes

Today: `admin.ops` is **240 cells over 66 operations**, all `driver: "http"`, built by
`testing/shadow-oracle/cells/__init__.py:462–690`. **Zero cells exist for any of the seventeen** (or
for the five ledger views) — CG-56 is why, and it is now decided.

Id format, unchanged: `admin.ops|<OperationId>|<outcome-slug>`, three pipe-separated segments, `/`
stripped. The 66 use the tag's PascalCase `operationId`. **Proposed for the seventeen:** the
`KernelVerb` variant name, which is that same PascalCase and is already the spelling both crates join
on (`crates/busbar/tests/admin_verb_ownership.rs:63` squashes case and separators to do exactly this
join): `Verify`, `PlaneFacts`, `PlaneRecordWrite`, `SetOperatorKey`, `SetEscrow`, `ChainBreak`,
`StoreRestore`, `ResealEpochFloor`, `SetDualControl`, `SetOverdraftCeiling`, `SetDisputeMaxAge`,
`CommitUpgrade`, `ResolveDispute`, `ResolveSlice`, `Adjust`, `ExportKeyset`, `Approve`.

Outcome slugs reused from the existing 240 where the condition is the same: `ok`, `unauth`,
`bad-body`, `not-found`, `rate-limit`, `idempotent-replay`, `if-match-stale`. New slugs this surface
needs, in the same hyphen-lowercase style: `noscope`, `operator-unset`, `approval-pending`,
`self-approval`, `payload-mismatch`, `insufficient-approvers`, `unsigned`, `already-resolved`.

Drivers (the vocabulary is closed at `__init__.py:33–36`): `http` for a single request; `script` for
a cell that must change node state between requests (the ceremony, "refuses to serve until reseal");
`exec` for the off-node CLI equivalents on a stopped node (§4.7:990 — `chain_break`, `store_restore`
and `reseal_epoch_floor` "also exist as off-node CLI"); `concurrent` for the in-flight reservation.

**107 cells** across the seventeen, listed per verb in §7 and totalled in §8. The 240 legacy cells are
untouched; the five ledger views owe their own cells and are out of this document's scope (D-10).

---

## 7. The seventeen

Every row: method and path as §4.7 declares · scope · request · success · refusals · idempotency ·
audit · executing unit · money view · cells · citation.

---

### 7.1 `verify` — `GET /api/v1/admin/verify`

- **Scope** `read-only` (`READ_ONLY_NEW_VERBS`, `verb.rs:702`; `required_scope` :149). Rate class
  `Forbidden` — never spends a mutation slot (`rate.rs:155–163`; a read that spent one would refuse
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
- **Refusals** the four shared (401 / 405 / 403-scope / never 429) plus
  `400 invalid_request` — ``since `<value>` is not a checkpoint id``. No posture refusal: a read is
  exempt from both gates (`posture.rs:106–113`).
- **Idempotency** none. A read reserves nothing.
- **Audit** no `ADMIN_LOG` row (`mod.rs:1869` — "a read is not a mutation and is not appended").
  Journal class `Access`, subject `Node`. *ARCHITECTURE silent on whether the verb form also writes a
  `Reconciliation` entry — §4.2:782 gives that to the every-T timer run. Proposed: it does not; only
  the timer writes `Reconciliation`.* (D-12)
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`. **Money view** yes —
  `IdentityDeltaView`.
- **Cells (7)** `Verify|ok` (http) · `|unauth` · `|noscope` · `|since-malformed` ·
  `|identity-closes` · `|identity-breaks` (script: corrupt a `priced_amount` older than the last
  checkpoint, then ask — the §4.2:778 cell, from this side) · `|anchor-mismatch` (script).
- **Cite** §4.2:765–782 (what `verify` is), §4.7:958 (`GET verify`), §8.3:1270 and :1276
  ("rotate the operator key; `verify`" · "drop one principal's pseudonym key: `verify` passes").

---

### 7.2 `plane_facts` — `GET /api/v1/admin/plane-facts`

- **Scope** `read-only`. Rate class `Forbidden`.
- **Request** query only. `?plane=<plane_key>&verb=<AdminVerbId>&subject=<name>`. The `subject`
  parameter is **CG-04, still open**: `Plane::plane_facts(&self, verb, ctx)` carries no subject, so
  both JSON-RPC planes declare only their list verb and leave per-name projections undeclared. This
  document assumes CG-04's recommendation (add the subject) and marks the parameter optional so the
  binding is correct either way. (D-5)
- **Success** `200 application/json`:
  `{ "plane": "string", "verb": "string", "subject": "string|null", "facts": { "<key>": <value> } }`
- **Refusals** shared 401/405/403-scope, plus
  `404 not_found` — ``plane `<key>` not found`` ·
  `400 invalid_request` — `plane is required` / `verb is required` ·
  `400 invalid_request` — ``plane `<key>` does not declare introspection verb `<verb>` `` ·
  `400 invalid_request` — ``verb `<verb>` requires a subject`` (only under CG-04's shape).
- **Idempotency** none. **Audit** no `ADMIN_LOG` row; journal `Access`.
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`, which reaches the plane's
  own `plane_facts`. **Money view** none.
- **Cells (6)** `PlaneFacts|ok` · `|unauth` · `|noscope` · `|unknown-plane` · `|unknown-verb` ·
  `|missing-subject`.
- **Cite** §3.2:580 (the signature), §1.4 (the plugin-kind table's `ADMIN_VERBS` row, "plane admin
  verbs (read-only introspection)"), §4.7:958 (`GET plane-facts`), CG-04 and CG-57 (the
  `ADMIN_VERBS` → `INTROSPECTION_VERBS` rename this verb's existence forces — D-6).

---

### 7.3 `plane_record_write` — `POST /api/v1/admin/plane-record-write`

- **Scope** `full`. Not irreducible. Rate class `Crud`.
- **Request** *ARCHITECTURE names the key tuple and nothing else; proposed:*
  ```json
  { "plane": "string", "schema": "string", "key": "string",
    "value": <json>, "if_match": "string|null" }
  ```
  `(plane, schema, key)` is exactly §2.3:437–438's `record_put` key.
- **Success** `200 application/json`:
  `{ "plane": "…", "schema": "…", "key": "…", "revision": "string", "written_at": 0 }`
- **Refusals** shared, plus
  `400 invalid_request` — ``plane is required`` / ``schema is required`` / ``key is required`` ·
  `404 not_found` — ``plane `<key>` not found`` ·
  `403 forbidden` — ``plane `<key>` may not write schema `<schema>` `` (the trust unit's verdict —
  §2.3:438 "verified by the trust unit") ·
  `409 version_conflict` — ``the record has changed since `<if_match>` `` ·
  `409 conflict` — in-flight idempotency reservation ·
  `403 forbidden` — `ApprovalPending` under `required` [D-1] ·
  `503 unavailable` — `the journal is unavailable`.
- **Idempotency** MUST probe. Key `(actor, "plane_record_write:<plane>:<schema>:<key>:<hdr>")`.
  Header optional (the verb is naturally re-runnable and `if_match` already guards lost updates).
- **Audit** `ADMIN_LOG` row `action = plane_record_write`, `resource = /api/v1/admin/plane-record-write`,
  outcome `applied`/`rejected`, principal = the resolved actor (`mod.rs:1869–1873`). Journal class
  **`Transaction`** for the write plus **`Access`** for the read-side of a verified write
  (§2.3:438 — "journaled `Access`/`Transaction`").
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`. **Money view** none.
- **Cells (9)** `PlaneRecordWrite|ok` · `|unauth` · `|noscope` · `|bad-body` · `|not-found` ·
  `|if-match-stale` · `|idempotent-replay` · `|approval-pending` · `|across-restart` (script — §8.3:1276
  already asks for "`PlaneRecord` across restart on every store"; this is that cell reached through the verb).
- **Cite** §2.3:437–439 (the whole contract), §4.7:958 (`POST plane-record-write`).

---

### 7.4 `set_operator_key` — `POST /api/v1/admin/set-operator-key`

- **Scope** `full`. **Irreducible** (`verb.rs:744`), **and one of the two admitted under
  `operator: unset`** (`verb.rs:753`). Rate class `Crud`. See §3.3 for the gate path.
- **Request** *ARCHITECTURE names `escrow` as mandatory and the signature as an argument; the rest is
  silent; proposed:*
  ```json
  { "operator_pubkey": "string",
    "escrow": { "m": 2, "n": 3, "shares": [ { "holder": "string", "pubkey": "string" } ] },
    "signature": "string|null" }
  ```
  `escrow` is **required on every call** — §4.7:992–993, "an M-of-N escrow — **a required argument of
  `set_operator_key`**". `signature` is required **only when `operator == Set`** (rotation is signed
  by the retiring key, §4.7:991–992) and must be absent-or-ignored under `unset`, where there is no
  key to sign with — that asymmetry is the ceremony.
- **Success** `200 application/json`:
  `{ "operator_fingerprint": "string", "escrow": { "m": 2, "n": 3, "holders": ["string"] },
     "policy_epoch": 0, "sealed_at": 0 }`
  Never the key material, never a share.
- **Refusals** shared, plus
  `400 invalid_request` — `escrow is required` ·
  `400 invalid_request` — `escrow m must be at least 1 and at most n` ·
  `400 invalid_request` — `operator_pubkey is not a valid public key` ·
  `403 forbidden` — `OperatorSignatureRequired` (rotation without one) [D-2] ·
  `403 forbidden` — `OperatorSignatureInvalid` [D-2] ·
  `409 conflict` — ``the sealed policy epoch has moved since `<epoch>` `` ·
  `409 conflict` — in-flight reservation · `503 unavailable` — store.
  **Never** `OperatorUnset`: that is the whole point of `ADMITTED_UNDER_UNSET`.
- **Idempotency** MUST probe, and the `Idempotency-Key` header is **required** (D-3): the ceremony is
  a once-per-fleet act and a retry must not seal a second key.
- **Audit** `ADMIN_LOG` row `action = set_operator_key`. Journal class **`Policy`** —
  §4.8:1063's `Policy { … operator_pubkey | unset, escrow }`, journaled, alarmed, and a
  ledger-endpoint line while `unset` (§4.7:988–989).
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`. **Money view** none.
- **Cells (8)** `SetOperatorKey|ok-under-unset` · `|ok-rotation-signed` · `|rotation-unsigned` ·
  `|missing-escrow` · `|bad-escrow-quorum` · `|unauth` · `|idempotent-replay` ·
  `|ceremony` (**script** — §8.1:1208's own words: "1.5.5 config, no operator key: boots;
  `commit_upgrade` refused; `set_operator_key` then `commit_upgrade` succeeds").
- **Cite** §4.7:979, :984–995 (ceremony, escrow, rotation), :987–990 (admitted under `unset`),
  §4.8:1063–1067 (`Policy`/`Bootstrap`), §8.1:1208–1209 (the ceremony cell), §4.7:958.

---

### 7.5 `set_escrow` — `POST /api/v1/admin/set-escrow`

- **Scope** `full`. **Irreducible**, **not** admitted under `unset`. Rate class `Crud`.
- **Request** *proposed:*
  `{ "escrow": { "m": 2, "n": 3, "shares": [ { "holder": "string", "pubkey": "string" } ] },
     "signature": "string", "break_glass": false }`
- **Success** `200`: `{ "escrow": { "m": 2, "n": 3, "holders": ["string"] }, "policy_epoch": 0,
  "break_glass": false, "sealed_at": 0 }`
- **Refusals** shared, plus `403 forbidden` `OperatorUnset` · `400 invalid_request`
  `escrow m must be at least 1 and at most n` · `403` signature required/invalid [D-2] ·
  `403` `ApprovalPending` under `required` [D-1] · `409` in-flight · `503` store.
- **Idempotency** MUST probe; header optional.
- **Audit** `ADMIN_LOG` `action = set_escrow`. Journal `Policy`; a `break_glass: true` change is
  journaled as such (§4.7:994 — "break-glass journaled").
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`. **Money view** none.
- **Cells (6)** `SetEscrow|ok` · `|operator-unset` · `|bad-escrow-quorum` · `|unsigned` ·
  `|approval-pending` · `|idempotent-replay`.
- **Cite** §4.7:979 (irreducible), :992–995 (escrow is changed only by this verb; without escrow the
  fleet can never `commit_upgrade` again), §4.7:958.

---

### 7.6 `chain_break` — `POST /api/v1/admin/chain-break`

- **Scope** `full`. **Irreducible**. Rate class `Crud`.
- **Request** *proposed:* `{ "reason": "string", "signature": "string" }`.
- **Success** **`204 No Content`, empty body** — this is what the loop already answers
  (`applied_answer()`, `mod.rs:1701–1707`) and what `crates/busbar/tests/admin_verb_ownership.rs`
  measures. Keeping it means this verb's contract is already half-shipped.
- **Refusals** shared, plus `403 forbidden` `OperatorUnset` · `403` signature required/invalid ·
  `400 invalid_request` `reason is required` · `403` `ApprovalPending` · `409` in-flight ·
  `503 unavailable` — the store leg's `StoreError::Failed` (`store.rs:30–36`).
- **Idempotency** MUST probe, header **required** (D-3). A chain break is not re-runnable, and the
  reservation must be `leak()`ed once the store call is entered — a caller disconnect after the break
  landed must not free the slot.
- **Audit** `ADMIN_LOG` `action = chain_break`. Journal class **`ChainBreak`** (§4.1:753's class
  list names it). Note §4.3:813 — "a restore below the `backup_watermark` is a `ChainBreak` by
  definition", so this class is also written by `store_restore`.
- **Executes in** `busbar-unit-verbs::Verbs::chain_break` → `Store::chain_break`
  (`verbs.rs:497–517`) — **not** the governance seam; already wired at `mod.rs:1568–1571`.
  **Money view** none.
- **Cells (6)** `ChainBreak|ok` · `|operator-unset` · `|unsigned` · `|store-failed` ·
  `|idempotent-replay` · `|off-node-cli` (**exec** — §4.7:990's off-node CLI on a stopped node).
- **Cite** §4.7:978 (irreducible), :990 (also an off-node CLI), §4.1:753 (the journal class),
  §4.2:782 ("WAL loss is a `ChainBreak`"), §4.3:813, §4.7:958.

---

### 7.7 `store_restore` — `POST /api/v1/admin/store-restore`

- **Scope** `full`. **Irreducible**. Rate class `Crud`.
- **Request** `{ "backup_ref": "string", "signature": "string" }`. `backup_ref` is **mandatory** and
  has no default — the root already refuses a body without one before the ceremony
  (`mod.rs:1574–1591`), on the stated ground that restoring "whatever the store thinks" is the most
  destructive thing this surface can be asked to do by accident. That refusal is `DecodeFailed`
  today; as a client answer it is **`400 invalid_request` — `backup_ref is required`**.
- **Success** `204 No Content`. After it, **the node refuses to serve until `reseal_epoch_floor`**
  (§4.6:932–934) and every node re-ships from `heads(node)` (§4.3:812).
- **Refusals** shared, plus `400` `backup_ref is required` · `404 not_found` —
  ``backup `<ref>` not found`` · `403` `OperatorUnset` · `403` signature · `403` `ApprovalPending` ·
  `409` in-flight · `503` store.
- **Idempotency** MUST probe, header **required**, reservation `leak()`ed on entry.
- **Audit** `ADMIN_LOG` `action = store_restore`. Journal class **`StoreRestore`**; **plus a
  `ChainBreak` entry** when the restore lands below the `backup_watermark` (§4.3:813 — that is not a
  refusal, it is a definition, and the entry is how it becomes visible).
- **Executes in** `busbar-unit-verbs::Verbs::store_restore` → `Store::store_restore`.
  **Money view** none.
- **Cells (6)** `StoreRestore|ok` · `|missing-backup-ref` · `|not-found` · `|operator-unset` ·
  `|below-watermark-is-chainbreak` (script) · `|refuses-to-serve-until-reseal` (script).
- **Cite** §4.3:812–813, §4.6:932–934, §4.7:978, :990, §4.1:753, §4.7:958.

---

### 7.8 `reseal_epoch_floor` — `POST /api/v1/admin/reseal-epoch-floor`

- **Scope** `full`. **Irreducible**. Rate class `Crud`.
- **Request** *proposed:* `{ "signature": "string" }`. No epoch argument: the floor is what the node
  computes from the re-shipped heads, and letting a caller name it is letting a caller lower it.
- **Success** `204 No Content`.
- **Refusals** shared, plus `403` `OperatorUnset` · `403` signature ·
  `409 conflict` — `not every node has re-shipped from its head` (§4.3:812 makes the re-ship the
  precondition — *ARCHITECTURE silent on the refusal; proposed*) · `403` `ApprovalPending` ·
  `409` in-flight · `503` store.
- **Idempotency** MUST probe; header optional (a reseal is naturally idempotent).
- **Audit** `ADMIN_LOG` `action = reseal_epoch_floor`. Journal class `Policy` (the floor is persisted
  in every WAL header and at the anchor, §4.6:932–933) — *ARCHITECTURE silent on the class;
  proposed.*
- **Executes in** `busbar-unit-verbs::Verbs::reseal_epoch_floor` → `Store::reseal_epoch_floor`.
  **Money view** none.
- **Cells (4)** `ResealEpochFloor|ok` · `|before-reship` · `|operator-unset` ·
  `|off-node-cli` (exec).
- **Cite** §4.3:812, §4.6:932–934, §4.7:978, :990, §4.7:958.

---

### 7.9 `set_dual_control` — `POST /api/v1/admin/set-dual-control`

- **Scope** `full`. **Irreducible**. Rate class `Crud`.
- **Request** `{ "posture": "single" | "required", "signature": "string" }`.
- **Success** `200`: `{ "posture": "required", "previous_posture": "single", "policy_epoch": 0,
  "distinct_admin_principals": 2, "sealed_at": 0 }`
- **Refusals** shared, plus
  `400 invalid_request` — ``posture must be `single` or `required` `` ·
  `409 conflict` — ``dual control `required` needs at least two distinct admin principals``
  (`InsufficientApprovers`; §4.7:975 names it `Refused(Approve, InsufficientApprovers)`;
  `posture::check_set_dual_control_required`, `posture.rs:154`) ·
  `403` `OperatorUnset` · `403` signature ·
  `403`/pending — **`required → single` needs dual control** (§4.7:975), so that direction always
  takes a maker-checker `approve` even though the *target* posture is `single` ·
  `409` in-flight · `503` store.
- **Idempotency** MUST probe; header optional.
- **Audit** `ADMIN_LOG` `action = set_dual_control`. Journal `Policy` (the posture is a sealed
  `Policy` field, §4.8:1063).
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`. **Money view** none.
- **Cells (6)** `SetDualControl|ok-to-required` · `|insufficient-approvers` ·
  `|required-to-single-needs-approval` · `|operator-unset` · `|bad-posture` · `|idempotent-replay`.
- **Cite** §4.7:972–976 (posture, default, the two-principal rule, the direction rule), :978–979
  (irreducible), §4.8:1063, §4.7:958.

---

### 7.10 `set_overdraft_ceiling` — `POST /api/v1/admin/set-overdraft-ceiling`

- **Scope** `full`. **Not** irreducible. Dual-controlled (§4.7:1462 names it among the two knobs that
  "let money move past a cap"). Rate class `Crud`.
- **Request** *proposed:*
  `{ "bucket": "string", "dimension": "string", "scope": "string",
     "ceiling_nanos": "string|null", "signature": "string|null" }`
  `null` restores the default — 10 % of the refusing window cap (§4.7:1036).
- **Success** `200`: a `CeilingView` (§5).
- **Refusals** shared, plus
  `404 not_found` — ``bucket `<b>` not found`` ·
  `400 invalid_request` — ``dimension `<d>` does not accrue mid-unit`` (§4.4:845–846 — `requests` and
  `concurrent` are known at Admit and have no overdraft) ·
  `400 invalid_request` — `an attribution bucket has no overdraft ceiling` (§4.4:850 — "attribution
  buckets never refuse and have none") ·
  `409 conflict` — `a Migration-sealed bucket's ceiling is unbounded` (§4.7:1036, PB-58) ·
  `400 invalid_request` — `ceiling_nanos must be a non-negative decimal` ·
  `403`/pending `ApprovalPending` · `409` in-flight · `503` store.
- **Idempotency** MUST probe; header optional.
- **Audit** `ADMIN_LOG` `action = set_overdraft_ceiling`. Journal `Policy`, and a ledger-endpoint
  line (PB-16) because it is a listed-key delta (§4.7:973).
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`. **Money view** yes —
  `CeilingView`.
- **Cells (7)** `SetOverdraftCeiling|ok` · `|not-found` · `|attribution-bucket` ·
  `|migration-sealed-bucket` · `|bad-body` · `|approval-pending` · `|idempotent-replay`.
- **Cite** §4.4:848–854 ("released by a dual-controlled `set_overdraft_ceiling`"), §4.7:1036 (the
  default), :1462 (the residual-risk row), §4.7:958.

---

### 7.11 `set_dispute_max_age` — `POST /api/v1/admin/set-dispute-max-age`

- **Scope** `full`. **Not** irreducible. Dual-controlled (§4.7:1462 — "which can hide overdue
  disputes"). Rate class `Crud`.
- **Request** *proposed:* `{ "seconds": 604800, "signature": "string|null" }`. Default 7 d
  (§4.7:1025).
- **Success** `200`: `{ "dispute_max_age_seconds": 604800, "previous_seconds": 604800,
  "policy_epoch": 0, "open_disputes": 0, "newly_overdue": 0, "newly_hidden": 0 }`.
  `newly_hidden` is the count of disputes that were overdue under the old value and are not under the
  new one — the number §4.7:1462's risk row is about, made visible in the answer rather than only in
  an alarm. *ARCHITECTURE silent on the response; proposed.*
- **Refusals** shared, plus `400 invalid_request` — `seconds must be at least 1` ·
  `403`/pending `ApprovalPending` · `409` in-flight · `503` store.
- **Idempotency** MUST probe; header optional.
- **Note that binds two rows together:** this value is the ceiling of the new-verb replay TTL
  (§4.4:834 — `min(dispute_max_age, …)`), so lowering it shortens every other verb's replay window.
  The answer should say so; see D-4.
- **Audit** `ADMIN_LOG` `action = set_dispute_max_age`. Journal `Policy` + ledger-endpoint line.
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`. **Money view** none (a
  duration is not a figure; the dispute *counts* are cardinalities, not amounts).
- **Cells (5)** `SetDisputeMaxAge|ok` · `|lowering-hides-overdue` (script — the alarm and
  `newly_hidden` both asserted) · `|bad-body` · `|approval-pending` · `|idempotent-replay`.
- **Cite** §4.7:1025 (default), :1057–1059 (the overdue-alarm rule), :1462 (the risk), §4.4:834
  (the TTL coupling), §4.7:958.

---

### 7.12 `commit_upgrade` — `POST /api/v1/admin/commit-upgrade`

- **Scope** `full`. **Irreducible**. Rate class `Crud`.
- **Request** *proposed:*
  `{ "schema_version": 0, "hash_algo_version": 0, "signature": "string" }`.
- **Success** `200`: `{ "committed": { "schema_version": 0, "hash_algo_version": 0 },
  "policy_epoch": 0, "nodes_at_or_above": 3, "committed_at": 0 }`.
- **Refusals** shared, plus
  `403 forbidden` `OperatorUnset` — **the refusal §8.1:1209's ceremony cell asserts by name** ·
  `403` signature required/invalid ·
  `409 conflict` — `no escrow is sealed; commit_upgrade is refused` (§4.7:994–995 — "without escrow
  the fleet can never `commit_upgrade` again, and the document says so") ·
  `409 conflict` — ``node `<n>` is below the committed version`` ·
  `400 invalid_request` — `schema_version is required` ·
  `403`/pending `ApprovalPending` · `409` in-flight · `503` store.
- **Idempotency** MUST probe, header **required** (D-3): after the commit, older nodes refuse to
  serve (§4.8:1069), so a duplicate commit is not a no-op to a fleet mid-roll.
- **Audit** `ADMIN_LOG` `action = commit_upgrade`. Journal `Policy` (the committed version is sealed
  there; `Migration` seals the initial one, §4.8:1068).
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`. **Money view** none.
- **Cells (5)** `CommitUpgrade|ok` · `|operator-unset` (this cell and `SetOperatorKey|ceremony` are
  the two halves of §8.1:1208–1209) · `|no-escrow` · `|node-below-version` · `|idempotent-replay`.
- **Cite** §4.7:978 (irreducible), :990 (refused under `unset`), :994–995 (escrow precondition),
  §4.8:1068–1071 (versions), §8.1:1208–1209 (the cell), §4.7:958.

---

### 7.13 `resolve_dispute` — `POST /api/v1/admin/resolve-dispute`

- **Scope** `full`. **Irreducible ONLY above `adjust_threshold`** (§4.7:984). `IRREDUCIBLE_VERBS`
  lists it unconditionally with the caveat carried in `verb.rs:732–737` — "that quantity is not
  decidable from the verb alone, so callers that need the threshold-gated form check it themselves".
  **This document decides which quantity:** the **amount named in the request** (for `amend`) or the
  **posted amount of the dispute** (for `uphold`/`overturn`), compared against `adjust_threshold` =
  1 % of the bucket's window budget, floor 10^9 nano-units (§4.7:1050). D-8.
- **Request** *proposed:*
  ```json
  { "dispute_id": "string", "verdict": "uphold" | "overturn" | "amend",
    "amount_nanos": "string|null", "note": "string", "signature": "string|null" }
  ```
  `amount_nanos` is required iff `verdict == "amend"`.
- **Success** `200`: a `DisputeVerdictView` (§5).
- **Refusals** shared, plus
  `404 not_found` — ``dispute `<id>` not found`` ·
  `409 conflict` — ``dispute `<id>` is already resolved`` ·
  `400 invalid_request` — ``verdict must be `uphold`, `overturn` or `amend` `` ·
  `400 invalid_request` — ``amount_nanos is required for verdict `amend` `` ·
  `403 forbidden` `OperatorUnset` — **only above the threshold** (§4.7:990: "so larger disputes stay
  open and alarmed") ·
  `403` signature required/invalid — only above the threshold ·
  `403`/pending `ApprovalPending` · `409` in-flight · `503` store.
- **Idempotency** MUST probe; header optional but strongly advised — the effect is a correcting
  posting.
- **Audit** `ADMIN_LOG` `action = resolve_dispute`. Journal: a correcting posting (class
  `Transaction`, or `Adjust` on an amend — §4.1:741 lists `Adjust` as a record), and the counts move
  on the next `Reconciliation` entry (§4.7:1058–1059).
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`. **Money view** yes —
  `DisputeVerdictView`.
- **Cells (7)** `ResolveDispute|ok-below-threshold` · `|ok-above-threshold-signed` ·
  `|above-threshold-operator-unset` · `|above-threshold-unsigned` · `|already-resolved` ·
  `|not-found` · `|idempotent-replay`.
- **Cite** §4.7:984 and :990 (the threshold gate), :1050 (`adjust_threshold`), :1057–1059 (the
  disputes report), §2.2's settlement table :362 (`dispute_max_age` bound), §4.7:958.

---

### 7.14 `resolve_slice` — `POST /api/v1/admin/resolve-slice`

- **Scope** `full`. **Not** irreducible. Rate class `Crud`.
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
  `403`/pending `ApprovalPending` · `409` in-flight · `503` store.
- **Idempotency** MUST probe; header optional.
- **Audit** `ADMIN_LOG` `action = resolve_slice`. Journal class `Slice` for the release plus a
  correcting posting; §4.2:771–772's rule applies in reverse — unreconciled is a **move out of**
  settled, so resolving it moves the amount back and the identity must still close. That is the
  cell's whole point.
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`. **Money view** yes —
  `UnreconciledSliceView`.
- **Cells (5)** `ResolveSlice|ok` · `|not-unreconciled` · `|not-found` ·
  `|identity-still-closes` (script — run `verify` after and assert `closes`) · `|idempotent-replay`.
- **Cite** §4.6:935–937 ("never-replayed spend is `UnreconciledSpend` until `resolve_slice`"),
  §4.2:770–772 (the identity and the move rule), Appendix A CG-41 (:1510–1512), §4.7:958.

---

### 7.15 `adjust` — `POST /api/v1/admin/adjust`

- **Scope** `full`. **Irreducible ONLY above `adjust_threshold`** — same rule and same resolution as
  `resolve_dispute` (D-8), against the request's own `amount_nanos`.
- **Request** *proposed:*
  ```json
  { "bucket": "string", "dimension": "string", "scope": "string", "window_start": 0,
    "amount_nanos": "string", "reason": "string", "signature": "string|null" }
  ```
  `amount_nanos` is a **signed** decimal string (an adjustment can go either way; §4.2:777 calls a
  closed-window adjustment a "pure ledger reversal").
- **Success** `200`: an `AdjustmentView` (§5).
- **Refusals** shared, plus
  `400 invalid_request` — `amount_nanos must be a non-zero signed decimal` ·
  `404 not_found` — ``bucket `<b>` not found`` ·
  `400 invalid_request` — `reason is required` ·
  `403 forbidden` `OperatorUnset` — only above the threshold ·
  `403` signature required/invalid — only above the threshold ·
  `403`/pending `ApprovalPending` · `409` in-flight · `503` store.
- **Idempotency** MUST probe; header **required** above the threshold (D-3) — a retried large
  adjustment applied twice is a money bug that the identity would then report as closing.
- **Audit** `ADMIN_LOG` `action = adjust`. Journal class **`Adjust`** (§4.1:741 names the record).
  Headroom is released to the store **only inside the open window**; outside it the entry is a pure
  reversal (§4.2:776–777) — `AdjustmentView.pure_reversal` says which happened.
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`. **Money view** yes —
  `AdjustmentView`.
- **Cells (8)** `Adjust|ok-below-threshold` · `|ok-above-threshold-signed` ·
  `|above-threshold-operator-unset` · `|above-threshold-unsigned` · `|zero-amount` · `|not-found` ·
  `|open-window-releases-headroom` (script — `verify` after) ·
  `|closed-window-pure-reversal` (script).
- **Cite** §4.1:741 (the `Adjust` record), §4.2:760 (Σ adjustments is a sealed checkpoint figure),
  :770 (Δ adjustments is a term of the identity), :776–777 (headroom rule), §4.7:984, :1050,
  §4.7:958.

---

### 7.16 `export_keyset` — `POST /api/v1/admin/export-keyset`

- **Scope** `full`. **Irreducible**, **and the second of the two admitted under `operator: unset`**
  (`verb.rs:753`) — "so the keyset can be backed up before the ceremony" (§4.7:987). Rate class
  `Crud`.
- **Request** `{ "recipient_pubkey": "string", "signature": "string|null" }`.
  `recipient_pubkey` is **MANDATORY under `unset`** (§4.7:987, the document's own capitals) and this
  contract makes it mandatory in **both** states: **plaintext export is never a path**, so there is
  never a call shape without a recipient.
- **Success** `200`: `{ "sealed_keyset": "<base64>", "algorithm": "string",
  "recipient_fingerprint": "string", "keyset_fingerprint": "string", "sealed_at": 0 }`.
  Never key material outside the sealed blob.
- **Refusals** shared, plus
  `400 invalid_request` — `recipient_pubkey is required` ·
  `400 invalid_request` — `recipient_pubkey is not a valid public key` ·
  `403` signature required/invalid — only when `operator == Set` ·
  `403`/pending `ApprovalPending` — only when `operator == Set` (under `unset` the posture is always
  `single`; see §3.3) ·
  `409` in-flight · `503` store.
  **Never** `OperatorUnset`.
- **Idempotency** MUST probe, header **required** (D-3). This is the archetypal
  credential-minting verb §4.4:833 has in mind: a replay must return the **same sealed blob byte for
  byte**, never a fresh sealing, so that a retry cannot produce two exports an auditor must reconcile.
- **Audit** `ADMIN_LOG` `action = export_keyset`. Journal class **`Access`**, and the entry
  **records the recipient fingerprint** (§4.7:987) — the `Access { KeysetExported }` entry the boot
  warning at §4.7:1020 looks for.
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`. **Money view** none.
- **Cells (6)** `ExportKeyset|ok-under-unset` · `|missing-recipient` · `|ok-operator-set-signed` ·
  `|unsigned` · `|idempotent-replay` (byte-identical sealed blob) ·
  `|access-entry-records-recipient` (script).
- **Cite** §4.7:979 (irreducible), :987–990 (admitted under `unset`, mandatory recipient, the
  `Access` entry, plaintext never a path), §4.8:1070 (the stop-the-world sequence), §4.7:1020
  (`Access { KeysetExported }`), §4.4:833 (the sealed cache), §4.7:958.

---

### 7.17 `approve` — `POST /api/v1/admin/approve`

- **Scope** `full`. **Not** irreducible (`verb.rs:738–749` correctly omits it) and **not itself
  dual-controlled** — "the checker step — its only controls are the payload-hash equality and the
  `SelfApproval` refusal" (§4.7:976; `posture.rs:103–105` returns early for it). Rate class `Crud`.
- **Request** `{ "key": "string", "payload_hash": "string", "signature": "string|null" }` —
  §4.7:999 names the entry `approve { key, payload_hash }` exactly.
- **Success** `200`: `{ "key": "string", "payload_hash": "string",
  "approver_fingerprint": "string", "maker_fingerprint": "string", "approved_at": 0,
  "applies_to": { "verb": "string", "pending_since": 0 } }`.
- **Refusals** shared, plus
  `403 forbidden` — `an approval may not come from the principal that made the request`
  (`SelfApproval`; §4.7:1000 `Refused(Approve, SelfApproval)`; `posture::check_approve`,
  `posture.rs:137`) ·
  `409 conflict` — `the approval's payload hash does not match the pending mutation`
  (`PayloadMismatch`) ·
  `404 not_found` — ``no pending mutation for key `<k>` `` ·
  `409 conflict` — ``the pending mutation for key `<k>` is already approved`` ·
  `400 invalid_request` — `key is required` / `payload_hash is required` ·
  `409` in-flight · `503` store.
- **Idempotency** MUST probe; header optional. `approve` is naturally idempotent on
  `(key, payload_hash)`, and the "already approved" 409 above is the honest answer for a **different**
  approver arriving second — the cache must not turn that into a replayed 200, which is why the key
  includes the actor (D-3).
- **Audit** `ADMIN_LOG` `action = approve`. Journal: the `approve` entry itself, and both the maker
  and the approver fingerprints are **sealed in the `Policy` entry** (§4.7:1000 — "both sealed in the
  `Policy` entry; cell").
- **Executes in** `busbar-unit-verbs` → `Governance::execute_new_verb`. **Money view** none — an
  approval names a hash, never a figure, even when the mutation it approves moves money.
- **Cells (6)** `Approve|ok` · `|self-approval` (§8.1:1196 already asks for "self-approval refused
  under `required`" on the reference-plane list; this is its `admin.ops` half) · `|payload-mismatch` ·
  `|no-pending` · `|already-approved` · `|bad-body`.
- **Cite** §4.7:955 (the maker-checker definition), :976 (exempt from its own gate), :999–1000
  (the entry shape, both refusals, the seal, the cell), §8.1:1196, §4.7:958.

---

## 8. The seventeen, in one table

| # | verb | method | path | scope | executes in | money view | cells | ARCHITECTURE cite |
|---|---|---|---|---|---|---|---|---|
| 1 | `verify` | **GET** | `/api/v1/admin/verify` | read-only | `busbar-unit-verbs` → `execute_new_verb` | `IdentityDeltaView` | 7 | §4.2:765–782 · §4.7:958 |
| 2 | `plane_facts` | GET | `/api/v1/admin/plane-facts` | read-only | `busbar-unit-verbs` → plane `plane_facts` | — | 6 | §3.2:580 · §1.4 · §4.7:958 |
| 3 | `plane_record_write` | POST | `/api/v1/admin/plane-record-write` | full | `busbar-unit-verbs` → `execute_new_verb` | — | 9 | §2.3:437–439 |
| 4 | `set_operator_key` | POST | `/api/v1/admin/set-operator-key` | full · irreducible · **unset-admitted** | `busbar-unit-verbs` → `execute_new_verb` | — | 8 | §4.7:984–995 · §8.1:1208 |
| 5 | `set_escrow` | POST | `/api/v1/admin/set-escrow` | full · irreducible | `busbar-unit-verbs` → `execute_new_verb` | — | 6 | §4.7:992–995 |
| 6 | `chain_break` | POST | `/api/v1/admin/chain-break` | full · irreducible | `busbar-unit-verbs::Verbs::chain_break` → `Store` | — | 6 | §4.7:978,:990 · §4.1:753 |
| 7 | `store_restore` | POST | `/api/v1/admin/store-restore` | full · irreducible | `busbar-unit-verbs::Verbs::store_restore` → `Store` | — | 6 | §4.3:812–813 · §4.6:932–934 |
| 8 | `reseal_epoch_floor` | POST | `/api/v1/admin/reseal-epoch-floor` | full · irreducible | `busbar-unit-verbs::Verbs::reseal_epoch_floor` → `Store` | — | 4 | §4.6:932–934 · §4.3:812 |
| 9 | `set_dual_control` | POST | `/api/v1/admin/set-dual-control` | full · irreducible | `busbar-unit-verbs` → `execute_new_verb` | — | 6 | §4.7:972–976 |
| 10 | `set_overdraft_ceiling` | POST | `/api/v1/admin/set-overdraft-ceiling` | full | `busbar-unit-verbs` → `execute_new_verb` | `CeilingView` | 7 | §4.4:848–854 · §4.7:1036,:1462 |
| 11 | `set_dispute_max_age` | POST | `/api/v1/admin/set-dispute-max-age` | full | `busbar-unit-verbs` → `execute_new_verb` | — | 5 | §4.7:1025,:1057–1059,:1462 |
| 12 | `commit_upgrade` | POST | `/api/v1/admin/commit-upgrade` | full · irreducible | `busbar-unit-verbs` → `execute_new_verb` | — | 5 | §4.8:1068–1071 · §4.7:994 · §8.1:1209 |
| 13 | `resolve_dispute` | POST | `/api/v1/admin/resolve-dispute` | full · irreducible **above `adjust_threshold`** | `busbar-unit-verbs` → `execute_new_verb` | `DisputeVerdictView` | 7 | §4.7:984,:990,:1050 |
| 14 | `resolve_slice` | POST | `/api/v1/admin/resolve-slice` | full | `busbar-unit-verbs` → `execute_new_verb` | `UnreconciledSliceView` | 5 | §4.6:937 · §4.2:770–772 |
| 15 | `adjust` | POST | `/api/v1/admin/adjust` | full · irreducible **above `adjust_threshold`** | `busbar-unit-verbs` → `execute_new_verb` | `AdjustmentView` | 8 | §4.1:741 · §4.2:776 · §4.7:984,:1050 |
| 16 | `export_keyset` | POST | `/api/v1/admin/export-keyset` | full · irreducible · **unset-admitted** | `busbar-unit-verbs` → `execute_new_verb` | — | 6 | §4.7:987–990 · §4.8:1070 · §4.4:833 |
| 17 | `approve` | POST | `/api/v1/admin/approve` | full · exempt from its own gate | `busbar-unit-verbs` → `execute_new_verb` | — | 6 | §4.7:955,:976,:999–1000 |

**Totals.** 2 GET · 15 POST. 2 read-only · 15 full. 10 irreducible (2 of them only above
`adjust_threshold`; 2 of them admitted under `operator: unset`). 3 execute against `Store`, 13
against `Governance::execute_new_verb`, 1 (`plane_facts`) against the named plane through it. 5 name
a figure, in 5 new `busbar-unit-cost` view types. **107 new `admin.ops` cells**; the 240 existing
cells are untouched.

No row above is "ARCHITECTURE silent" on its **method or path** — CG-56 closed that. The silences
that remain are all body shapes, status codes for success, and the wording of new refusals, and they
are collected below.

---

## 9. Owner decisions this document needs

| id | decision | why it cannot be an implementer's |
|---|---|---|
| **D-1** | **Is the `required`-posture "pending" a refusal or a response?** §4.7:976 calls it "the pending response … a named exception", and §8.1:1218 makes it the *only* named exception to byte-parity. `busbar-unit-verbs` returns `Refusal(Admit, ApprovalPending)` and the root maps it to `HookVeto`. Proposed: **`202 Accepted`** with `{"pending":{"key":"…","payload_hash":"…","approvers_needed":1}}`, so the maker learns the key a checker must `approve`. | It changes a status code on 13 verbs and is the one exception the effects spec allows |
| **D-2** | **Add `ReasonCode::OperatorSignatureRequired` / `OperatorSignatureInvalid`?** §4.7:991 makes the signature a verb argument; the vocabulary has no arm for a bad one (§3.2). | A missing arm forces a wrong code (`Validation` 400 or `Unauthorized` 403) onto every irreducible verb |
| **D-3** | **The sealed replay key shape and when the header is required.** Proposed `(actor, "<verb>:<idempotency-key>")`; header **required** for `set_operator_key`, `export_keyset`, `chain_break`, `store_restore`, `commit_upgrade` and for `adjust` above threshold. The shim's test helper keys `(verb, key)` and drops the actor. | Two principals sharing a key would replay each other's answer — one of which is a sealed keyset |
| **D-4** | **The replay TTL.** §4.4:834 says `min(dispute_max_age, max(600 s, longest finite cap window + max_unit_duration))`; `plugin-loader/src/store_adapter.rs:170` pins 600 s. | §8.1:1207's t = 500 s / t = 700 s cells are written against a specific window |
| **D-5** | **CG-04 — does `plane_facts` carry a subject?** Decides whether `?subject=` is in the binding. | Two planes already decline to declare per-name projections because of it |
| **D-6** | **CG-57 — rename `PlaneMeta::ADMIN_VERBS` to `INTROSPECTION_VERBS`.** The name collides with the admin surface's own 88-row table, which is what `plane_facts` reads *about*. | It has already confused one implementer |
| **D-7** | **Which verbs carry the operator signature as a request argument?** §4.7:991 says "verbs carry the signature"; §4.7:1462 lists `set_overdraft_ceiling` and `set_dispute_max_age` as dual-controlled but **not** irreducible. Proposed: signature required for the 10 irreducible verbs only; the two knobs take dual control alone. | It decides four request schemas |
| **D-8** | **Which quantity crosses `adjust_threshold`** for `adjust` and `resolve_dispute`. Proposed: the request's own `amount_nanos` (and the dispute's posted amount for `uphold`/`overturn`). `verb.rs:732–737` deliberately declines to decide it. | It decides whether an operator-unset fleet can resolve a given dispute |
| **D-9** | **Success statuses.** Proposed: `204` for the three recovery verbs (already shipped, `mod.rs:1701`) and `200` + body for the other fourteen; never `201`. | The 240 legacy cells pin 1.5.5's `201`-vs-`200` behaviour; the seventeen must not drift into it by accident |
| **D-10** | **The five ledger views' cells** are owed too (`GET /api/v1/admin/ledger/{totals,checkpoints,reconciliation,migration,openapi.json}` — the paths are *not* a guess, §4.7). Out of this document's seventeen; ruling wanted on whether they land in the same wave. | 22 additive operations are currently pinned by nothing |
| **D-11** | **Confirm the money views' home and shape.** New `busbar-unit-cost::view` module, five types, nano-units as decimal strings. `busbar-unit-cost` currently declares "NO WORKSPACE DEPENDENCIES BEYOND THE CAPABILITY CRATE" — bucket/dimension/scope arrive as `String`. | It is the owner's 2026-09-08 ruling made concrete; the crate ceiling and the dependency rule are both touched |
| **D-12** | **Does the `verify` verb write a `Reconciliation` entry**, or only the every-T timer run (§4.2:782)? Proposed: only the timer. | An operator polling `verify` would otherwise rewrite the recompute watermark |
| **D-13** | **`plane_record_write` concurrency shape** — `if_match` + `revision`, or last-write-wins? ARCHITECTURE gives `record_put/get/scan` and no concurrency rule. | `409 version_conflict` exists or it does not |
| **D-14** | **Rate class for the fifteen mutating new verbs.** They fall through to `Crud` (60/min) because they have no `ADMIN_PREFIX`-relative rule (`rate.rs:164–167`). Several are blast-radius operations that §4.7 treats like `/config/*`. Proposed: add `set-operator-key`, `set-escrow`, `set-dual-control`, `commit-upgrade`, `chain-break`, `store-restore`, `reseal-epoch-floor` to `CONFIG_CLASS_RULES` (10/min). | CG-38 already flags the config-class table as supplied-at-integration and "must not ship" wrong |
| **D-15** | **The `control` kind's declaration** (owner ruling 08:5x). Needs: its row in §1.4's plugin-kind table; whether it takes `PLANE_ABI` or a `CONTROL_ABI` of its own (cf. CG-12); the declared shape of "routes as data" (the 88-row table is already that shape — is it the contract's type or the surface's?); and the AST/gate rule that keeps a control surface unmetered and money-free. Also: does `control` replace the admin plane's `Claim`/`CLAIMS` declaration, or reuse it? | It decides whether the seventeen are contracted against a plane trait or a new one, and R7's rename (`busbar-plane-admin` → `busbar-control-admin`) lands on it |
| **D-16** | **Where the control path hangs in the kernel loop.** Today all seventeen run inside the `Route` step (`mod.rs:1500`) because there is no `control` kind. Proposed: keep it there until D-15 lands, since the contract in §7 does not depend on it. | A control surface with a Route step is the shape §1.1 says it does not have |
