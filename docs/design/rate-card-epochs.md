# Rate-card epochs: read-time pricing vs priced-at-admission

Status: decision note for the owner. No code changes.
Scope: what a rate-card edit does to money already earned, and which of three
models 1.6.0 should ship.

The owner's instinct, stated as it was put: *"storing tokens and pricing
separately was better, so you could change pricing and back-date it."* That
instinct is what 1.5.5 actually implements, and the note takes it seriously
rather than treating it as a bug to be designed away. What follows is the case
for and against, and a third shape that keeps the capability while removing the
part of it that is a hazard.

Every claim below is cited to a file and line in this tree
(`origin/integration/oracle-phase0`) or to a recorded oracle cell.

---

## 1. The two models, precisely

### Model A — 1.5.5: store quantities, price on read

**What is stored.** A metering row per `(key, day, model, provider)` holding raw
counts only: `tokens_input`, `tokens_output`, `tokens_cache_read`,
`tokens_cache_write`, `requests`. No money.

**What is computed, and when.** `spend_micros` does not exist until somebody
reads it. `GET /api/v1/admin/usage` clones the *current* cost model
(`crates/busbar-core/src/admin/v1/service.rs:2187`), walks the stored rows, and
derives spend per row at that instant
(`service.rs:2217-2230` → `derive_spend_micros_row`, `service.rs:101-117`).

**The contract says so out loud.**
`crates/busbar-core/src/admin/v1/contract/mod.rs:1077`:

> LEDGER RULE (one loud contract sentence): `spend_micros` is a MUTABLE ESTIMATE
> — derived at read time from the operator's CURRENT prices, so a price change
> re-prices history. Never store it as a ledger charge; bill from the raw token
> split.

**A card edit is live, not boot-scoped.** `PUT /api/v1/admin/config/settings`
writes `rate_card` and `per_request_fee`, and neither is in the boot-frozen set:
the exhaustive destructure at
`crates/busbar-core/src/admin/v1/json/handlers.rs:2770` classifies
`rate_card: _` and `per_request_fee: _` as GENUINELY LIVE
(`handlers.rs:2790-2791`). No restart, no epoch boundary.

**What an invoice is.** A rendering. `GET /admin/usage` at time *T* against the
card in force at *T*. Two renderings of the same window, taken either side of a
card edit, are different invoices with no record that anything changed.

### Model B — 1.6.0 root book: price once, at admission

**What is stored.** A `Posting`
(`crates/busbar-unit-cost/src/posting.rs:41-50`) holding the priced figure
itself — `pre_tier_amount`, `priced_amount`, `fee_count`, every `PricedLine` —
together with the `rate_card_version` it was priced against
(`posting.rs:42`, accessor `posting.rs:54-56`).

**What is computed, and when.** Once, at settlement, against the card *pinned at
admission*. The root holds one swappable card (`RootCard`,
`crates/busbar/src/root/kernel.rs:115-144`), repointed on every apply by
`CardRepricer` (`kernel.rs:161-175`). A unit takes its `Arc` at the door and
keeps it: `crates/busbar/src/root/units_llm.rs:464` (`ROOT_CARD.pin()` at
admission), with the reasoning stated at `units_llm.rs:268-281` — *"an apply
landing mid-body cannot reprice a request halfway through"*. Late accruals price
against the same pinned card (`units_llm.rs:695`).

**Journaled.** The `Posting` journal record carries `rate_card_version` in its
body bytes (`crates/busbar/src/root/durability.rs:423`, serialised at
`durability.rs:440` and `durability.rs:467`), as does the migration marker
(`durability.rs:501`, `crates/busbar/src/root/migration.rs:74`, served at
`crates/busbar/src/root/units_admin.rs:964-965`).

**What an invoice is.** A read of immutable records. Two reads of the same window
agree, always, because there is nothing in the read path that can move.

### The tension already written into ARCHITECTURE.md

`docs/design/ARCHITECTURE.md:856-858` holds both models at once, on purpose:

> *Immutability*: priced once at settlement with the rate-card version captured
> at hold … a card change applies to holds opened after it and never to history;
> postings already made are immutable INTERNALLY — but the legacy `/usage`
> projection derives at READ TIME from the CURRENT card exactly as 1.5.5 does
> (retroactive repricing is 1.5.5 behaviour and is reproduced byte for byte; the
> immutable posting is on the 1.6.0 endpoints only) — parity clause.

So 1.6.0 as designed already ships **both**: Model B on
`/api/v1/admin/ledger/*` (`units_admin.rs:750, 781, 895, 942`) and Model A on
legacy `/usage`. This note is about whether that is the end state, and what the
1.6.0 endpoints should offer that neither model offers today.

---

## 2. The worked example (the recorded figures)

Oracle cell `billing|rate-card|epoch-mid-window`, recorded from the published
1.5.5 binary (`48e2800c`) on branch `keep-oracle-cells`
(`testing/shadow-oracle/golden/1.5.5/cells/billing__rate-card__epoch-mid-window.json`;
definition at `testing/shadow-oracle/enumerate-cells.py:783-806`).

One boot, one window, four billable requests. The mock returns a fixed 11 input
/ 7 output tokens per call. Two requests are the recorder's boot priming; then
one chat request; then the card edit; then one more chat request.

| Card | `input_utok` | `output_utok` | `per_request_fee` |
|---|---|---|---|
| boot (`oracle-config.sh:146-153`) | 100,000 | 200,000 | 0 |
| written mid-window (`enumerate-cells.py:694-697`) | 10,000,000 | 20,000,000 | 3 cents |

Per-request arithmetic at the new card: `11 × 10,000,000 + 7 × 20,000,000 =
250,000,000` micros, plus a 3-cent fee = `30,000` micros → **250,030,000**.

Three hypotheses, three totals — this is exactly why the cell was built:

| Hypothesis | Predicted total for the window |
|---|---|
| priced per row at charge time (an epoch boundary mid-window) | 257,530,000 |
| restart-to-apply (edit lands, prices nothing until reboot) | 10,000,000 |
| **read-time derivation over the whole ledger** | **1,000,120,000** |

**Recorded: 1,000,120,000.** Four rows at 250,030,000 each. The two boot priming
requests, the request *before* the edit and the request *after* it all come back
at the new rate. The comparable baseline cell
(`billing__admin-usage__after-2.json`) shows the same window shape at
2,500,000/row, total 10,000,000, at the boot card.

No epoch boundary exists. There is no row left at the old price. An invoice read
off `/admin/usage` before the edit is not reproducible from `/admin/usage` after
it, and nothing in the response says a card changed.

One footnote worth keeping, because it is how this was nearly got wrong: an
earlier pass drove a *partial* card, concluded "restart-to-apply", and was wrong.
1.5.5 refuses a partial card 400 — *"rate_card is AUTHORITATIVE and COMPLETE:
you either price nothing or price everything"* — and a `pre` request need only be
answered, not 2xx, so the refusal was invisible and the cell recorded the boot
card twice (`enumerate-cells.py:753-762`).

---

## 3. Pros and cons

| Dimension | A — price on read (1.5.5) | B — price at admission (1.6.0 book) |
|---|---|---|
| **Invoicing** | One card prices everything; correcting a rate fixes every affected invoice in one PUT. But an invoice is only true at the instant it was rendered. | An invoice is a sum of immutable records; re-rendering is idempotent. Correcting a rate cannot fix an invoice already sent — it needs a credit note. |
| **Refunds / credits** | Implicit: lower the card, history re-prices down. No record that a credit was granted, to whom, or by whom. | Explicit: a reversal posting, journaled, attributable. `docs/design/ARCHITECTURE.md:749` — adjustments are pure ledger reversals. |
| **Disputes** | Weak. The customer's evidence (a saved response body) and the operator's current read disagree, and neither can show which card produced which. | Strong. The posting names `rate_card_version`; the disputed figure and the card that made it are both on the record. |
| **Audit trail** | The *card* is versioned in config history; the *money* is not. No record ties "the total moved" to "somebody PUT a card". | The journal is the trail. `Posting` bodies carry the version (`durability.rs:440`), chains and checkpoints seal them (`ARCHITECTURE.md:727-754`). |
| **Reproducibility** | None across a card edit. This is the money class the oracle cell exists to pin. | Total. Two reads of a sealed window are byte-equal by construction. |
| **Storage** | Smallest. Counts only, one row per `(key, day, model, provider)`. | Larger: per-unit postings with priced lines, plus journal segments. Bounded by retention (`ARCHITECTURE.md:755`), not by window count. |
| **Reload behaviour** | Card is live on apply (`handlers.rs:2790`); nothing to reconcile because nothing was stored. | Card swap is atomic and pinned per reader (`kernel.rs:104-113`, `units_llm.rs:464`); a request that opened before an apply bills at the rates it was admitted under. |
| **Migration from 1.5.5 data** | N/A — it *is* 1.5.5. | Already solved: the first boot after upgrade seals an opening balance priced under a named `rate_card_version` (`migration.rs:60-74`, `migration.rs:155`), served at `/api/v1/admin/ledger/migration`. Its honesty depends entirely on the operator naming the card the historical rows were *earned* under, not today's. |

The instinct is correct about one thing and the cell proves it: separating
quantity from price is what makes back-dating *possible at all*. Model B does not
lose that — the quantities are still on every `PricedLine`. What Model B removes
is the ability to back-date **as a side effect of a config PUT, with no record**.
Those are two different properties, and 1.5.5 conflates them.

---

## 4. Option C — store both, price on read against the *stored* version, reprice by verb

**Storage.** Each posting keeps what Model B keeps — quantities per line *and*
`rate_card_version` — and the card registry keeps every version, addressable.

**Read.** `/api/v1/admin/ledger/*` prices each posting against the version the
posting names, by default. That is what the posting already carries
(`posting.rs:42`); Option C is the read path honouring it rather than the write
path baking the amount in irreversibly.

**Back-dating.** Not a config side effect. An explicit admin verb:

```
POST /api/v1/admin/ledger/reprice
  { "window": {...}, "scope": {...}, "from_version": V0, "to_version": V1,
    "reason": "...", "signature": ... }
```

which (a) refuses without an operator signature, (b) writes an `Adjust`/
`Reconciliation` journal entry naming both versions, the scope, the operator and
the reason (`ARCHITECTURE.md:713`, `:727-754`), (c) leaves the original postings
in place with reversal entries beside them, and (d) is idempotent on a repeat.

**Pros.** Keeps the owner's capability in full, and makes it *better*: back-dating
becomes attributable, scoped to a window rather than "all of history", and
reviewable after the fact. A rate correction is a decision somebody made, not
something that happened. It also makes the dispute case answerable: "this window
was repriced from V0 to V1 on 2026-09-06 by <operator>, reason <r>".

**Cons.** More surface: a card registry (versions must outlive the config they
came from), a new admin verb with its own authz and idempotency, a new journal
entry class, and the reprice must interact correctly with sealed checkpoints —
repricing behind an anchored checkpoint means the checkpoint's `Σ settled` no
longer matches its segment unless the reprice is expressed as forward
adjustments. It also does not give the operator what a config PUT gives them
today: a one-line fix that silently makes the numbers right. That is the point,
but it is a real ergonomic loss and should be named as one.

**Cost of a signature that is not there.** Nothing in this tree implements an
operator-signed admin verb today; `/api/v1/admin/ledger/*` is read-only
(`units_admin.rs:4310-4314`). Option C is genuinely new work, not a rewiring.

---

## 5. The reconciliation identity across an epoch

The identity, stated at `crates/busbar/src/root/ledger_identity.rs:8-14`:

```text
  Σ ledger priced_amount, projected once to micro-units  ==  the row's spend_micros
  Σ ledger fee_count                                     ==  the row's billable_requests
```

The module already names the failure mode this note is about
(`ledger_identity.rs:16-18`): *"a card edit moves the money and leaves the count
alone."*

| Option | What the identity proves across a card edit |
|---|---|
| A (both sides read-time) | Trivially holds — both sides derive from the same current card, so it proves the *projection arithmetic*, not that history is stable. It cannot detect that the window's money moved. |
| B (posting immutable, legacy read-time) | **Breaks by design** at the first mid-window card edit: the legacy side re-prices, the ledger side does not. The residual equals exactly the retroactive delta. This is the current 1.6.0 shape and `ARCHITECTURE.md:865-868` already schedules *"a mid-window rate edit asserting the expected divergence"* as a cell. |
| C (posting priced at its own version) | Same as B: the divergence is expected and now *explained* by a journal entry naming the reprice. The residual after applying the reprice adjustment returns to zero — the identity becomes a check that the back-dating was applied correctly. |

The `fee_count` half is unaffected by any card change under all three, which is
why it is checked separately (`ledger_identity.rs:16-18`).

**`/usage` parity in 1.6.0.** PB-16 (`ARCHITECTURE.md:1542`) makes the legacy
surface byte-identical with no additive lines. Combined with the parity clause at
`ARCHITECTURE.md:856-858`, that means: **under every option, legacy `/usage`
stays retroactive.** It re-prices history off the current card, exactly as 1.5.5
does, and `billing|rate-card|epoch-mid-window` holds it to 1,000,120,000. Making
`/usage` non-retroactive is a `status`/`effects.usage`-class divergence, which
`testing/shadow-oracle/accepted-differences.json` will only accept as
`kind: breaking` with a `changelog` field — never as an improvement. That is not a
line to cross for this.

Consequence worth stating plainly: for the whole of 1.6.0, the same window read
two ways gives two answers after a card edit, and that is *correct*. The ledger
endpoints are the reproducible surface; `/usage` is the compatibility surface.
The `currency`/`as_of` fields on `UsageView` (`contract/mod.rs:1096`, `:1102`) are
the only hint a reader gets that the figure is an estimate as of a read.

---

## 6. What changes, per option

| Surface | A (keep 1.5.5 shape everywhere) | B (ship as designed) | C (versioned postings + reprice verb) |
|---|---|---|---|
| **Ledger schema** | Drop `rate_card_version` from `Posting`/`PostingStamp`; store quantities only | No change — `posting.rs:41-50`, `durability.rs:368-373`, `:423` are already right | Add a card *registry* (version → card, persisted beside the journal); add an `Adjust`-class record for a reprice naming `(from_version, to_version, scope, operator, reason)` |
| **Kernel** | Remove the admission pin (`units_llm.rs:464`); price at read | No change — pin at admission, price once, journal it | No change to the hot path; the pin still fixes the version. Reprice is an out-of-band admin unit |
| **Admin surface** | None; `PUT /config/settings` remains the only lever | None; `/ledger/*` stays read-only (`units_admin.rs:4310-4314`) | New signed `POST /ledger/reprice`; `/ledger/totals` gains a per-version breakdown; `/ledger/reconciliation` gains the reprice adjustments |
| **Oracle** | `billing\|rate-card\|epoch-mid-window` stays as the sole pin | Add the mid-window-edit divergence cell `ARCHITECTURE.md:867` already schedules: `/usage` moves, `/ledger/totals` does not | The B cell, plus a reprice cell (reprice window W to V1 → `/ledger/totals` moves, journal entry present, `/usage` unchanged by the verb) |
| **Migration** | N/A | `migration.rs:60-74` as-is; operator must name the historical card | Same, plus: a wrong opening version is now *fixable* by a reprice instead of unfixable |

---

## 7. Recommendation

**Ship B for 1.6.0. Design C's storage now; defer C's verb to 1.6.x.**

Reasoning:

1. **B is already built and already correct.** `Posting.rate_card_version`,
   `PostingStamp`, the journal body bytes and the admission pin all exist in this
   tree. Nothing has to be invented to ship a reproducible ledger.
2. **A is not an option for the 1.6.0 endpoints.** A ledger whose totals move
   when an operator edits config is not a ledger, and the reconciliation
   identity over it proves nothing. The oracle cell is the evidence: a *four
   hundredfold* swing in a window's total, with no record and no restart.
3. **A must nevertheless survive on `/usage`**, and does, unchanged, under the
   parity clause. The owner's capability is therefore *not removed in 1.6.0* —
   the retroactive lever is still there, on the legacy surface, doing exactly
   what it does today.
4. **C is the right destination and B is on the way to it.** Because B already
   stores quantities per `PricedLine` *and* the version, upgrading to C is a
   read-path and admin-surface change, not a data migration. Deciding for B now
   costs nothing later.
5. **The one thing to change before shipping B**: the migration marker's
   `rate_card_version` (`migration.rs:74`) is the operator's assertion about what
   history was earned under, and today nothing checks it. It should be required
   explicitly rather than defaulted, because it is the single figure that decides
   whether the opening balance is honest.

The instinct — separate the quantity from the price — is preserved in full. What
is given up is only the *implicit* back-date, and the argument against that is
the recorded number: 10,000,000 became 1,000,120,000, and the endpoint said
nothing.

---

## 8. Registration text for the recommendation

B is not a change to any 1.5.5 surface: `/usage` stays byte-identical and the
ledger endpoints are new. Under `testing/shadow-oracle/accepted-differences.json`
that is an **`improvement`** (additive; a 1.5.5 operator keeps working
unchanged), and every entry — improvement or breaking — owes a verbatim
CHANGELOG line.

```json
{
  "id": "D-NN ledger postings are priced once, at admission",
  "kind": "improvement",
  "changelog": "The 1.6.0 ledger endpoints price each unit once, against the rate card in force when it was admitted, and record that card's version with the posting; legacy `/usage` continues to derive spend at read time from the current card, unchanged.",
  "by": "owner (Matthew Jackson), 2026-09-06 rate-card epoch decision",
  "rationale": "1.5.5 stores raw token counts and derives spend_micros at read time from the current cost model (busbar-core/src/admin/v1/service.rs:2187-2230; contract/mod.rs:1077 'MUTABLE ESTIMATE'), so a PUT /config/settings rate_card re-prices every past row (oracle cell billing|rate-card|epoch-mid-window: a window totalling 10,000,000 micros reads back as 1,000,120,000 after a 100x card, with no restart and no epoch boundary). The 1.6.0 root book prices at admission against the pinned card and journals rate_card_version with the posting, so a ledger read of a settled window is reproducible. The legacy /usage surface is untouched and stays retroactive (PB-16 parity clause, ARCHITECTURE.md:856-858), so no 1.5.5 client or operator sees a difference. The two surfaces diverging after a mid-window card edit is expected and is asserted by its own oracle cell.",
  "classes": ["body"],
  "cells": ["^ledger\\|"]
}
```

CHANGELOG.md line (verbatim, as `scripts/changelog-register-check.sh` requires):

> The 1.6.0 ledger endpoints price each unit once, against the rate card in force
> when it was admitted, and record that card's version with the posting; legacy
> `/usage` continues to derive spend at read time from the current card,
> unchanged.

If and when C's verb ships, `POST /api/v1/admin/ledger/reprice` is additive and
also registers as `improvement`; it becomes `breaking` only if it is ever wired
to change what legacy `/usage` returns, which it must not be.
