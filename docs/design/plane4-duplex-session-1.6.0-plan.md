# Plane 4 — duplex/session 1.6.0 plan — §T1.5 D2 metering-lease signatures (CORRECTED)

Status: **signature pin only.** This file pins the frozen-ready `cost_reserve` / `cost_settle` ABI
slot signatures for the D2 per-frame budget lease. It does **not** add the slots to any vtable — that
is a later T1 step. The `CostHold` lease type these slots drive was reworked to this shape in the
companion code change (`crates/busbar-core/src/plane/cost.rs`), so the signatures below and the type
now agree.

Companion docs: `docs/design/plane4-seam-audit-B-session.md` (the read-only adversarial audit whose
D2 verdict this section implements) and `docs/design/plane4-duplex-session.md` (the authoritative
design, §6-D2).

---

## §T1.5 — the D2 metering-lease slots (the ABI one-way door)

**CORRECTED per seam-audit-B — FREEZE THIS SHAPE, not the original §B.1.** The original §B.1
signatures (design §6-D2 / plan §B.1) are **withdrawn**: seam-audit-B ranked four defects in them, two
signature-level, that would freeze the wrong shape at airlock minor-19 (after which a reshape is a
breaking MAJOR). The two-trailing-`Option`-slot *mechanism* and the opaque-id `CostLeaseId` are
unchanged and correct; the **argument shapes** below are the corrected ones.

### What changed vs the original §B.1 (audit-B findings, ranked)

| # | Sev | Original §B.1 defect | Correction below |
|---|-----|----------------------|------------------|
| 1 | CRITICAL | `CostReserveFn` carried `magnitude: *const MagnitudePod` — a coarse **unit count**. Converting units→nanodollars is PRICING, and core prices nothing; the slot would force the host to price. | Reserve carries **money scalars only** (`reserve_nanos`, `cap_nanos`). The PLANE (or a substrate pricing seam) prices units→nanodollars **before** the call. `MagnitudePod` is **removed from the D2 ABI entirely** — the unit-space caller-cap refusal (`Magnitude`) is a separate, plane-side pre-admission check, not this slot. |
| 2 | CRITICAL | `out_exhausted` had no backing in `CostHold`, and debit-up-front/refund-at-finalize could not surface a mid-session "cell dry" except via `settled ≥ reserved`, which conflicts with the mandated coarse over-estimate (fires the stop late). | Reserve carries the caller's **true money `cap`** (`cap_nanos` + `cap_present`) held separately from the coarse `reserve_nanos`. `out_exhausted` is backed by `CostHold::is_exhausted()` = `settled ≥ cap`, so an over-estimated reserve cannot delay the stop. |
| 3 | HIGH | `CostSettleFn` forced a serialize+parse of the full itemized `CostBreakdown` **per settle** just to recover one `u128 total` — wrong hot-path shape for the high-rate carrier the slot exists for. | Settle carries a `total_nanos: u128` scalar the host accrues in O(1) (`CostHold::settle_partial`). The itemized `CostBreakdown` becomes an **optional, audit-only** opaque suffix (nullable). |
| 5 | MEDIUM | `MagnitudePod.caller_cap: u64` with `0 = none` silently lost the `Some(0)` (refuse-all) case. | The money cap uses an explicit **`cap_present: bool`** flag beside `cap_nanos`, so `Some(0)` (refuse-all) is representable distinctly from "no cap" (`CostHold`'s cap is `Option<CostAmount>`). |

### Frozen-ready signatures (freeze at airlock minor 18 → 19)

```rust
// APPENDED at hot/host.rs:536 (trailing Option slots below the reserved EXTENSION POINT) + mirrored
// on hot/pod.rs. Airlock MINOR 18 → 19 — an append-only add, never a reshape.
//
// CORRECTED per docs/design/plane4-seam-audit-B-session.md. Freeze THIS shape, not the original §B.1.

/// An opaque, host-minted lease id. The host carries NO per-session state and is re-minted per frame
/// (`LiveHostFactory`), so the lease lives in durable host/engine-side state keyed by this id; any
/// re-minted host resolves the same lease. Opaque u64; `0` is the NONE sentinel (reserve failed).
#[repr(transparent)]
pub struct CostLeaseId(pub u64);

/// Open a reserve-then-settle budget lease for a streaming session. Drives `CostHold::reserve`
/// (`crates/busbar-core/src/plane/cost.rs`). ALL amounts are MONEY (nanodollars) — the PLANE (or a
/// substrate pricing seam it delegates to) has already priced its unit projection; core prices
/// nothing. `MagnitudePod` does NOT appear: the unit-space caller-cap refusal is a separate plane-side
/// pre-admission check, not this slot.
///
/// - `reserve_nanos` — the coarse over-estimate the host debits from the budget cell now.
/// - `flat_fee_nanos` — the once-only per-session fee, folded into `reserved` once (never re-added on settle).
/// - `cap_nanos` + `cap_present` — the caller's TRUE money budget ceiling that exhaustion fires against
///   (`settled ≥ cap`), held SEPARATELY from the coarse `reserve_nanos`. `cap_present == false` ⇒ uncapped
///   (never exhausts). `cap_present == true` with `cap_nanos == 0` ⇒ refuse-all (`Some(0)`, dry from the
///   outset) — representable distinctly from "no cap".
/// - `out_lease` — the host mints the opaque lease id here.
pub type CostReserveFn = extern "C-unwind" fn(
    host: HostCtx,
    reserve_nanos: u128,          // PRICED by the plane; coarse over-estimate debited from the cell
    flat_fee_nanos: u128,         // once-only per-session fee, folded into `reserved` once
    cap_nanos: u128,              // the caller's TRUE money budget ceiling (exhaustion fires here)
    cap_present: bool,            // false ⇒ uncapped; true + cap_nanos==0 ⇒ refuse-all (Some(0) preserved)
    out_lease: *mut CostLeaseId,  // host mints the opaque id (host carries no per-session state)
) -> StatusClass;

/// Settle one EXACT increment against an open lease and read back exhaustion so a live session can
/// HARD-CLOSE mid-stream. Drives `CostHold::settle_partial` + `CostHold::is_exhausted`.
///
/// - `total_nanos` — the EXACT priced increment (a turn's true cost). The host accrues in O(1); it does
///   NOT parse a breakdown on this hot path (the shape the high-rate carrier the slot exists for needs).
/// - `audit_ptr` / `audit_len` — an OPTIONAL opaque `CostBreakdown` audit suffix (the
///   `journal_append_scoped` pattern). `audit_ptr == null` (with `audit_len == 0`) ⇒ no breakdown this
///   settle. The host NEVER parses the component labels; itemization travels a separate audit tap.
/// - `out_exhausted` — `CostHold::is_exhausted()` readback: `settled ≥ cap` ⇒ budget dry ⇒ plane
///   hard-closes the session. Always `false` for an uncapped lease. Fires against `cap`, NOT `reserved`.
///
/// Refund/finalize stays plane-side on `CostHold::finalize` — no refund policy is baked into the ABI.
pub type CostSettleFn = extern "C-unwind" fn(
    host: HostCtx,
    lease: CostLeaseId,
    total_nanos: u128,            // EXACT priced increment; host accrues in O(1) (settle_partial)
    audit_ptr: *const u8,         // OPTIONAL opaque CostBreakdown audit suffix; null ⇒ none
    audit_len: usize,             // 0 when audit_ptr is null
    out_exhausted: *mut bool,     // is_exhausted() readback: settled ≥ cap ⇒ plane hard-closes
) -> StatusClass;

pub cost_reserve: Option<CostReserveFn>,   // trailing slot (host.rs, below the reserved extension point)
pub cost_settle:  Option<CostSettleFn>,    // trailing slot
```

### Append-only / non-breaking proof (unchanged from §B.1, still holds)

Both are `Option` trailing slots under the sized/versioned `AbiPreamble` discipline every appended
cluster follows (the minor-18 `gate_decide` cluster is the precedent, `hot/host.rs:526-532`); an older
plugin reads the struct through its preamble size and never touches the new tail. The two existing
carriers of this ABI (the LLM plane and MCP/A2A) call neither slot; their vtable offset for every slot
they *do* call is unchanged. The airlock MINOR bump (18→19) is the exact mechanism the reservation
comment prescribes (`hot/host.rs:536-538`).

### Plane-agnostic proof

Core mints nothing from the settle but the accrued `total_nanos`; the itemized labels cross as an
optional opaque suffix the host never parses. Every amount is a neutral money scalar. No
voice/audio/WS noun appears in any argument. `CostLeaseId` is an opaque u64.

### DO NOT (scope guard for this pass)

- Do **not** add `cost_reserve` / `cost_settle` to `PlaneHostVtable` or `PlaneHostPod` — that is a
  later T1 step (the slots stay reserved comments at `hot/host.rs:536-538` / `hot/pod.rs`).
- Do **not** bump `ABI_MINOR` yet — the 18→19 bump ships with the slots, not with this signature pin.
