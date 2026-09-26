// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The HOST side of the [`PlaneHostVtable`]: the construction point that fills every slot with a
//! host-side `extern "C-unwind"` fn wired over a real core primitive. After the Phase-1 capability
//! fan-out (breaker, govern, trust, journal, egress, dispatch) every slot is now wired — ZERO
//! `unimplemented!()` stubs remain. The three PROOF-OF-LIFE impls (`clock_now`, `metrics_emit`,
//! `govern_admit`) live here; the rest forward into their capability modules ([`super::breaker`],
//! [`super::govern`], [`super::trust`], [`super::journal`], [`super::egress`], [`super::dispatch`]).
//!
//! ## Boundary discipline (reused from `plugin-sdk/boundary.rs`)
//!
//! Every wired fn:
//! 1. recovers its [`HostState`](super::HostState) from the opaque [`HostCtx`] FIRST (the recovery
//!    invariant lives on [`super::recover`]);
//! 2. runs its body inside a MANDATORY `catch_unwind` so no panic unwinds across the seam — a caught
//!    panic maps to the FAIL-CLOSED value for that slot (`Decision::Deny`, `StatusClass::Fault`, a `0`
//!    clock), never to a permissive one;
//! 3. translates POD ↔ primitive by pointer, writing any out-param only on the `Ok` path.

use super::{recover, trust};
use busbar_plugin::hot::host::{HostCtx, PlaneHostVtable};
use busbar_plugin::hot::{
    AuthQuery, AuthResolved, Decision, DeclStr, Facts, GovRefusal, MeterOutcome, MetricSample,
    StatusClass, Usage,
};
use busbar_plugin::AbiPreamble;
use core::mem::MaybeUninit;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Build the host's [`PlaneHostVtable`]: the FROZEN preamble + sized/versioned header, then every
/// capability slot `Some(<a host-side fn>)`. Three slots are wired over real primitives here
/// (`clock_now`, `metrics_emit`, `govern_admit`); every other slot forwards into its capability
/// module. After the Phase-1 fan-out every slot is wired — no `unimplemented!()` stub remains.
#[must_use]
pub fn build_plane_host_vtable() -> PlaneHostVtable {
    PlaneHostVtable {
        abi: AbiPreamble::CURRENT,
        size: core::mem::size_of::<PlaneHostVtable>() as u32,
        version: busbar_plugin::ABI_MINOR,

        // ── WIRED proof-of-life (real primitives) ──────────────────────────────────────────────
        govern_admit: Some(govern_admit),
        govern_admit_reason: Some(govern_admit_reason),
        metrics_emit: Some(metrics_emit),
        clock_now: Some(clock_now),

        // ── WIRED capability slots — each forwards into its capability module (breaker / trust /
        //    egress / journal / dispatch), or a wired local fn (meter_charge, auth_resolve) ────────
        meter_charge: Some(meter_charge),
        breaker_admit: Some(super::breaker::breaker_admit),
        breaker_admit_reason: Some(super::breaker::breaker_admit_reason),
        breaker_settle: Some(super::breaker::breaker_settle),
        verify_lookup: Some(trust::verify_lookup),
        verify_store: Some(trust::verify_store),
        egress_open: Some(super::egress::egress_open),
        egress_poll: Some(super::egress::egress_poll),
        egress_write: Some(super::egress::egress_write),
        egress_close: Some(super::egress::egress_close),
        egress_fault: Some(super::egress::egress_fault),
        journal_append: Some(super::journal::journal_append),
        journal_read: Some(super::journal::journal_read),
        nested_dispatch: Some(super::dispatch::nested_dispatch),
        workhandle_open: Some(super::dispatch::workhandle_open),
        workhandle_resume: Some(super::dispatch::workhandle_resume),
        drift_quarantine: Some(trust::drift_quarantine),
        approval_redeem: Some(trust::approval_redeem),
        auth_resolve: Some(auth_resolve),
        trust_evaluate: Some(trust::trust_evaluate),
        entitlement_check: Some(super::dispatch::entitlement_check),
        gate_scan: Some(super::dispatch::gate_scan),
        // ── The stateless verify-freshness DECISION + expiry-carrying approval redemption (verify/
        //    approval faithfulness). The `verify_decide` slot funnels to `trust::verify_decide_q`,
        //    which shares the `trust::verify_decide_due` body with the a2a plane; the MCP plane's own
        //    `VerifyGate` now lives in the neutral substrate and names `reverify::due` directly. ─────
        verify_decide: Some(trust::verify_decide_q),
        approval_redeem_q: Some(trust::approval_redeem_q),
        // ── The byte-duplex PIPE tier (CLUSTER-3 egress): raw-connection / subprocess byte channels,
        //    keyed by a `PipeId`, wired over the real governed child process in `super::pipe`. ──────
        pipe_read: Some(super::pipe::pipe_read),
        pipe_write: Some(super::pipe::pipe_write),
        // ── The DURABLE journal seam (minor-9): each slot wired over the store-backed
        //    `audit::journal::Journal<PlaneJournalRecord>` in `super::journal`. ───────────────────────
        journal_register: Some(super::journal::journal_register),
        journal_append_scoped: Some(super::journal::journal_append_scoped),
        journal_read_scoped: Some(super::journal::journal_read_scoped),
        journal_restore: Some(super::journal::journal_restore),
        journal_seed: Some(super::journal::journal_seed),
        journal_forget: Some(super::journal::journal_forget),
        journal_compact: Some(super::journal::journal_compact),
        journal_verify_scoped: Some(super::journal::journal_verify_scoped),
        // ── The CARD-SIGN seam (minor-10): the host derives the deployment's domain-separated card
        //    subkey and signs a plane-framed input, so the card SECRET never crosses to the plane.
        //    Wired only when a plane declares a card-signing domain (the neutral `card-signing`
        //    capability marker, enabled by that plane); absent otherwise. ──
        #[cfg(feature = "card-signing")]
        subkey_sign: Some(card_sign),
        #[cfg(not(feature = "card-signing"))]
        subkey_sign: None,
        // ── WIRED `guard_url` (minor-12) → the host-owned structural URL guard in `super::guard`: the
        //    SSRF/URL-guard chokepoint for a URL-shaped tool argument. Always wired (the host owns the
        //    net_guard internals whatever the plane); no plane feature gates it. ─────────────────────────
        guard_url: Some(super::guard::guard_url),
        // ── WIRED `identity_admit` (minor-17) → the host-side inbound admission in
        //    `super::identity_admit`: the configured auth chain + the one verdict resolution over the
        //    caller's own credential, returning an opaque resolved-identity handle. Always wired (the
        //    host owns the auth chain whatever the plane); no plane feature gates it. ────────────────────
        identity_admit: Some(super::identity_admit::identity_admit),
        // ── WIRED `gate_decide` (minor-18) → the host-side request-admission gate in
        //    `super::dispatch`: re-select the resolved gate set by `(plane_key, container)` and run the
        //    REAL `crate::hooks::gate::decide` over the reconstructed subject, so an MCP/A2A plane body
        //    fires its hook gates without naming the gate engine. Always wired (the host owns the gate
        //    set whatever the plane); no plane feature gates it. ───────────────────────────────────────
        gate_decide: Some(super::dispatch::gate_decide),
        // ── WIRED `cost_reserve`/`cost_settle` (minor-19, the METERING-LEASE seam) → the host-owned
        //    reserve-then-settle `CostHold` lease registry in `super::cost_host`: open a lease over
        //    ALREADY-PRICED nanodollars (widened host-side to the internal u128 `CostAmount`), settle
        //    EXACT increments against it, and read back exhaustion so a high-rate carrier plane can
        //    hard-close a live session mid-stream. Always wired (the host owns the lease state whatever
        //    the plane); no plane feature gates it. ─────────────────────────────────────────────────────
        cost_reserve: Some(super::cost_host::cost_reserve),
        cost_settle: Some(super::cost_host::cost_settle),
        // ── WIRED `counter_add` (minor-25, the METRIC-FAMILY seam) → the recorder, over a family the
        //    emitting plane DECLARED. Always wired; what a plane may add to is its declaration's. ──
        counter_add: Some(counter_add),
    }
}

/// WIRED `card_sign` → the REAL host-side card signer over `crate::governance` (see
/// [`crate::governance::GovState::card_sign`]): derive the deployment's domain-separated agent-card
/// subkey and sign the plane-framed signing input, writing the 64-byte Ed25519 signature into `out`
/// on the `Ok` path. The subkey secret is derived and used entirely host-side; only the signature
/// bytes cross back. `Refused` on a null in/out pointer or a deployment with no card-signing key;
/// `Fault` on any panic (`out` untouched).
#[cfg(feature = "card-signing")]
extern "C-unwind" fn card_sign(
    host: HostCtx,
    input_ptr: *const u8,
    input_len: usize,
    out: *mut u8,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`).
        let Some(state) = (unsafe { recover(host) }) else {
            return StatusClass::Refused;
        };
        if input_ptr.is_null() || out.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: `(input_ptr, input_len)` is a live borrowed range for the call (ABI discipline).
        let input = unsafe { std::slice::from_raw_parts(input_ptr, input_len) };
        match state
            .app
            .governance
            .as_ref()
            .and_then(|g| g.card_sign(input))
        {
            Some(sig) => {
                // SAFETY: `out` is a caller-provided writable range of at least 64 bytes (ABI); `sig`
                // is a live 64-byte array. Written only on the Ok path (init-only-on-Ok).
                unsafe { std::ptr::copy_nonoverlapping(sig.as_ptr(), out, 64) };
                StatusClass::Ok
            }
            None => StatusClass::Refused, // no card-signing key → out-buffer left untouched.
        }
    }))
    .unwrap_or(StatusClass::Fault) // caught panic → the distinct fault class, never `Ok`.
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// WIRED slots — real primitives, full boundary discipline.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// WIRED `clock_now` → `busbar_kernel::store::now_ms`, the host wall clock. The ABI contract is Unix
/// NANOSECONDS, so the host-side milliseconds clock is scaled up; sourcing it through
/// `busbar_kernel::store::now_ms` keeps the plane off any ambient clock (the whole point of the slot).
extern "C-unwind" fn clock_now(host: HostCtx) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the host passes a live `HostState` ptr for the dispatch duration (see `recover`).
        let Some(_state) = (unsafe { recover(host) }) else {
            return 0;
        };
        busbar_kernel::store::now_ms().saturating_mul(1_000_000)
    }))
    .unwrap_or(0) // fail-closed: a panicked clock reads 0, never a wild value.
}

/// WIRED `metrics_emit` → the real `metrics` recorder (`crate::metrics`), through the SAME rule the
/// COLD lane's envelope is folded by.
///
/// A plane REPORTS a sample; the host decides whether it is allowed to have said it (DECISIONS #85).
/// This slot is the hot lane's half of that, and it used to have no half at all: it took whatever
/// name the plane handed over, verbatim, and — when the plane handed over no name — INVENTED
/// `busbar_plane_metric`, writing into the reserved first-party namespace on the plane's behalf.
/// Nothing checked the charset, so a plane could emit a name Prometheus cannot parse and cost the
/// whole exposition; nothing checked the value, so a `NaN` from `f64::from_bits` went straight to
/// the recorder; and nothing stopped a plane shadowing a real `busbar_*` series.
///
/// Now: the name goes through [`crate::metrics::observe::admits_metric_name`] — the one predicate both lanes
/// ask — and a non-finite value is refused. A rejected sample is `Refused`, not `Ok`, because the
/// plane is entitled to know its telemetry did not land; and it is `Refused` rather than a fault
/// because a badly-named metric is bad DATA, not a broken peer.
///
/// PROVENANCE is the host's, from [`super::HostState::emitter`] — stamped when the host MINTS the
/// `HostCtx`, never read off the sample. A handle minted for the host's own use carries no emitter
/// and this slot refuses it, because a series nobody can be held to is a series an operator cannot
/// act on.
///
/// CARDINALITY is bounded on the same budget the cold lane uses
/// ([`crate::metrics::observe::admits_cardinality`]): a cap on distinct series per plugin and on
/// distinct label sets per series, refused rather than silently dropped. The labels stay opaque —
/// this ABI says the host does not interpret them — and are fingerprinted instead, so the bound
/// exists before the label encoding does.
extern "C-unwind" fn metrics_emit(host: HostCtx, sample: *const MetricSample) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`).
        let Some(state) = (unsafe { recover(host) }) else {
            return StatusClass::Refused;
        };
        // WHO IS EMITTING. Taken from the host's own `HostState`, never from the sample — an
        // identity the emitter supplies is a claim, not an attribution, and is the same class of
        // defect as the metric NAME this slot used to take verbatim. A handle minted for the host's
        // own use (`calllog`, `auditlog`, trust, the breaker) carries no emitter and is refused
        // here: a sample nobody can be held to is a series an operator cannot act on.
        let Some(emitter) = state.emitter else {
            return StatusClass::Refused;
        };
        if sample.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: a non-null `sample` is a live, initialized `MetricSample` for the call (ABI).
        let s = unsafe { &*sample };
        let value = f64::from_bits(s.value_bits);
        // A non-finite sample is not a value. `from_bits` will hand back `NaN`/`inf` for bit
        // patterns a plane can produce by accident or on purpose, and the cold lane's validator has
        // always dropped those; there is no reading of #85 on which one lane admits what the other
        // refuses.
        if !value.is_finite() {
            return StatusClass::Refused;
        }
        if s.name_ptr.is_null() || s.name_len == 0 {
            // No name is not a metric. Inventing one put a plane's sample in the reserved namespace
            // under a name no plane chose and no operator could attribute.
            return StatusClass::Refused;
        }
        // SAFETY: `(name_ptr, name_len)` is a live borrowed range for the call (ABI discipline).
        let bytes = unsafe { std::slice::from_raw_parts(s.name_ptr, s.name_len) };
        let name = String::from_utf8_lossy(bytes);
        if !crate::metrics::observe::admits_metric_name(&name) {
            return StatusClass::Refused;
        }
        // THE CARDINALITY BUDGET — the second question, and the same one the cold lane asks. The
        // labels are an OPAQUE packed blob this ABI says the host does not interpret, so they are
        // fingerprinted rather than parsed: telling two label sets apart is all a budget needs, and
        // it means the bound exists BEFORE the label encoding is designed rather than after the
        // first explosion. A refusal here is returned to the plane, not swallowed.
        let labels: &[u8] = if s.labels_ptr.is_null() || s.labels_len == 0 {
            &[]
        } else {
            // SAFETY: `(labels_ptr, labels_len)` is a live borrowed range for the call (ABI).
            unsafe { std::slice::from_raw_parts(s.labels_ptr, s.labels_len) }
        };
        if !crate::metrics::observe::admits_cardinality_opaque(emitter, &name, labels) {
            return StatusClass::Refused;
        }
        // Routes to the process-wide `metrics-exporter-prometheus` recorder installed by
        // `crate::metrics::init` (a no-op sink when the operator did not opt in). The host's
        // provenance label is attached here, from the host's own knowledge — the same
        // `plugin="<name>"` the cold lane's fold attaches, so one plugin reporting on either lane
        // produces series an operator reads the same way.
        metrics::gauge!(
            name.into_owned(),
            vec![metrics::Label::new(
                crate::metrics::observe::PLUGIN_LABEL,
                emitter
            )]
        )
        .set(value);
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault) // caught panic → the distinct fault class, never `Ok`.
}

/// WIRED `counter_add` → the real `metrics` recorder, over a metric family the emitting plane
/// DECLARED (ARCHITECT RULING S2-c; #2 rule (2), #65).
///
/// The emitter is the host's own attribution ([`super::HostState::emitter`]); the family is looked
/// up in THAT plane's registered declaration, so a plane adds only to what it declared — and a
/// declaration reaches the registry only through the host's boot guard, which admits a `busbar_`
/// family only when the host lists it as one a plane may carry. The label VALUES are decoded here,
/// for a declared family only: one per declared key, positionally, each bounded UTF-8. The series
/// renders exactly the declared name and keys — no provenance label — so a carried first-party
/// series is byte-identical to the host's own. The label set is bounded on the same cardinality
/// budget every plugin-reported series spends. Anything else is `Refused`; a panic is `Fault`.
extern "C-unwind" fn counter_add(
    host: HostCtx,
    family_ptr: *const u8,
    family_len: usize,
    values_ptr: *const DeclStr,
    values_len: usize,
    delta: u64,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`); every range below is live for the call (ABI).
        let emitter = unsafe { recover(host) }.and_then(|s| s.emitter);
        let name = unsafe { borrowed(family_ptr, family_len, 64) };
        let declared = emitter.and_then(crate::plane::registry::plane_decl_for);
        let family = declared.and_then(|d| {
            let mut families = d.metric_families.iter();
            families.find(|f| name == Some(f.name.as_bytes()))
        });
        let (Some(emitter), Some(family)) = (emitter, family) else {
            return StatusClass::Refused;
        };
        if values_len != family.label_keys.len() || (values_ptr.is_null() && values_len > 0) {
            return StatusClass::Refused;
        }
        let mut labels = Vec::with_capacity(values_len);
        for (i, key) in family.label_keys.iter().enumerate() {
            // SAFETY: `values_ptr` addresses `values_len` live entries (ABI), each a live range.
            let v = unsafe { core::ptr::read_unaligned(values_ptr.add(i)) };
            let bytes =
                unsafe { borrowed(v.ptr, v.len, crate::hooks::wire::MAX_METRIC_LABEL_CHARS) };
            let Some(value) = bytes.and_then(|b| std::str::from_utf8(b).ok()) else {
                return StatusClass::Refused;
            };
            labels.push(metrics::Label::new(*key, value.to_owned()));
        }
        let fingerprint = std::hash::BuildHasher::hash_one(
            &std::hash::BuildHasherDefault::<std::collections::hash_map::DefaultHasher>::default(),
            &labels,
        );
        if !crate::metrics::observe::admits_cardinality(emitter, family.name, fingerprint) {
            return StatusClass::Refused;
        }
        metrics::counter!(family.name, labels).increment(delta);
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault) // caught panic → the distinct fault class, never `Ok`.
}

/// A plane-borrowed `(ptr, len)` range as bytes — `None` for a null range or one over `cap` bytes,
/// judged BEFORE the slice is formed (the length is plane-attested).
///
/// # Safety
/// A non-null `ptr` with `len <= cap` addresses `len` live bytes for the call (ABI discipline).
unsafe fn borrowed<'a>(ptr: *const u8, len: usize, cap: usize) -> Option<&'a [u8]> {
    // SAFETY: the caller's contract, with `len` bounded by `cap` before the slice exists.
    (!ptr.is_null() && len <= cap).then(|| unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// WIRED `govern_admit` → the REAL admission over `crate::governance` (see [`super::govern::admit`]):
/// the budget gate the [`Facts`] POD encodes, then the `GovState::try_admit` limit engine. On `Admit`
/// the RAII [`AdmitGrant`](crate::governance::AdmitGrant) it yields is REGISTERED in the
/// [`DispatchScope`](super::DispatchScope) arena, so it is released on scope-drop no matter how the
/// dispatch future ends (the leak keystone). Fail-closed (`Deny`) on a null POD or any panic.
extern "C-unwind" fn govern_admit(host: HostCtx, facts: *const Facts) -> Decision {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`).
        let Some(state) = (unsafe { recover(host) }) else {
            return Decision::Deny;
        };
        if facts.is_null() {
            return Decision::Deny;
        }
        // SAFETY: a non-null `facts` is a live, initialized `Facts` for the call (ABI discipline).
        let f = unsafe { &*facts };
        super::govern::admit(state, f)
    }))
    .unwrap_or(Decision::Deny) // fail-closed: a panicked admit denies.
}

/// Copy up to `cap` of `bytes` into the caller's `buf` (tolerating a null/zero-cap slot), returning
/// the number of bytes written. The `egress_poll` variable-length copy: a caller sizes `buf` and
/// learns the written length from [`GovRefusal::reason_len`].
///
/// # Safety
/// `buf`, when non-null, is a writable range of at least `cap` bytes for the call.
unsafe fn write_reason(buf: *mut u8, cap: usize, bytes: &[u8]) -> usize {
    if buf.is_null() || cap == 0 {
        return 0;
    }
    let n = bytes.len().min(cap);
    // SAFETY: `bytes[..n]` is initialized and `buf[..n]` is a writable range (n ≤ cap, caller ABI).
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, n) };
    n
}

/// Write the [`GovRefusal`] out-param (tolerating a null slot): the recovery floor + the rendered
/// reason length.
///
/// # Safety
/// `out`, when non-null, is a writable, aligned `MaybeUninit<GovRefusal>` for the call.
unsafe fn write_gov_refusal(
    out: *mut MaybeUninit<GovRefusal>,
    retry_after_secs: u64,
    reason_len: usize,
) {
    let refusal = GovRefusal {
        size: core::mem::size_of::<GovRefusal>() as u32,
        version: busbar_plugin::hot::POD_VERSION,
        _reserved: 0,
        retry_after_secs,
        reason_len,
    };
    // SAFETY: `out` is a writable, aligned MaybeUninit slot (or null, which `write_out` tolerates).
    unsafe { busbar_plugin::write_out(out, refusal) };
}

/// WIRED `govern_admit_reason` — [`govern_admit`] WITH REFUSAL FIDELITY. Identical admit behaviour
/// (the budget-POD gate, the real `try_admit` chain, the RAII grant registered in the dispatch arena),
/// the difference being that a BLOCKED limit RENDERS its reason into `reason_buf` (the exact
/// `format!("{blocked:?}")` bytes the mcp budget refusal surfaces today — the plane can no longer hold
/// `LimitBlocked`, so the host formats it) and records its length + recovery floor in [`GovRefusal`],
/// instead of discarding it. `out` is initialized up front (never left uninitialized): on an `Admit`
/// it holds `reason_len == 0`; on a `Deny` it holds the reason length; on a caught panic the eagerly
/// written zero. Fail-closed: a null POD or a caught panic denies.
extern "C-unwind" fn govern_admit_reason(
    host: HostCtx,
    facts: *const Facts,
    reason_buf: *mut u8,
    reason_cap: usize,
    out: *mut MaybeUninit<GovRefusal>,
) -> Decision {
    catch_unwind(AssertUnwindSafe(|| {
        // Initialize `out` up front so no path (admit, block, or a caught panic below) leaves it
        // uninitialized; a block overwrites it with the rendered reason length + recovery floor.
        // SAFETY: ABI out-param discipline (writable/aligned or null; see `write_gov_refusal`).
        unsafe { write_gov_refusal(out, 0, 0) };
        // SAFETY: recovery invariant (see `recover`).
        let Some(state) = (unsafe { recover(host) }) else {
            return Decision::Deny;
        };
        if facts.is_null() {
            return Decision::Deny;
        }
        // SAFETY: a non-null `facts` is a live, initialized `Facts` for the call (ABI discipline).
        let f = unsafe { &*facts };
        match super::govern::admit_reason(state, f) {
            Ok(()) => Decision::Admit,
            Err(blocked) => {
                // SAFETY: `reason_buf`/`reason_cap` are a writable range (or null) per the ABI.
                let written =
                    unsafe { write_reason(reason_buf, reason_cap, blocked.reason.as_bytes()) };
                // SAFETY: as above.
                unsafe { write_gov_refusal(out, blocked.retry_after_secs, written) };
                Decision::Deny
            }
        }
    }))
    .unwrap_or(Decision::Deny) // fail-closed: a panicked admit denies (out already zero).
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// WIRED capability slots — local host-side fns and forwarders into the capability modules. No
// `unimplemented!()` stub remains: the Phase-1 fan-out filled every slot.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// WIRED `meter_charge` → the REAL metering over `crate::governance` + `crate::plane::cost` (see
/// [`super::govern::charge`]): compute the money-scalar [`CostBreakdown`](crate::plane::cost::CostBreakdown)
/// this usage settles, then accrue it into the write-behind metering time-series. Fail-closed
/// (`Rejected`) on a null POD, a malformed breakdown, or any panic.
extern "C-unwind" fn meter_charge(host: HostCtx, usage: *const Usage) -> MeterOutcome {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`).
        let Some(state) = (unsafe { recover(host) }) else {
            return MeterOutcome::Rejected;
        };
        if usage.is_null() {
            return MeterOutcome::Rejected;
        }
        // SAFETY: a non-null `usage` is a live, initialized `Usage` for the call (ABI discipline).
        let u = unsafe { &*usage };
        super::govern::charge(state, u)
    }))
    .unwrap_or(MeterOutcome::Rejected) // fail-closed: a panicked charge rejects.
}
// `breaker_admit` / `breaker_settle` are WIRED over the real breaker in `super::breaker` (the BREAKER
// family fan-out); `verify_lookup` / `verify_store` are WIRED over the real trust store in
// `super::trust` (the TRUST family fan-out); their vtable slots reference those modules directly.
// The EGRESS family (`egress_open`/`_poll`/`_write`/`_close`/`_fault`) and `guard_url` are WIRED in
// `super::egress` and `super::guard`; their vtable slots reference those modules directly.
// journal_append / journal_read are WIRED in `super::journal` (the JOURNAL family, over the real
// `crate::audit` hash chain). The builder references them directly; no stub lives here.
// `nested_dispatch` / `workhandle_open` / `workhandle_resume` / `entitlement_check` / `gate_scan`
// are WIRED in `super::dispatch` (the DISPATCH family); their vtable slots reference that module.
// `drift_quarantine` / `approval_redeem` / `trust_evaluate` are WIRED over the real trust store in
// `super::trust` (the TRUST family fan-out); their vtable slots reference that module directly.
/// WIRED `auth_resolve` → the REAL principal resolution over `crate::auth` (see
/// [`super::govern::resolve_auth`]): resolve a credential REF to an OPAQUE host-side reference (NEVER
/// plaintext), writing the [`AuthResolved`] out-param ONLY on `Ok`. Fail-closed (`Refused`) on a null
/// query or a query naming no credential; `Fault` on any panic.
extern "C-unwind" fn auth_resolve(
    host: HostCtx,
    query: *const AuthQuery,
    out: *mut MaybeUninit<AuthResolved>,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`).
        let Some(state) = (unsafe { recover(host) }) else {
            return StatusClass::Refused;
        };
        if query.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: a non-null `query` is a live, initialized `AuthQuery` for the call (ABI discipline).
        let q = unsafe { &*query };
        match super::govern::resolve_auth(state, q) {
            Some(resolved) => {
                // SAFETY: `out` is a writable, aligned `MaybeUninit<AuthResolved>` for the call; the
                // write publishes ONLY on the Ok path (init-only-on-Ok), tolerating a null slot.
                unsafe { busbar_plugin::write_out(out, resolved) };
                StatusClass::Ok
            }
            None => StatusClass::Refused, // nothing to resolve → out-param left uninitialized.
        }
    }))
    .unwrap_or(StatusClass::Fault) // caught panic → the distinct fault class, never `Ok`.
}
