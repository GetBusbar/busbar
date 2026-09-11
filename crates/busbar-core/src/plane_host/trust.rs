// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The TRUST family of the plane host-vtable, wired over busbar-core's real trust/verify primitives.
//!
//! This module fills five capability slots the Phase-1 scaffold left stubbed, each phrased over the
//! NEUTRAL counterparty (an MCP server OR an A2A agent — the code never branches on which):
//!
//! | slot | primitive | fail-closed value |
//! |---|---|---|
//! | [`verify_lookup`] | [`busbar_unit_trust::VerifyFreshness`] — freshness + single-flight leadership | non-`Ok` status (never a spurious `Hit`) |
//! | [`verify_store`] | the same ledger — the leader records a completed fetch | non-`Ok` status |
//! | [`drift_quarantine`] | [`crate::plane::quarantine`] durable demotion record | `Fault`/`Refused` |
//! | [`approval_redeem`] | [`crate::plane::approvals`] spent-approval ledger | `Refused` (already-spent OR store error) |
//! | [`trust_evaluate`] | `busbar_unit_trust::counterparty` over the durable drift state | [`TrustVerdict::Denied`] |
//!
//! ## The design split (why the host holds the freshness, and why it decides nothing)
//!
//! The HOST coordinates; the PLANE does the fetch. The freshness rule, the single flight and the
//! release a dropped leader depends on are [`busbar_unit_trust::VerifyFreshness`]'s, and are stated
//! there. What belongs here is WHY the host asks at all: the real `crate::trust::verify::VerifyGate`
//! is an async coalescer riding the `App`, the synchronous `#[repr(C)]` ABI cannot drive it, and
//! [`VerifyStoreFn`](busbar_plugin::hot::host::VerifyStoreFn) carries no digest — so a `Hit` reports
//! "verified within ttl", never a cached payload, and its `digest_ptr` is null, which is exactly
//! what a `VerifyGate` that stores no verdict of its own can promise.
//!
//! ## The verdict is DECIDED elsewhere; this module only reads the POD
//!
//! `trust_evaluate` takes no trust decision. It recovers the books' own standing, decodes the
//! asserted fact tail into [`busbar_contract::counterparty::CounterpartyFacts`], and hands both to
//! `busbar_unit_trust::counterparty::evaluate` — the verify step, where the ordered fold and the
//! rule that a plane's facts may only NARROW the host's standing are stated. What is written here
//! is the TRANSLATION, in one place, because this is the only place the `#[repr(C)]` POD is read.
//!
//! ## Fail-closed, because trust fails closed
//!
//! Every fn recovers its [`HostState`] first, runs its body inside a mandatory `catch_unwind`, and
//! maps any panic (and any null/empty POD it cannot trust) to the DENY value for its slot — never to
//! a permissive one. A caught `verify_lookup` panic returns `Fault` rather than a `Hit`, a caught
//! `trust_evaluate` panic returns `Denied`, a redemption whose ledger cannot answer is `Refused`.
//!
//! ## Phase-2 notes
//!
//! * The single-flight FOLLOWER-BLOCKING detail (a follower parking until the leader's store, rather
//!   than being told `Follow` and re-polling) is the large piece deferred here: `verify_lookup`
//!   designates leadership faithfully and `verify_store` releases it, but the follower does not yet
//!   block on a host-side condvar keyed to the leader's completion.
//! * The freshness ledger is a module-global here rather than an `App` field, so `verify_store` →
//!   `verify_lookup` persists across dispatch invocations without reshaping `App`. Phase 2 moves it
//!   onto the `App` beside `mcp_verify` and keys it to the real `VerifyGate` epochs for cross-node
//!   coordination.

use super::{recover, HostState};
use busbar_contract::counterparty::{
    Artifact, CounterpartyFacts, Grant, Liveness, RegistrationState, Verdict,
};
use busbar_plugin::hot::host::HostCtx;
use busbar_plugin::hot::{
    ApprovalQuery, CounterpartyRef, Key, StatusClass, TrustVerdict, VerifyDecision, VerifyLease,
    VerifyOutcome, VerifyQuery, VerifyVerdict, POD_VERSION,
};
use busbar_plugin::read_sized_field;
use core::mem::MaybeUninit;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::LazyLock;

/// The process-wide verify freshness ledger — [`busbar_unit_trust::VerifyFreshness`], which states
/// the freshness-only rule, the single flight and the release a dropped leader depends on. A
/// module-global (not an `App` field) so `store` → `lookup` persists across dispatch invocations
/// without reshaping `App`; see the Phase-2 note in the header.
static FRESHNESS: LazyLock<busbar_unit_trust::VerifyFreshness> =
    LazyLock::new(busbar_unit_trust::VerifyFreshness::default);

/// Copy a [`Key`]'s owned subject from its borrowed range, or `None` when the range is null/empty —
/// an unusable key is fail-closed at the call site (a verify with no subject is never a `Hit`).
///
/// # Safety
/// `key` must be a live `&Key` whose `(key_ptr, key_len)`, when non-null, borrows an initialized
/// range for the call (the ABI's borrow discipline).
unsafe fn cache_key(key: &Key) -> Option<(u32, Vec<u8>)> {
    if key.key_ptr.is_null() || key.key_len == 0 {
        return None;
    }
    // SAFETY: a non-null `(key_ptr, key_len)` borrows a live, initialized range for the call.
    let bytes = unsafe { std::slice::from_raw_parts(key.key_ptr, key.key_len) };
    Some((key.scope, bytes.to_vec()))
}

/// The counterparty/approval SUBJECT as a string, or `None` when the borrowed identity is null/empty
/// — an unidentifiable counterparty is fail-closed by its caller (denied / refused).
///
/// # Safety
/// `ptr`/`len`, when non-null, borrow a live initialized range for the call.
unsafe fn subject(ptr: *const u8, len: usize) -> Option<String> {
    if ptr.is_null() || len == 0 {
        return None;
    }
    // SAFETY: a non-null `(ptr, len)` borrows a live, initialized range for the call.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// Write a fully-initialized [`VerifyVerdict`] into a non-null out-slot. Returns whether it wrote —
/// `false` on a null out-slot, which the caller maps to a fail-closed status (never a readable `Ok`).
fn write_verdict(
    out: *mut MaybeUninit<VerifyVerdict>,
    outcome: VerifyOutcome,
    lease: VerifyLease,
) -> bool {
    if out.is_null() {
        return false;
    }
    // SAFETY: a non-null `out` is a live, writable `MaybeUninit<VerifyVerdict>` for the call (ABI).
    unsafe {
        (*out).write(VerifyVerdict {
            size: core::mem::size_of::<VerifyVerdict>() as u32,
            version: POD_VERSION,
            outcome,
            _reserved: 0,
            lease,
            // Freshness-only cache: a `Hit` carries no cached payload, so the digest is always null.
            digest_ptr: core::ptr::null(),
            digest_len: 0,
        });
    }
    true
}

/// WIRED `verify_lookup` → the host-side verify freshness cache + single-flight leadership.
///
/// `Hit` when this subject was verified within its ttl; else this caller either LEADS the re-fetch
/// (the first to reach a stale/unseen subject — it gets a leadership lease registered in the dispatch
/// scope, and must call [`verify_store`] once fetched) or FOLLOWS (a leader is already fetching). The
/// out-slot is written ONLY on `Ok`; a null key or a null out-slot is `Refused` and a caught panic is
/// `Fault` — trust never returns a spurious `Hit`.
pub(crate) extern "C-unwind" fn verify_lookup(
    host: HostCtx,
    key: *const Key,
    out: *mut MaybeUninit<VerifyVerdict>,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let state: &HostState = unsafe { recover(host) };
        if key.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: a non-null `key` is a live, initialized `Key` for the call (ABI discipline).
        let k = unsafe { &*key };
        // SAFETY: `k` is a live `&Key`; `cache_key` upholds the borrow discipline.
        let Some(ckey) = (unsafe { cache_key(k) }) else {
            return StatusClass::Refused; // no subject bytes → fail-closed, never a Hit.
        };

        let now = busbar_substrate::store::now_ms();
        // THE DECISION IS THE VERIFY UNIT'S. It is taken with the ledger's lock and released before
        // the lease is registered (which takes the dispatch-scope lock), so the two locks are never
        // held nested — the scope's reclaim path takes the ledger's lock alone on drop, so ordering
        // cannot deadlock.
        let (outcome, lease) = match FRESHNESS.look_up(ckey.0, &ckey.1, now) {
            busbar_unit_trust::Lookup::Fresh => (VerifyOutcome::Hit, VerifyLease::NONE),
            busbar_unit_trust::Lookup::Follow => (VerifyOutcome::Follow, VerifyLease::NONE),
            busbar_unit_trust::Lookup::Lead => {
                // Register the leadership RELEASE in the dispatch scope so a leader whose dispatch
                // is dropped BEFORE it stores does not wedge followers forever: the reclaim clears
                // the claim when the scope ends (the leak-safety keystone, applied to trust). It is
                // idempotent with `verify_store`, which clears the same claim on the happy path.
                let reclaim = ckey.clone();
                let lease = state
                    .scope
                    .register_lease(Box::new(move || FRESHNESS.release(reclaim.0, &reclaim.1)));
                (VerifyOutcome::Lead, lease)
            }
        };

        if write_verdict(out, outcome, lease) {
            StatusClass::Ok
        } else {
            StatusClass::Refused // null out-slot → fail-closed.
        }
    }))
    .unwrap_or(StatusClass::Fault) // caught panic → fault, never a Hit.
}

/// WIRED `verify_store` → [`busbar_unit_trust::VerifyFreshness::record`]: the LEADER records that it
/// completed a fetch for this subject, marking it fresh for `ttl_secs` and releasing its leadership
/// so the next caller reads a `Hit` rather than re-leading. `ttl_secs == 0` is strict-live
/// (immediately stale again). A null key is `Refused`; a caught panic is `Fault`.
///
/// `_lease` is carried by the ABI and is not consulted: the ledger is keyed by the SUBJECT, which
/// arrives with this call. It indexed a lease->subject map no code path ever read.
pub(crate) extern "C-unwind" fn verify_store(
    host: HostCtx,
    key: *const Key,
    _lease: VerifyLease,
    ttl_secs: u64,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let _state: &HostState = unsafe { recover(host) };
        if key.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: a non-null `key` is a live, initialized `Key` for the call (ABI discipline).
        let k = unsafe { &*key };
        // SAFETY: `k` is a live `&Key`; `cache_key` upholds the borrow discipline.
        let Some(ckey) = (unsafe { cache_key(k) }) else {
            return StatusClass::Refused;
        };
        // The ledger marks the subject verified for `ttl_secs` AND releases this subject's
        // leadership in the one step — so the scope reclaim registered at `verify_lookup` becomes a
        // no-op (idempotent) when it later runs.
        FRESHNESS.record(ckey.0, &ckey.1, ttl_secs, busbar_substrate::store::now_ms());
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault)
}

/// THE ONE READER of the substrate's frozen `reverify::due` (`busbar_substrate::trust::reverify`,
/// re-exported as [`crate::trust::reverify`]) left in this tree: the extracted planes each name the
/// substrate arithmetic themselves, so what funnels through here is the wired [`verify_decide_q`]
/// slot and nothing else. Returns the full [`crate::trust::reverify::Due`] REASON, never a lossy
/// bool. `operator_sync` OUTRANKS the timer, exactly as `due` promises. Reconstructs a minimal
/// ledger/policy because `due` reads only `last_checked_ms` and `ttl_ms`.
pub(crate) fn verify_decide_due(
    last_checked_ms: Option<u64>,
    ttl_ms: u64,
    now_ms: u64,
    operator_sync: bool,
) -> crate::trust::reverify::Due {
    let ledger = crate::trust::reverify::Ledger {
        last_checked_ms,
        ..Default::default()
    };
    let policy = crate::trust::reverify::Policy {
        ttl_ms,
        recovery_backoff_ms: 0,
    };
    crate::trust::reverify::due(&ledger, &policy, now_ms, operator_sync)
}

/// WIRED `verify_decide` → [`verify_decide_due`]: the STATELESS freshness DECISION over a
/// [`VerifyQuery`] (the plane's own `last_checked_ms` + present flag, `ttl_ms`, `now_ms`). No host
/// state is touched — the plane's `VerifyGate` keeps its ledger, coalescing and await; only the
/// `reverify::due` arithmetic crosses here. Marshals the FULL [`crate::trust::reverify::Due`] REASON
/// onto its neutral [`VerifyDecision`] mirror (`Fresh` for reuse; a specific reason —
/// `NeverChecked`/`TtlExpired`/`ClockWentBackwards` — when the subject is DUE), so the plane can
/// reconstruct the rich reason it audits rather than a lossy bool. `operator_sync` stays the slot's
/// FALSE default (the only forced-sync caller keeps the compiled-in veneer), so the slot never answers
/// `OperatorSync`. A null query or a caught panic answers the GENERIC
/// [`VerifyDecision::Stale`] — fail-closed (re-verify rather than serve unchecked).
pub(crate) extern "C-unwind" fn verify_decide_q(
    _host: HostCtx,
    query: *const VerifyQuery,
) -> VerifyDecision {
    catch_unwind(AssertUnwindSafe(|| {
        if query.is_null() {
            return VerifyDecision::Stale; // no query → fail-closed (re-verify).
        }
        // SAFETY: a non-null `query` is a live, initialized `VerifyQuery` for the call (ABI).
        let q = unsafe { &*query };
        // `Option<u64>` reconstructed from the marshalled (present flag, value): absent = never checked.
        let last_checked_ms = (q.last_checked_present != 0).then_some(q.last_checked_ms);
        // The full reason, marshalled onto its neutral mirror — `operator_sync = false` (the slot's
        // fixed default: a forced sync is decided plane-side, never over this query).
        verify_decide_due(last_checked_ms, q.ttl_ms, q.now_ms, false).to_verify_decision()
    }))
    .unwrap_or(VerifyDecision::Stale) // caught panic → fail-closed.
}

/// WIRED `approval_redeem_q` → [`crate::plane::approvals::SpentTokenLedger::spend`], over a richer
/// [`ApprovalQuery`]: it spends against the seal's OWN `expires_at` and the caller's `now` rather
/// than recomputing a default TTL. `Ok` iff this is the FIRST redemption; `Refused` when already
/// spent OR the ledger could not answer ( a ledger that cannot say "already spent" must not be read
/// as "not spent"); a null query is `Refused` and a caught panic is `Fault`.
// A plane's completion arm calls this ABI slot directly, so it is `pub`. It derefs the raw
// `*const ApprovalQuery` the ABI dictates under the audited recovery invariant, and cannot be marked
// `unsafe` without changing the registered fn-pointer type — so the deref lint is allowed here
// exactly as at every other host-call slot.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C-unwind" fn approval_redeem_q(
    host: HostCtx,
    query: *const ApprovalQuery,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let state: &HostState = unsafe { recover(host) };
        if query.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: a non-null `query` is a live, initialized `ApprovalQuery` for the call (ABI).
        let q = unsafe { &*query };
        // SAFETY: `(key_ptr, key_len)` upholds the borrow discipline.
        let Some(nonce) = (unsafe { subject(q.key_ptr, q.key_len) }) else {
            return StatusClass::Refused;
        };
        if state
            .app
            .spent_token_ledger
            .spend(&nonce, q.expires_at, q.now)
        {
            StatusClass::Ok // first redemption, against the seal's own expiry.
        } else {
            StatusClass::Refused // already spent, or the ledger could not answer (fail-closed).
        }
    }))
    .unwrap_or(StatusClass::Fault)
}

/// WIRED `drift_quarantine` → [`crate::plane::quarantine::settle`]: settle the durable demotion
/// record for a counterparty a caller just took a live observation of, so the disposition outlives
/// the process that noticed it. The CALLER's disposition rides in [`Key::drift_state`], and the one
/// settle rule is the primitive's. The write is fire-and-forget there (the disposition is already in
/// force in-process; a store hiccup costs durability, not the refusal), so a clean call is `Ok`. A
/// null key is `Refused`; a caught panic is `Fault`.
pub(crate) extern "C-unwind" fn drift_quarantine(host: HostCtx, key: *const Key) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let state: &HostState = unsafe { recover(host) };
        if key.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: a non-null `key` is a live, initialized `Key` for the call (ABI discipline).
        let k = unsafe { &*key };
        // SAFETY: `k` is a live `&Key`; `subject` upholds the borrow discipline.
        let Some(subject) = (unsafe { subject(k.key_ptr, k.key_len) }) else {
            return StatusClass::Refused;
        };
        // The caller's disposition, read ONLY when `size` proves the field was written; a predating
        // sender (or an unknown value) falls back to the demote-only `Quarantined`.
        let settle_state =
            trust_state_from_u8(read_sized_field!(k, k.size, Key, drift_state).unwrap_or(0));
        // THE ONE settle rule, stated on the primitive: `Quarantined` records the demotion,
        // `Approved` clears it, and every other disposition leaves the row as it is.
        crate::plane::quarantine::settle(&state.app.demotion_record, &subject, settle_state);
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault)
}

/// Settle a drift disposition for `subject` through the host `drift_quarantine` vtable slot — the SAFE
/// wrapper a core plane call site uses to reach the slot without naming the core-private
/// [`DemotionRecord`](crate::plane::quarantine::DemotionRecord) an extracted plane could not hold
/// (the [`card_sign_over`](crate::plane_host::card_sign_over) pattern applied to drift). It marshals
/// `state` into [`Key::drift_state`] and lets the slot pull the demotion store host-side, so the
/// caller passes only the subject bytes and its disposition. Returns whether the slot answered `Ok`;
/// the settle is fire-and-forget at the primitive, so the caller may treat a non-`Ok` as a durability
/// miss, not a refusal. Opens its own [`DispatchScope`] — the drift settle registers no host handle,
/// so which arena reclaims is immaterial.
// Reached by the MCP plane's verify-on-call/admin settle sites via the `EngineHost::quarantine_settle`
// method (the core impl is always compiled), so it is a plain fn with a dead-code allow rather than a
// feature gate — it must exist for the trait impl even when no plane is compiled in.
#[allow(dead_code)]
pub fn quarantine_settle_over(
    app: &crate::state::App,
    subject: &str,
    state: crate::trust::TrustState,
) -> bool {
    let scope = crate::plane_host::DispatchScope::new();
    crate::plane_host::with_borrowed_host(app, &scope, |host, vt| {
        let key = Key {
            size: core::mem::size_of::<Key>() as u32,
            version: POD_VERSION,
            _reserved: 0,
            scope: 0,
            _reserved2: 0,
            key_ptr: subject.as_ptr(),
            key_len: subject.len(),
            drift_state: trust_state_u8(state),
        };
        (vt.drift_quarantine
            .expect("drift_quarantine is a wired slot"))(host, &key as *const Key)
            == StatusClass::Ok
    })
}

/// WIRED `approval_redeem` → [`crate::plane::approvals::SpentTokenLedger::spend`]: redeem a one-time
/// approval (the [`Key`] bytes are the sealed nonce) against the shared spent-approval ledger, at a
/// default TTL. Same fail-closed reading as [`approval_redeem_q`]: `Ok` only on the FIRST
/// redemption, `Refused` when already spent OR the ledger could not answer, `Fault` on a panic.
pub(crate) extern "C-unwind" fn approval_redeem(host: HostCtx, key: *const Key) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let state: &HostState = unsafe { recover(host) };
        if key.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: a non-null `key` is a live, initialized `Key` for the call (ABI discipline).
        let k = unsafe { &*key };
        // SAFETY: `k` is a live `&Key`; `subject` upholds the borrow discipline.
        let Some(nonce) = (unsafe { subject(k.key_ptr, k.key_len) }) else {
            return StatusClass::Refused;
        };
        let now = busbar_substrate::store::now();
        let expires_at = now.saturating_add(crate::plane::approvals::DEFAULT_TTL_SECS);
        if state.app.spent_token_ledger.spend(&nonce, expires_at, now) {
            StatusClass::Ok // first redemption.
        } else {
            StatusClass::Refused // already spent, or the ledger could not answer (fail-closed).
        }
    }))
    .unwrap_or(StatusClass::Fault)
}

/// The ABI's OWN NUMBERING for a registration state, carried in
/// [`CounterpartyRef::registration_state`] and [`Key::drift_state`]. What each state MEANS is
/// [`RegistrationState`]'s; this module is the one place the two are spelled against each other,
/// because it is the only place the POD is read.
mod reg_state {
    pub(super) const PENDING: u8 = 1;
    pub(super) const APPROVED: u8 = 2;
    pub(super) const QUARANTINED: u8 = 3;
    pub(super) const SUSPENDED: u8 = 4;
    pub(super) const FAILED: u8 = 5;
}

/// Marshal a [`crate::trust::TrustState`] into [`Key::drift_state`] — the same [`reg_state`]
/// numbering the fact path decodes, so a settled drift and an asserted registration are one
/// vocabulary. Always compiled (`quarantine_settle_over` needs it under any feature set), so a
/// dead-code allow replaces the former `plane-mcp` gate. The inverse of [`trust_state_from_u8`].
#[allow(dead_code)]
pub(crate) fn trust_state_u8(state: crate::trust::TrustState) -> u8 {
    use crate::trust::TrustState;
    match state {
        TrustState::Pending => reg_state::PENDING,
        TrustState::Approved => reg_state::APPROVED,
        TrustState::Quarantined => reg_state::QUARANTINED,
        TrustState::Suspended => reg_state::SUSPENDED,
        TrustState::Error => reg_state::FAILED,
    }
}

/// Reconstruct a [`crate::trust::TrustState`] from [`Key::drift_state`]. `0`/absent and any unknown
/// value fail SAFE to [`crate::trust::TrustState::Quarantined`]. The settle path's safe value is
/// NOT the fact path's ([`asserted_facts`] reads an unnamable state as
/// [`RegistrationState::Unknown`], which refuses): a drift nobody could name must still be WRITTEN,
/// and a registration nobody could name must not SERVE.
fn trust_state_from_u8(v: u8) -> crate::trust::TrustState {
    use crate::trust::TrustState;
    match v {
        reg_state::PENDING => TrustState::Pending,
        reg_state::APPROVED => TrustState::Approved,
        reg_state::QUARANTINED => TrustState::Quarantined,
        reg_state::SUSPENDED => TrustState::Suspended,
        reg_state::FAILED => TrustState::Error,
        _ => TrustState::Quarantined,
    }
}

/// THE ONE POD -> CONTRACT TRANSLATION of the asserted fact tail, read through the sized-struct
/// guard so the decision never sees a raw byte. `None` when the sender wrote no tail (bit 0 of
/// `fact_flags` clear, or a `size` too short), which the decision reads as "nothing asserted".
/// Every byte this build cannot name decodes to the value the ABI's own field docs define as
/// absent — which passes for the three outcome bytes and REFUSES for the registration state.
fn asserted_facts(cp: &CounterpartyRef) -> Option<CounterpartyFacts> {
    let written =
        read_sized_field!(cp, cp.size, CounterpartyRef, fact_flags).is_some_and(|f| f & 0x01 != 0);
    if !written {
        return None;
    }
    Some(CounterpartyFacts {
        // STEP 1 — `0` not-live, `1` live, `2` no-principal (the honest ungoverned `None`).
        liveness: match read_sized_field!(cp, cp.size, CounterpartyRef, identity_live).unwrap_or(0)
        {
            0 => Liveness::NotLive,
            2 => Liveness::NoPrincipal,
            _ => Liveness::Live,
        },
        // STEP 2 — `0` all held, `1` not-granted, `2` egress-denied.
        grant: match read_sized_field!(cp, cp.size, CounterpartyRef, grant_outcome).unwrap_or(0) {
            1 => Grant::NotGranted,
            2 => Grant::EgressDenied,
            _ => Grant::Held,
        },
        // STEP 3a — the lifecycle state, in the one numbering `reg_state` names.
        registration: match read_sized_field!(cp, cp.size, CounterpartyRef, registration_state)
            .unwrap_or(0)
        {
            reg_state::PENDING => RegistrationState::Pending,
            reg_state::APPROVED => RegistrationState::Approved,
            reg_state::QUARANTINED => RegistrationState::Quarantined,
            reg_state::SUSPENDED => RegistrationState::Suspended,
            reg_state::FAILED => RegistrationState::Failed,
            _ => RegistrationState::Unknown,
        },
        // STEP 3b — `0` no-capability, `1` serves, `2` drifted, `3` unobservable.
        artifact: match read_sized_field!(cp, cp.size, CounterpartyRef, artifact_outcome)
            .unwrap_or(0)
        {
            1 => Artifact::Serves,
            2 => Artifact::Drifted,
            3 => Artifact::Unobservable,
            _ => Artifact::NotAsked,
        },
        // STEP 4 — the two generations, compared by the decision and not here.
        generation_admitted: read_sized_field!(cp, cp.size, CounterpartyRef, generation_admitted)
            .unwrap_or(0),
        generation_live: read_sized_field!(cp, cp.size, CounterpartyRef, generation_live)
            .unwrap_or(0),
    })
}

/// THE BOOKS' OWN DISPOSITION as a contract verdict: a demotion on record is
/// [`Verdict::Quarantined`], a null/empty identity is [`Verdict::Denied`] (nothing to look up), and
/// anything else is [`Verdict::Allow`] — a CEILING, never a pass; the rule is the unit's.
fn standing(state: &HostState, cp: &CounterpartyRef) -> Verdict {
    // SAFETY: `cp` is a live `&CounterpartyRef`; `subject` upholds the borrow discipline.
    let Some(subject) = (unsafe { subject(cp.ref_ptr, cp.ref_len) }) else {
        return Verdict::Denied; // no identity -> fail-closed.
    };
    let quarantined = state
        .app
        .demotion_record
        .list()
        .iter()
        .any(|row| row.server == subject);
    if quarantined {
        Verdict::Quarantined
    } else {
        Verdict::Allow
    }
}

/// The RETURN half of the one translation: the decided [`Verdict`] on the ABI's [`TrustVerdict`].
/// Total by construction, so no verdict can fall through to a permissive default.
fn verdict_pod(verdict: Verdict) -> TrustVerdict {
    match verdict {
        Verdict::Allow => TrustVerdict::Allow,
        Verdict::Quarantined => TrustVerdict::Quarantined,
        Verdict::Denied => TrustVerdict::Denied,
        Verdict::NeedsApproval => TrustVerdict::NeedsApproval,
        Verdict::IdentityNotLive => TrustVerdict::IdentityNotLive,
        Verdict::NotGranted => TrustVerdict::NotGranted,
        Verdict::EgressDenied => TrustVerdict::EgressDenied,
        Verdict::ArtifactDrifted => TrustVerdict::ArtifactDrifted,
        Verdict::GenerationMoved => TrustVerdict::GenerationMoved,
    }
}

/// WIRED `trust_evaluate` -> the admission-time verdict for a counterparty, DECIDED BY THE VERIFY
/// UNIT (`busbar_unit_trust::counterparty::evaluate`, which owns the ceiling rule and the ordered
/// fold). This slot reads the POD and nothing else. A null POD, or a caught panic, is
/// [`TrustVerdict::Denied`] — trust fails closed.
pub(crate) extern "C-unwind" fn trust_evaluate(
    host: HostCtx,
    counterparty: *const CounterpartyRef,
) -> TrustVerdict {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let state: &HostState = unsafe { recover(host) };
        if counterparty.is_null() {
            return TrustVerdict::Denied;
        }
        // SAFETY: a non-null `counterparty` is a live, initialized `CounterpartyRef` for the call.
        let cp = unsafe { &*counterparty };
        verdict_pod(busbar_unit_trust::counterparty::evaluate(
            standing(state, cp),
            asserted_facts(cp).as_ref(),
        ))
    }))
    .unwrap_or(TrustVerdict::Denied) // caught panic -> denied, never allowed.
}

#[cfg(test)]
#[path = "tests/trust_tests.rs"]
mod tests;
