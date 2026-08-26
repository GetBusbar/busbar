// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The TRUST family of the plane host-vtable, wired over busbar-core's real trust/verify primitives.
//!
//! This module fills five capability slots the Phase-1 scaffold left stubbed, each phrased over the
//! NEUTRAL counterparty (an MCP server OR an A2A agent — the code never branches on which):
//!
//! | slot | primitive | fail-closed value |
//! |---|---|---|
//! | [`verify_lookup`] | the host-side verify freshness cache + single-flight leadership | non-`Ok` status (never a spurious `Hit`) |
//! | [`verify_store`] | the same cache — the leader records a completed fetch | non-`Ok` status |
//! | [`drift_quarantine`] | [`crate::plane::quarantine`] durable demotion record | `Fault`/`Refused` |
//! | [`approval_redeem`] | [`crate::plane::approvals`] spent-approval ledger | `Refused` (already-spent OR store error) |
//! | [`trust_evaluate`] | the durable drift/quarantine trust state | [`TrustVerdict::Denied`] |
//!
//! ## The design split (why the cache lives host-side)
//!
//! The HOST owns the verify CACHE and the single-flight COORDINATION; the PLANE does the fetch. So
//! [`verify_lookup`] answers `Hit` when a fresh entry exists, else designates this caller `Lead` (it
//! fetches, then calls [`verify_store`]) or `Follow` (it awaits the leader's store). The real
//! `crate::trust::verify::VerifyGate` is the async, clock-independent single-flight coalescer that
//! rides the `App`; it stamps the plane's ledger and bumps a per-subject epoch but stores no verdict
//! digest of its own. The synchronous `#[repr(C)]` ABI cannot drive that async coalescer, so the
//! host-side FRESHNESS cache here is the faithful synchronous scaffold for it. Because
//! [`VerifyStoreFn`](busbar_plugin::hot::host::VerifyStoreFn) carries no digest, the cache is
//! freshness-only: a `Hit` reports "verified within ttl", never a cached payload, and its
//! `digest_ptr` is null — exactly what a `VerifyGate` that stores no verdict can promise.
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
//! * `trust_evaluate` consults the real durable drift state (the demotion records) and maps it to a
//!   verdict; the FULL ordered validator (`crate::trust::validate::validate_request` —
//!   identity → grant → artifact → generation) is wired once the counterparty→registration
//!   resolution (a registry lookup that turns opaque identity bytes into an `Approval`/`Sighting`)
//!   lands. Until then an un-demoted counterparty is `Allow` and a demoted one is `Quarantined`.
//! * The freshness cache is a module-global here rather than an `App` field, so `verify_store` →
//!   `verify_lookup` persists across dispatch invocations without reshaping `App`. Phase 2 moves it
//!   onto the `App` beside `mcp_verify` and keys it to the real `VerifyGate` epochs for cross-node
//!   coordination.

use super::{recover, HostState};
use busbar_plugin::hot::host::HostCtx;
use busbar_plugin::hot::{
    ApprovalQuery, CounterpartyRef, Key, StatusClass, TrustVerdict, VerifyDecision, VerifyLease,
    VerifyOutcome, VerifyQuery, VerifyVerdict, POD_VERSION,
};
use busbar_plugin::read_sized_field;
use core::mem::MaybeUninit;
use std::collections::{HashMap, HashSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Mutex, OnceLock};

/// A cache key: the [`Key`]'s host-defined scope plus a copy of its opaque bytes. Owned, so it can
/// live in the map past the borrowed range the call handed us.
type CacheKey = (u32, Vec<u8>);

/// The host-side verify FRESHNESS cache and single-flight leadership registry — the state the design
/// split places host-side. Freshness-only (the store ABI carries no digest): a subject is "verified"
/// for a ttl after a [`verify_store`], and at most one caller leads the re-fetch of a stale subject.
#[derive(Default)]
struct VerifyCache {
    /// `key` → the wall-clock millisecond after which the verification is stale. Written by the
    /// original [`verify_store`] (opaque baked expiry); read by the original [`verify_lookup`].
    fresh: HashMap<CacheKey, u64>,
    /// The keys with an ACTIVE leader fetching right now (single-flight: a second caller follows).
    leading: HashSet<CacheKey>,
    /// A leadership lease's raw id → the key it leads, so [`verify_store`] can resolve the lease the
    /// plane hands back to the subject it completed.
    inflight: HashMap<u64, CacheKey>,
}

/// The process-wide verify cache. A module-global (not an `App` field) so `store` → `lookup`
/// persists across dispatch invocations without reshaping `App`; see the Phase-2 note in the header.
fn cache() -> &'static Mutex<VerifyCache> {
    static CACHE: OnceLock<Mutex<VerifyCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(VerifyCache::default()))
}

/// Poison-recovering lock, the same discipline every request-path lock in this process takes: a
/// panic mid-update must not wedge the cache for every later call.
fn lock_cache() -> std::sync::MutexGuard<'static, VerifyCache> {
    cache().lock().unwrap_or_else(|e| e.into_inner())
}

/// Copy a [`Key`]'s owned cache key from its borrowed range, or `None` when the range is null/empty —
/// an unusable key is fail-closed at the call site (a verify with no subject is never a `Hit`).
///
/// # Safety
/// `key` must be a live `&Key` whose `(key_ptr, key_len)`, when non-null, borrows an initialized
/// range for the call (the ABI's borrow discipline).
unsafe fn cache_key(key: &Key) -> Option<CacheKey> {
    // SAFETY: `(key_ptr, key_len)` upholds the borrow discipline (delegated to `cache_key_raw`).
    unsafe { cache_key_raw(key.scope, key.key_ptr, key.key_len) }
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

        let now = crate::store::now_ms();
        // Decide the outcome under the cache lock, RELEASING it before registering a lease (which
        // takes the dispatch-scope lock) so the two locks are never held nested — the scope's
        // reclaim path (on drop) takes the cache lock alone, so ordering cannot deadlock.
        enum Decision {
            Hit,
            Follow,
            Lead,
        }
        let decision = {
            let mut c = lock_cache();
            if c.fresh.get(&ckey).is_some_and(|&exp| now < exp) {
                Decision::Hit
            } else if c.leading.insert(ckey.clone()) {
                // We are the first to reach a stale/unseen subject: we lead the fetch.
                Decision::Lead
            } else {
                // A leader is already fetching this subject.
                Decision::Follow
            }
        };

        let (outcome, lease) = match decision {
            Decision::Hit => (VerifyOutcome::Hit, VerifyLease::NONE),
            Decision::Follow => (VerifyOutcome::Follow, VerifyLease::NONE),
            Decision::Lead => {
                // Register the leadership lease in the dispatch scope so a leader whose dispatch is
                // dropped BEFORE it stores does not wedge followers forever: the reclaim clears the
                // leadership when the scope ends (the leak-safety keystone, applied to trust). It
                // is idempotent with `verify_store`, which clears the same entry on the happy path.
                let reclaim_key = ckey.clone();
                let lease = state.scope.register_lease(Box::new(move || {
                    let mut c = lock_cache();
                    c.leading.remove(&reclaim_key);
                    c.inflight.retain(|_, v| v != &reclaim_key);
                }));
                lock_cache().inflight.insert(lease.0, ckey);
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

/// WIRED `verify_store` → the host-side verify freshness cache: the LEADER records that it completed
/// a fetch for this subject, marking it fresh for `ttl_secs` and releasing its leadership so the next
/// caller reads a `Hit` rather than re-leading. `ttl_secs == 0` is strict-live (immediately stale
/// again). A null key is `Refused`; a caught panic is `Fault`.
pub(crate) extern "C-unwind" fn verify_store(
    host: HostCtx,
    key: *const Key,
    lease: VerifyLease,
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
        let expires = crate::store::now_ms().saturating_add(ttl_secs.saturating_mul(1_000));
        let mut c = lock_cache();
        c.fresh.insert(ckey.clone(), expires);
        // Release this subject's leadership: clear it, and drop the lease→subject mapping. The scope
        // reclaim registered at `verify_lookup` becomes a no-op (idempotent) when it later runs.
        c.leading.remove(&ckey);
        c.inflight.remove(&lease.0);
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault)
}

/// Copy an owned cache key from a borrowed `(scope, ptr, len)` range, or `None` when null/empty — the
/// shared body of [`cache_key`] (over a [`Key`]) and the [`VerifyQuery`]/[`ApprovalQuery`] paths.
///
/// # Safety
/// `(ptr, len)`, when non-null, borrow a live, initialized range for the call.
unsafe fn cache_key_raw(scope: u32, ptr: *const u8, len: usize) -> Option<CacheKey> {
    if ptr.is_null() || len == 0 {
        return None;
    }
    // SAFETY: a non-null `(ptr, len)` borrows a live, initialized range for the call.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    Some((scope, bytes.to_vec()))
}

/// THE reverify-`due` REACH, wrapped once — returns the full [`crate::trust::reverify::Due`] REASON
/// (never a lossy bool). The compiled-in bool veneer that once collapsed it for the MCP plane is gone
/// with that plane's `VerifyGate`, which now lives in the neutral substrate and names
/// `reverify::due` directly; what remains funnels through here. The plane's a2a
/// re-verify job (`crate::a2a::verify::reverify_once`) and the operator `sync` verb
/// (`crate::a2a::verbs::sync`) funnel through here, so the a2a plane never reaches
/// `crate::trust::reverify::due` itself post-extraction — only this host veneer does. `operator_sync`
/// OUTRANKS the timer (an operator who asks does not wait): it is unconditionally [`Due::OperatorSync`],
/// exactly as `due` promises. Reconstructs a minimal ledger/policy because `due` reads only
/// `last_checked_ms` and `ttl_ms` — `recovery_backoff_ms` and the drift counters never enter the
/// freshness decision.
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

/// Drive the WIRED [`verify_decide_q`] slot over a [`HostCtx`] the caller ALREADY holds, returning the
/// reconstructed [`crate::trust::reverify::Due`] — the a2a re-verify job's inversion of the compiled-in
/// [`verify_decide_due`] veneer onto the host seam (the [`super::clock_now_secs_via`] pattern applied to
/// verify-freshness). It marshals the freshness inputs into a [`VerifyQuery`], calls the slot against
/// the caller's live host, and maps the returned [`VerifyDecision`] back to the rich reason via
/// [`Due::from_verify_decision`](crate::trust::reverify::Due::from_verify_decision) — BYTE-IDENTICAL to
/// the veneer for every genuine input.
///
/// `operator_sync` is NOT marshalled (the slot keeps its false default): a forced sync OUTRANKS
/// the timer and is decided HERE (unconditionally [`crate::trust::reverify::Due::OperatorSync`], exactly
/// as `reverify::due` promises) rather than crossing the seam. A SAFE wrapper — building the vtable and
/// driving the slot's safe fn-pointer needs no `unsafe` (busbar-core denies it elsewhere).
#[cfg(feature = "plane-a2a")]
pub(crate) fn verify_decide_due_via(
    host: HostCtx,
    last_checked_ms: Option<u64>,
    ttl_ms: u64,
    now_ms: u64,
    operator_sync: bool,
) -> crate::trust::reverify::Due {
    // A forced sync is unconditionally due, and the slot does not carry `operator_sync`; decide it here.
    if operator_sync {
        return crate::trust::reverify::Due::OperatorSync;
    }
    let vtable = super::build_plane_host_vtable();
    let q = VerifyQuery {
        size: core::mem::size_of::<VerifyQuery>() as u32,
        version: POD_VERSION,
        _reserved: 0,
        last_checked_present: u32::from(last_checked_ms.is_some()),
        _reserved2: 0,
        ttl_ms,
        now_ms,
        last_checked_ms: last_checked_ms.unwrap_or(0),
    };
    let decision = (vtable.verify_decide.expect("verify_decide is a wired slot"))(
        host,
        &q as *const VerifyQuery,
    );
    crate::trust::reverify::Due::from_verify_decision(decision)
}

/// WIRED `approval_redeem_q` → [`crate::plane::approvals::SpentTokenLedger::spend`], over a richer
/// [`ApprovalQuery`]. Identical to [`approval_redeem`] except it spends against the seal's OWN
/// `expires_at` and the caller's `now` (marshalled in the query) rather than recomputing a default
/// TTL — the behavior-identity the `mcp::callerask` call site requires. `Ok` iff this is the FIRST
/// redemption; `Refused` when already spent OR the ledger could not answer (fail-closed). A null query
/// is `Refused`; a caught panic is `Fault`.
// The MCP plane's `callerask` completion arm calls this ABI slot directly, so it is `pub`. It takes
// the raw `*const ApprovalQuery` the plane ABI dictates and derefs it under the audited recovery
// invariant; it cannot be marked `unsafe` without changing the extern fn-pointer type the slot is
// registered as, so the deref lint is allowed here exactly as at every other host-call slot.
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
        if redeem_approval(&state.app.spent_token_ledger, &nonce, q.expires_at, q.now) {
            StatusClass::Ok // first redemption, against the seal's own expiry.
        } else {
            StatusClass::Refused // already spent, or the ledger could not answer (fail-closed).
        }
    }))
    .unwrap_or(StatusClass::Fault)
}

/// WIRED `drift_quarantine` → [`crate::plane::quarantine::settle`]: settle the durable demotion record
/// for a counterparty a plane just took a live observation of, so the disposition outlives the process
/// that noticed it. The slot carries the CALLER's trust-state in [`Key::drift_state`]: a `Quarantined`
/// observation RECORDS the demotion, an `Approved` one CLEARS it (an operator's remedy, or a clean
/// re-verification) — the one settle rule, so a caller that demotes and a caller that clears reach the
/// same books. A sender that predates the field (guarded out by `size`) settles the pre-extension
/// demote-only [`crate::trust::TrustState::Quarantined`]. The write is fire-and-forget at the primitive
/// (the disposition is already in force in-process; a store hiccup costs durability, not the refusal),
/// so a clean call is `Ok`. A null key is `Refused`; a caught panic is `Fault`.
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
        let settle_state = trust_state_from_u8(read_sized_field!(k, Key, drift_state).unwrap_or(0));
        // THE ONE settle rule, written once: `Quarantined` records the demotion, `Approved` clears it.
        quarantine_drift(&state.app.demotion_record, &subject, settle_state);
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault)
}

/// THE ONE drift-settle body — the compiled-in veneer both the extern-C [`drift_quarantine`] slot and
/// the in-process plane (`mcp`'s verify-on-call and the admin trust-view verb) funnel through, the
/// drift analogue of [`redeem_approval`]. Records `state` for `subject` in the durable demotion store:
/// a `Quarantined` observation writes the demotion, an `Approved` one CLEARS it — the one settle rule,
/// written once, so a single call site can never record a demotion the other never clears. The write
/// is fire-and-forget at the primitive (the demotion is already in force in-process; a store hiccup
/// costs durability, not the refusal). NEITHER the extern-C slot nor the plane reimplements the rule.
pub(crate) fn quarantine_drift(
    demotions: &crate::plane::quarantine::DemotionRecord,
    subject: &str,
    state: crate::trust::TrustState,
) {
    crate::plane::quarantine::settle(demotions, subject, state);
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
#[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
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

/// THE ONE redemption body — the compiled-in veneer both approval veneers funnel through, the trust
/// analogue of CLUSTER-1's [`crate::plane_host::scope::DispatchScope::settle_admission`]. Redeem a
/// one-time approval against the shared spent-approval ledger, spending against the seal's OWN
/// `expires_at` and the caller's `now`. `true` iff this is the FIRST redemption; `false` when already
/// spent OR the durable ledger could not answer — [`spend`](crate::plane::approvals::SpentTokenLedger::spend)
/// fails closed on a store error (a ledger that cannot say "already spent" must not be read as "not
/// spent"). The extern-C [`approval_redeem`]/[`approval_redeem_q`] slots map this bool onto the ABI
/// [`StatusClass`]; the in-process plane (`mcp::callerask`) calls it directly — NEITHER reimplements
/// the check-and-record, so the atomic redemption is written once.
pub(crate) fn redeem_approval(
    approvals: &crate::plane::approvals::SpentTokenLedger,
    nonce: &str,
    expires_at: u64,
    now: u64,
) -> bool {
    approvals.spend(nonce, expires_at, now)
}

/// WIRED `approval_redeem` → [`crate::plane::approvals::SpentTokenLedger::spend`]: redeem a one-time
/// approval (the [`Key`] bytes are the sealed state's nonce) against the shared spent-approval
/// ledger. `Ok` iff this is the FIRST redemption; `Refused` when it was already spent OR the durable
/// ledger could not answer — `spend` fails closed on a store error (a ledger that cannot say "already
/// spent" must not be read as "not spent"), and this slot carries that refusal through. A null key is
/// `Refused`; a caught panic is `Fault`.
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
        let now = crate::store::now();
        let expires_at = now.saturating_add(crate::plane::approvals::DEFAULT_TTL_SECS);
        if redeem_approval(&state.app.spent_token_ledger, &nonce, expires_at, now) {
            StatusClass::Ok // first redemption.
        } else {
            StatusClass::Refused // already spent, or the ledger could not answer (fail-closed).
        }
    }))
    .unwrap_or(StatusClass::Fault)
}

/// The neutral mirror of the plane's registration lifecycle state, as marshalled into
/// [`CounterpartyRef::registration_state`] (see the POD field doc). `2` is `Approved` — the only
/// state that serves; every other value is a `NotServing` fact the fold maps to a specific verdict.
mod reg_state {
    pub(super) const PENDING: u8 = 1;
    pub(super) const APPROVED: u8 = 2;
    pub(super) const QUARANTINED: u8 = 3;
    pub(super) const SUSPENDED: u8 = 4;
    pub(super) const FAILED: u8 = 5;
}

/// Marshal a [`crate::trust::TrustState`] into the neutral u8 mirror the drift path carries in
/// [`Key::drift_state`] (the same numbering [`reg_state`] names). Always compiled (the
/// `EngineHost::quarantine_settle` core impl reaches `quarantine_settle_over`, which needs it, under
/// any feature set), so a dead-code allow replaces the former `plane-mcp` gate. The inverse of
/// [`trust_state_from_u8`]; the drift call sites use it to hand the slot the CALLER's disposition.
#[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
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

/// Reconstruct a [`crate::trust::TrustState`] from the neutral u8 mirror in [`Key::drift_state`].
/// `0`/absent (a sender that predates the field, guarded out by `size`) and any unknown value fail
/// SAFE to [`crate::trust::TrustState::Quarantined`] — the pre-extension demote-only disposition, so
/// a drift the caller could not name still records rather than silently clearing.
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

/// The legacy `trust_evaluate` disposition — the durable DRIFT map — used as the forward-compat
/// fallback for a sender that predates the fact tail (bit 0 of `fact_flags` clear, or a `size` too
/// short to reach it). A counterparty with a durable demotion on record is
/// [`TrustVerdict::Quarantined`]; otherwise [`TrustVerdict::Allow`]; a null/empty identity is
/// [`TrustVerdict::Denied`] (fail-closed). Preserves the exact pre-enrichment behaviour.
fn legacy_drift_verdict(state: &HostState, cp: &CounterpartyRef) -> TrustVerdict {
    // SAFETY: `cp` is a live `&CounterpartyRef`; `subject` upholds the borrow discipline.
    let Some(subject) = (unsafe { subject(cp.ref_ptr, cp.ref_len) }) else {
        return TrustVerdict::Denied; // no identity → fail-closed.
    };
    let quarantined = state
        .app
        .demotion_record
        .list()
        .iter()
        .any(|row| row.server == subject);
    if quarantined {
        TrustVerdict::Quarantined
    } else {
        TrustVerdict::Allow
    }
}

/// FOLD the plane's marshalled per-step FACTS into a [`TrustVerdict`] in the EXACT order of
/// `crate::trust::validate::validate_request` (identity → grant → artifact → generation) — the
/// `Signal`→`classify` precedent applied to trust. The plane computes each step's fact (its
/// `validate_request` runs plane-side over its own registry); the host reproduces the ORDER and the
/// verdict MAPPING, so a refusal keeps its SPECIFIC step rather than collapsing to `Denied`. Proven
/// the inverse of the plane's `Refusal` disposition by `trust_evaluate_folds_validate_request_order`.
fn fold_facts(cp: &CounterpartyRef) -> TrustVerdict {
    // ── 1. IDENTITY ──────────────────────────────────────────────────────────────────────────────
    // `0` not-live, `1` live, `2` no-principal (honest ungoverned `None` — passes identity).
    if read_sized_field!(cp, CounterpartyRef, identity_live).unwrap_or(0) == 0 {
        return TrustVerdict::IdentityNotLive;
    }
    // ── 2. GRANT ─────────────────────────────────────────────────────────────────────────────────
    match read_sized_field!(cp, CounterpartyRef, grant_outcome).unwrap_or(0) {
        1 => return TrustVerdict::NotGranted,
        2 => return TrustVerdict::EgressDenied,
        _ => {}
    }
    // ── 3a. REGISTRATION STATE ───────────────────────────────────────────────────────────────────
    // Only `Approved` serves; every other state is a `NotServing` refusal mapped to the verdict that
    // names its remedy (quarantine/failed → re-establish; pending → redeem approval; suspended →
    // operator denial; absent/unknown → fail closed).
    match read_sized_field!(cp, CounterpartyRef, registration_state).unwrap_or(0) {
        reg_state::APPROVED => {}
        reg_state::QUARANTINED | reg_state::FAILED => return TrustVerdict::Quarantined,
        reg_state::PENDING => return TrustVerdict::NeedsApproval,
        reg_state::SUSPENDED => return TrustVerdict::Denied,
        _ => return TrustVerdict::Denied,
    }
    // ── 3b. ARTIFACT ─────────────────────────────────────────────────────────────────────────────
    // `2` drifted, `3` unobservable — both are the plane's `ARTIFACT_DRIFTED` refusal word.
    match read_sized_field!(cp, CounterpartyRef, artifact_outcome).unwrap_or(0) {
        2 | 3 => return TrustVerdict::ArtifactDrifted,
        _ => {}
    }
    // ── 4. GENERATION ────────────────────────────────────────────────────────────────────────────
    let admitted = read_sized_field!(cp, CounterpartyRef, generation_admitted).unwrap_or(0);
    let live = read_sized_field!(cp, CounterpartyRef, generation_live).unwrap_or(0);
    if admitted != live {
        return TrustVerdict::GenerationMoved;
    }
    TrustVerdict::Allow
}

/// WIRED `trust_evaluate` → the admission-time trust verdict for a counterparty. When the plane wrote
/// the fact tail (bit 0 of `fact_flags`, proven present by the sized-struct guard), the host FOLDS
/// those facts in `validate_request`'s exact order via [`fold_facts`] and reproduces the plane's
/// disposition (identity → grant → artifact → generation, mapping each refusal to its specific
/// verdict). A sender that predates the tail falls back to [`legacy_drift_verdict`] (the durable
/// drift map). A null POD, or a caught panic, is [`TrustVerdict::Denied`] — trust fails closed.
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
        // The fact tail is authoritative only when the sender WROTE it (sized guard + flag bit 0);
        // otherwise the legacy drift map is the faithful pre-enrichment disposition.
        let facts_written =
            read_sized_field!(cp, CounterpartyRef, fact_flags).is_some_and(|f| f & 0x01 != 0);
        if facts_written {
            fold_facts(cp)
        } else {
            legacy_drift_verdict(state, cp)
        }
    }))
    .unwrap_or(TrustVerdict::Denied) // caught panic → denied, never allowed.
}

#[cfg(test)]
#[path = "tests/trust_tests.rs"]
mod tests;
