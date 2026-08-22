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

/// THE ONE verify-freshness DECISION body — the compiled-in veneer the plane's
/// [`crate::trust::verify::VerifyGate`] calls in-process AND the extern-C [`verify_decide_q`] slot
/// funnels through, the verify analogue of [`redeem_approval`] and CLUSTER-1's
/// [`crate::plane_host::scope::DispatchScope::settle_admission`]. Returns whether `subject` is DUE to
/// re-verify, reproducing `crate::trust::reverify::due(.., operator_sync = false).should_check()`
/// EXACTLY — by CALLING `reverify::due` itself, so the veneer can never drift from the arithmetic.
/// Due (`true`) covers never-checked, ttl-elapsed (reaching the ttl is due), and clock-went-backwards
/// (treated as due, never as permanent freshness); `false` means fresh — reuse the snapshot.
///
/// The host owns NO freshness cache and NO single-flight. The plane keeps its OWN ledger, its
/// coalescing (the epoch/leadership), and its async await entirely plane-side — only this pure
/// arithmetic crosses the seam, over the plane's authoritative `last_checked_ms`.
pub(crate) fn verify_decide(last_checked_ms: Option<u64>, ttl_ms: u64, now_ms: u64) -> bool {
    verify_decide_due(last_checked_ms, ttl_ms, now_ms, false).should_check()
}

/// THE reverify-`due` REACH, wrapped once — the richer sibling of [`verify_decide`] that returns the
/// full [`crate::trust::reverify::Due`] REASON rather than collapsing it to a bool. The plane's a2a
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

/// WIRED `verify_decide` → [`verify_decide`]: the STATELESS freshness DECISION over a [`VerifyQuery`]
/// (the plane's own `last_checked_ms` + present flag, `ttl_ms`, `now_ms`). No host state is touched —
/// the plane's `VerifyGate` keeps its ledger, coalescing and await; only the `reverify::due`
/// arithmetic crosses here. Returns [`VerifyDecision::Stale`] when the subject is DUE (must re-fetch)
/// and [`VerifyDecision::Fresh`] when the recorded observation may be reused. A null query or a caught
/// panic answers `Stale` — fail-closed (re-verify rather than serve unchecked).
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
        if verify_decide(last_checked_ms, q.ttl_ms, q.now_ms) {
            VerifyDecision::Stale
        } else {
            VerifyDecision::Fresh
        }
    }))
    .unwrap_or(VerifyDecision::Stale) // caught panic → fail-closed.
}

/// WIRED `approval_redeem_q` → [`crate::plane::approvals::PlaneApprovals::spend`], over a richer
/// [`ApprovalQuery`]. Identical to [`approval_redeem`] except it spends against the seal's OWN
/// `expires_at` and the caller's `now` (marshalled in the query) rather than recomputing a default
/// TTL — the behavior-identity the `mcp::callerask` call site requires. `Ok` iff this is the FIRST
/// redemption; `Refused` when already spent OR the ledger could not answer (fail-closed). A null query
/// is `Refused`; a caught panic is `Fault`.
pub(crate) extern "C-unwind" fn approval_redeem_q(
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
        if redeem_approval(&state.app.plane_approvals, &nonce, q.expires_at, q.now) {
            StatusClass::Ok // first redemption, against the seal's own expiry.
        } else {
            StatusClass::Refused // already spent, or the ledger could not answer (fail-closed).
        }
    }))
    .unwrap_or(StatusClass::Fault)
}

/// WIRED `drift_quarantine` → [`crate::plane::quarantine::settle`]: record a durable demotion for a
/// counterparty a plane found DRIFTED, so the quarantine outlives the process that noticed it. The
/// write is fire-and-forget at the primitive (the demotion is already in force in-process; a store
/// hiccup costs durability, not the refusal), so a clean call is `Ok`. A null key is `Refused`; a
/// caught panic is `Fault` — either way the counterparty is treated as untrusted.
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
        // THE ONE settle rule, written once: `Quarantined` records the durable demotion.
        quarantine_drift(
            &state.app.mcp_demotions,
            &subject,
            crate::trust::TrustState::Quarantined,
        );
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
    demotions: &crate::plane::quarantine::PlaneQuarantine,
    subject: &str,
    state: crate::trust::TrustState,
) {
    crate::plane::quarantine::settle(demotions, subject, state);
}

/// THE ONE redemption body — the compiled-in veneer both approval veneers funnel through, the trust
/// analogue of CLUSTER-1's [`crate::plane_host::scope::DispatchScope::settle_admission`]. Redeem a
/// one-time approval against the shared spent-approval ledger, spending against the seal's OWN
/// `expires_at` and the caller's `now`. `true` iff this is the FIRST redemption; `false` when already
/// spent OR the durable ledger could not answer — [`spend`](crate::plane::approvals::PlaneApprovals::spend)
/// fails closed on a store error (a ledger that cannot say "already spent" must not be read as "not
/// spent"). The extern-C [`approval_redeem`]/[`approval_redeem_q`] slots map this bool onto the ABI
/// [`StatusClass`]; the in-process plane (`mcp::callerask`) calls it directly — NEITHER reimplements
/// the check-and-record, so the atomic redemption is written once.
pub(crate) fn redeem_approval(
    approvals: &crate::plane::approvals::PlaneApprovals,
    nonce: &str,
    expires_at: u64,
    now: u64,
) -> bool {
    approvals.spend(nonce, expires_at, now)
}

/// WIRED `approval_redeem` → [`crate::plane::approvals::PlaneApprovals::spend`]: redeem a one-time
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
        if redeem_approval(&state.app.plane_approvals, &nonce, expires_at, now) {
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
        .mcp_demotions
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
mod tests {
    use super::*;
    use crate::plane_host::{recover, with_dispatch_scope, DispatchScope, HostState};
    use busbar_plugin::hot::host::{HostCtx, PlaneHostVtable};
    use busbar_plugin::hot::Key;

    /// Drive the trust slots through the REAL recovery path over a live `App` from the test-support
    /// builder, exactly as the sibling `plane_host` tests do.
    fn with_test_state<R>(f: impl FnOnce(HostCtx, &PlaneHostVtable, &DispatchScope) -> R) -> R {
        let app = crate::test_support::TestApp::new().build();
        with_dispatch_scope(&app, |host, vt| {
            // SAFETY: `host` is the live HostState minted by `with_dispatch_scope`.
            let state: &HostState = unsafe { recover(host) };
            let scope = state.scope;
            f(host, vt, scope)
        })
    }

    /// Build a borrowed `Key` over `bytes` for the duration of `f`.
    fn with_key<R>(scope: u32, bytes: &[u8], f: impl FnOnce(*const Key) -> R) -> R {
        let key = Key {
            size: core::mem::size_of::<Key>() as u32,
            version: POD_VERSION,
            _reserved: 0,
            scope,
            _reserved2: 0,
            key_ptr: bytes.as_ptr(),
            key_len: bytes.len(),
        };
        f(&key as *const Key)
    }

    fn read_lookup(
        host: HostCtx,
        vt: &PlaneHostVtable,
        key: *const Key,
    ) -> (StatusClass, VerifyVerdict) {
        let mut out = MaybeUninit::<VerifyVerdict>::uninit();
        let status = (vt.verify_lookup.unwrap())(host, key, core::ptr::from_mut(&mut out));
        // SAFETY: on `Ok` the out-slot is initialized; the tests only read it on `Ok`.
        let verdict = if status == StatusClass::Ok {
            unsafe { out.assume_init() }
        } else {
            VerifyVerdict {
                size: 0,
                version: 0,
                outcome: VerifyOutcome::Follow,
                _reserved: 0,
                lease: VerifyLease::NONE,
                digest_ptr: core::ptr::null(),
                digest_len: 0,
            }
        };
        (status, verdict)
    }

    #[test]
    fn store_then_lookup_returns_hit() {
        // A subject nobody has verified: the first lookup LEADS the fetch (not a Hit).
        let subject = b"trust-test/store-then-hit/counterparty-A";
        with_test_state(|host, vt, _scope| {
            let (lease_raw, status) = with_key(7, subject, |key| {
                let (status, verdict) = read_lookup(host, vt, key);
                (verdict.lease, status)
            });
            assert_eq!(status, StatusClass::Ok);
            // The leader stores a completed fetch with a long ttl.
            let stored = with_key(7, subject, |key| {
                (vt.verify_store.unwrap())(host, key, lease_raw, 3_600)
            });
            assert_eq!(stored, StatusClass::Ok);
            // Now the SAME subject reads back a fresh Hit.
            let (status, verdict) = with_key(7, subject, |key| read_lookup(host, vt, key));
            assert_eq!(status, StatusClass::Ok);
            assert_eq!(verdict.outcome, VerifyOutcome::Hit, "fresh subject → Hit");
        });
    }

    #[test]
    fn first_lookup_leads_second_follows() {
        // Two lookups of an unseen subject WITHOUT a store between: one leads, the next follows
        // (single-flight — only one caller fetches).
        let subject = b"trust-test/lead-follow/counterparty-B";
        with_test_state(|host, vt, _scope| {
            let first = with_key(9, subject, |key| read_lookup(host, vt, key).1.outcome);
            let second = with_key(9, subject, |key| read_lookup(host, vt, key).1.outcome);
            assert_eq!(first, VerifyOutcome::Lead, "first caller leads the fetch");
            assert_eq!(
                second,
                VerifyOutcome::Follow,
                "a leader is fetching → follow"
            );
        });
    }

    #[test]
    fn verify_lookup_is_fail_closed() {
        with_test_state(|host, vt, _scope| {
            // Null key → Refused (out not written), never a Hit.
            let mut out = MaybeUninit::<VerifyVerdict>::uninit();
            let status =
                (vt.verify_lookup.unwrap())(host, core::ptr::null(), core::ptr::from_mut(&mut out));
            assert_eq!(status, StatusClass::Refused);
            // Null out-slot with a valid key → Refused.
            let status = with_key(1, b"x", |key| {
                (vt.verify_lookup.unwrap())(host, key, core::ptr::null_mut())
            });
            assert_eq!(status, StatusClass::Refused);
        });
    }

    #[test]
    fn verify_store_fail_closed_on_null_key() {
        with_test_state(|host, vt, _scope| {
            let status = (vt.verify_store.unwrap())(host, core::ptr::null(), VerifyLease::NONE, 60);
            assert_eq!(status, StatusClass::Refused);
        });
    }

    /// Build a borrowed `VerifyQuery` with the given freshness inputs (an absent `last_checked_ms`
    /// marshals `last_checked_present = 0`) for `f`.
    fn with_vquery<R>(
        last_checked_ms: Option<u64>,
        ttl_ms: u64,
        now_ms: u64,
        f: impl FnOnce(*const VerifyQuery) -> R,
    ) -> R {
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
        f(&q as *const VerifyQuery)
    }

    /// The boundary cases that pin `reverify::due`'s meaning: never-checked, just-checked/within-ttl
    /// (fresh), the exact-ttl boundary (reaching it is due), ttl-elapsed (due), and clock-backwards
    /// (due, never permanent freshness). `true` = due (re-verify).
    const DUE_CASES: &[(Option<u64>, u64, u64, bool)] = &[
        (None, 1_000, 10_000, true),        // never checked → due
        (Some(5_000), 1_000, 5_000, false), // just checked → fresh
        (Some(5_000), 1_000, 5_999, false), // within ttl → fresh
        (Some(5_000), 1_000, 6_000, true),  // exactly ttl → due
        (Some(5_000), 1_000, 9_000, true),  // ttl elapsed → due
        (Some(5_000), 1_000, 4_000, true),  // clock went backwards → due
    ];

    /// THE VERIFY FAITHFULNESS PROOF: the compiled-in [`verify_decide`] body reproduces the plane's
    /// `reverify::due(..).should_check()` EXACTLY across every boundary case — by construction (it
    /// CALLS `reverify::due`), pinned here so a future refactor that inlines the arithmetic cannot
    /// drift from it. The trust-verify analogue of the breaker's `classify_reproduces_normalize_raw_error`.
    #[test]
    fn verify_decide_reproduces_reverify_due() {
        use crate::trust::reverify::{due, Ledger, Policy};
        for &(last, ttl_ms, now, want) in DUE_CASES {
            let ledger = Ledger {
                last_checked_ms: last,
                ..Ledger::default()
            };
            let policy = Policy {
                ttl_ms,
                recovery_backoff_ms: 0,
            };
            assert_eq!(
                verify_decide(last, ttl_ms, now),
                due(&ledger, &policy, now, false).should_check(),
                "verify_decide must equal reverify::due for last={last:?} now={now}"
            );
            assert_eq!(
                verify_decide(last, ttl_ms, now),
                want,
                "verify_decide expected {want} for last={last:?} ttl={ttl_ms} now={now}"
            );
        }
    }

    /// THE EXTERN-C SLOT funnels to the SAME body: `Stale` iff due, `Fresh` otherwise, over the
    /// marshalled `last_checked_present`/value — so the dynamic-load veneer and the compiled-in one
    /// cannot diverge.
    #[test]
    fn verify_decide_q_maps_due_onto_fresh_or_stale() {
        with_test_state(|host, vt, _scope| {
            for &(last, ttl_ms, now, want_due) in DUE_CASES {
                let got = with_vquery(last, ttl_ms, now, |q| (vt.verify_decide.unwrap())(host, q));
                let want = if want_due {
                    VerifyDecision::Stale
                } else {
                    VerifyDecision::Fresh
                };
                assert_eq!(
                    got, want,
                    "verify_decide_q for last={last:?} ttl={ttl_ms} now={now}"
                );
            }
        });
    }

    #[test]
    fn verify_decide_q_fail_closed_on_null() {
        with_test_state(|host, vt, _scope| {
            // No query to decide over → Stale (re-verify), never a spurious Fresh.
            assert_eq!(
                (vt.verify_decide.unwrap())(host, core::ptr::null()),
                VerifyDecision::Stale
            );
        });
    }

    #[test]
    fn approval_redeem_q_spends_against_the_marshalled_expiry() {
        with_test_state(|host, vt, _scope| {
            let nonce = b"verify-q/approval/one-time";
            let q = ApprovalQuery {
                size: core::mem::size_of::<ApprovalQuery>() as u32,
                version: POD_VERSION,
                _reserved: 0,
                scope: 0,
                _reserved2: 0,
                expires_at: crate::store::now().saturating_add(3_600),
                now: crate::store::now(),
                key_ptr: nonce.as_ptr(),
                key_len: nonce.len(),
            };
            let first = (vt.approval_redeem_q.unwrap())(host, &q as *const ApprovalQuery);
            let second = (vt.approval_redeem_q.unwrap())(host, &q as *const ApprovalQuery);
            assert_eq!(first, StatusClass::Ok, "first redemption is fresh");
            assert_eq!(second, StatusClass::Refused, "already spent → refused");
            // Null query → fail-closed.
            assert_eq!(
                (vt.approval_redeem_q.unwrap())(host, core::ptr::null()),
                StatusClass::Refused
            );
        });
    }

    #[test]
    fn drift_quarantine_records_and_is_fail_closed() {
        with_test_state(|host, vt, _scope| {
            // A real subject: the demotion write is fire-and-forget (no sink in the test app), so a
            // clean call is Ok.
            let status = with_key(3, b"drifted-counterparty", |key| {
                (vt.drift_quarantine.unwrap())(host, key)
            });
            assert_eq!(status, StatusClass::Ok);
            // Null key → fail-closed.
            let status = (vt.drift_quarantine.unwrap())(host, core::ptr::null());
            assert_eq!(status, StatusClass::Refused);
        });
    }

    #[test]
    fn approval_redeem_is_single_use_and_fail_closed() {
        with_test_state(|host, vt, _scope| {
            let nonce = b"trust-test/approval/one-time-nonce";
            // First redemption succeeds; the second is refused (single-use).
            let first = with_key(0, nonce, |key| (vt.approval_redeem.unwrap())(host, key));
            let second = with_key(0, nonce, |key| (vt.approval_redeem.unwrap())(host, key));
            assert_eq!(first, StatusClass::Ok, "first redemption is fresh");
            assert_eq!(second, StatusClass::Refused, "already spent → refused");
            // Null key → fail-closed.
            let status = (vt.approval_redeem.unwrap())(host, core::ptr::null());
            assert_eq!(status, StatusClass::Refused);
        });
    }

    /// The six per-step facts a plane marshals into the [`CounterpartyRef`] tail — the inverse of the
    /// arms the plane's own `validate_request` refuses at. A `would_pass` value fills every step so a
    /// single failing step can be isolated (exactly as the ordered validator short-circuits).
    #[derive(Clone, Copy)]
    struct Facts {
        identity_live: u8,
        grant_outcome: u8,
        registration_state: u8,
        artifact_outcome: u8,
        generation_admitted: u64,
        generation_live: u64,
    }

    impl Facts {
        /// Every step passes: live identity, all grants held, an Approved registration serving its
        /// artifact, and a still-live generation.
        fn would_pass() -> Self {
            Facts {
                identity_live: 1,
                grant_outcome: 0,
                registration_state: reg_state::APPROVED,
                artifact_outcome: 1,
                generation_admitted: 5,
                generation_live: 5,
            }
        }
    }

    /// The neutral u8 mirror of the plane's `TrustState`, as the plane marshals it.
    fn state_u8(state: crate::trust::TrustState) -> u8 {
        match state {
            crate::trust::TrustState::Pending => reg_state::PENDING,
            crate::trust::TrustState::Approved => reg_state::APPROVED,
            crate::trust::TrustState::Quarantined => reg_state::QUARANTINED,
            crate::trust::TrustState::Suspended => reg_state::SUSPENDED,
            crate::trust::TrustState::Error => reg_state::FAILED,
        }
    }

    /// Build a `CounterpartyRef` carrying `facts` (fact tail written) over `id` for the duration of
    /// `f`.
    fn with_facts<R>(id: &[u8], facts: Facts, f: impl FnOnce(*const CounterpartyRef) -> R) -> R {
        let cp = CounterpartyRef {
            size: core::mem::size_of::<CounterpartyRef>() as u32,
            version: POD_VERSION,
            _reserved: 0,
            scope: 0,
            _reserved2: 0,
            ref_ptr: id.as_ptr(),
            ref_len: id.len(),
            identity_live: facts.identity_live,
            grant_outcome: facts.grant_outcome,
            registration_state: facts.registration_state,
            artifact_outcome: facts.artifact_outcome,
            fact_flags: 0x01, // the fact tail is authoritative.
            _reserved3: 0,
            _reserved4: 0,
            generation_admitted: facts.generation_admitted,
            generation_live: facts.generation_live,
        };
        f(&cp as *const CounterpartyRef)
    }

    /// THE FAITHFULNESS PROOF: the host `trust_evaluate` FOLD reproduces the plane's
    /// `validate_request` disposition EXACTLY — every `Refusal` arm (and the passing case) marshalled
    /// to its per-step facts folds to the verdict that names that arm, in the validator's order. This
    /// is the trust analogue of `failure_signal_round_trips_through_classify`: the facts encode the
    /// step outcome, the fold independently reconstructs the disposition, and the two must agree.
    #[test]
    fn trust_evaluate_folds_validate_request_order() {
        use crate::trust::TrustState;
        // (a description, the facts that produce it, the verdict the plane's Refusal maps to).
        let id = b"faithfulness/counterparty";
        let cases: &[(&str, Facts, TrustVerdict)] = &[
            ("all steps pass", Facts::would_pass(), TrustVerdict::Allow),
            (
                "identity not live",
                Facts {
                    identity_live: 0,
                    ..Facts::would_pass()
                },
                TrustVerdict::IdentityNotLive,
            ),
            (
                "not granted",
                Facts {
                    grant_outcome: 1,
                    ..Facts::would_pass()
                },
                TrustVerdict::NotGranted,
            ),
            (
                "egress denied",
                Facts {
                    grant_outcome: 2,
                    ..Facts::would_pass()
                },
                TrustVerdict::EgressDenied,
            ),
            (
                "not serving: quarantined",
                Facts {
                    registration_state: state_u8(TrustState::Quarantined),
                    ..Facts::would_pass()
                },
                TrustVerdict::Quarantined,
            ),
            (
                "not serving: error (last contact failed)",
                Facts {
                    registration_state: state_u8(TrustState::Error),
                    ..Facts::would_pass()
                },
                TrustVerdict::Quarantined,
            ),
            (
                "not serving: pending",
                Facts {
                    registration_state: state_u8(TrustState::Pending),
                    ..Facts::would_pass()
                },
                TrustVerdict::NeedsApproval,
            ),
            (
                "not serving: suspended",
                Facts {
                    registration_state: state_u8(TrustState::Suspended),
                    ..Facts::would_pass()
                },
                TrustVerdict::Denied,
            ),
            (
                "artifact drifted",
                Facts {
                    artifact_outcome: 2,
                    ..Facts::would_pass()
                },
                TrustVerdict::ArtifactDrifted,
            ),
            (
                "artifact unobservable",
                Facts {
                    artifact_outcome: 3,
                    ..Facts::would_pass()
                },
                TrustVerdict::ArtifactDrifted,
            ),
            (
                "generation moved",
                Facts {
                    generation_admitted: 5,
                    generation_live: 6,
                    ..Facts::would_pass()
                },
                TrustVerdict::GenerationMoved,
            ),
        ];
        with_test_state(|host, vt, _scope| {
            for (desc, facts, expect) in cases {
                let got = with_facts(id, *facts, |cp| (vt.trust_evaluate.unwrap())(host, cp));
                assert_eq!(got, *expect, "fold disposition for `{desc}`");
            }
        });
    }

    /// THE ORDER IS THE CONTENT: when several steps would refuse at once, the EARLIER step wins,
    /// exactly as `validate_request` short-circuits. Identity beats grant beats registration beats
    /// artifact beats generation.
    #[test]
    fn trust_evaluate_short_circuits_in_step_order() {
        let id = b"faithfulness/order";
        // Every step fails simultaneously.
        let all_fail = Facts {
            identity_live: 0,
            grant_outcome: 1,
            registration_state: reg_state::QUARANTINED,
            artifact_outcome: 2,
            generation_admitted: 5,
            generation_live: 6,
        };
        with_test_state(|host, vt, _scope| {
            // Identity is step 1 — it wins over every later failure.
            assert_eq!(
                with_facts(id, all_fail, |cp| (vt.trust_evaluate.unwrap())(host, cp)),
                TrustVerdict::IdentityNotLive
            );
            // Fix identity → grant (step 2) wins over registration/artifact/generation.
            let grant_first = Facts {
                identity_live: 1,
                ..all_fail
            };
            assert_eq!(
                with_facts(id, grant_first, |cp| (vt.trust_evaluate.unwrap())(host, cp)),
                TrustVerdict::NotGranted
            );
            // Fix grant → registration (step 3a) wins over artifact/generation.
            let reg_first = Facts {
                grant_outcome: 0,
                ..grant_first
            };
            assert_eq!(
                with_facts(id, reg_first, |cp| (vt.trust_evaluate.unwrap())(host, cp)),
                TrustVerdict::Quarantined
            );
            // Fix registration → artifact (step 3b) wins over generation.
            let artifact_first = Facts {
                registration_state: reg_state::APPROVED,
                ..reg_first
            };
            assert_eq!(
                with_facts(id, artifact_first, |cp| (vt.trust_evaluate.unwrap())(
                    host, cp
                )),
                TrustVerdict::ArtifactDrifted
            );
            // Fix artifact → generation (step 4) is the last refusal.
            let gen_first = Facts {
                artifact_outcome: 1,
                ..artifact_first
            };
            assert_eq!(
                with_facts(id, gen_first, |cp| (vt.trust_evaluate.unwrap())(host, cp)),
                TrustVerdict::GenerationMoved
            );
        });
    }

    /// FORWARD-COMPAT: a sender that predates the fact tail (fact flag clear) falls back to the
    /// legacy drift map — an un-demoted counterparty is `Allow`, a null identity is `Denied` — so the
    /// enrichment never changes the disposition an older plane would have received.
    #[test]
    fn trust_evaluate_falls_back_to_drift_map_without_facts() {
        with_test_state(|host, vt, _scope| {
            let id = b"faithfulness/legacy";
            // fact_flags = 0 → the tail is ignored even though present; legacy map → Allow (undemoted).
            let cp = CounterpartyRef {
                size: core::mem::size_of::<CounterpartyRef>() as u32,
                version: POD_VERSION,
                _reserved: 0,
                scope: 0,
                _reserved2: 0,
                ref_ptr: id.as_ptr(),
                ref_len: id.len(),
                identity_live: 0, // would be IdentityNotLive IF the tail were authoritative
                grant_outcome: 1,
                registration_state: reg_state::SUSPENDED,
                artifact_outcome: 2,
                fact_flags: 0, // NOT authoritative → legacy drift map.
                _reserved3: 0,
                _reserved4: 0,
                generation_admitted: 5,
                generation_live: 6,
            };
            assert_eq!(
                (vt.trust_evaluate.unwrap())(host, &cp as *const CounterpartyRef),
                TrustVerdict::Allow,
                "no fact tail → legacy drift map, not the folded refusal"
            );
        });
    }

    #[test]
    fn trust_evaluate_allows_unknown_and_denies_null() {
        with_test_state(|host, vt, _scope| {
            let id = b"trust-test/eval/unknown-counterparty";
            let cp = CounterpartyRef {
                size: core::mem::size_of::<CounterpartyRef>() as u32,
                version: POD_VERSION,
                _reserved: 0,
                scope: 2,
                _reserved2: 0,
                ref_ptr: id.as_ptr(),
                ref_len: id.len(),
                // No fact tail → the legacy drift map governs (this test's subject).
                identity_live: 0,
                grant_outcome: 0,
                registration_state: 0,
                artifact_outcome: 0,
                fact_flags: 0,
                _reserved3: 0,
                _reserved4: 0,
                generation_admitted: 0,
                generation_live: 0,
            };
            // No demotion on record → Allow.
            assert_eq!(
                (vt.trust_evaluate.unwrap())(host, &cp as *const CounterpartyRef),
                TrustVerdict::Allow
            );
            // Null counterparty → Denied (fail-closed).
            assert_eq!(
                (vt.trust_evaluate.unwrap())(host, core::ptr::null()),
                TrustVerdict::Denied
            );
        });
    }
}
