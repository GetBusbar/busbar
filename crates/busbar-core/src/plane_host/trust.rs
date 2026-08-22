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
    CounterpartyRef, Key, StatusClass, TrustVerdict, VerifyLease, VerifyOutcome, VerifyVerdict,
    POD_VERSION,
};
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
    /// `key` → the wall-clock millisecond after which the verification is stale.
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
                // leadership when the scope ends (the §4 leak-safety keystone, applied to trust). It
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
        crate::plane::quarantine::settle(
            &state.app.mcp_demotions,
            &subject,
            crate::trust::TrustState::Quarantined,
        );
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault)
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
        if state.app.plane_approvals.spend(&nonce, expires_at, now) {
            StatusClass::Ok // first redemption.
        } else {
            StatusClass::Refused // already spent, or the ledger could not answer (fail-closed).
        }
    }))
    .unwrap_or(StatusClass::Fault)
}

/// WIRED `trust_evaluate` → the admission-time trust verdict for a counterparty, over the real
/// durable DRIFT state.
///
/// A counterparty with a durable demotion on record is [`TrustVerdict::Quarantined`] (drift the
/// operator has not yet worked); otherwise it is [`TrustVerdict::Allow`]. The full ordered validator
/// (`crate::trust::validate::validate_request`: identity → grant → artifact → generation, mapping to
/// `Denied`/`NeedsApproval` too) is the Phase-2 wiring once the counterparty→registration resolution
/// lands (see the header). A null/empty identity, or a caught panic, is [`TrustVerdict::Denied`] —
/// trust fails closed.
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
        // SAFETY: `cp` is a live `&CounterpartyRef`; `subject` upholds the borrow discipline.
        let Some(subject) = (unsafe { subject(cp.ref_ptr, cp.ref_len) }) else {
            return TrustVerdict::Denied; // no identity → fail-closed.
        };
        // The durable demotion records ARE the "drift lives host-side" trust state the ABI describes.
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

    fn read_lookup(host: HostCtx, vt: &PlaneHostVtable, key: *const Key) -> (StatusClass, VerifyVerdict) {
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
            assert_eq!(second, VerifyOutcome::Follow, "a leader is fetching → follow");
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
