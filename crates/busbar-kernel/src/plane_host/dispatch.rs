// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The DISPATCH FAMILY of the plane host vtable, wired over busbar-core's real primitives.
//!
//! These are the five slots by which a plane RE-ENTERS core rather than merely reading from it:
//!
//! | slot | primitive | scope | fail-closed value |
//! |---|---|---|---|
//! | [`nested_dispatch`] | the operation router ([`crate::ingress::operation_resolved`]) | dispatch, DEPTH-BOUND | `Refused` / `Fault` |
//! | [`workhandle_open`] / [`workhandle_resume`] | the durable unit-of-work registry ([`crate::plane::taskstore`] shape) | [`DurableScope`](super::DurableScope) — SURVIVES the dispatch future | `WorkHandleId::NONE` / `Gone` |
//! | [`entitlement_check`] | the caller key's scope grant ([`busbar_contract::records::VirtualKey::scope_allowed`]) | — | `false` |
//! | [`gate_scan`] | the streaming content-governance gate ([`crate::hooks::gate::decide`]) | — | `Block` |
//!
//! Every fn follows the boundary discipline reused from the wired proof-of-life slots (see
//! [`super::vtable`]): recover the [`HostState`] from the opaque [`HostCtx`] FIRST, run the body inside
//! a MANDATORY `catch_unwind`, and map any caught panic (or malformed input) to the FAIL-CLOSED value
//! for that slot — never a permissive one.
//!
//! ## The two scopes this family straddles
//!
//! [`nested_dispatch`] and [`gate_scan`] live at the DISPATCH scope: they run and complete within the
//! originating work-item's future. The work-handle pair does NOT — a durable work-handle is the
//! [`DurableScope`](super::DurableScope) primitive: it SURVIVES the dispatch future (the async plane
//! parks it at a `202` and resumes it by lookup on a later callback), so it is registered in a
//! process-lifetime durable registry, NOT the per-dispatch [`DispatchScope`](super::DispatchScope)
//! arena that reclaims at future-drop. Reclaiming a durable handle at future-drop was the v4 arena bug.

use super::recover;
use busbar_contract::abi::hot::host::HostCtx;
use busbar_contract::abi::hot::{
    CallerRef, ContentChunk, GateDecision, OpDesc, OpResult, StatusClass, TargetRef,
    WorkHandleDesc, WorkHandleId,
};
use core::mem::MaybeUninit;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{LazyLock, Mutex};

// ─────────────────────────────────────────────────────────────────────────────────────────────
// nested_dispatch — re-enter core's OWN operation router, DEPTH-BOUND.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The HOST CEILING on nested re-entry. A plane→dispatch→plane loop is bounded by the per-request
/// `OpDesc::depth` (remaining budget, refused at zero), but a plane could also present an arbitrarily
/// LARGE remaining depth to buy itself unbounded re-entry; the host clamps that too, refusing any
/// claim beyond this ceiling. Small on purpose: the one shipped nested caller (MCP sampling,
/// `mcp/sampling.rs`) re-enters exactly once.
const MAX_NESTED_DEPTH: u32 = 8;

/// WIRED `nested_dispatch` → route an OPAQUE sub-request back through the SAME operation router the
/// host uses for an arriving request ([`crate::ingress::operation_resolved`]). The host never learns
/// the sub-request is an LLM completion (that is the whole point of the slot — MCP sampling re-enters
/// the governed pipeline this way, `mcp/sampling.rs`).
///
/// DEPTH-BOUND: the re-entry is REFUSED when the caller's remaining `depth` is exhausted
/// (`0`) or exceeds [`MAX_NESTED_DEPTH`], which bounds unbounded plane→dispatch→plane recursion. The
/// originating `correlation_id` is carried so the sub-operation is metered and audited against the
/// ORIGINATING request's budget/correlation rather than double-counted as a fresh top-level request.
///
/// Phase 2: the full pipeline re-entry ([`crate::ingress::operation_resolved`]) needs an `Arc<App>` +
/// a live `GovCtx` + an async bridge (the router is `async`, this seam is a synchronous `extern` fn),
/// which is the large piece deferred here; the DEPTH-BOUND governance decision above is real and
/// enforced now. Within budget the seam answers `Unsupported` (the honest "capability present, router
/// re-entry not yet wired" class) and does NOT write the `out` param — only `Ok` writes it.
pub(crate) extern "C-unwind" fn nested_dispatch(
    host: HostCtx,
    desc: *const OpDesc,
    out: *mut MaybeUninit<OpResult>,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the host passes a live `HostState` ptr for the dispatch duration (see `recover`).
        let Some(_state) = (unsafe { recover(host) }) else {
            return StatusClass::Refused;
        };
        if desc.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: a non-null `desc` is a live, initialized `OpDesc` for the call (ABI discipline).
        let d = unsafe { &*desc };
        // DEPTH-BOUND: refuse at exhaustion OR beyond the host ceiling — both are the re-entrancy
        // guard rejecting, and conflating them is correct (each is "this re-entry is not permitted").
        if d.depth == 0 || d.depth > MAX_NESTED_DEPTH {
            return StatusClass::Refused;
        }
        // Carry the originating correlation for SINGLE budget/audit accounting: the router re-entry
        // threads this so the sub-op charges the originating request, not a new one.
        let _correlation_id = d.correlation_id;
        // SAFETY: `(work_ptr, work_len)` is a live borrowed range for the call (ABI discipline).
        let _work: &[u8] = unsafe { borrow_bytes(d.work_ptr, d.work_len) };
        // Phase 2: re-enter `crate::ingress::operation_resolved` with `depth - 1` and `_correlation_id`,
        // then write the `OpResult` on the Ok path. Deferred: needs Arc<App> + GovCtx + an async bridge.
        let _ = out; // untouched: no Ok path yet, and only Ok may write the out-param.
        StatusClass::Unsupported
    }))
    .unwrap_or(StatusClass::Fault) // caught panic → the distinct fault class, never a routed Ok.
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// workhandle_open / workhandle_resume — the DURABLE unit-of-work primitive (DurableScope).
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// One parked durable unit of work. Mirrors the fact set a [`crate::plane::taskstore`] row carries for
/// a resume (scope namespace, ttl, correlation), minus the A2A-task-specific provenance chain.
struct DurableEntry {
    /// The durable scope namespace the handle was opened under.
    scope: u32,
    /// Time-to-live in seconds; `0` = no expiry.
    ttl_secs: u32,
    /// The originating unit-of-work correlation id (carried for the resume's audit join).
    correlation_id: u64,
    /// Epoch-millis the handle was opened (for the ttl check on resume).
    opened_at_ms: u64,
}

/// The PROCESS-LIFETIME durable work-handle registry. Process state, not config-derived state, so it
/// lives as a global exactly like [`crate::plane::taskstore`]'s `TASKS`: a durable handle SURVIVES the
/// dispatch future (and, once Phase 2 attaches the taskstore sink, the process), so it must NOT hang
/// off the swappable per-dispatch arena. Reclaiming it at future-drop was the v4 arena bug.
struct DurableRegistry {
    handles: HashMap<u64, DurableEntry>,
    /// Monotonic id source; `0` is the reserved `NONE` sentinel of [`WorkHandleId`], so ids start at 1.
    next: u64,
}

static DURABLE: LazyLock<Mutex<DurableRegistry>> = LazyLock::new(|| {
    Mutex::new(DurableRegistry {
        handles: HashMap::new(),
        next: 0,
    })
});

/// Poison-recovering lock: a panic mid-mutation must not wedge the durable registry for every later
/// open/resume (same discipline as the taskstore and the dispatch arena).
fn durable() -> std::sync::MutexGuard<'static, DurableRegistry> {
    DURABLE.lock().unwrap_or_else(|e| e.into_inner())
}

/// WIRED `workhandle_open` → open a DURABLE unit of work at the [`DurableScope`](super::DurableScope):
/// allocate a non-zero [`WorkHandleId`], register it in the process-lifetime durable registry, and
/// return the id. The handle SURVIVES the dispatch future — it is deliberately NOT registered in the
/// per-dispatch [`DispatchScope`](super::DispatchScope) arena, so a dropped/cancelled dispatch future
/// does not reclaim it (that was the v4 bug; a `202`-parked handle must outlive the request that
/// parked it and be resumable by lookup later).
///
/// Phase 2: write-through to the configured governance store via [`crate::plane::taskstore`]'s durable
/// sink so the handle survives the PROCESS too (today it is an in-process durable registry that
/// survives the dispatch future but not a restart). Fail-closed: a null desc yields `WorkHandleId::NONE`.
pub(crate) extern "C-unwind" fn workhandle_open(
    host: HostCtx,
    desc: *const WorkHandleDesc,
) -> WorkHandleId {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`).
        let Some(_state) = (unsafe { recover(host) }) else {
            return WorkHandleId::NONE;
        };
        if desc.is_null() {
            return WorkHandleId::NONE;
        }
        // SAFETY: a non-null `desc` is a live, initialized `WorkHandleDesc` for the call (ABI).
        let d = unsafe { &*desc };
        let mut reg = durable();
        reg.next += 1;
        let raw = reg.next;
        reg.handles.insert(
            raw,
            DurableEntry {
                scope: d.scope,
                ttl_secs: d.ttl_secs,
                correlation_id: d.correlation_id,
                opened_at_ms: busbar_kernel::store::now_ms(),
            },
        );
        WorkHandleId(raw)
    }))
    .unwrap_or(WorkHandleId::NONE) // fail-closed: a panicked open yields no handle.
}

/// WIRED `workhandle_resume` → resume a durable work-handle BY LOOKUP on a later callback. `Ok` if the
/// handle is live; `Gone` if it is unknown (never opened, or already expired/completed) — the ABI's
/// stale-handle class. Resuming a handle whose ttl has elapsed drops it and answers `Gone`, so an
/// expired park is indistinguishable from a missing one (the same posture the taskstore's scoped read
/// takes for a foreign/absent id).
///
/// Phase 2: rehydrate from the taskstore durable sink so a handle opened before a restart still
/// resumes. Fail-closed: a panic answers `Fault`; a missing/expired handle answers `Gone`.
pub(crate) extern "C-unwind" fn workhandle_resume(
    host: HostCtx,
    handle: WorkHandleId,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`).
        let Some(_state) = (unsafe { recover(host) }) else {
            // A stale host handle IS the ABI's stale-handle class here too.
            return StatusClass::Gone;
        };
        if handle.is_none() {
            return StatusClass::Gone;
        }
        let mut reg = durable();
        let Some(entry) = reg.handles.get(&handle.0) else {
            return StatusClass::Gone;
        };
        // TTL check: `ttl_secs == 0` never expires; else expire once `opened_at + ttl` has passed.
        if entry.ttl_secs != 0 {
            let expires_at = entry
                .opened_at_ms
                .saturating_add(u64::from(entry.ttl_secs).saturating_mul(1_000));
            if busbar_kernel::store::now_ms() >= expires_at {
                reg.handles.remove(&handle.0);
                return StatusClass::Gone;
            }
        }
        // Live: the handle exists and has not expired. The `scope`/`correlation_id` it carries are what
        // the Phase-2 resume threads into the re-opened dispatch; touching them here proves they survive.
        let _resumed = (entry.scope, entry.correlation_id);
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault) // fail-closed: a panicked resume faults, never falsely resumes.
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// entitlement_check — may this caller use this target? (VirtualKey scope grant, fail-closed).
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Map a [`TargetRef::scope_kind`] discriminant to the [`busbar_contract::records::ScopeRef`] kind string the caller
/// key's grant is partitioned by — resolved from REGISTRY DATA (see
/// [`crate::plane::registry::scope_kind_at`]): index `0` is core's neutral admission-pool kind, `1..`
/// are the installed planes' declared `scope_kinds` in registration order, so core spells no plane's
/// kind token. UNKNOWN kinds return `None` → the entitlement FAILS CLOSED, so a future kind that
/// reaches this seam before its plane is registered denies rather than silently widens.
fn scope_kind_str(scope_kind: u32) -> Option<&'static str> {
    crate::plane::registry::scope_kind_at(scope_kind)
}

/// WIRED `entitlement_check` → does the CALLER's scope grant permit this TARGET? The host owns the
/// caller's scopes/keys: the [`CallerRef`] identity bytes name a governance key id, which is resolved
/// to its [`busbar_contract::records::VirtualKey`] and asked [`busbar_contract::records::VirtualKey::scope_allowed`] for the
/// target's `(kind, value)`.
///
/// FAIL-CLOSED (`false`) on every non-affirmative path: a null caller/target POD, governance disabled,
/// a non-UTF-8 identity/target, an unmapped [`scope_kind`](TargetRef::scope_kind), an unknown caller
/// key, a tombstoned/disabled key, or a caught panic. Only a live enabled key whose grant explicitly
/// covers the target returns `true`.
///
/// Stays `pub(crate)`: `EntitlementCheckFn` (`busbar_contract::abi::hot::host`) is a SAFE
/// `extern "C-unwind" fn` type — widening this definition to plain `pub` trips clippy's
/// `not_unsafe_ptr_arg_deref` (a public fn dereferencing a raw pointer without being `unsafe fn`),
/// and this function's contract is exactly that risk (a forged/dangling `caller`/`target` is UB).
/// The composition root's `crates/busbar/tests/plane_host_dispatch_cross_plane.rs` reaches the REAL
/// wired fn through the PUBLIC `PlaneHostVtable::entitlement_check` field instead
/// (`Some(dispatch::entitlement_check)`, wired in `vtable.rs`) — the same seam a real plane calls
/// through — rather than naming this item directly.
pub(crate) extern "C-unwind" fn entitlement_check(
    host: HostCtx,
    caller: *const CallerRef,
    target: *const TargetRef,
) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`).
        let Some(state) = (unsafe { recover(host) }) else {
            return false;
        };
        if caller.is_null() || target.is_null() {
            return false;
        }
        // SAFETY: non-null POD pointers are live, initialized structs for the call (ABI discipline).
        let (c, t) = unsafe { (&*caller, &*target) };
        // The host owns the caller's scopes/keys via governance; with governance disabled there is no
        // grant to consult, so the honest answer is a denial, not a wildcard.
        let Some(gov) = state.app.governance.as_ref() else {
            return false;
        };
        // SAFETY: the borrowed identity/target ranges are live for the call (ABI discipline).
        let (Some(caller_id), Some(kind), Some(value)) = (
            unsafe { borrow_str(c.ref_ptr, c.ref_len) },
            scope_kind_str(t.scope_kind),
            unsafe { borrow_str(t.ref_ptr, t.ref_len) },
        ) else {
            return false;
        };
        let Some(key) = gov.lookup_by_sub(caller_id) else {
            return false; // unknown caller → deny.
        };
        // A tombstoned or administratively-disabled key is entitled to NOTHING, whatever its grant list.
        if !key.is_live() || !key.enabled {
            return false;
        }
        key.scope_allowed(kind, value)
    }))
    .unwrap_or(false) // fail-closed: a panicked check denies.
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// gate_scan — feed a content chunk to the real content-governance gate (fail-closed to Block).
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// WIRED `gate_scan` → feed one streaming [`ContentChunk`] to the REAL content-governance gate
/// ([`crate::hooks::gate::decide`]) and map its verdict: `Proceed` → [`GateDecision::Continue`],
/// `Reject` → [`GateDecision::Block`].
///
/// Phase 2 resolves the per-session / per-container content gates and projects the chunk bytes into
/// the gate's `ContentItem` set (and threads the `IncrementalScan` session substrate so a long stream
/// re-scans only new content); until then no gate is wired to THIS seam, so `decide` runs over an
/// EMPTY gate set and returns its zero-cost `Proceed` early-out → `Continue`.
///
/// FAIL-CLOSED to `Block`: a null chunk POD, a gate that `Reject`s, or a caught panic all block the
/// stream. This matches the gate's own fail-closed posture — a broken load-bearing gate refuses.
pub(crate) extern "C-unwind" fn gate_scan(
    host: HostCtx,
    chunk: *const ContentChunk,
) -> GateDecision {
    // No gate is wired to this seam yet (Phase 2 resolves the real per-session/per-container set).
    const NO_GATES: &[(u16, crate::hooks::ResolvedPolicy)] = &[];
    gate_scan_inner(host, chunk, NO_GATES)
}

/// The gate_scan body, parameterized over the resolved gate set so a test can drive the REAL
/// [`crate::hooks::gate::decide`] with an actual rejecting gate and prove the `Reject` → `Block`
/// mapping through this exact seam. The `extern` slot calls it with an empty set (see [`gate_scan`]).
fn gate_scan_inner(
    host: HostCtx,
    chunk: *const ContentChunk,
    gates: &[(u16, crate::hooks::ResolvedPolicy)],
) -> GateDecision {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`).
        let Some(_state) = (unsafe { recover(host) }) else {
            return GateDecision::Block; // fail-closed: a stale handle refuses the stream too.
        };
        if chunk.is_null() {
            return GateDecision::Block; // fail-closed: no chunk to clear → refuse the stream.
        }
        // SAFETY: a non-null `chunk` is a live, initialized `ContentChunk` for the call (ABI).
        let c = unsafe { &*chunk };
        // SAFETY: `(data_ptr, data_len)` is a live borrowed range for the call (ABI discipline).
        let _data: &[u8] = unsafe { borrow_bytes(c.data_ptr, c.data_len) };
        // Phase 2 projects `_data` into `ContentItem`s and threads the session substrate; today the
        // real gate runs over the resolved gate set as-is.
        match run_content_gate(gates) {
            crate::hooks::gate::GateVerdict::Proceed => GateDecision::Continue,
            crate::hooks::gate::GateVerdict::Reject { .. } => GateDecision::Block,
        }
    }))
    .unwrap_or(GateDecision::Block) // fail-closed: a panicked scan blocks the stream.
}

/// Drive the REAL [`crate::hooks::gate::decide`] to a verdict. `decide` is `async` (a gate is a policy
/// sidecar) and this seam is a synchronous `extern` fn, so the gate runs on a fresh current-thread
/// runtime. Phase 2 threads the host's own runtime handle here instead of minting one per scan.
///
/// The subject is a neutral, content-free projection: with the shipped EMPTY gate set `decide` returns
/// before it ever reads the subject (its `gates.is_empty()` early-out), and the Phase-2 chunk
/// projection replaces this placeholder subject when real gates are resolved. A runtime that fails to
/// build is treated as the gate being unable to complete → a fail-closed `Reject`.
fn run_content_gate(
    gates: &[(u16, crate::hooks::ResolvedPolicy)],
) -> crate::hooks::gate::GateVerdict {
    let facts = busbar_contract::ir::facts::NeutralFacts(crate::operation::OpVerb::SUBSCRIBE);
    let subject = crate::hooks::gate::GateSubject {
        facts: &facts,
        container: "",
        ingress_protocol: "plane",
        request_id: 0,
        key: None,
        incremental: None,
        session: None,
    };
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt.block_on(crate::hooks::gate::decide(gates, &subject)),
        Err(_) => crate::hooks::gate::GateVerdict::Reject {
            status: 403,
            message: "the content gate could not be run".to_string(),
            hook: "plane_host::gate_scan",
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Shared borrow helpers — validate an ABI `(ptr, len)` range into a Rust view.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Borrow an ABI `(ptr, len)` byte range for the call. A null pointer or zero length is an EMPTY
/// slice (a legitimately absent range), never a dereference.
///
/// # Safety
/// A non-null `ptr`/`len` MUST describe a live, initialized byte range for the call (ABI discipline).
unsafe fn borrow_bytes<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        // SAFETY: by the ABI, a non-null range is live and initialized for the call.
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }
}

/// Borrow an ABI `(ptr, len)` range as UTF-8. `None` when the range is absent (null/empty) or not
/// valid UTF-8 — both drive the caller's fail-closed path.
///
/// # Safety
/// Same contract as [`borrow_bytes`].
unsafe fn borrow_str<'a>(ptr: *const u8, len: usize) -> Option<&'a str> {
    if ptr.is_null() || len == 0 {
        return None;
    }
    // SAFETY: by the ABI, a non-null range is live and initialized for the call.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    std::str::from_utf8(bytes).ok()
}

#[cfg(test)]
#[path = "tests/dispatch_tests.rs"]
mod tests;
