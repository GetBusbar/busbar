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
//! | [`entitlement_check`] | the caller key's scope grant ([`busbar_api::VirtualKey::scope_allowed`]) | — | `false` |
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

use super::{recover, HostState};
use busbar_plugin::hot::host::HostCtx;
use busbar_plugin::hot::{
    CallerRef, ContentChunk, GateDecision, GateSubjectRef, GateVerdictOut, OpDesc, OpResult,
    StatusClass, TargetRef, WorkHandleDesc, WorkHandleId, POD_VERSION,
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
        let _state: &HostState = unsafe { recover(host) };
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
        let _state: &HostState = unsafe { recover(host) };
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
                opened_at_ms: crate::store::now_ms(),
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
        let _state: &HostState = unsafe { recover(host) };
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
            if crate::store::now_ms() >= expires_at {
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

/// Map a [`TargetRef::scope_kind`] discriminant to the [`busbar_api::ScopeRef`] kind string the caller
/// key's grant is partitioned by. UNKNOWN kinds return `None` → the entitlement FAILS CLOSED, so a
/// future kind that reaches this seam before its mapping is added denies rather than silently widens.
fn scope_kind_str(scope_kind: u32) -> Option<&'static str> {
    match scope_kind {
        0 => Some("pool"),
        1 => Some("mcp_server"),
        2 => Some("mcp_tool"),
        3 => Some("agent"),
        _ => None,
    }
}

/// WIRED `entitlement_check` → does the CALLER's scope grant permit this TARGET? The host owns the
/// caller's scopes/keys: the [`CallerRef`] identity bytes name a governance key id, which is resolved
/// to its [`busbar_api::VirtualKey`] and asked [`busbar_api::VirtualKey::scope_allowed`] for the
/// target's `(kind, value)`.
///
/// FAIL-CLOSED (`false`) on every non-affirmative path: a null caller/target POD, governance disabled,
/// a non-UTF-8 identity/target, an unmapped [`scope_kind`](TargetRef::scope_kind), an unknown caller
/// key, a tombstoned/disabled key, or a caught panic. Only a live enabled key whose grant explicitly
/// covers the target returns `true`.
pub(crate) extern "C-unwind" fn entitlement_check(
    host: HostCtx,
    caller: *const CallerRef,
    target: *const TargetRef,
) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `recover`).
        let state: &HostState = unsafe { recover(host) };
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
        let _state: &HostState = unsafe { recover(host) };
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
    let facts = crate::ir::facts::NeutralFacts(crate::operation::Operation::SUBSCRIBE);
    let subject = crate::hooks::gate::GateSubject {
        facts: &facts,
        container: "",
        ingress_protocol: "plane",
        request_id: 0,
        key: None,
        incremental: None,
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
// gate_decide — fire the operator's request-admission hook gates (fail-closed to a 403 reject).
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Copy up to `cap` of `bytes` into the caller's `buf` (tolerating a null/zero-cap slot), returning the
/// number of bytes written — the `govern_admit_reason` variable-length copy-out, used for the gate's
/// `message` and `hook` strings alike.
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

/// Write the [`GateVerdictOut`] out-param (tolerating a null slot): the verdict + clamped status + the
/// rendered `message`/`hook` lengths.
///
/// # Safety
/// `out`, when non-null, is a writable, aligned `MaybeUninit<GateVerdictOut>` for the call.
unsafe fn write_gate_verdict(
    out: *mut MaybeUninit<GateVerdictOut>,
    proceed: u8,
    status: u16,
    message_len: u32,
    hook_len: u32,
) {
    let verdict = GateVerdictOut {
        size: core::mem::size_of::<GateVerdictOut>() as u32,
        version: POD_VERSION,
        proceed,
        _reserved: 0,
        status,
        message_len,
        hook_len,
    };
    // SAFETY: `out` is a writable, aligned MaybeUninit slot (or null, which `write_out` tolerates).
    unsafe { busbar_plugin::write_out(out, verdict) };
}

/// WIRED `gate_decide` → fire the operator's REQUEST-ADMISSION hook gates over the REAL
/// [`crate::hooks::gate::decide`]. The host re-selects the resolved gate set by `(plane_key, container)`
/// — it owns the `ResolvedPolicy` set the plane never holds — reconstructs the SAME `InvokeReq`-shaped
/// facts the in-process firing site builds (`tool` + the caller's `arguments` JSON), threads the caller
/// key identity and the incremental-scan session substrate (subsumed host-side: the host reads its own
/// `session_store` + clock), and runs the async gate on a fresh current-thread runtime — the same
/// async→sync bridge [`gate_scan`]'s `run_content_gate` uses.
///
/// `out` is initialized UP FRONT to a fail-closed reject (`proceed = 0`, `status = 403`, zero lengths),
/// so a null subject ([`StatusClass::Refused`]), a runtime that will not start or a caught panic
/// ([`StatusClass::Fault`]) all leave a refusal — the gate's own fail-closed posture (a load-bearing gate
/// that cannot run refuses). A REJECT writes the clamped 4xx status and copies the hook's
/// `message`/`hook` bytes into the caller's buffers.
///
/// Driven from a BLOCKING thread (`spawn_blocking`, see [`super::gate_decide_over`]): the fresh runtime's
/// `block_on` would panic on a runtime worker.
#[allow(clippy::too_many_arguments)]
pub(crate) extern "C-unwind" fn gate_decide(
    host: HostCtx,
    subject: *const GateSubjectRef,
    msg_buf: *mut u8,
    msg_cap: usize,
    hook_buf: *mut u8,
    hook_cap: usize,
    out: *mut MaybeUninit<GateVerdictOut>,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // Initialize `out` up front so NO path (refuse, fault, or a caught panic below) leaves it
        // uninitialized: the fail-closed reject a `Proceed`/`Reject` overwrites on the Ok path.
        // SAFETY: ABI out-param discipline (writable/aligned or null; see `write_gate_verdict`).
        unsafe { write_gate_verdict(out, 0, 403, 0, 0) };
        // SAFETY: recovery invariant (see `recover`).
        let state: &HostState = unsafe { recover(host) };
        if subject.is_null() {
            return StatusClass::Refused; // no subject to judge → `out` stays the fail-closed reject.
        }
        // SAFETY: a non-null `subject` is a live, initialized `GateSubjectRef` for the call (ABI).
        let s = unsafe { &*subject };
        let app = state.app;
        // SAFETY: each borrowed `(ptr, len)` is a live range for the call (ABI discipline).
        let container = unsafe { borrow_str(s.container_ptr, s.container_len) }.unwrap_or("");
        let tool = unsafe { borrow_str(s.tool_ptr, s.tool_len) }.unwrap_or("");
        // SAFETY: as above.
        let args = unsafe { borrow_bytes(s.args_ptr, s.args_len) };
        // The host OWNS the resolved gate set; the plane passes only `(plane_key, container)`. An unknown
        // plane key or an unattached container selects the empty set (`decide`'s zero-cost `Proceed`).
        let gates: &[(u16, crate::hooks::ResolvedPolicy)] = match s.plane_key {
            0 => app.mcp_server_gates.get(container),
            1 => app.a2a_agent_gates.get(container),
            _ => None,
        }
        .map(Vec::as_slice)
        .unwrap_or(&[]);
        // The `ingress_protocol` label is DERIVED from the plane key host-side (not carried), spelled
        // exactly as the in-process site spells it.
        let ingress = match s.plane_key {
            0 => crate::plane::Plane::Mcp.key(),
            1 => crate::plane::Plane::A2a.key(),
            _ => "",
        };
        // Rebuild the caller's arguments `Value`. Byte-safe because `serde_json`'s `preserve_order` is
        // OFF (a `Value` object is a sorted-stable `BTreeMap`), so `to_vec`→`from_slice` round-trips to
        // the identical `Value` and the gate's `value.to_string()` projection is unchanged.
        let arguments: serde_json::Value =
            serde_json::from_slice(args).unwrap_or(serde_json::Value::Null);
        let facts = crate::ir::invoke::InvokeReq {
            tool: tool.to_string(),
            arguments,
            extra: Default::default(),
        };
        // The caller's key identity — the gate reads ONLY `id`/`name`, so a reconstruction from those two
        // is byte-identical to the resolved key the in-process site passes.
        let key = (s.key_present != 0).then(|| busbar_api::VirtualKey {
            // SAFETY: borrowed ranges live for the call (ABI).
            id: unsafe { borrow_str(s.key_id_ptr, s.key_id_len) }
                .unwrap_or("")
                .to_string(),
            name: unsafe { borrow_str(s.key_name_ptr, s.key_name_len) }
                .unwrap_or("")
                .to_string(),
            ..Default::default()
        });
        // SAFETY: borrowed range lives for the call (ABI).
        let sid = unsafe { borrow_str(s.session_id_ptr, s.session_id_len) }.unwrap_or("");
        // The session substrate is SUBSUMED: the host reads its own `session_store` + clock. Gated on the
        // operator opt-in AND a non-empty session id, exactly as the in-process site gates it.
        let incremental =
            (s.incremental != 0 && app.incremental_scan && !sid.is_empty()).then(|| {
                crate::hooks::gate::IncrementalScan {
                    store: &app.session_store,
                    session: crate::session::SessionKey(crate::store::fnv1a_u64(sid)),
                    now_ms: crate::store::now_ms(),
                }
            });
        let subject = crate::hooks::gate::GateSubject {
            facts: &facts,
            container,
            ingress_protocol: ingress,
            request_id: s.request_id,
            key: key.as_ref(),
            incremental,
        };
        // Drive the ASYNC gate on a fresh current-thread runtime (the `run_content_gate` precedent). A
        // runtime that will not start is fail-closed (`out` already holds the reject).
        let verdict = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt.block_on(crate::hooks::gate::decide(gates, &subject)),
            Err(_) => return StatusClass::Fault,
        };
        match verdict {
            crate::hooks::gate::GateVerdict::Proceed => {
                // SAFETY: ABI out-param discipline.
                unsafe { write_gate_verdict(out, 1, 0, 0, 0) };
            }
            crate::hooks::gate::GateVerdict::Reject {
                status,
                message,
                hook,
            } => {
                // SAFETY: the buffers are writable ranges (or null) per the ABI.
                let m = unsafe { write_reason(msg_buf, msg_cap, message.as_bytes()) };
                // SAFETY: as above.
                let h = unsafe { write_reason(hook_buf, hook_cap, hook.as_bytes()) };
                // SAFETY: ABI out-param discipline.
                unsafe { write_gate_verdict(out, 0, status, m as u32, h as u32) };
            }
        }
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault) // caught panic → Fault; `out` already holds the fail-closed reject.
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
mod tests {
    use super::*;
    use crate::plane_host::{with_dispatch_scope, DurableScope};
    use busbar_plugin::hot::POD_VERSION;
    use std::sync::Arc;

    // The durable-scope type is named by this family but exercised only through the process-lifetime
    // registry the wired slots use; assert it constructs so a rider extending it stays append-only.
    #[test]
    fn durable_scope_stub_constructs() {
        let _ = DurableScope::new();
    }

    fn op_desc(depth: u32, correlation_id: u64) -> OpDesc {
        OpDesc {
            size: core::mem::size_of::<OpDesc>() as u32,
            version: POD_VERSION,
            _reserved: 0,
            depth,
            _reserved2: 0,
            correlation_id,
            work_ptr: core::ptr::null(),
            work_len: 0,
        }
    }

    fn workhandle_desc(scope: u32, ttl_secs: u32, correlation_id: u64) -> WorkHandleDesc {
        WorkHandleDesc {
            size: core::mem::size_of::<WorkHandleDesc>() as u32,
            version: POD_VERSION,
            _reserved: 0,
            scope,
            ttl_secs,
            correlation_id,
        }
    }

    fn caller_ref(id: &[u8], scope: u32) -> CallerRef {
        CallerRef {
            size: core::mem::size_of::<CallerRef>() as u32,
            version: POD_VERSION,
            _reserved: 0,
            scope,
            _reserved2: 0,
            ref_ptr: id.as_ptr(),
            ref_len: id.len(),
        }
    }

    fn target_ref(value: &[u8], scope_kind: u32) -> TargetRef {
        TargetRef {
            size: core::mem::size_of::<TargetRef>() as u32,
            version: POD_VERSION,
            _reserved: 0,
            scope_kind,
            _reserved2: 0,
            ref_ptr: value.as_ptr(),
            ref_len: value.len(),
        }
    }

    fn content_chunk(data: &[u8]) -> ContentChunk {
        ContentChunk {
            size: core::mem::size_of::<ContentChunk>() as u32,
            version: POD_VERSION,
            is_final: 1,
            _reserved: 0,
            session_id: 0,
            offset: 0,
            data_ptr: data.as_ptr(),
            data_len: data.len(),
        }
    }

    /// Drive a slot over a REAL recovered `HostState` from an app with no governance.
    fn with_bare_app<R>(f: impl FnOnce(HostCtx) -> R) -> R {
        let app = crate::test_support::TestApp::new().build();
        with_dispatch_scope(&app, |host, _vt| f(host))
    }

    // ── nested_dispatch: the DEPTH-BOUND governance decision ────────────────────────────────────

    #[test]
    fn nested_dispatch_refuses_at_depth_zero() {
        with_bare_app(|host| {
            let desc = op_desc(0, 42);
            let mut out = MaybeUninit::<OpResult>::uninit();
            assert_eq!(
                nested_dispatch(host, &desc, std::ptr::from_mut(&mut out)),
                StatusClass::Refused,
                "an exhausted depth budget refuses re-entry"
            );
        });
    }

    #[test]
    fn nested_dispatch_refuses_beyond_the_host_ceiling() {
        with_bare_app(|host| {
            let desc = op_desc(MAX_NESTED_DEPTH + 1, 42);
            let mut out = MaybeUninit::<OpResult>::uninit();
            assert_eq!(
                nested_dispatch(host, &desc, std::ptr::from_mut(&mut out)),
                StatusClass::Refused,
                "a remaining-depth claim beyond the host ceiling refuses re-entry"
            );
        });
    }

    #[test]
    fn nested_dispatch_within_budget_is_unsupported_not_refused() {
        with_bare_app(|host| {
            let desc = op_desc(1, 42);
            let mut out = MaybeUninit::<OpResult>::uninit();
            // Within the depth bound the re-entrancy guard PASSES; the router re-entry itself is Phase 2.
            assert_eq!(
                nested_dispatch(host, &desc, std::ptr::from_mut(&mut out)),
                StatusClass::Unsupported
            );
        });
    }

    #[test]
    fn nested_dispatch_null_desc_is_refused() {
        with_bare_app(|host| {
            let mut out = MaybeUninit::<OpResult>::uninit();
            assert_eq!(
                nested_dispatch(host, core::ptr::null(), std::ptr::from_mut(&mut out)),
                StatusClass::Refused
            );
        });
    }

    // ── workhandle_open / resume: the DURABLE unit-of-work ──────────────────────────────────────

    #[test]
    fn workhandle_open_then_resume_is_ok_and_survives_the_dispatch() {
        // Open the durable handle inside ONE dispatch scope...
        let id = with_bare_app(|host| {
            let desc = workhandle_desc(7, 0, 99);
            let id = workhandle_open(host, &desc);
            assert!(!id.is_none(), "an opened durable handle is a non-zero id");
            id
        });
        // ...and resume it inside a DIFFERENT, later dispatch scope: it was NOT reclaimed at the first
        // future's drop (the DurableScope property; a DispatchScope-arena handle would be gone here).
        with_bare_app(|host| {
            assert_eq!(
                workhandle_resume(host, id),
                StatusClass::Ok,
                "the durable handle survives the dispatch future and resumes by lookup"
            );
        });
    }

    #[test]
    fn workhandle_resume_unknown_is_gone() {
        with_bare_app(|host| {
            assert_eq!(
                workhandle_resume(host, WorkHandleId(u64::MAX)),
                StatusClass::Gone
            );
            assert_eq!(
                workhandle_resume(host, WorkHandleId::NONE),
                StatusClass::Gone
            );
        });
    }

    #[test]
    fn workhandle_open_null_desc_yields_none() {
        with_bare_app(|host| {
            assert!(workhandle_open(host, core::ptr::null()).is_none());
        });
    }

    // ── entitlement_check: the caller key's scope grant ─────────────────────────────────────────

    fn scoped_key(id: &str, scopes: Option<Vec<busbar_api::ScopeRef>>) -> busbar_api::VirtualKey {
        busbar_api::VirtualKey {
            id: id.to_string(),
            generation_hash: String::new(),
            name: "test".to_string(),
            allowed_scopes: scopes,
            enabled: true,
            created_at: 1_700_000_000,
            group: None,
            labels: Default::default(),
            expires_at: None,
            deleted_at: None,
            revision: 1,
            ..Default::default()
        }
    }

    /// An app whose governance holds `key`, built so `lookup_by_sub` resolves it from the loaded cache.
    fn app_with_key(key: &busbar_api::VirtualKey) -> Arc<crate::state::App> {
        use busbar_api::Store;
        let store = Arc::new(busbar_store_memory::MemoryStore::new());
        store.put_key(key).expect("memory store accepts the key");
        let gov = Arc::new(crate::governance::GovState::new(store, None).expect("gov constructs"));
        crate::test_support::TestApp::new().governance(gov).build()
    }

    #[test]
    fn entitlement_check_allows_a_target_the_grant_covers() {
        let key = scoped_key("k-1", Some(vec![busbar_api::ScopeRef::pool("fast")]));
        let app = app_with_key(&key);
        with_dispatch_scope(&app, |host, _vt| {
            let caller = caller_ref(b"k-1", 0);
            let target = target_ref(b"fast", 0); // scope_kind 0 = "pool"
            assert!(
                entitlement_check(host, &caller, &target),
                "the key's pool grant covers `fast` → entitled"
            );
        });
    }

    #[test]
    fn entitlement_check_denies_a_target_outside_the_grant() {
        let key = scoped_key("k-1", Some(vec![busbar_api::ScopeRef::pool("fast")]));
        let app = app_with_key(&key);
        with_dispatch_scope(&app, |host, _vt| {
            let caller = caller_ref(b"k-1", 0);
            let cold = target_ref(b"cold", 0); // pool the grant does NOT list
            assert!(
                !entitlement_check(host, &caller, &cold),
                "a pool the grant omits is denied"
            );
            // Cross-kind is fail-closed: a pool-only grant does not cover an mcp_server target.
            let server = target_ref(b"fast", 1); // scope_kind 1 = "mcp_server"
            assert!(!entitlement_check(host, &caller, &server));
            // An unknown caller id is denied.
            let stranger = caller_ref(b"nobody", 0);
            let fast = target_ref(b"fast", 0);
            assert!(!entitlement_check(host, &stranger, &fast));
        });
    }

    #[test]
    fn entitlement_check_fails_closed_on_null_and_no_governance() {
        // No governance → deny, and null PODs → deny, and a panic-free bare app.
        with_bare_app(|host| {
            let caller = caller_ref(b"k-1", 0);
            let target = target_ref(b"fast", 0);
            assert!(
                !entitlement_check(host, &caller, &target),
                "no governance → deny"
            );
            assert!(!entitlement_check(host, core::ptr::null(), &target));
            assert!(!entitlement_check(host, &caller, core::ptr::null()));
        });
    }

    // ── gate_scan: the real content-governance gate ─────────────────────────────────────────────

    #[test]
    fn gate_scan_continues_a_clean_chunk_with_no_gates() {
        with_bare_app(|host| {
            let chunk = content_chunk(b"hello world");
            assert_eq!(
                gate_scan(host, &chunk),
                GateDecision::Continue,
                "no gate is attached → the real decide proceeds → Continue"
            );
        });
    }

    #[test]
    fn gate_scan_blocks_a_null_chunk() {
        with_bare_app(|host| {
            assert_eq!(
                gate_scan(host, core::ptr::null()),
                GateDecision::Block,
                "a null chunk fails closed to Block"
            );
        });
    }

    /// A content gate that always REJECTS — the shape a real screening hook takes on a policy hit.
    struct RejectGate;

    #[async_trait::async_trait]
    impl crate::hooks::RoutingPolicy for RejectGate {
        async fn decide(
            &self,
            _req: &crate::hooks::RoutingRequest<'_>,
            _candidates: &[crate::hooks::Candidate<'_>],
            _ctx: &crate::hooks::RoutingContext<'_>,
            _budget: std::time::Duration,
        ) -> crate::hooks::PolicyResult {
            Ok(crate::hooks::RoutingDecision::Reject {
                status: 451,
                message: "screened".to_string(),
            })
        }
        fn name(&self) -> &'static str {
            "reject-gate"
        }
    }

    #[test]
    fn gate_scan_blocks_when_a_real_gate_rejects() {
        let gates: Vec<(u16, crate::hooks::ResolvedPolicy)> = vec![(
            0,
            crate::hooks::ResolvedPolicy::Policy {
                policy: Arc::new(RejectGate),
                on_error: crate::config::PolicyOnError::Reject,
                on_error_chain: Vec::new(),
                timeout: std::time::Duration::from_secs(5),
                send_prompt: true,
                send_user: false,
                on_empty: crate::config::PolicyOnError::Reject,
            },
        )];
        with_bare_app(|host| {
            let chunk = content_chunk(b"screen me");
            // Drive the seam body with a REAL rejecting gate through the REAL `hooks::gate::decide`.
            assert_eq!(
                gate_scan_inner(host, &chunk, &gates),
                GateDecision::Block,
                "a real gate Reject maps to Block through this seam"
            );
        });
    }
}
