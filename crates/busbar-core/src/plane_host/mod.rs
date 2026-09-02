// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plane_host` — the HOST side of the plane ABI: the construction point + lifecycle arena the
//! capability fan-out fills in.
//!
//! The HOT-lane ABI ([`busbar_plugin::hot`]) defines the `#[repr(C)] PlaneHostVtable` — the inbound
//! seam a plane calls BACK into core (`govern_admit`, `meter_charge`, `egress_open`, `clock_now`, …).
//! This module is core's HOST-SIDE implementation of that seam: it builds the vtable, recovers core's
//! own state from the opaque [`HostCtx`] the ABI threads through every call, and owns the per-dispatch
//! [`DispatchScope`] arena that reclaims every host handle a plane acquired when the dispatch ends.
//!
//! ADDITIVE and UNUSED: nothing in the engine calls the plane seam yet. Phase 2 wires the in-place
//! plane calls against [`with_dispatch_scope`]. After the Phase-1 capability fan-out (breaker,
//! govern, trust, journal, egress, dispatch) EVERY vtable slot is wired over a real primitive — no
//! `unimplemented!()` stub remains (see [`vtable`]). The shipped in-process `plane::host` seam is
//! untouched.
//!
//! ## The three pieces
//!
//! * [`HostState`] + [`recover`] — the `HostCtx` recovery invariant. The ABI hands every host call an
//!   opaque `HostCtx` (a `*mut c_void`); core recovers its [`HostState`] (the live `App` + the active
//!   [`DispatchScope`]) from it.
//! * [`scope`] — the [`DispatchScope`] arena (the leak keystone) plus the [`SessionScope`] /
//!   [`DurableScope`] stubs.
//! * [`vtable`] — [`build_plane_host_vtable`]; every slot wired (three proof-of-life fns here, the
//!   rest forwarding into the capability modules), zero stubs remaining.

pub mod breaker;
mod creds;
pub mod dispatch;
pub mod egress;
mod govern;
pub mod guard;
// The mTLS client-identity registry and the extra-root trust-anchor registry are PURE
// (process-atomic registries; no `App`, no engine, no FFI), so they live NEUTRALLY in
// `busbar_substrate::plane_host` and are re-exported here — core's egress chokepoint names the
// same `crate::plane_host::{identity, trust_anchor}` paths as before. The peer-SPKI DER walk's
// last in-core reader is gone with the engine cutover (the ENGINE computes the pin at connect
// and the chokepoint reads it off the response extensions), so `spki` is no longer re-exported;
// the A2A plane and the engine name the neutral `busbar_substrate::plane_host::spki` directly.
pub(crate) use busbar_substrate::plane_host::{identity, trust_anchor};
pub(crate) mod identity_admit;
pub mod journal;
pub mod pipe;
pub mod scope;
pub mod trust;
pub mod vtable;

pub use guard::{guard_url_over, GuardOutcome};
pub use scope::{DispatchScope, DurableScope, SessionScope};
pub use vtable::build_plane_host_vtable;

use crate::state::App;
use busbar_plugin::hot::host::{HostCtx, PlaneHostVtable};
use std::sync::Arc;

/// Core's own state behind the opaque [`HostCtx`] the plane ABI threads through every host call. A
/// plane never dereferences the `HostCtx`; it passes it back, and core recovers THIS via [`recover`].
///
/// Holds the live [`App`] (the config generation the dispatch was admitted on) and the per-invocation
/// [`DispatchScope`] arena. Borrowed, not owned: a `HostState` lives on the stack of the core frame
/// that opened the dispatch (see [`with_dispatch_scope`]) and outlives every host call made during it.
pub struct HostState<'a> {
    /// The live engine snapshot backing the host calls (governance, metrics, egress, … primitives).
    pub app: &'a App,
    /// The per-dispatch-invocation arena; every acquired host handle registers here and is reclaimed
    /// when this `HostState`'s owning scope drops.
    pub scope: &'a DispatchScope,
}

/// Recover core's [`HostState`] from the opaque [`HostCtx`] the plane handed back.
///
/// # Invariant
///
/// The host ALWAYS passes, as the `HostCtx` of every vtable call, exactly a `*const HostState` that is
/// LIVE for the entire dispatch duration — it is [`with_dispatch_scope`] that mints the `HostCtx` from
/// a stack `HostState` and keeps that `HostState` alive across the whole `f(host, &vtable)` call. The
/// plane never fabricates, mutates, or outlives the pointer (it only stores and returns it). Under that
/// invariant this is sound: the pointer is non-null, aligned, and points at a live `HostState` for a
/// lifetime the caller's frame bounds.
///
/// # Safety
///
/// `host` MUST be a `HostCtx` produced by [`with_dispatch_scope`] for a dispatch that is still on the
/// stack, per the invariant above. Calling with any other pointer is undefined behavior.
#[must_use]
pub unsafe fn recover<'a>(host: HostCtx) -> &'a HostState<'a> {
    debug_assert!(!host.is_null(), "HostCtx must never be null in a live call");
    // SAFETY: by the documented invariant `host` is a live `*const HostState` for the call's duration.
    unsafe { &*(host as *const HostState<'a>) }
}

/// Open a [`DispatchScope`], build the host vtable, and hand a plane a [`HostCtx`] + `&PlaneHostVtable`
/// for the duration of `f` — reclaiming every registered host handle when the scope ends. This is the
/// seam the in-place plane will dogfood in Phase 2 (it is ADDITIVE — nothing calls it yet).
///
/// The `HostState` is built on this frame's stack and its address becomes the `HostCtx`; it stays live
/// for the whole `f` call, satisfying [`recover`]'s invariant. When `f` returns (or unwinds), the
/// `DispatchScope` drops and [`DispatchScope::reclaim_all`] runs — so a dropped/cancelled dispatch
/// future never leaks a bare host handle (the HalfOpen-wedge bug).
pub fn with_dispatch_scope<R>(app: &App, f: impl FnOnce(HostCtx, &PlaneHostVtable) -> R) -> R {
    // Delegated to the owned [`HostDispatch`] guard so the SYNC seam and the ASYNC seam mint the exact
    // same `HostCtx` from the exact same stack-pinned `HostState` — one recovery invariant, two entry
    // shapes. `HostDispatch::new` allocates nothing (an empty `DispatchScope`), and the arena reclaim
    // still fires when the guard drops at the end of this call.
    HostDispatch::new(app).with_host(f)
}

/// Run `f` with a [`HostCtx`] + host `&PlaneHostVtable` materialized over a BORROWED `app` and an
/// EXISTING [`DispatchScope`] arena — the seam a sync plane leg uses to drive a host vtable slot while
/// REGISTERING acquired handles into the request-wide arena it already owns (e.g. the one threaded
/// through [`crate::mcp`]'s `Ctx::scope`), rather than a fresh per-call arena a [`HostDispatch`] would
/// mint. The `HostState` is stack-pinned for exactly the duration of `f` (the [`recover`] invariant);
/// the pointer must not escape it. Reclaim of the borrowed arena stays with WHOEVER owns it, not `f`.
pub fn with_borrowed_host<R>(
    app: &App,
    scope: &DispatchScope,
    f: impl FnOnce(HostCtx, &PlaneHostVtable) -> R,
) -> R {
    let state = HostState { app, scope };
    let vtable = build_plane_host_vtable();
    // The stack `HostState`'s address IS the opaque HostCtx; it outlives every call `f` makes.
    let host: HostCtx = (&state as *const HostState)
        .cast_mut()
        .cast::<std::os::raw::c_void>();
    let out = f(host, &vtable);
    let _keep_alive = &state;
    out
}

/// Sign a plane-framed agent-card signing input through the host [`card_sign`](vtable) seam,
/// returning the 64-byte Ed25519 signature. The card subkey is derived and held HOST-side (see
/// [`GovState::card_sign`](crate::governance::GovState::card_sign)); the caller passes only the bytes
/// to sign and receives only the signature — no signing material crosses to the plane. A SAFE wrapper
/// that keeps the raw fn-pointer + out-buffer read inside this audited module (busbar-core denies
/// `unsafe` elsewhere). `None` when this deployment holds no card-signing key (the `Refused` status).
#[must_use]
pub fn card_sign_over(app: &App, signing_input: &[u8]) -> Option<[u8; 64]> {
    let scope = DispatchScope::new();
    with_borrowed_host(app, &scope, |host, vt| {
        // The slot is wired whenever a plane declares a card-signing domain (`plane-a2a`) and `None`
        // otherwise (see the vtable's `subkey_sign`): an unwired slot signs nothing, so degrade to
        // `None` rather than panic — the trait method must exist unconditionally across every feature combo.
        let sign = vt.subkey_sign?;
        let mut out = [0u8; 64];
        let status = sign(
            host,
            signing_input.as_ptr(),
            signing_input.len(),
            out.as_mut_ptr(),
        );
        (status == busbar_plugin::hot::StatusClass::Ok).then_some(out)
    })
}

// The refusal-fidelity admit outcome is a pure POD naming only `busbar_plugin::hot` + std, so it now
// lives in the substrate beside the neutral `EngineHost` seam; core re-exports it so every in-core
// caller (`govern_admit_reason_over`, a2a) is unchanged.
pub use busbar_substrate::plane_host::GovAdmit;

/// Admit one unit of work over the host [`govern_admit_reason`](vtable) seam, REGISTERING the RAII
/// grant in `scope`'s arena on success and returning the RENDERED refusal reason on a blocked limit —
/// a SAFE wrapper that keeps the `#[repr(C)]` [`GovRefusal`](busbar_plugin::hot::GovRefusal) out-param
/// read inside this audited module (busbar-core denies `unsafe` everywhere else). The `Facts` carry the
/// caller's REAL `(identity_id, group)` and `tokens = budget_remaining = 0`, so the POD gate is a no-op
/// and the reconstructed chain is the sole decider — identical to the in-place `try_admit`.
#[must_use]
pub fn govern_admit_reason_over(
    app: &App,
    scope: &DispatchScope,
    pool: &[u8],
    identity_id: &[u8],
    group: Option<&[u8]>,
) -> GovAdmit {
    let mut reason_buf = [0u8; 512];
    let mut out = core::mem::MaybeUninit::<busbar_plugin::hot::GovRefusal>::uninit();
    let decision = with_borrowed_host(app, scope, |hctx, vt| {
        let facts =
            busbar_plugin::hot::Facts::with_attribution(0, 0, 0, 0, 0, pool, identity_id, group);
        (vt.govern_admit_reason
            .expect("govern_admit_reason is a wired slot"))(
            hctx,
            &*facts as *const busbar_plugin::hot::Facts,
            reason_buf.as_mut_ptr(),
            reason_buf.len(),
            std::ptr::from_mut(&mut out),
        )
    });
    if decision == busbar_plugin::hot::Decision::Admit {
        return GovAdmit::Admitted;
    }
    // SAFETY: the host ALWAYS initializes `out` up front (see `vtable::govern_admit_reason`), so it is
    // a live `GovRefusal` on every non-`Admit` return.
    let refusal = unsafe { out.assume_init() };
    let n = refusal.reason_len.min(reason_buf.len());
    GovAdmit::Blocked {
        reason: String::from_utf8_lossy(&reason_buf[..n]).into_owned(),
        retry_after_secs: refusal.retry_after_secs,
    }
}

/// Resolve INBOUND data-plane identity over the wired [`identity_admit`](vtable) seam: run the
/// configured auth chain + the ONE verdict resolution over the caller's OWN wire credential and the live
/// governance state, and reconstruct the resolved `(AuthPrincipal, PlaneRequestCtx)` — or the specific
/// [`IdentityRefusal`](crate::auth::IdentityRefusal) — from the host's answer. A SAFE wrapper that keeps
/// the `#[repr(C)]` [`IdentityAdmitted`](busbar_plugin::hot::IdentityAdmitted) out-param read and the
/// opaque-handle recovery inside this audited module, so a plane admits an inbound session without ever
/// naming `crate::auth`. Byte-identical to the in-process resolution: the resolved principal and gov
/// context are the EXACT objects the host produced (recovered through the opaque handle), and a refusal
/// keeps its exact variant.
///
/// The slot drives the ASYNC auth chain on a fresh current-thread runtime, so it is invoked from a
/// BLOCKING thread (`spawn_blocking`) — calling `block_on` on a runtime worker would panic. The bridge
/// is fail-closed: a join panic maps to [`IdentityRefusal::Denied`](crate::auth::IdentityRefusal),
/// exactly as a chain that could not run denies.
// Only the inbound stdio admission path consumes this seam today; a build whose planes resolve
// identity on their own door leaves it with no caller, hence the unconditional dead-code allow (the
// fn is always compiled — it backs the always-present `EngineHost::identity_admit` impl).
#[allow(dead_code)]
pub async fn identity_admit_over(
    app: Arc<App>,
    token: Option<String>,
    audience: String,
    resource: String,
) -> Result<
    (
        crate::auth::AuthPrincipal,
        crate::governance::PlaneRequestCtx,
    ),
    crate::auth::IdentityRefusal,
> {
    let guard = SendHostDispatch::new(app);
    tokio::task::spawn_blocking(move || {
        guard.with_host(|hctx, vt| {
            let token_bytes: &[u8] = token.as_deref().map(str::as_bytes).unwrap_or(&[]);
            let query = busbar_plugin::hot::IdentityQuery {
                size: core::mem::size_of::<busbar_plugin::hot::IdentityQuery>() as u32,
                version: busbar_plugin::hot::POD_VERSION,
                _reserved: 0,
                token_present: u32::from(token.is_some()),
                _reserved2: 0,
                token_ptr: token_bytes.as_ptr(),
                token_len: token_bytes.len(),
                audience_ptr: audience.as_ptr(),
                audience_len: audience.len(),
                resource_ptr: resource.as_ptr(),
                resource_len: resource.len(),
            };
            let mut out = core::mem::MaybeUninit::<busbar_plugin::hot::IdentityAdmitted>::uninit();
            let status = (vt.identity_admit.expect("identity_admit is a wired slot"))(
                hctx,
                &query as *const busbar_plugin::hot::IdentityQuery,
                std::ptr::from_mut(&mut out),
            );
            if status != busbar_plugin::hot::StatusClass::Ok {
                // A null query is impossible here (we pass a live POD); a runtime that will not start /
                // a caught panic fails closed to a refusal, never an admit.
                return Err(crate::auth::IdentityRefusal::Denied);
            }
            // SAFETY: the `Ok` status published the out-param (init-only-on-Ok).
            let admitted = unsafe { out.assume_init() };
            match admitted.outcome {
                busbar_plugin::hot::IdentityOutcome::Admitted => {
                    // Consume the opaque handle to recover the EXACT resolved (principal, gov). A handle
                    // that vanished (double-consume / eviction) fails closed to a refusal.
                    identity_admit::take(admitted.identity)
                        .ok_or(crate::auth::IdentityRefusal::Denied)
                }
                busbar_plugin::hot::IdentityOutcome::Denied => {
                    Err(crate::auth::IdentityRefusal::Denied)
                }
                busbar_plugin::hot::IdentityOutcome::NoGrant => {
                    Err(crate::auth::IdentityRefusal::NoGrant)
                }
            }
        })
    })
    .await
    .unwrap_or(Err(crate::auth::IdentityRefusal::Denied))
}

/// Read the host wall clock in whole SECONDS through the wired [`clock_now`](vtable) seam — the
/// host-driven form of a plane's [`crate::store::now`]. The slot's ABI unit is Unix NANOSECONDS
/// (see [`vtable`]'s `clock_now`, which scales the host milliseconds clock up), so this scales it
/// back down to the seconds `store::now` returns; the value is identical to reading `store::now`
/// in place. A fresh per-call [`DispatchScope`] backs the borrow — a clock read acquires no host
/// handle, so nothing outlives the call — mirroring [`card_sign_over`]. A SAFE wrapper that keeps
/// the raw fn-pointer read inside this audited module (busbar-core denies `unsafe` elsewhere).
#[must_use]
pub fn clock_now_secs_over(app: &App) -> u64 {
    let scope = DispatchScope::new();
    with_borrowed_host(app, &scope, |host, vt| {
        (vt.clock_now.expect("clock_now is a wired slot"))(host)
    }) / 1_000_000_000
}

/// Read the host wall clock in MILLISECONDS through the wired [`clock_now`](vtable) seam — the
/// host-driven form of [`crate::store::now_ms`]. The slot's ABI unit is Unix NANOSECONDS, sourced
/// host-side from `store::now_ms` scaled up; this scales it back to milliseconds, so the value is
/// identical to reading `store::now_ms` in place. `store::now_ms` is crate-private, so this is the
/// form a plane compiled apart from the host reaches the same clock through. Backed by a fresh
/// per-call [`DispatchScope`], as [`clock_now_secs_over`].
#[must_use]
pub fn clock_now_ms_over(app: &App) -> u64 {
    let scope = DispatchScope::new();
    with_borrowed_host(app, &scope, |host, vt| {
        (vt.clock_now.expect("clock_now is a wired slot"))(host)
    }) / 1_000_000
}

/// Synthesize ONE non-streaming chat completion by driving `body` through the ENTIRE resolved ingress
/// pipeline over the live `app`, returning the raw wire outcome — the core-resident veneer behind
/// [`EngineHost::synthesize_completion`](busbar_substrate::plane_host::EngineHost::synthesize_completion).
/// This is the ONLY place the `ingress::operation_resolved` + `handlers::chat` + `proxy::LazyBody`
/// reaches now live: an extracted plane hands a NEUTRAL request (gov + model + body bytes) and gets a
/// NEUTRAL [`HostCompletion`](busbar_substrate::plane_host::HostCompletion) (status + body bytes) back,
/// never naming a core type.
///
/// A line-for-line lift of the former `mcp::sampling::complete`'s pre-response body: the argument
/// tuple handed to `operation_resolved` is preserved BYTE-IDENTICALLY — the chat `proto` is the
/// registry's residual-default dialect (read by NAME, so this neutral core spells none),
/// [`Transport::Http`](crate::transport::Transport), the `handlers::chat(proto, Http)` op,
/// `caller_token = None`, `model_not_found_message = None`, `charged_at = crate::store::now()` (whole
/// SECONDS, the same source [`clock_now_secs_over`] scales to), and `LazyBody::parse` over the SAME
/// bytes — so governance attribution and metering are unchanged. The async future stays `Send`: it
/// only `.await`s the native core async fn; no `HostCtx` is minted here, and any minted inside
/// `operation_resolved`'s own frames is consumed there, never crossing this `.await`.
#[allow(dead_code)]
pub async fn synthesize_completion_over(
    app: Arc<App>,
    gov: &crate::governance::PlaneRequestCtx,
    model: &str,
    body: bytes::Bytes,
    max_body_bytes: usize,
) -> Result<busbar_substrate::plane_host::HostCompletion, String> {
    // FRESH headers, not the inbound request's: the caller's own headers carry affinity keys and
    // per-request parameters addressed to the caller's request, and replaying them onto a leg the
    // caller did not compose would let one exchange steer another.
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    // The resolved-completion synthesizer (`operation_resolved` over the residual-default chat
    // dialect, `LazyBody::parse` over these bytes, `model` explicit, `caller_token = None`) reads the
    // LLM routing tables and RELOCATED into the LLM plane; core reaches it through the neutral
    // resolved-completion seam, threading `App`/`GovCtx` back opaquely as [`ArrivalCtx`]. `None` is
    // the all-planes-off deletion configuration: with no LLM plane installed there is no chat dialect
    // to drive, and the caller gets that as an error rather than a hard-coded protocol identity.
    let Some(synth) = busbar_substrate::ingress::arrival::completion_ingress() else {
        return Err("no default chat protocol is installed".to_string());
    };
    let ctx = busbar_substrate::ingress::arrival::ArrivalCtx::new(
        crate::ingress::arrival_host::ArrivalPayload {
            app,
            gov: gov.clone(),
            caller_token: None,
        },
    );
    let response = synth(busbar_substrate::ingress::arrival::CompletionArrival {
        ctx,
        model: model.to_string(),
        headers,
        body,
    })
    .await;
    let status = response.status().as_u16();
    let body = axum::body::to_bytes(response.into_body(), max_body_bytes)
        .await
        .map_err(|e| format!("the sampling completion's body could not be read: {e}"))?;
    Ok(busbar_substrate::plane_host::HostCompletion { status, body })
}

/// Core's implementation of the neutral [`EngineHost`](busbar_substrate::plane_host::EngineHost)
/// seam over the live [`App`]. A plane holds this behind an
/// `Arc<dyn busbar_substrate::plane_host::EngineHost>` and calls typed, safe methods on it INSTEAD of
/// naming `plane_host::*_over(&App, …)` — so a plane compiled apart from the host reaches the same
/// host vtable slots without ever naming a core type.
///
/// Owns an `Arc<App>` (the config generation the reaches run against) so the handle is
/// `Send + Sync + 'static` and safe to carry across `.await`. That is sound precisely because no
/// method exposes the `!Send` [`HostCtx`]: each mints the transient `HostCtx` INTERNALLY (via
/// [`with_borrowed_host`] over a fresh per-call [`DispatchScope`]), drives the slot SYNCHRONOUSLY,
/// and returns an owned value — the raw host pointer never escapes the call.
pub struct EngineHostImpl {
    /// The BOUND engine snapshot the host reaches run against — loaded once at mint. Serves
    /// `plane_slot` and every existing method, byte-identically to the pre-`handle` host.
    app: Arc<App>,
    /// The LIVE handle, retained so `plane_slot_live` re-reads the CURRENT snapshot after a config
    /// swap. `None` for a snapshot-only mint (the `Fn(&Arc<App>)` factory / [`new`](Self::new)), where
    /// the bound snapshot is the only snapshot the host was ever handed.
    handle: Option<Arc<crate::state::AppHandle>>,
}

impl EngineHostImpl {
    /// Build the host implementation over the live `app` — a SNAPSHOT-ONLY mint (no live handle, so
    /// `plane_slot_live` degrades to the bound snapshot).
    #[must_use]
    pub fn new(app: Arc<App>) -> Self {
        EngineHostImpl { app, handle: None }
    }

    /// Build the host over a live [`AppHandle`](crate::state::AppHandle): the bound snapshot is the
    /// handle's CURRENT load (keeping frozen-snapshot semantics byte-identical to `new(handle.load())`),
    /// and the handle is retained so `plane_slot_live` sees a later config swap.
    #[must_use]
    pub fn from_handle(handle: Arc<crate::state::AppHandle>) -> Self {
        EngineHostImpl {
            app: handle.load(),
            handle: Some(handle),
        }
    }
}

#[async_trait::async_trait]
impl busbar_substrate::plane_host::EngineHost for EngineHostImpl {
    fn clock_now_secs(&self) -> u64 {
        // SAME dispatch as the veneer: a fresh per-call `DispatchScope`, the `clock_now` slot driven
        // synchronously over a stack-pinned `HostState`, the `HostCtx` never escaping the call.
        clock_now_secs_over(&self.app)
    }

    fn clock_now_ms(&self) -> u64 {
        clock_now_ms_over(&self.app)
    }

    fn gate_decide(
        &self,
        plane_key: &str,
        container: &str,
        request_id: u64,
        tool: &str,
        args_json: &[u8],
        key: Option<(&str, &str)>,
        session_id: Option<&str>,
    ) -> busbar_substrate::plane_host::GateOutcome {
        gate_decide_over(
            &self.app, plane_key, container, request_id, tool, args_json, key, session_id,
        )
    }

    fn govern_admit_reason(
        &self,
        scope: &DispatchScope,
        pool: &[u8],
        identity_id: &[u8],
        group: Option<&[u8]>,
    ) -> busbar_substrate::plane_host::GovAdmit {
        govern_admit_reason_over(&self.app, scope, pool, identity_id, group)
    }

    fn quarantine_settle(&self, subject: &str, state: crate::trust::TrustState) -> bool {
        trust::quarantine_settle_over(&self.app, subject, state)
    }

    fn meter_charge(&self, scope: &DispatchScope, usage: &busbar_plugin::hot::Usage) {
        // SAME dispatch as the in-place `with_borrowed_host` meter the plane's round-charge drove: mint
        // the transient `HostCtx` over the caller's arena, fire the `meter_charge` slot, and drop the
        // host pointer without letting it escape. Fire-and-forget, exactly as the direct call was.
        with_borrowed_host(&self.app, scope, |host, vt| {
            let _ = (vt.meter_charge.expect("meter_charge is a wired slot"))(
                host,
                usage as *const busbar_plugin::hot::Usage,
            );
        });
    }

    fn breaker_admit(
        &self,
        scope: &DispatchScope,
        pool: &[u8],
        lane: u32,
    ) -> Result<busbar_plugin::hot::AdmissionId, crate::store::Unavailable> {
        breaker::breaker_admit_over(&self.app, scope, pool, lane)
    }

    fn breaker_settle(
        &self,
        scope: &DispatchScope,
        admission: busbar_plugin::hot::AdmissionId,
        signal: &busbar_plugin::hot::Signal,
    ) -> busbar_plugin::hot::StatusClass {
        // SAME dispatch as the in-place `with_borrowed_host` settle the plane's sync leg drove: mint
        // the transient `HostCtx` over the caller's arena, fold the leg through the `breaker_settle`
        // slot, and return the class — the raw host pointer never escapes the call.
        with_borrowed_host(&self.app, scope, |host, vt| {
            (vt.breaker_settle.expect("breaker_settle is a wired slot"))(
                host,
                admission,
                signal as *const busbar_plugin::hot::Signal,
            )
        })
    }

    fn breaker_record_success(&self, pool: &str, lane: usize) {
        self.app.plane_breakers.record_success(pool, lane);
    }

    fn breaker_record_signal(
        &self,
        pool: &str,
        lane: usize,
        sig: &busbar_substrate::breaker::CanonicalSignal,
    ) {
        self.app.plane_breakers.record_signal(pool, lane, sig);
    }

    fn breaker_retry_after_secs(&self, pool: &str, lane: usize) -> u64 {
        self.app.plane_breakers.retry_after_secs(pool, lane)
    }

    fn approval_redeem(&self, nonce: &str, expires_at: u64, now: u64) -> bool {
        // A fresh per-call arena backs the borrow; the redemption registers no host handle, so which
        // arena reclaims is immaterial. The `ApprovalQuery` is built HERE so the plane passes only the
        // nonce/expiry/now — it never names the `#[repr(C)]` POD or the `SpentTokenLedger`.
        let scope = DispatchScope::new();
        with_borrowed_host(&self.app, &scope, |host, _vt| {
            let query = busbar_plugin::hot::ApprovalQuery {
                size: core::mem::size_of::<busbar_plugin::hot::ApprovalQuery>() as u32,
                version: busbar_plugin::hot::POD_VERSION,
                _reserved: 0,
                scope: 0,
                _reserved2: 0,
                expires_at,
                now,
                key_ptr: nonce.as_ptr(),
                key_len: nonce.len(),
            };
            trust::approval_redeem_q(host, &query as *const busbar_plugin::hot::ApprovalQuery)
                == busbar_plugin::hot::StatusClass::Ok
        })
    }

    fn next_request_id(&self) -> u64 {
        self.app.next_request_id()
    }

    fn request_finished(
        &self,
        plane: &str,
        ingress_protocol: &str,
        pool: &str,
        outcome: &'static str,
        seconds: f64,
    ) {
        // Same frozen-snapshot semantics as every sibling: the completion is stamped against the BOUND
        // snapshot this host was minted over, byte-identically to the plane's own in-place call.
        crate::telemetry::request_finished(
            &self.app,
            plane,
            ingress_protocol,
            pool,
            outcome,
            seconds,
        );
    }

    fn telemetry_upstream_attempt(&self, pool_label: &str, lane: usize) {
        crate::telemetry::upstream_attempt(&self.app, pool_label, lane);
    }

    fn telemetry_upstream_failure(&self, pool_label: &str, lane: usize, disposition: &'static str) {
        crate::telemetry::upstream_failure(&self.app, pool_label, lane, disposition);
    }

    fn telemetry_breaker_trip(&self, pool_label: &str, lane: usize) {
        crate::telemetry::breaker_trip(&self.app, pool_label, lane);
    }

    fn telemetry_failover(&self, pool_label: &str, reason: &'static str) {
        crate::telemetry::failover(&self.app, pool_label, reason);
    }

    fn telemetry_translation(&self, from: &str, to: &str) {
        crate::telemetry::translation(from, to);
    }

    fn pool_label<'a>(&self, model: &'a str) -> &'a str {
        crate::ingress::pool_label(&self.app, model)
    }

    fn destination_guard(
        &self,
        gov: &busbar_api::PlaneRequestCtx,
        proto: &'static str,
        pool: &str,
        started: std::time::Instant,
        charged_at: u64,
    ) -> Result<(), Box<axum::response::Response>> {
        crate::ingress::destination_guard(&self.app, gov, proto, pool, started, charged_at)
    }

    fn finish_admitted(
        &self,
        gov: &busbar_api::PlaneRequestCtx,
        ingress_protocol: &str,
        pool: &str,
        started: std::time::Instant,
        charged_at: u64,
        resp: axum::response::Response,
        charged: bool,
    ) -> axum::response::Response {
        crate::ingress::finish_admitted(
            &self.app,
            gov,
            ingress_protocol,
            pool,
            started,
            charged_at,
            resp,
            charged,
        )
    }

    fn finish_rejected(
        &self,
        gov: &busbar_api::PlaneRequestCtx,
        ingress_protocol: &str,
        pool: &str,
        started: std::time::Instant,
        charged_at: u64,
        resp: axum::response::Response,
    ) -> axum::response::Response {
        crate::ingress::finish_rejected(
            &self.app,
            gov,
            ingress_protocol,
            pool,
            started,
            charged_at,
            resp,
        )
    }

    fn governance_enabled(&self) -> bool {
        self.app.governance.is_some()
    }

    fn lane_store(&self) -> &dyn busbar_substrate::store::LaneRuntime {
        // A pure borrow of the bound snapshot's store: `App::store` is `Arc<dyn LaneRuntime>` where
        // `LaneRuntime` is re-exported from `busbar_substrate::store` (wedge 1), so the returned
        // trait object IS the substrate one — byte-identical to the engine's `&*app.store`.
        &*self.app.store
    }

    fn default_probe_interval_secs(&self) -> u64 {
        crate::limits::default_probe_interval_secs()
    }

    fn default_probe_timeout_secs(&self) -> u64 {
        crate::limits::default_probe_timeout_secs()
    }

    fn caller_in_hook_groups(&self, caller_group: Option<&str>, hook_groups: &[String]) -> bool {
        // Fold the `&App::groups_registry` argument host-side; the walk itself is byte-identical.
        crate::config::caller_in_hook_groups(caller_group, hook_groups, &self.app.groups_registry)
    }

    // ── HOOK/CONFIG FACADE READS (App-retype WEDGE 2d) — each a pure borrow of the bound snapshot ──

    fn pool_rewrites(
        &self,
        pool: &str,
    ) -> &[(std::time::Duration, Arc<dyn busbar_api::RoutingPolicy>)] {
        // `App::pool_rewrites` already returns the neutral api tuple slice; byte-identical borrow.
        self.app.pool_rewrites(pool)
    }

    fn rewrite_hooks(&self) -> &[(std::time::Duration, Arc<dyn busbar_api::RoutingPolicy>)] {
        &self.app.rewrite_hooks
    }

    fn any_content_hook(&self) -> bool {
        self.app.any_content_hook
    }

    fn tap_hooks(&self) -> &[busbar_substrate::hooks::TapEntry] {
        &self.app.tap_hooks
    }

    fn tap_hooks_response(&self) -> &[busbar_substrate::hooks::TapEntry] {
        &self.app.tap_hooks_response
    }

    fn tap_hooks_routing(&self) -> &[busbar_substrate::hooks::TapEntry] {
        &self.app.tap_hooks_routing
    }

    fn tap_hooks_candidate(&self) -> &[busbar_substrate::hooks::TapEntry] {
        &self.app.tap_hooks_candidate
    }

    fn pool_gates(&self, pool: &str) -> &[(u16, busbar_substrate::hooks::ResolvedPolicy)] {
        self.app.pool_gates(pool)
    }

    fn global_gates(&self) -> &[(u16, busbar_substrate::hooks::ResolvedPolicy)] {
        &self.app.global_gates
    }

    fn pool_policy(&self, pool: &str) -> Option<&busbar_substrate::hooks::ResolvedPolicy> {
        self.app.pool_policy(pool)
    }

    fn requested_signals(&self) -> &busbar_substrate::hooks::RequestedSignals {
        &self.app.requested_signals
    }

    fn rate_headroom(
        &self,
        gov: &busbar_substrate::plane_host::GovHandle,
        cost: &busbar_substrate::plane_host::CostHandle,
        key: &busbar_api::VirtualKey,
        pool: Option<&str>,
        now: u64,
    ) -> Option<f64> {
        // Recover the concrete gov/cost the caller's handles were minted from and drive the SAME pure
        // observation `gov.rate_headroom(&app.cost, …)` did — byte-identical, no re-read of the host
        // snapshot. A downcast miss (never in practice) reads as no constraint, matching the
        // `gov`-absent arm at the engine call site.
        let (Ok(g), Ok(c)) = (
            gov.0.clone().downcast::<crate::governance::GovState>(),
            cost.0.clone().downcast::<crate::cost::CostModel>(),
        ) else {
            return None;
        };
        g.rate_headroom(&c, key, pool, now)
    }

    fn budget_state(
        &self,
        gov: &busbar_substrate::plane_host::GovHandle,
        cost: &busbar_substrate::plane_host::CostHandle,
        key: &busbar_api::VirtualKey,
        now: u64,
    ) -> Vec<busbar_api::BudgetBucketState> {
        let (Ok(g), Ok(c)) = (
            gov.0.clone().downcast::<crate::governance::GovState>(),
            cost.0.clone().downcast::<crate::cost::CostModel>(),
        ) else {
            return Vec::new();
        };
        g.budget_state(&c, key, now)
    }

    fn default_max_tokens(&self) -> u32 {
        self.app.default_max_tokens
    }

    fn reasoning_effort_budgets(&self) -> &[u32; 4] {
        &self.app.reasoning_effort_budgets
    }

    fn governance(&self) -> Option<busbar_substrate::plane_host::GovHandle> {
        // One Arc bump, erased to `dyn Any` — byte-identical to the sink's `app.governance.clone()`.
        self.app
            .governance
            .clone()
            .map(|g| busbar_substrate::plane_host::GovHandle(g as Arc<dyn std::any::Any + Send + Sync>))
    }

    fn cost(&self) -> busbar_substrate::plane_host::CostHandle {
        busbar_substrate::plane_host::CostHandle(
            self.app.cost.clone() as Arc<dyn std::any::Any + Send + Sync>
        )
    }

    fn meter_ledger(
        &self,
        gov: &busbar_substrate::plane_host::GovHandle,
        cost: &busbar_substrate::plane_host::CostHandle,
        key: &busbar_api::VirtualKey,
        pool: &str,
        model: &str,
        tokens: &busbar_api::TierTokens,
        now: u64,
    ) {
        // Recover the concrete gov/cost the plane's sink minted these handles from and drive the SAME
        // accrual `sink.gov.record_usage(&sink.cost, …)` did — byte-identical, no re-read of the host
        // snapshot. A downcast miss (never in practice — the handles are minted here) is a silent no-op,
        // matching `record_usage`'s own fail-soft posture.
        if let (Ok(g), Ok(c)) = (
            gov.0.clone().downcast::<crate::governance::GovState>(),
            cost.0.clone().downcast::<crate::cost::CostModel>(),
        ) {
            g.record_usage(&c, key, pool, model, tokens, now);
        }
    }

    fn meter_series(
        &self,
        gov: &busbar_substrate::plane_host::GovHandle,
        key_id: &str,
        model: &str,
        provider: &str,
        usage: Option<&busbar_substrate::billing::TokenUsage>,
        now: u64,
    ) {
        if let Ok(g) = gov.0.clone().downcast::<crate::governance::GovState>() {
            g.record_metering(key_id, model, provider, usage, now);
        }
    }

    fn admission_door(
        &self,
        gov: &busbar_api::PlaneRequestCtx,
        proto: &'static str,
        pool: &str,
        started: std::time::Instant,
        charged_at: u64,
    ) -> Result<
        (Option<busbar_substrate::plane_host::AdmitHandle>, Option<String>),
        Box<axum::response::Response>,
    > {
        // Byte-identical to the in-place door (`GovCtx` IS `PlaneRequestCtx`); the produced `AdmitGrant`
        // is wrapped in the opaque `AdmitHandle` the plane's sink holds Drop-only. The `Arc::new` here
        // mirrors the engine's own `admit.map(Arc::new)` at the sink-build site.
        crate::ingress::admission_door(&self.app, gov, proto, pool, started, charged_at).map(
            |(admit, downgraded)| {
                (
                    admit.map(|a| {
                        busbar_substrate::plane_host::AdmitHandle(
                            Arc::new(a) as Arc<dyn std::any::Any + Send + Sync>
                        )
                    }),
                    downgraded,
                )
            },
        )
    }

    fn plane_slot(&self, key: &str) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        // Pure map read + Arc clone, mirroring next_request_id: no HostCtx, no vtable slot.
        self.app.plane_slot(key).cloned()
    }

    fn plane_slot_live(&self, key: &str) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        match &self.handle {
            // Re-read the CURRENT snapshot so a swap after mint is seen.
            Some(h) => h.load().plane_slot(key).cloned(),
            // Snapshot-only mint: the bound snapshot is the only snapshot this host was handed.
            None => self.app.plane_slot(key).cloned(),
        }
    }

    fn tool_pool_members(&self, server: &str) -> Option<(String, Vec<String>, Vec<String>)> {
        self.app
            .tool_pools
            .iter()
            .find(|(_, cfg)| cfg.members.iter().any(|m| m == server))
            .map(|(name, cfg)| (name.clone(), cfg.members.clone(), cfg.repeatable.clone()))
    }

    fn gate_attached(&self, plane_key: &str, container: &str) -> bool {
        // Pure snapshot read of the generic per-plane gate map, keyed by the opaque registry key.
        self.app
            .plane_gates(plane_key)
            .is_some_and(|g| g.contains_key(container))
    }

    fn plane_pool_members(&self, plane_key: &str, member: &str) -> Option<(String, Vec<String>)> {
        // Scan the plane's failover pool map for the pool `member` belongs to and return its name +
        // members (the walk derives lanes from member position). A pure snapshot read over the generic
        // per-plane pool map, keyed by the opaque registry key.
        self.app
            .plane_pools(plane_key)?
            .iter()
            .find(|(_, cfg)| cfg.members.iter().any(|m| m == member))
            .map(|(name, cfg)| (name.clone(), cfg.members.clone()))
    }

    fn plane_audience_bound(&self, plane_key: &str) -> bool {
        // Pure snapshot read: is the plane identified by the opaque registry key mounted under an
        // audience-bound door?
        self.app
            .planes
            .mount_of(plane_key)
            .and_then(|m| self.app.planes.admission_for(m))
            .is_some()
    }

    fn secret_resolver(&self) -> Arc<dyn busbar_api::SecretResolve> {
        // Pure snapshot read: hand the plane the live `Arc<SecretResolver>` behind the neutral
        // `busbar_api::SecretResolve` seam. The concrete resolver impls the trait (same crate), so the
        // clone coerces to the trait object — no wrapping, the SAME resolver (built-ins + any wired
        // `kind: secret` plugin), fail-closed exactly as core resolution.
        self.app.secret_resolver.clone()
    }

    fn card_sign(&self, signing_input: &[u8]) -> Option<[u8; 64]> {
        // SAME dispatch as the veneer: a fresh per-call `DispatchScope`, the `card_sign` slot driven
        // synchronously over a stack-pinned `HostState`, the `HostCtx` never escaping the call. `None`
        // when no card-signing key is held (or, in a build without `plane-a2a`, the slot is unwired).
        card_sign_over(&self.app, signing_input)
    }

    fn agent_defs(&self) -> Arc<dyn std::any::Any + Send + Sync> {
        // Pure snapshot read: the type-erased per-plane config the owning plane downcasts, cloned so it
        // outlives the call. Already an `Arc<dyn Any + Send + Sync>` on `App`, so the clone is the whole seam.
        self.app.agent_defs.clone()
    }

    fn audit_emit(&self, action: &str, resource: &str, outcome: &str, principal: &str) {
        // Hostless: the admin-audit engine reads `store::now` + the global ring and needs no `HostCtx`.
        // A plain forward to the UNCHANGED core engine.
        crate::plane::auditlog::emit_admin_hostless_now(action, resource, outcome, principal);
    }

    fn call_log_emit(&self, principal: &str, input: busbar_substrate::plane::calllog::CallInput) {
        // Mint a fresh per-call arena over the live engine and drive the chain seam SYNCHRONOUSLY — the
        // `HostCtx` never escapes the call. The plane's former `Some(scope)`/`None` selection (reuse the
        // request arena vs open a fresh one) was a no-op distinction for THIS write: a chain append
        // registers no host handle, so which arena reclaims is immaterial. Same dispatch as the plane's
        // in-place `with_dispatch_scope` leg.
        with_dispatch_scope(&self.app, |host, _| {
            crate::calllog::emit(host, principal, input)
        });
    }

    fn call_log_emit_hostless(
        &self,
        principal: &str,
        input: busbar_substrate::plane::calllog::CallInput,
    ) {
        crate::calllog::emit_hostless(principal, input);
    }

    fn identity_audience_binding(
        &self,
        token: &str,
        expected_aud: &str,
    ) -> busbar_substrate::plane_host::AudienceBinding {
        // A pure judgement — no `HostCtx`, no engine state. `inspect_bearer` returns the enum this
        // trait method's type re-exports, so this is a direct forward to the UNCHANGED core seam.
        crate::auth::audience::inspect_bearer(token, expected_aud)
    }

    async fn identity_admit(
        &self,
        token: Option<String>,
        audience: String,
        resource: String,
    ) -> Result<(busbar_api::AuthPrincipal, busbar_api::PlaneRequestCtx), busbar_api::IdentityRefusal>
    {
        // The veneer already spawns a blocking closure that mints + consumes the `HostCtx` on a
        // blocking thread; this only awaits the join, so no `HostCtx` crosses the `.await` and the
        // future stays `Send`.
        identity_admit_over(Arc::clone(&self.app), token, audience, resource).await
    }

    fn principal_standing(
        &self,
        standing: &busbar_substrate::trust::validate::Standing,
        live_gen: u64,
        now: u64,
    ) -> Result<Option<Arc<busbar_api::VirtualKey>>, busbar_substrate::trust::validate::Lapsed>
    {
        // Inject the host's live `GovState` through the `GovResolve` seam so the plane holds only the
        // `Standing`. Byte-identical to the pre-relocation `Standing::still_permitted(app.governance, …)`.
        standing.still_permitted(
            self.app
                .governance
                .as_deref()
                .map(|g| g as &dyn busbar_substrate::trust::validate::GovResolve),
            live_gen,
            now,
        )
    }

    fn ask_state_sealer(&self) -> Option<busbar_substrate::plane::approvals::Sealer> {
        self.app
            .governance
            .as_ref()
            .and_then(|g| crate::plane::approvals::ask_state_sealer(g))
    }

    async fn synthesize_completion(
        &self,
        gov: &busbar_api::PlaneRequestCtx,
        model: &str,
        body: bytes::Bytes,
        max_body_bytes: usize,
    ) -> Result<busbar_substrate::plane_host::HostCompletion, String> {
        // The veneer keeps the `ingress::operation_resolved` + `handlers::chat` + `proxy::LazyBody`
        // reaches in core; it only `.await`s the native async fn, so no `HostCtx` crosses the
        // `.await` and the future stays `Send`.
        synthesize_completion_over(Arc::clone(&self.app), gov, model, body, max_body_bytes).await
    }
}

/// Mint an `Arc<dyn EngineHost>` over the live `app` — the constructor core hands a plane so the
/// plane calls the neutral seam instead of naming `plane_host::*_over(&App, …)`. Cheap: one `Arc`
/// clone; the transient `HostCtx` is minted per method call, never here.
#[must_use]
pub fn engine_host(app: &Arc<App>) -> Arc<dyn busbar_substrate::plane_host::EngineHost> {
    Arc::new(EngineHostImpl::new(Arc::clone(app)))
}

/// THE ALLOC-FREE BORROWED HOST CARRIER (1.6.0 KEYSTONE): an owned [`EngineHost`] value the caller
/// keeps on its STACK and coerces to `&dyn EngineHost`, so a plane reaches the host seam WITHOUT the
/// per-request `Arc::new` heap allocation [`engine_host`] pays. The whole cost is one `Arc::clone` of
/// the snapshot (an atomic refcount bump — NOT a heap allocation, so it never touches the engine's
/// alloc-gate count), and the `&dyn` coercion of the stack value allocates nothing. Returned opaque
/// (`impl EngineHost`) so the plane names no core type. The two async seam methods
/// (`identity_admit`/`synthesize_completion`) still work — they `Arc::clone` internally — but the
/// engine hot path calls only the SYNC methods, so this borrowed carrier is the right one there.
#[must_use]
pub fn engine_host_value(app: &Arc<App>) -> impl busbar_substrate::plane_host::EngineHost + 'static {
    EngineHostImpl::new(Arc::clone(app))
}

/// Mint an `Arc<dyn EngineHost>` over the CURRENT snapshot of a live [`AppHandle`] — the form the
/// route adapter and the detached-runner / stdio paths reach for, which hold a swappable handle
/// rather than a pinned `Arc<App>`. Loads the handle once; the clock the seam reads is engine-snapshot
/// independent (it drives the host wall clock), so a later config swap does not change the value.
#[must_use]
pub fn engine_host_from_handle(
    handle: &Arc<crate::state::AppHandle>,
) -> Arc<dyn busbar_substrate::plane_host::EngineHost> {
    // `from_handle` (not `engine_host(&handle.load())`): retains the live handle so `plane_slot_live`
    // re-reads the CURRENT snapshot on the route/detached-runner/stdio paths, which must see a config
    // swap that lands after admission. The bound snapshot stays `handle.load()` — byte-identical.
    Arc::new(EngineHostImpl::from_handle(Arc::clone(handle)))
}

/// Mint a NEUTRAL [`LiveHostFactory`](busbar_substrate::plane_host::LiveHostFactory) closing over a live
/// [`AppHandle`](crate::state::AppHandle): each call returns a fresh `from_handle` host whose BOUND
/// snapshot is the handle's CURRENT load and whose `plane_slot_live` re-reads the live handle — so a
/// transport that re-mints per frame sees a config swap that lands between calls. Byte-identical to
/// calling [`engine_host_from_handle`] on each frame, handed to a plane that must not name the handle.
#[must_use]
pub fn live_host_factory(
    handle: std::sync::Arc<crate::state::AppHandle>,
) -> busbar_substrate::plane_host::LiveHostFactory {
    std::sync::Arc::new(move || {
        std::sync::Arc::new(EngineHostImpl::from_handle(std::sync::Arc::clone(&handle)))
            as Arc<dyn busbar_substrate::plane_host::EngineHost>
    })
}

/// A neutral, reusable HOST FACTORY: an owned closure that mints an `Arc<dyn EngineHost>` over any live
/// `Arc<App>` handed to it. Threaded from a non-route transport's core BOOT boundary (e.g. the `busbar`
/// binary's stdio start) into a plane that must re-mint the host over its per-frame LIVE snapshot, so the
/// plane calls the neutral seam WITHOUT ever naming this `plane_host` factory. Each mint is one `Arc`
/// clone; the transient `HostCtx` is minted per method call on the returned host, never here.
pub type EngineHostFactory =
    Arc<dyn Fn(&Arc<App>) -> Arc<dyn busbar_substrate::plane_host::EngineHost> + Send + Sync>;

/// Mint the neutral [`EngineHostFactory`] — the closure a non-route transport boot threads into a plane.
#[must_use]
pub fn engine_host_factory() -> EngineHostFactory {
    Arc::new(|app: &Arc<App>| engine_host(app))
}

/// Read the host wall clock in whole SECONDS through the wired [`clock_now`](vtable) seam using a
/// [`HostCtx`] the caller ALREADY holds — the form a plane leg that was handed a raw host (over
/// [`with_borrowed_host`] / a [`HostDispatch`]) but has no `&App` in scope to mint a fresh
/// [`DispatchScope`] reaches the same clock through. It builds the host vtable and drives the
/// `clock_now` slot against the caller's live host directly (the slot recovers and discards the
/// [`HostState`], so no scope is minted); the value is identical to [`clock_now_secs_over`] and to
/// reading `store::now` in place. A SAFE wrapper that keeps the raw fn-pointer read inside this
/// audited module (busbar-core denies `unsafe` elsewhere).
// Always compiled — the body drives only the neutral host vtable, so it needs no plane feature; a
// build whose planes never hand a raw host to a hostless leg simply leaves it uncalled (dead-code
// allowed).
#[allow(dead_code)]
#[must_use]
pub fn clock_now_secs_via(host: HostCtx) -> u64 {
    let vtable = build_plane_host_vtable();
    (vtable.clock_now.expect("clock_now is a wired slot"))(host) / 1_000_000_000
}

// The request-admission gate verdict is a pure POD naming only `busbar_plugin::hot` + std, so it now
// lives in the substrate beside the neutral `EngineHost` seam; core re-exports it so every in-core
// caller (`gate_decide_over`, a2a) is unchanged.
pub use busbar_substrate::plane_host::GateOutcome;

/// Fire the operator's REQUEST-ADMISSION hook gates over the wired [`gate_decide`](vtable) seam and
/// reconstruct the [`GateOutcome`] — so an MCP/A2A plane body admits a request through its
/// `tools.hooks:` / `agents.hooks:` gates without ever naming `crate::hooks::gate::decide` or holding the
/// resolved `ResolvedPolicy` set (the host owns and re-selects it by `(plane_key, container)`). A SAFE
/// wrapper that keeps the `#[repr(C)]` [`GateVerdictOut`](busbar_plugin::hot::GateVerdictOut) out-param
/// read + the two copy-out buffers inside this audited module (busbar-core denies `unsafe` elsewhere).
///
/// Byte-identical to the in-process firing site: the host reconstructs the same `InvokeReq`-shaped facts
/// (`tool` + the caller's `arguments` JSON, which round-trips losslessly because `serde_json`'s
/// `preserve_order` is OFF), the same key identity (`id`/`name`), and the same incremental-scan session
/// substrate, and runs the SAME gate decision.
///
/// The slot drives the ASYNC gate on a fresh current-thread runtime, so it MUST be invoked from a
/// BLOCKING thread (`spawn_blocking`) — calling `block_on` on a runtime worker would panic. Fail-closed:
/// the host ALWAYS initializes the out-param to a 403 reject, so a null subject or a caught panic
/// reconstructs a `Reject` (an empty message/hook), exactly as a gate that could not run refuses.
///
/// `plane_key` is the plane's stable decl key; the host resolves it to the ABI registration INDEX for
/// the POD (see [`crate::plane::registry::plane_key_index`]) and the vtable slot resolves the index
/// back to the key to select the gate set and the `ingress_protocol` label — no hard-coded numbering,
/// no plane token. `key` is the caller's resolved `(id, name)`; `session_id` is the caller's session,
/// `Some` only when non-empty.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn gate_decide_over(
    app: &App,
    plane_key: &str,
    container: &str,
    request_id: u64,
    tool: &str,
    args_json: &[u8],
    key: Option<(&str, &str)>,
    session_id: Option<&str>,
) -> GateOutcome {
    // Resolve the plane's stable decl key to its opaque ABI registration index for the FFI POD; the
    // vtable slot resolves it back to the key string (see `dispatch::gate_decide`).
    let plane_key_idx = crate::plane::registry::plane_key_index(plane_key);
    let mut msg_buf = [0u8; 512];
    let mut hook_buf = [0u8; 512];
    let mut out = core::mem::MaybeUninit::<busbar_plugin::hot::GateVerdictOut>::uninit();
    let (key_id, key_name) = key.unwrap_or(("", ""));
    let sid = session_id.unwrap_or("");
    let scope = DispatchScope::new();
    let status = with_borrowed_host(app, &scope, |hctx, vt| {
        let subject = busbar_plugin::hot::GateSubjectRef {
            size: core::mem::size_of::<busbar_plugin::hot::GateSubjectRef>() as u32,
            version: busbar_plugin::hot::POD_VERSION,
            plane_key: plane_key_idx,
            key_present: u8::from(key.is_some()),
            incremental: u8::from(session_id.is_some()),
            _reserved: [0; 3],
            request_id,
            container_ptr: container.as_ptr(),
            container_len: container.len(),
            method_ptr: tool.as_ptr(),
            method_len: tool.len(),
            args_ptr: args_json.as_ptr(),
            args_len: args_json.len(),
            key_id_ptr: key_id.as_ptr(),
            key_id_len: key_id.len(),
            key_name_ptr: key_name.as_ptr(),
            key_name_len: key_name.len(),
            session_id_ptr: sid.as_ptr(),
            session_id_len: sid.len(),
        };
        (vt.gate_decide.expect("gate_decide is a wired slot"))(
            hctx,
            &subject as *const busbar_plugin::hot::GateSubjectRef,
            msg_buf.as_mut_ptr(),
            msg_buf.len(),
            hook_buf.as_mut_ptr(),
            hook_buf.len(),
            std::ptr::from_mut(&mut out),
        )
    });
    // SAFETY: the host ALWAYS initializes `out` up front (see `dispatch::gate_decide`), so it is a live
    // `GateVerdictOut` on every return.
    let v = unsafe { out.assume_init() };
    if status == busbar_plugin::hot::StatusClass::Ok && v.proceed != 0 {
        return GateOutcome::Proceed;
    }
    // A REJECT (Ok + proceed=0) OR a fail-closed refusal (Refused/Fault leaves the eager 403 header):
    // both reconstruct a `Reject`, so a gate that could not run refuses.
    let m = (v.message_len as usize).min(msg_buf.len());
    let h = (v.hook_len as usize).min(hook_buf.len());
    GateOutcome::Reject {
        status: v.status,
        message: String::from_utf8_lossy(&msg_buf[..m]).into_owned(),
        hook: String::from_utf8_lossy(&hook_buf[..h]).into_owned(),
    }
}

/// The ASYNC-CAPABLE dispatch guard: an OWNED RAII handle a core `async` dispatch fn creates at the top
/// of its body and holds as a LOCAL across every `.await`, so the [`DispatchScope`] arena lives for the
/// whole future and reclaims on ANY exit — normal return, client-disconnect cancel, or panic. This is
/// the fix for the sync-only [`with_dispatch_scope`]: an `async move {}` passed to the closure form
/// would make `R` the future and drop the scope BEFORE it was awaited; an owned guard held on the async
/// stack frame closes that hole (the HalfOpen-wedge fix on the real `async` dispatch paths).
///
/// Zero-alloc on the fast lane: it BORROWS the live [`App`] and STACK-PINS its own [`DispatchScope`]
/// (no heap until a handle is actually registered), so holding one across awaits costs no per-dispatch
/// allocation — only the LLM-alloc-sensitive budget's price of a couple of pointers on the frame.
///
/// The raw [`HostCtx`] pointer is `!Send` (it aliases this stack `HostState`), so it is materialized
/// ONLY inside the synchronous [`with_host`](Self::with_host) / [`host_ctx`](Self::host_ctx) runs and
/// MUST NOT be held across an `.await` — the guard itself is `Send` (it holds only `&App` + the arena),
/// so the enclosing future stays `Send`. For a `Send + 'static` route into `spawn_blocking`, take a
/// [`SendHostDispatch`] on that branch instead.
pub struct HostDispatch<'a> {
    app: &'a App,
    scope: DispatchScope,
}

impl<'a> HostDispatch<'a> {
    /// Open an async dispatch guard over the live `app`. Allocates nothing (an empty arena).
    #[must_use]
    pub fn new(app: &'a App) -> Self {
        HostDispatch {
            app,
            scope: DispatchScope::new(),
        }
    }

    /// The per-dispatch arena. Every host handle a plane acquires during this dispatch registers here
    /// and is reclaimed when this guard drops.
    #[must_use]
    pub fn scope(&self) -> &DispatchScope {
        &self.scope
    }

    /// The live engine snapshot this dispatch was admitted on.
    #[must_use]
    pub fn app(&self) -> &App {
        self.app
    }

    /// Borrow a [`HostState`] over this guard's `app` + arena. The raw `HostCtx` materialized from it
    /// (see [`with_host`](Self::with_host)) is `!Send` and valid only while the returned borrow lives.
    #[must_use]
    pub fn host_state(&self) -> HostState<'_> {
        HostState {
            app: self.app,
            scope: &self.scope,
        }
    }

    /// Run `f` SYNCHRONOUSLY with a materialized [`HostCtx`] + the host `&PlaneHostVtable` — the
    /// between-awaits seam a plane call rides. The `HostState` backing the `HostCtx` is stack-pinned
    /// for exactly the duration of `f` (the [`recover`] invariant); the pointer must not escape it.
    pub fn with_host<R>(&self, f: impl FnOnce(HostCtx, &PlaneHostVtable) -> R) -> R {
        let state = self.host_state();
        let vtable = build_plane_host_vtable();
        // The stack `HostState`'s address IS the opaque HostCtx; it outlives every call `f` makes.
        let host: HostCtx = (&state as *const HostState)
            .cast_mut()
            .cast::<std::os::raw::c_void>();
        let out = f(host, &vtable);
        let _keep_alive = &state;
        out
    }
}

/// A `Send + 'static` route to a host for the `spawn_blocking` breaker paths (a2a relay admit/settle
/// run on a blocking thread; see `a2a::receive::{unary_hop,stream_hop}`). Unlike [`HostDispatch`] it
/// OWNS its inputs — an `Arc<App>` (Send + Sync) and its own [`DispatchScope`] — so the whole guard can
/// be MOVED into the `spawn_blocking` closure, which materializes the raw `HostCtx` INSIDE the closure
/// (where the blocking body actually calls the vtable) and never carries the `!Send` pointer across the
/// task boundary. The arena reclaims when the closure ends and the guard drops (reclaim at HOP end).
///
/// Hot-path note: this is taken ONLY on the `spawn_blocking` branch, never on the sync LLM fast lane —
/// it is one `Arc<App>` refcount bump (~ns) and a stack-moved guard, no heap arena until a handle is
/// registered. Do NOT reach for it on the fast path; use the borrowing [`HostDispatch`] there.
pub struct SendHostDispatch {
    app: Arc<App>,
    scope: DispatchScope,
}

impl SendHostDispatch {
    /// Open a Send host guard owning `app`. Allocates nothing beyond the caller's existing `Arc` bump.
    #[must_use]
    pub fn new(app: Arc<App>) -> Self {
        SendHostDispatch {
            app,
            scope: DispatchScope::new(),
        }
    }

    /// The per-hop arena (reclaimed when this guard drops at the end of the blocking closure).
    #[must_use]
    pub fn scope(&self) -> &DispatchScope {
        &self.scope
    }

    /// The live engine snapshot the hop was admitted on.
    #[must_use]
    pub fn app(&self) -> &App {
        &self.app
    }

    /// Borrow a [`HostState`] over the owned `app` + arena — the materialization seam, called INSIDE
    /// the blocking closure so the raw `HostCtx` never crosses the `spawn_blocking` boundary.
    #[must_use]
    pub fn host_state(&self) -> HostState<'_> {
        HostState {
            app: &self.app,
            scope: &self.scope,
        }
    }

    /// Run `f` synchronously with a materialized [`HostCtx`] + host vtable, INSIDE the blocking body.
    pub fn with_host<R>(&self, f: impl FnOnce(HostCtx, &PlaneHostVtable) -> R) -> R {
        let state = self.host_state();
        let vtable = build_plane_host_vtable();
        let host: HostCtx = (&state as *const HostState)
            .cast_mut()
            .cast::<std::os::raw::c_void>();
        let out = f(host, &vtable);
        let _keep_alive = &state;
        out
    }
}

/// A `Send + 'static` route to a host whose lifecycle arena is a [`DurableScope`] the DETACHED runner
/// owns — the create_task settle path (`mcp::tasks::Runner`). Unlike [`SendHostDispatch`] its arena is
/// NOT reclaimed at request-future drop: the breaker probe-hold `into_task_dispatch` handed off rides
/// here and releases only when THIS guard drops WITH the runner (normal end OR a `tasks/cancel` abort),
/// the v4-arena-bug guard. A `HostState` materialized over `durable.arena()` drives the exact same host
/// `breaker_settle` seam the per-request path does, so the runner's detached leg can settle the durable
/// admission through the vtable with no change to the breaker path.
///
/// ADDITIVE and UNUSED by the breaker inversion: the guard is REACHABLE at the durable site (the runner
/// carries one), but `tasks::run` does not yet call settle — the durable scope's drop still reclaims the
/// probe, exactly as before. Phase-2 CLUSTER-1 flips the detached leg to `settle` through this route.
pub struct DurableHostDispatch {
    app: Arc<App>,
    /// The durable arena holding the handed-off breaker probe-hold; drops (and reclaims) with the guard.
    durable: DurableScope,
    /// The durable admission's id — what the detached leg settles by. [`AdmissionId::NONE`] when no
    /// settling admission was handed off (a degenerate route that won nothing to re-home).
    admission: busbar_plugin::hot::AdmissionId,
}

impl DurableHostDispatch {
    /// Open a durable host route owning `app` and the runner's `durable` scope, keyed by the durable
    /// `admission` id the detached leg settles.
    #[must_use]
    pub fn new(
        app: Arc<App>,
        durable: DurableScope,
        admission: busbar_plugin::hot::AdmissionId,
    ) -> Self {
        DurableHostDispatch {
            app,
            durable,
            admission,
        }
    }

    /// The durable admission id the detached leg settles (or [`AdmissionId::NONE`]).
    #[must_use]
    pub fn admission(&self) -> busbar_plugin::hot::AdmissionId {
        self.admission
    }

    /// The durable arena (reclaimed with this guard at task end).
    #[must_use]
    pub fn durable(&self) -> &DurableScope {
        &self.durable
    }

    /// The live engine snapshot the task was admitted on.
    #[must_use]
    pub fn app(&self) -> &App {
        &self.app
    }

    /// Borrow a [`HostState`] over the owned `app` + the DURABLE arena — the materialization seam the
    /// detached leg calls to reach `breaker_settle` for the durable admission.
    #[must_use]
    pub fn host_state(&self) -> HostState<'_> {
        HostState {
            app: &self.app,
            scope: self.durable.arena(),
        }
    }

    /// Run `f` synchronously with a materialized [`HostCtx`] + host vtable over the durable arena.
    pub fn with_host<R>(&self, f: impl FnOnce(HostCtx, &PlaneHostVtable) -> R) -> R {
        let state = self.host_state();
        let vtable = build_plane_host_vtable();
        let host: HostCtx = (&state as *const HostState)
            .cast_mut()
            .cast::<std::os::raw::c_void>();
        let out = f(host, &vtable);
        let _keep_alive = &state;
        out
    }
}

#[cfg(test)]
#[path = "tests/mod_tests.rs"]
mod tests;
