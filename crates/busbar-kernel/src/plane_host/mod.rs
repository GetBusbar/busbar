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
// The host side of the metering-lease seam (minor-19): the real `cost_reserve`/`cost_settle` shims
// backed by a host-owned `CostHold` lease registry. The vtable's two cost slots forward into it.
pub mod cost_host;
mod creds;
pub mod dispatch;
pub mod egress;
mod govern;
pub mod guard;
// The mTLS client-identity registry and the extra-root trust-anchor registry are PURE
// (process-atomic registries; no `App`, no engine, no FFI), so they live NEUTRALLY in
// `busbar_kernel::plane_host` and are re-exported here — core's egress chokepoint names the
// same `crate::plane_host::{identity, trust_anchor}` paths as before. The peer-SPKI DER walk's
// last in-core reader is gone with the engine cutover (the ENGINE computes the pin at connect
// and the chokepoint reads it off the response extensions), so `spki` is no longer re-exported;
// the A2A plane and the engine name the neutral `busbar_kernel::plane_host::spki` directly.
pub(crate) mod identity_admit;
pub mod journal;
pub mod pipe;
pub mod scope;
pub mod session_meter;
pub mod trust;
pub mod vtable;

pub use guard::{guard_url_over, GuardOutcome};
pub use scope::{DispatchScope, DurableScope, SessionScope};
pub use vtable::build_plane_host_vtable;

use crate::state::App;
use busbar_plugin::hot::host::{HostCtx, HostGeneration, PlaneHostVtable};
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
    /// WHO the host is running this dispatch on behalf of — the plane's registry key, as the HOST
    /// knows it, stamped at the moment the host mints the `HostCtx`.
    ///
    /// **Provenance the plane cannot supply, cannot omit and cannot forge** (DECISIONS #85). A
    /// metric has to be attributable to the thing that emitted it, and an identity the emitter hands
    /// over is not an attribution — it is a claim, and the same class of defect as the metric NAME
    /// the `metrics_emit` slot used to take verbatim. So it is set here, by the minter, or it is not
    /// set at all.
    ///
    /// `None` for the host's OWN uses of the vtable — `calllog`, `auditlog`, `trust`, `guard` and
    /// the breaker all mint a host handle to drive a slot themselves, on nobody's behalf. Those are
    /// not planes and have no plane to be attributed to, so rather than invent a name for them the
    /// slots that REQUIRE an attributable emitter refuse a `None`. Use
    /// [`with_borrowed_host_as`] to mint a handle that carries one.
    pub emitter: Option<&'static str>,
    /// WHOSE request this dispatch runs for (DEC-SERVE G1/G1b, DECISIONS #65/#40): the caller the auth
    /// middleware resolved, stamped by the minter from that context — never a word the plane wrote.
    /// THE ONE ATTRIBUTION RULE: `govern_admit`/`govern_admit_reason` admit, and `meter_charge`
    /// bills, THIS caller; the identity words of a `Facts`/`Usage` tail are never read. `None` (an
    /// open route, or a mint with no request behind it) admits and bills the named synthetic keys
    /// (`govern::SYNTH_TENANT_KEY`, `govern::SYNTH_ADMISSION_KEY`).
    caller: Option<HostCaller>,
    /// The operator's destinations for the plane this handle was minted for (DEC-SERVE G3): the only
    /// source of the privilege scope the `egress_open` slot judges a hop against. `None` ⇒ scope `0`.
    destinations: Option<&'a egress::OperatorDestinations>,
}

/// The middleware-resolved caller behind a plane mint (DEC-SERVE G1): an OPAQUE, kernel-only handle.
/// It has no public constructor — the only way one comes to exist is [`with_plane_door`] lifting it
/// off the auth context the middleware attached — so neither a plane nor a crate outside the kernel
/// can hand the host a caller of its choosing (#65).
pub(crate) struct HostCaller(Arc<busbar_contract::records::VirtualKey>);

impl HostCaller {
    /// Lift the caller off the middleware-resolved request context (`None`: no key resolved).
    fn of(ctx: Option<&busbar_contract::records::PlaneRequestCtx>) -> Option<Self> {
        ctx.and_then(|g| g.key.clone()).map(HostCaller)
    }

    /// The resolved key this dispatch is admitted and billed as.
    pub(crate) fn key(&self) -> &busbar_contract::records::VirtualKey {
        &self.0
    }
}

/// Recover core's [`HostState`] from the opaque [`HostCtx`] the plane handed back — or refuse it.
///
/// ## Generation guard (ABI review A6 use-after-free hardening, DECISIONS #40/#65)
///
/// A plane that stashes a `HostCtx` and replays it AFTER the dispatch that minted it has ended (its
/// [`HostGeneration`] token dropped) is exactly the use-after-free A6 found: the host slot the pointer
/// addressed may already be reclaimed/reused. Before ever dereferencing `host.ptr()`, this checks
/// `host.kind()` (the type-confusion guard — only [`HostCtx::KIND_PLANE_HOST`] is a live `HostState`
/// handle) and [`HostGeneration::is_live`] (the use-after-free guard — the generation stamped into
/// `host` must still be open on THIS thread). Either check failing returns `None`; the pointer is never
/// read. A null handle (`host.is_null()`) also refuses, one branch earlier.
///
/// # Invariant
///
/// The host ALWAYS passes, as the `HostCtx` of every vtable call, exactly a handle over a
/// `*const HostState` that is LIVE for the entire dispatch duration — it is [`with_dispatch_scope`]
/// (and its sibling mint sites) that mints the `HostCtx` from a stack `HostState`, stamps it with a
/// freshly opened [`HostGeneration`], and keeps both alive across the whole `f(host, &vtable)` call. The
/// plane never fabricates, mutates, or outlives the pointer (it only stores and returns it) — but MAY
/// replay a stale one, which the generation check above catches. Under that invariant, once the checks
/// pass, dereferencing is sound: the pointer is non-null, aligned, and points at a live `HostState` for
/// a lifetime the caller's frame bounds.
///
/// # Safety
///
/// `host`, WHEN its kind/generation checks pass, MUST be a `HostCtx` produced by
/// [`with_dispatch_scope`] (or a sibling mint site) for a dispatch that is still on the stack, per the
/// invariant above. Calling with any other non-null, correctly-kinded, live-generation pointer is
/// undefined behavior — the checks above narrow the input space but do not themselves prove the pointer
/// is a real `HostState` (a forged-but-live-looking handle is still out of contract).
#[must_use]
pub unsafe fn recover<'a>(host: HostCtx) -> Option<&'a HostState<'a>> {
    if host.is_null() || host.kind() != HostCtx::KIND_PLANE_HOST {
        return None;
    }
    // The use-after-free check: a handle whose minting dispatch already ended (its `HostGeneration`
    // token dropped, popping it off this thread's live set) is REFUSED here, never dereferenced.
    if !HostGeneration::is_live(host.generation()) {
        return None;
    }
    // SAFETY: by the documented invariant, once the kind/generation checks above pass, `host` is a
    // live `*const HostState` for the call's duration.
    Some(unsafe { &*(host.ptr() as *const HostState<'a>) })
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
    // A host-internal mint: nobody's plane. See `HostState::emitter`.
    mint(None, None, None, app, scope, f)
}

/// Run `f` with a [`HostCtx`] ATTRIBUTED to `plane` — the mint site a real plane dispatch uses.
///
/// Identical to [`with_borrowed_host`] in every respect but one: the `HostState` carries the plane's
/// registry key, so a host slot that must attribute what it is handed
/// ([`vtable`]'s `metrics_emit`) has an emitter to attribute it to. `plane` is the HOST's word for
/// which plane it is dispatching — never a string the plane supplied — which is what makes the
/// attribution unforgeable rather than merely present.
///
/// The mint a plane dispatched over the C ABI rides: every host call the plane makes back during the
/// dispatch is recovered, and attributed, as that plane's. It carries no caller, so it admits and
/// bills the named synthetic keys (see `HostState::caller`) — [`with_plane_door`] carries one.
pub fn with_borrowed_host_as<R>(
    plane: &'static str,
    app: &App,
    scope: &DispatchScope,
    f: impl FnOnce(HostCtx, &PlaneHostVtable) -> R,
) -> R {
    mint(Some(plane), None, None, app, scope, f)
}

/// THE HOT DOOR'S MINT (DEC-SERVE G1 + G3): [`with_borrowed_host_as`], plus the two facts only the
/// host knows about this request — the `caller` the auth middleware resolved (the request's
/// [`PlaneRequestCtx`](busbar_contract::records::PlaneRequestCtx), `None` on an open route), which
/// `meter_charge` bills; and the operator's `destinations` for `plane`, which `egress_open` derives a
/// hop's privilege scope from. Neither is a word the plane can supply.
pub fn with_plane_door<R>(
    plane: &'static str,
    caller: Option<&busbar_contract::records::PlaneRequestCtx>,
    destinations: &egress::OperatorDestinations,
    app: &App,
    scope: &DispatchScope,
    f: impl FnOnce(HostCtx, &PlaneHostVtable) -> R,
) -> R {
    mint(
        Some(plane),
        HostCaller::of(caller),
        Some(destinations),
        app,
        scope,
        f,
    )
}

/// THE ONE MINT: run `f` with a [`HostCtx`] over a [`HostState`] of `app` + `scope` (attributed to
/// `emitter`) + the host vtable. The `HostState` is pinned on this frame for exactly the duration of
/// `f` (the [`recover`] invariant), and a fresh [`HostGeneration`] opens for exactly this call on
/// THIS thread (`HostGeneration` is thread-local): it drops right after `f` returns, so a `HostCtx`
/// that escapes `f` and is replayed later is stamped with a generation no longer live. Every mint
/// site — borrowed, attributed, async, Send, durable — is this function.
fn mint<R>(
    emitter: Option<&'static str>,
    caller: Option<HostCaller>,
    destinations: Option<&egress::OperatorDestinations>,
    app: &App,
    scope: &DispatchScope,
    f: impl FnOnce(HostCtx, &PlaneHostVtable) -> R,
) -> R {
    let state = HostState {
        app,
        scope,
        emitter,
        caller,
        destinations,
    };
    let vtable = build_plane_host_vtable();
    let generation = HostGeneration::open();
    // The stack `HostState`'s address IS the opaque HostCtx; it outlives every call `f` makes.
    let ptr = (&state as *const HostState)
        .cast_mut()
        .cast::<std::os::raw::c_void>();
    let host = HostCtx::new(ptr, generation.value(), HostCtx::KIND_PLANE_HOST);
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

/// Admit one unit of work over the host [`govern_admit_reason`](vtable) seam, REGISTERING the RAII
/// grant in `scope`'s arena on success and returning the RENDERED refusal reason on a blocked limit —
/// a SAFE wrapper that keeps the `#[repr(C)]` [`GovRefusal`](busbar_plugin::hot::GovRefusal) out-param
/// read inside this audited module (busbar-core denies `unsafe` everywhere else). The mint carries
/// `caller` — the middleware-resolved request context (DEC-SERVE G1b) — and the host admits THAT key's
/// chain; `tokens = budget_remaining = 0`, so the POD gate is a no-op and the chain is the sole
/// decider — identical to the in-place `try_admit(cost, key, pool)`.
#[must_use]
pub fn govern_admit_reason_over(
    app: &App,
    scope: &DispatchScope,
    caller: &busbar_contract::records::PlaneRequestCtx,
    pool: &[u8],
) -> GovAdmit {
    let mut reason_buf = [0u8; 512];
    let mut out = core::mem::MaybeUninit::<busbar_plugin::hot::GovRefusal>::uninit();
    let decision = mint(
        None,
        HostCaller::of(Some(caller)),
        None,
        app,
        scope,
        |hctx, vt| {
            let facts = busbar_plugin::hot::Facts::new(0, 0, 0, 0, 0, pool);
            (vt.govern_admit_reason
                .expect("govern_admit_reason is a wired slot"))(
                hctx,
                &*facts as *const busbar_plugin::hot::Facts,
                reason_buf.as_mut_ptr(),
                reason_buf.len(),
                std::ptr::from_mut(&mut out),
            )
        },
    );
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
/// host-driven form of a plane's [`busbar_kernel::store::now`]. The slot's ABI unit is Unix NANOSECONDS
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
/// host-driven form of [`busbar_kernel::store::now_ms`]. The slot's ABI unit is Unix NANOSECONDS, sourced
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
/// [`EngineHost::synthesize_completion`](busbar_kernel::plane_host::EngineHost::synthesize_completion).
/// This is the ONLY place the `ingress::operation_resolved` + `handlers::chat` + `proxy::LazyBody`
/// reaches now live: an extracted plane hands a NEUTRAL request (gov + model + body bytes) and gets a
/// NEUTRAL [`HostCompletion`](busbar_kernel::plane_host::HostCompletion) (status + body bytes) back,
/// never naming a core type.
///
/// A line-for-line lift of the former `mcp::sampling::complete`'s pre-response body: the argument
/// tuple handed to `operation_resolved` is preserved BYTE-IDENTICALLY — the chat `proto` is the
/// registry's residual-default dialect (read by NAME, so this neutral core spells none),
/// [`Transport::Http`](crate::transport::Transport), the `handlers::chat(proto, Http)` op,
/// `caller_token = None`, `model_not_found_message = None`, `charged_at = busbar_kernel::store::now()` (whole
/// SECONDS, the same source [`clock_now_secs_over`] scales to), and `LazyBody::parse` over the SAME
/// bytes — so governance attribution and metering are unchanged. The async future stays `Send`: it
/// only `.await`s the native core async fn; no `HostCtx` is minted here, and any minted inside
/// `operation_resolved`'s own frames is consumed there, never crossing this `.await`.
pub async fn synthesize_completion_over(
    app: Arc<App>,
    gov: &crate::governance::PlaneRequestCtx,
    model: &str,
    body: bytes::Bytes,
    max_body_bytes: usize,
) -> Result<busbar_kernel::plane_host::HostCompletion, String> {
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
    let Some(synth) = busbar_kernel::ingress::arrival::completion_ingress() else {
        return Err("no default chat protocol is installed".to_string());
    };
    let ctx = busbar_kernel::ingress::arrival::ArrivalCtx::new(
        crate::ingress::arrival_host::ArrivalPayload {
            host: engine_host(&app),
            gov: gov.clone(),
            caller_token: None,
        },
    );
    let response = synth(busbar_kernel::ingress::arrival::CompletionArrival {
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
    Ok(busbar_kernel::plane_host::HostCompletion { status, body })
}

/// Core's implementation of the neutral [`EngineHost`](busbar_kernel::plane_host::EngineHost)
/// seam over the live [`App`]. A plane holds this behind an
/// `Arc<dyn busbar_kernel::plane_host::EngineHost>` and calls typed, safe methods on it INSTEAD of
/// naming `plane_host::*_over(&App, …)` — so a plane compiled apart from the host reaches the same
/// host vtable slots without ever naming a core type.
///
/// Owns an `Arc<App>` (the config generation the reaches run against) so the handle is
/// `Send + Sync + 'static` and safe to carry across `.await`. That is sound precisely because no
/// method exposes the `!Send` [`HostCtx`]: each mints the transient `HostCtx` INTERNALLY (via
/// [`with_borrowed_host`] over a fresh per-call [`DispatchScope`]), drives the slot SYNCHRONOUSLY,
/// and returns an owned value — the raw host pointer never escapes the call.
#[derive(Clone)]
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

// AUDIT-D BRAKE: the BREAKER family, split off `EngineHost` into its `BreakerHost` supertrait. The
// bodies are relocated byte-for-byte — same-dispatch reaches, same arenas — so the split is purely
// structural. `EngineHost: BreakerHost` (in substrate) makes these visible on every `dyn EngineHost`.
impl busbar_kernel::plane_host::BreakerHost for EngineHostImpl {
    fn breaker_admit(
        &self,
        scope: &DispatchScope,
        pool: &[u8],
        lane: u32,
    ) -> Result<busbar_plugin::hot::AdmissionId, busbar_kernel::store::Unavailable> {
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
        sig: &busbar_substrate_values::breaker::CanonicalSignal,
    ) {
        self.app.plane_breakers.record_signal(pool, lane, sig);
    }

    fn breaker_retry_after_secs(&self, pool: &str, lane: usize) -> u64 {
        self.app.plane_breakers.retry_after_secs(pool, lane)
    }
}

// AUDIT-D BRAKE: the LANE/POOL family, split off `EngineHost` into its `LanePoolHost` supertrait.
// Relocated byte-for-byte from the flat impl; `EngineHost: LanePoolHost` keeps every call site working.
impl busbar_kernel::plane_host::LanePoolHost for EngineHostImpl {
    fn lane_store(&self) -> &dyn busbar_kernel::store::LaneRuntime {
        // A pure borrow of the bound snapshot's store: `App::store` is `Arc<dyn LaneRuntime>` where
        // `LaneRuntime` is re-exported from `busbar_kernel::store` (wedge 1), so the returned
        // trait object IS the substrate one — byte-identical to the engine's `&*app.store`.
        &*self.app.store
    }

    fn default_probe_interval_secs(&self) -> u64 {
        crate::limits::default_probe_interval_secs()
    }

    fn default_probe_timeout_secs(&self) -> u64 {
        crate::limits::default_probe_timeout_secs()
    }

    fn pool_members_repeatable(&self, member: &str) -> Option<(String, Vec<String>, Vec<String>)> {
        self.app
            .tool_pools
            .iter()
            .find(|(_, cfg)| cfg.members.iter().any(|m| m == member))
            .map(|(name, cfg)| (name.clone(), cfg.members.clone(), cfg.repeatable.clone()))
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
}

// THE KERNEL'S OWN PRICING (#43): `MeteringHost` is NOT a supertrait of `EngineHost`, so no plane-side
// host implements it and no plane names it. The lease legs take the trait's defaults — the host-owned
// `CostHold` registry in [`cost_host`], the SAME registry the FFI `cost_reserve`/`cost_settle` slots fill,
// so a statically-linked plane's session and a dlopen plane's lease are one ledger. Only the pricing is
// this host's: its bound snapshot's rate card.
impl busbar_kernel::plane_host::MeteringHost for EngineHostImpl {
    fn price_usage(
        &self,
        model: &str,
        usage: &busbar_substrate_values::billing::Usage,
    ) -> Option<u128> {
        // Price against the BOUND snapshot's resolved `CostModel` — the SAME rate card + arithmetic the
        // LLM enforcement/derive path prices with (a new reader, not a new pricer), so a live voice
        // carrier meters against the deployment's real rates while staying plane-neutral.
        self.app.cost.price_usage_nanos(model, usage)
    }
}

// M4 (god-trait split): the single `EngineHostImpl` implements each capability slice `EngineHost` now
// sums. Every method body is byte-identical to the pre-split flat `impl EngineHost` — only the impl
// block it lives in changed. `EngineHost` itself declares no method of its own (beyond the provided
// `run_gauntlet`), so the blanket `impl EngineHost for EngineHostImpl` below is empty: the sum is
// satisfied entirely through the slice impls.

impl busbar_kernel::plane_host::ClockHost for EngineHostImpl {
    fn clock_now_secs(&self) -> u64 {
        // SAME dispatch as the veneer: a fresh per-call `DispatchScope`, the `clock_now` slot driven
        // synchronously over a stack-pinned `HostState`, the `HostCtx` never escaping the call.
        clock_now_secs_over(&self.app)
    }

    fn clock_now_ms(&self) -> u64 {
        clock_now_ms_over(&self.app)
    }
}

impl busbar_kernel::plane_host::TelemetryHost for EngineHostImpl {
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
}

impl busbar_kernel::plane_host::JournalHost for EngineHostImpl {
    fn audit_emit(&self, action: &str, resource: &str, outcome: &str, principal: &str) {
        // Hostless: the admin-audit engine reads `store::now` + the global ring and needs no `HostCtx`.
        // A plain forward to the UNCHANGED core engine.
        crate::plane::auditlog::emit_admin_hostless_now(action, resource, outcome, principal);
    }

    fn audit_record(&self, action: &str, resource: &str, outcome: &'static str, principal: &str) {
        // The in-process admin ring `record_by` seals into the retained ring AND cascades the SAME
        // sealed record onto the durable hostless journal — the superset of `audit_emit`'s durable-only
        // path. The egress audit-and-allow trail reads this ring, so a dropped cross-dialect control
        // lands here byte-identically to the pre-flip `AUDIT.record_by(...)` reach.
        crate::audit_ring::AUDIT.record_by(action, resource, outcome, principal);
    }

    fn call_log_emit(&self, principal: &str, input: busbar_kernel::plane::calllog::CallInput) {
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
        input: busbar_kernel::plane::calllog::CallInput,
    ) {
        crate::calllog::emit_hostless(principal, input);
    }
}

impl busbar_kernel::plane_host::MountHost for EngineHostImpl {
    fn arrival_envelope_dialect(&self, path: &str) -> &'static str {
        // Pure snapshot mount-table read — the host-driven form of the dropped `ArrivalPayload::app`
        // reach `envelope_dialect(app.planes.ingress_of(path))`.
        crate::ingress::native::envelope_dialect(self.app.planes.ingress_of(path))
    }

    fn arrival_fallback_error(
        &self,
        path: &str,
        status: axum::http::StatusCode,
        kind: &str,
        message: &str,
    ) -> axum::response::Response {
        // Pure snapshot mount-table read — the host-driven form of the dropped `ArrivalPayload::app`
        // reach `fallback_error_response(&app.planes, …)`.
        crate::fallback_error_response(&self.app.planes, path, status, kind, message)
    }
}

impl busbar_kernel::plane_host::RegistryHost for EngineHostImpl {
    fn next_request_id(&self) -> u64 {
        self.app.next_request_id()
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

    fn secret_resolver(&self) -> Arc<dyn busbar_contract::secret::SecretResolve> {
        // Pure snapshot read: hand the plane the live `Arc<SecretResolver>` behind the neutral
        // `busbar_contract::secret::SecretResolve` seam. The concrete resolver impls the trait (same crate), so the
        // clone coerces to the trait object — no wrapping, the SAME resolver (built-ins + any wired
        // `kind: secret` plugin), fail-closed exactly as core resolution.
        self.app.secret_resolver.clone()
    }

    fn subkey_sign(&self, signing_input: &[u8]) -> Option<[u8; 64]> {
        // SAME dispatch as the veneer: a fresh per-call `DispatchScope`, the `card_sign` slot driven
        // synchronously over a stack-pinned `HostState`, the `HostCtx` never escaping the call. `None`
        // when no card-signing key is held (or, in a build without `plane-a2a`, the slot is unwired).
        card_sign_over(&self.app, signing_input)
    }

    fn plane_defs(&self) -> Arc<dyn std::any::Any + Send + Sync> {
        // Pure snapshot read: the type-erased per-plane config the owning plane downcasts, cloned so it
        // outlives the call. Already an `Arc<dyn Any + Send + Sync>` on `App`, so the clone is the whole seam.
        self.app.agent_defs.clone()
    }
}

impl busbar_kernel::plane_host::HookConfigHost for EngineHostImpl {
    fn caller_in_hook_groups(&self, caller_group: Option<&str>, hook_groups: &[String]) -> bool {
        // Fold the `&App::groups_registry` argument host-side; the walk itself is byte-identical.
        crate::config::caller_in_hook_groups(caller_group, hook_groups, &self.app.groups_registry)
    }

    // ── HOOK/CONFIG FACADE READS (App-retype WEDGE 2d) — each a pure borrow of the bound snapshot ──

    fn pool_rewrites(
        &self,
        pool: &str,
    ) -> &[(
        std::time::Duration,
        Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )] {
        // `App::pool_rewrites` already returns the neutral api tuple slice; byte-identical borrow.
        self.app.pool_rewrites(pool)
    }

    fn rewrite_hooks(
        &self,
    ) -> &[(
        std::time::Duration,
        Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )] {
        &self.app.rewrite_hooks
    }

    fn any_content_hook(&self) -> bool {
        self.app.any_content_hook
    }

    fn tap_hooks(&self) -> &[busbar_kernel::hooks::TapEntry] {
        &self.app.tap_hooks
    }

    fn tap_hooks_response(&self) -> &[busbar_kernel::hooks::TapEntry] {
        &self.app.tap_hooks_response
    }

    fn tap_hooks_routing(&self) -> &[busbar_kernel::hooks::TapEntry] {
        &self.app.tap_hooks_routing
    }

    fn tap_hooks_candidate(&self) -> &[busbar_kernel::hooks::TapEntry] {
        &self.app.tap_hooks_candidate
    }

    fn pool_gates(&self, pool: &str) -> &[(u16, busbar_kernel::hooks::ResolvedPolicy)] {
        self.app.pool_gates(pool)
    }

    fn global_gates(&self) -> &[(u16, busbar_kernel::hooks::ResolvedPolicy)] {
        &self.app.global_gates
    }

    fn pool_policy(&self, pool: &str) -> Option<&busbar_kernel::hooks::ResolvedPolicy> {
        self.app.pool_policy(pool)
    }

    fn requested_signals(&self) -> &busbar_kernel::hooks::RequestedSignals {
        &self.app.requested_signals
    }
}

impl busbar_kernel::plane_host::BudgetHost for EngineHostImpl {
    fn governance_enabled(&self) -> bool {
        self.app.governance.is_some()
    }

    fn meter_charge(
        &self,
        scope: &DispatchScope,
        caller: &busbar_contract::records::PlaneRequestCtx,
        usage: &busbar_plugin::hot::Usage,
    ) {
        // Mint the transient `HostCtx` over the caller's arena CARRYING the middleware-resolved
        // `caller` (DEC-SERVE G1b — the host bills that key, never the `Usage` tail's), fire the
        // `meter_charge` slot, and drop the host pointer without letting it escape. Fire-and-forget.
        let caller = HostCaller::of(Some(caller));
        mint(None, caller, None, &self.app, scope, |host, vt| {
            let _ = (vt.meter_charge.expect("meter_charge is a wired slot"))(
                host,
                usage as *const busbar_plugin::hot::Usage,
            );
        });
    }

    fn rate_headroom(
        &self,
        pin: &busbar_kernel::plane_host::MeterPin,
        key: &busbar_contract::records::VirtualKey,
        pool: Option<&str>,
        now: u64,
    ) -> Option<f64> {
        // Recover the concrete gov/cost the caller's pin was minted over and drive the SAME pure
        // observation `gov.rate_headroom(&app.cost, …)` did — byte-identical, no re-read of the host
        // snapshot. A downcast miss (never in practice) reads as no constraint, matching the
        // `gov`-absent arm at the engine call site.
        pin_models(pin).and_then(|(g, c)| g.rate_headroom(&c, key, pool, now))
    }

    fn budget_state(
        &self,
        pin: &busbar_kernel::plane_host::MeterPin,
        key: &busbar_contract::records::VirtualKey,
        now: u64,
    ) -> Vec<busbar_contract::hooks::BudgetBucketState> {
        pin_models(pin).map_or_else(Vec::new, |(g, c)| g.budget_state(&c, key, now))
    }

    fn governance(&self) -> Option<busbar_kernel::plane_host::GovHandle> {
        // One Arc bump, erased to `dyn Any` — byte-identical to the sink's `app.governance.clone()`.
        self.app.governance.clone().map(|g| {
            busbar_kernel::plane_host::GovHandle(g as Arc<dyn std::any::Any + Send + Sync>)
        })
    }

    // The pin carries THIS snapshot's card (one Arc bump) — the card a request's money is settled
    // against for its whole life, whatever a reload does meanwhile. Only the kernel's host can pin one.
    fn meter_pin(&self) -> Option<busbar_kernel::plane_host::MeterPin> {
        let cost = busbar_kernel::plane_host::CostHandle(self.app.cost.clone());
        self.governance()
            .map(|gov| busbar_kernel::plane_host::MeterPin { gov, cost })
    }

    fn cost_model_unpriced(&self, model: &str) -> bool {
        // The SAME read the in-place pre-admission guard makes off `app.cost`: `false` for every name
        // when no card is configured (there is no card to miss).
        self.app.cost.model_unpriced(model)
    }

    fn meter_ledger(
        &self,
        pin: &busbar_kernel::plane_host::MeterPin,
        key: &busbar_contract::records::VirtualKey,
        pool: &str,
        model: &str,
        usage: &busbar_substrate_values::billing::Usage,
        now: u64,
    ) {
        // Recover the concrete gov/cost the plane's pin was minted over and drive the SAME accrual
        // `sink.gov.record_usage(&sink.cost, …)` did. The neutral `Usage` carries the one name-keyed
        // unit map (reserved four + opens); accrual folds it straight into the cell. A downcast miss
        // (never in practice — the pin is minted here) is a silent no-op, matching `record_usage`'s
        // own fail-soft posture.
        if let Some((g, c)) = pin_models(pin) {
            g.record_usage(&c, key, pool, model, &usage.usage_units, now);
        }
    }

    fn meter_series(
        &self,
        gov: &busbar_kernel::plane_host::GovHandle,
        key_id: &str,
        model: &str,
        provider: &str,
        usage: Option<&busbar_substrate_values::billing::TokenUsage>,
        now: u64,
    ) {
        if let Ok(g) = gov.0.clone().downcast::<crate::governance::GovState>() {
            g.record_metering(key_id, model, provider, usage, now);
        }
    }
}

/// Recover the concrete `CostModel` an opaque [`CostHandle`](busbar_kernel::plane_host::CostHandle)
/// was minted over; `None` on a handle the kernel's host did not mint (a plane-side host's pin).
fn cost_model(cost: &busbar_kernel::plane_host::CostHandle) -> Option<Arc<crate::cost::CostModel>> {
    cost.0.clone().downcast().ok()
}

/// The `(GovState, CostModel)` pair behind a [`MeterPin`](busbar_kernel::plane_host::MeterPin) — the
/// one recovery every pinned budget seam above makes; `None` when either handle misses.
fn pin_models(
    pin: &busbar_kernel::plane_host::MeterPin,
) -> Option<(
    Arc<crate::governance::GovState>,
    Arc<crate::cost::CostModel>,
)> {
    Some((pin.gov.0.clone().downcast().ok()?, cost_model(&pin.cost)?))
}

#[async_trait::async_trait]
impl busbar_kernel::plane_host::IdentityHost for EngineHostImpl {
    fn quarantine_settle(&self, subject: &str, state: crate::trust::TrustState) -> bool {
        trust::quarantine_settle_over(&self.app, subject, state)
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

    #[cfg(any(test, feature = "test-support"))]
    fn verify_token_test(&self, token: &str) -> Option<Arc<busbar_contract::records::VirtualKey>> {
        self.app
            .governance
            .as_ref()
            .and_then(|g| g.verify_token(token, busbar_kernel::store::now(), None))
    }

    fn identity_audience_binding(
        &self,
        token: &str,
        expected_aud: &str,
    ) -> busbar_kernel::plane_host::AudienceBinding {
        // A pure judgement — no `HostCtx`, no engine state. `inspect_bearer` returns the enum this
        // trait method's type re-exports, so this is a direct forward to the UNCHANGED core seam.
        crate::auth::audience::inspect_bearer(token, expected_aud)
    }

    async fn identity_admit(
        &self,
        token: Option<String>,
        audience: String,
        resource: String,
    ) -> Result<
        (
            busbar_contract::auth::AuthPrincipal,
            busbar_contract::records::PlaneRequestCtx,
        ),
        busbar_contract::auth::IdentityRefusal,
    > {
        // The veneer already spawns a blocking closure that mints + consumes the `HostCtx` on a
        // blocking thread; this only awaits the join, so no `HostCtx` crosses the `.await` and the
        // future stays `Send`.
        identity_admit_over(Arc::clone(&self.app), token, audience, resource).await
    }

    fn principal_standing(
        &self,
        standing: &busbar_kernel::trust::validate::Standing,
        live_gen: u64,
        now: u64,
    ) -> Result<
        Option<Arc<busbar_contract::records::VirtualKey>>,
        busbar_kernel::trust::validate::Lapsed,
    > {
        // Inject the host's live `GovState` AND the live `role_bindings` through the `GovResolve` seam
        // so the plane holds only the `Standing`. The bindings are per-snapshot (rebuilt on every
        // config apply), so they are read off the CURRENT snapshot when the host retains the live
        // handle: a role-bound principal is re-checked against the bindings in force now, never the
        // ones it was admitted under. A registry key re-resolves exactly as before.
        let live = self.handle.as_ref().map(|h| h.load());
        let app = live.as_ref().unwrap_or(&self.app);
        let resolve = crate::governance::LiveResolve {
            governance: app.governance.as_deref(),
            role_bindings: &app.role_bindings,
        };
        standing.still_permitted(
            Some(&resolve as &dyn busbar_kernel::trust::validate::GovResolve),
            live_gen,
            now,
        )
    }

    fn ask_state_sealer(&self) -> Option<busbar_kernel::plane::approvals::Sealer> {
        self.app
            .governance
            .as_ref()
            .and_then(|g| crate::plane::approvals::ask_state_sealer(g))
    }
}

impl busbar_kernel::plane_host::AdmissionHost for EngineHostImpl {
    fn gate_decide(
        &self,
        plane_key: &str,
        container: &str,
        request_id: u64,
        tool: &str,
        args_json: &[u8],
        key: Option<(&str, &str)>,
        session_id: Option<&str>,
    ) -> busbar_kernel::plane_host::GateOutcome {
        gate_decide_over(
            &self.app, plane_key, container, request_id, tool, args_json, key, session_id,
        )
    }

    fn gate_attached(&self, plane_key: &str, container: &str) -> bool {
        // Pure snapshot read of the generic per-plane gate map, keyed by the opaque registry key.
        self.app
            .plane_gates(plane_key)
            .is_some_and(|g| g.contains_key(container))
    }

    fn tap_attached(&self, plane_key: &str, container: &str) -> bool {
        // Pure snapshot read of the generic per-plane REWRITE map — the tap twin of `gate_attached`.
        // `resolve_container_rewrites` never files an empty chain, so presence == a real rewrite hook.
        self.app
            .plane_rewrites(plane_key)
            .and_then(|m| m.get(container))
            .is_some_and(|c| !c.is_empty())
    }

    fn transform_over(
        &self,
        plane_key: &str,
        container: &str,
        request_id: u64,
        tool: &str,
        args_json: &[u8],
        _key: Option<(&str, &str)>,
        _session_id: Option<&str>,
    ) -> busbar_kernel::plane_host::TransformVerdict {
        transform_over_over(&self.app, plane_key, container, request_id, tool, args_json)
    }

    fn govern_admit_reason(
        &self,
        scope: &DispatchScope,
        caller: &busbar_contract::records::PlaneRequestCtx,
        pool: &[u8],
    ) -> busbar_kernel::plane_host::GovAdmit {
        govern_admit_reason_over(&self.app, scope, caller, pool)
    }

    fn destination_guard(
        &self,
        gov: &busbar_contract::records::PlaneRequestCtx,
        proto: &'static str,
        pool: &str,
        started: std::time::Instant,
        charged_at: u64,
    ) -> Result<(), Box<axum::response::Response>> {
        crate::ingress::destination_guard(&self.app, gov, proto, pool, started, charged_at)
    }

    fn admission_door(
        &self,
        gov: &busbar_contract::records::PlaneRequestCtx,
        proto: &'static str,
        pool: &str,
        started: std::time::Instant,
        charged_at: u64,
    ) -> Result<
        (
            Option<busbar_kernel::plane_host::AdmitHandle>,
            Option<String>,
        ),
        Box<axum::response::Response>,
    > {
        // Byte-identical to the in-place door (`GovCtx` IS `PlaneRequestCtx`); the produced `AdmitGrant`
        // is wrapped in the opaque `AdmitHandle` the plane's sink holds Drop-only. The `Arc::new` here
        // mirrors the engine's own `admit.map(Arc::new)` at the sink-build site.
        crate::ingress::admission_door(&self.app, gov, proto, pool, started, charged_at).map(
            |(admit, downgraded)| {
                (
                    admit.map(|a| {
                        busbar_kernel::plane_host::AdmitHandle(
                            Arc::new(a) as Arc<dyn std::any::Any + Send + Sync>
                        )
                    }),
                    downgraded,
                )
            },
        )
    }

    fn admission_check(
        &self,
        gov: &busbar_contract::records::PlaneRequestCtx,
        proto: &'static str,
        pool: &str,
        charged_at: u64,
    ) -> Result<
        (
            Option<busbar_kernel::plane_host::AdmitHandle>,
            Option<String>,
        ),
        Box<axum::response::Response>,
    > {
        // The door's own body, minus the `finish_rejected` the door wraps its refusing arm in: same
        // buckets, same charge, same downgrade, same bytes. The grant is wrapped in the opaque
        // handle exactly as `admission_door` wraps it, so the two seams differ in nothing but which
        // side of them posts the refusal.
        crate::ingress::admit_check(&self.app, gov, proto, pool, charged_at).map(
            |(admit, downgraded)| {
                (
                    admit.map(|a| {
                        busbar_kernel::plane_host::AdmitHandle(
                            Arc::new(a) as Arc<dyn std::any::Any + Send + Sync>
                        )
                    }),
                    downgraded,
                )
            },
        )
    }

    fn finish_admitted(
        &self,
        gov: &busbar_contract::records::PlaneRequestCtx,
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
        gov: &busbar_contract::records::PlaneRequestCtx,
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

    fn plane_audience_bound(&self, plane_key: &str) -> bool {
        // Pure snapshot read: is the plane identified by the opaque registry key mounted under an
        // audience-bound door?
        self.app
            .planes
            .mount_of(plane_key)
            .and_then(|m| self.app.planes.admission_for(m))
            .is_some()
    }
}

#[async_trait::async_trait]
impl busbar_kernel::plane_host::CompletionHost for EngineHostImpl {
    async fn synthesize_completion(
        &self,
        gov: &busbar_contract::records::PlaneRequestCtx,
        model: &str,
        body: bytes::Bytes,
        max_body_bytes: usize,
    ) -> Result<busbar_kernel::plane_host::HostCompletion, String> {
        // The veneer keeps the `ingress::operation_resolved` + `handlers::chat` + `proxy::LazyBody`
        // reaches in core; it only `.await`s the native async fn, so no `HostCtx` crosses the
        // `.await` and the future stays `Send`.
        synthesize_completion_over(Arc::clone(&self.app), gov, model, body, max_body_bytes).await
    }
}

// `EngineHost` declares no method of its own beyond the provided `run_gauntlet`; it is purely the SUM
// of the capability slices above. This blanket impl is therefore empty — the sum is satisfied through
// the slice impls, and the substrate-side compile-time witness enforces that equality.
#[async_trait::async_trait]
impl busbar_kernel::plane_host::EngineHost for EngineHostImpl {}

/// Mint an `Arc<dyn EngineHost>` over the live `app` — the constructor core hands a plane so the
/// plane calls the neutral seam instead of naming `plane_host::*_over(&App, …)`. Cheap: one `Arc`
/// clone; the transient `HostCtx` is minted per method call, never here.
#[must_use]
pub fn engine_host(app: &Arc<App>) -> Arc<dyn busbar_kernel::plane_host::EngineHost> {
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
pub fn engine_host_value(app: &Arc<App>) -> impl busbar_kernel::plane_host::EngineHost + 'static {
    EngineHostImpl::new(Arc::clone(app))
}

/// Mint an `Arc<dyn EngineHost>` over the CURRENT snapshot of a live [`AppHandle`] — the form the
/// route adapter and the detached-runner / stdio paths reach for, which hold a swappable handle
/// rather than a pinned `Arc<App>`. Loads the handle once; the clock the seam reads is engine-snapshot
/// independent (it drives the host wall clock), so a later config swap does not change the value.
#[must_use]
pub fn engine_host_from_handle(
    handle: &Arc<crate::state::AppHandle>,
) -> Arc<dyn busbar_kernel::plane_host::EngineHost> {
    // `from_handle` (not `engine_host(&handle.load())`): retains the live handle so `plane_slot_live`
    // re-reads the CURRENT snapshot on the route/detached-runner/stdio paths, which must see a config
    // swap that lands after admission. The bound snapshot stays `handle.load()` — byte-identical.
    Arc::new(EngineHostImpl::from_handle(Arc::clone(handle)))
}

/// Mint a NEUTRAL [`LiveHostFactory`](busbar_kernel::plane_host::LiveHostFactory) closing over a live
/// [`AppHandle`](crate::state::AppHandle): each call returns a fresh `from_handle` host whose BOUND
/// snapshot is the handle's CURRENT load and whose `plane_slot_live` re-reads the live handle — so a
/// transport that re-mints per frame sees a config swap that lands between calls. Byte-identical to
/// calling [`engine_host_from_handle`] on each frame, handed to a plane that must not name the handle.
#[must_use]
pub fn live_host_factory(
    handle: std::sync::Arc<crate::state::AppHandle>,
) -> busbar_kernel::plane_host::LiveHostFactory {
    std::sync::Arc::new(move || {
        std::sync::Arc::new(EngineHostImpl::from_handle(std::sync::Arc::clone(&handle)))
            as Arc<dyn busbar_kernel::plane_host::EngineHost>
    })
}

// The request-admission gate verdict is a pure POD naming only `busbar_plugin::hot` + std, so it now
// lives in the substrate beside the neutral `EngineHost` seam; core re-exports it so every in-core
// caller (`gate_decide_over`, a2a) is unchanged.

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

/// Fire the operator's REQUEST-ADMISSION TRANSFORM (`<section>.hooks:` `prompt: rw`) chain over the
/// container's resolved rewrite hooks and reconstruct the [`TransformVerdict`] — the TAP/observe-
/// transform twin of [`gate_decide_over`]. The host owns and re-selects the chain by `(plane_key,
/// container)`, so an MCP/A2A plane body admits a rewrite pass over its payload without ever naming
/// `crate::hooks` or holding the resolved `Arc<dyn RoutingPolicy>` set (the Seam-B inversion), exactly
/// as it fires the gate.
///
/// The projection is the SAME `InvokeReq` the gate builds from `(tool, arguments)` — rebuilt from the
/// CURRENT arguments on every iteration so a later hook sees the earlier rewrite (a true transform
/// chain, mirroring the LLM `apply_global_rewrites` seam). Precedence on the transform path is the
/// canonical **reject > rewrite > abstain**.
///
/// FAIL-SAFE, not fail-closed: a rewrite is an OBSERVE/transform pass (the admission GATE already ran
/// and screened the request), so a hook that errors, times out or abstains — or a runtime that will
/// not start — proceeds with the ORIGINAL payload, byte-for-byte. Only an explicit `reject` stops the
/// request, and only a committed `rewrite` changes a byte.
///
/// Drives the ASYNC hooks on a fresh current-thread runtime, so it MUST be called from a BLOCKING
/// thread (`spawn_blocking`) — `block_on` on a runtime worker would panic — exactly like
/// [`gate_decide_over`].
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn transform_over_over(
    app: &App,
    plane_key: &str,
    container: &str,
    request_id: u64,
    tool: &str,
    args_json: &[u8],
) -> busbar_kernel::plane_host::TransformVerdict {
    // Resolve THIS container's rewrite chain. Empty ⇒ nothing attached ⇒ byte-identical no-op. The
    // caller already guards on `tap_attached`; the re-check keeps the fn correct if invoked directly.
    let chain: &[(std::time::Duration, Arc<dyn crate::hooks::RoutingPolicy>)] = app
        .plane_rewrites(plane_key)
        .and_then(|m| m.get(container))
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if chain.is_empty() {
        return TransformVerdict::Proceed {
            applied: false,
            args_json: args_json.to_vec(),
        };
    }
    // Rebuild the caller's arguments `Value`. Byte-safe because `serde_json`'s `preserve_order` is OFF
    // (a `Value` object is a sorted-stable `BTreeMap`), so `to_vec`→`from_slice` round-trips to the
    // identical `Value` — the same guarantee the gate seam relies on.
    let mut arguments: serde_json::Value =
        serde_json::from_slice(args_json).unwrap_or(serde_json::Value::Null);
    // The `ingress_protocol` label IS the plane's stable decl key (the gate seam's convention).
    let ingress = plane_key;
    // Drive the async chain on a fresh current-thread runtime (the gate precedent). A runtime that will
    // not start is FAIL-SAFE here (proceed with the original body) because the admission gate already
    // ran — a transform is not an admission point.
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => {
            return TransformVerdict::Proceed {
                applied: false,
                args_json: args_json.to_vec(),
            }
        }
    };
    let mut applied = false;
    for (timeout, hook) in chain {
        // Re-read the InvokeReq facts from the CURRENT arguments so a later hook sees the earlier
        // rewrite — a true transform chain.
        let facts = crate::ir::invoke::InvokeReq {
            tool: tool.to_string(),
            arguments: arguments.clone(),
            extra: Default::default(),
        };
        let req = build_invoke_rewrite_request(&facts, ingress, request_id);
        crate::audit::amend::hook_read(hook.name(), None, ingress, false);
        let outcome = rt.block_on(hook.transform(&req, *timeout));
        drop(req); // end the immutable borrow of `facts` before the next iteration reuses `arguments`
        match outcome {
            busbar_contract::hooks::TransformOutcome::Rewrite(rw) => {
                applied |= apply_rewrite_to_invoke_args(&mut arguments, &rw);
            }
            busbar_contract::hooks::TransformOutcome::Reject { status, message } => {
                // Already status-clamped + message-sanitized at the wire seam.
                return TransformVerdict::Reject {
                    status,
                    message,
                    hook: hook.name().to_string(),
                };
            }
            busbar_contract::hooks::TransformOutcome::Abstain => {}
            // The hook could not answer, and its disposition says to carry on — a load-bearing
            // hook's failed call arrived as `Reject` above, applied by the resolver's decorator
            // before it reached this (or any other) firing site. Logged, never silent.
            busbar_contract::hooks::TransformOutcome::Failed { message } => {
                tracing::warn!(
                    hook = hook.name(),
                    error = %message,
                    "invoke rewrite hook could not answer; proceeding with the original arguments"
                );
            }
        }
    }
    // Re-serialize ONLY when a rewrite actually landed; otherwise hand back the caller's ORIGINAL bytes
    // untouched, so a chain of purely-abstaining hooks is byte-identical to no chain at all.
    let out = if applied {
        serde_json::to_vec(&arguments).unwrap_or_else(|_| args_json.to_vec())
    } else {
        args_json.to_vec()
    };
    TransformVerdict::Proceed {
        applied,
        args_json: out,
    }
}

/// Build the rewrite (`prompt: rw`) request projection over the NEUTRAL [`IrFacts`] content walk — the
/// core-side, chat-type-free twin of the LLM plane's `build_rewrite_request`. A rewrite hook is a
/// content hook, so the prompt is ALWAYS sent (a `prompt: rw` grant is the resolution ticket); identity
/// is omitted (rewrite operates on content, not caller identity). For the invoke family this projects
/// ONE `("user", <arguments json>)` message — the arguments are the untrusted content a screening
/// rewrite hook acts on. The content ceiling is enforced on serialized bytes exactly as the LLM seam
/// enforces it.
///
/// [`IrFacts`]: busbar_substrate_values::ir::facts::IrFacts
fn build_invoke_rewrite_request<'a>(
    facts: &'a dyn busbar_substrate_values::ir::facts::IrFacts,
    ingress_protocol: &'a str,
    request_id: u64,
) -> busbar_contract::hooks::RoutingRequest<'a> {
    use busbar_substrate_values::ir::facts::Slot;
    use std::borrow::Cow;
    let shape = facts.shape();
    let mut system_pieces: Vec<String> = Vec::new();
    let mut messages: Vec<(Cow<'a, str>, Cow<'a, str>)> = Vec::new();
    for item in facts.content() {
        let text = item.screenable_text().into_owned();
        if matches!(item.slot(), Slot::System) {
            system_pieces.push(text);
        } else {
            messages.push((Cow::Borrowed(item.author()), Cow::Owned(text)));
        }
    }
    let system = if system_pieces.is_empty() {
        None
    } else {
        Some(Cow::Owned(system_pieces.join("\n")))
    };
    let prompt =
        enforce_invoke_content_cap(busbar_contract::hooks::PromptProjection { system, messages });
    busbar_contract::hooks::RoutingRequest {
        request_id,
        // A rewrite over a plane payload has no LLM routing pool; the wire omits it for the rewrite
        // projection (RESERVED field, no reader), so the empty label is neutral.
        pool: "",
        ingress_protocol,
        requested_model: None,
        message_count: shape.turn_count,
        tool_count: shape.tool_count,
        has_tools: shape.has_tools,
        total_chars: shape.text_chars,
        system_chars: shape.system_chars,
        max_tokens: shape.max_tokens,
        stream: facts.wants_stream(),
        prompt: Some(prompt),
        identity: None,
        signals: Default::default(),
    }
}

/// Enforce the hook content ceiling on a built invoke projection, on SERIALIZED bytes and BEFORE the
/// call — the same rule the LLM seam's `enforce_content_cap` applies: over-cap content is OMITTED
/// WHOLE (the hook is sent an empty projection), never truncated mid-value.
fn enforce_invoke_content_cap(
    p: busbar_contract::hooks::PromptProjection<'_>,
) -> busbar_contract::hooks::PromptProjection<'_> {
    let cap = busbar_kernel::proxy::hook_content_max_bytes();
    if cap == 0 {
        // Explicitly UNLIMITED — the operator turned the ceiling off (`0 = unlimited`), exactly as the
        // LLM seam's `enforce_content_cap` reads it. Without this a `0` ceiling would zero EVERY
        // projection (`bytes <= 0` is false for any content), blinding a screening rewrite hook.
        return p;
    }
    let bytes = p.system.as_deref().map(str::len).unwrap_or(0)
        + p.messages
            .iter()
            .map(|(role, text)| role.len() + text.len())
            .sum::<usize>();
    if bytes <= cap {
        return p;
    }
    metrics::counter!(busbar_kernel::metrics::HOOK_CONTENT_TRUNCATED_TOTAL).increment(1);
    busbar_contract::hooks::PromptProjection {
        system: None,
        messages: Vec::new(),
    }
}

/// Apply a hook's `rewrite` reply to an INVOKE payload's `arguments` — the invoke-family twin of the
/// LLM plane's `apply_rewrite_to_body`. This seam names no dialect: an invocation has no conversation
/// container to reframe, it has one untrusted content member (the `arguments` object), and the rewrite
/// REPLACES it.
///
/// # The invoke rewrite contract
///
/// A `prompt: rw` hook rewrites a tool call by returning a replacement arguments OBJECT, carried as a
/// rewrite `messages` entry — either the message's `content` (an object verbatim, or a JSON string
/// that parses to an object) or, for a bare message with no `role`, the message value itself. The LAST
/// message that yields a usable object wins (a true chain: a later hook overrides an earlier one).
///
/// FAIL-CLOSED end to end: a reply with no usable object (empty messages, plain-text content, a
/// non-object) leaves `arguments` UNTOUCHED and returns `false` — never a corrupted call.
fn apply_rewrite_to_invoke_args(
    args: &mut serde_json::Value,
    rw: &busbar_contract::hooks::RewriteReply,
) -> bool {
    let mut new_args: Option<serde_json::Value> = None;
    for msg in &rw.messages {
        // Prefer an explicit `content`; fall back to the message value itself only when it carries no
        // `role` (a bare args object), so a `{role, content:"text"}` message never leaks its role key
        // into the arguments.
        let candidate = match msg.get("content") {
            Some(c) => c,
            None if msg.get("role").is_none() => msg,
            None => continue,
        };
        let resolved = match candidate {
            serde_json::Value::Object(_) => Some(candidate.clone()),
            serde_json::Value::String(s) => serde_json::from_str::<serde_json::Value>(s)
                .ok()
                .filter(serde_json::Value::is_object),
            _ => None,
        };
        if resolved.is_some() {
            new_args = resolved;
        }
    }
    match new_args {
        Some(v) => {
            *args = v;
            true
        }
        None => false,
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
            emitter: None,
            caller: None,
            destinations: None,
        }
    }

    /// Run `f` SYNCHRONOUSLY with a materialized [`HostCtx`] + the host `&PlaneHostVtable` — the
    /// between-awaits seam a plane call rides. The `HostState` backing the `HostCtx` is stack-pinned
    /// for exactly the duration of `f` (the [`recover`] invariant); the pointer must not escape it. A
    /// fresh [`HostGeneration`] opens for exactly this call and drops when it returns, so a `HostCtx`
    /// that escapes `f` anyway is refused (its generation is no longer live) rather than dereferenced.
    pub fn with_host<R>(&self, f: impl FnOnce(HostCtx, &PlaneHostVtable) -> R) -> R {
        mint(None, None, None, self.app, &self.scope, f)
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
            emitter: None,
            caller: None,
            destinations: None,
        }
    }

    /// Run `f` synchronously with a materialized [`HostCtx`] + host vtable, INSIDE the blocking body.
    /// The [`HostGeneration`] opens HERE (on the blocking thread the closure actually runs on —
    /// `HostGeneration` is thread-local, so opening it back on the async task's thread in
    /// [`new`](Self::new) would mint a stamp that is never live on the thread that checks it) and
    /// drops when this call returns.
    pub fn with_host<R>(&self, f: impl FnOnce(HostCtx, &PlaneHostVtable) -> R) -> R {
        mint(None, None, None, &self.app, &self.scope, f)
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
            emitter: None,
            caller: None,
            destinations: None,
        }
    }

    /// Run `f` synchronously with a materialized [`HostCtx`] + host vtable over the durable arena. A
    /// fresh [`HostGeneration`] opens for exactly this call (on this thread) and drops when it
    /// returns, so a `HostCtx` from a prior/foreign call is refused rather than dereferenced.
    pub fn with_host<R>(&self, f: impl FnOnce(HostCtx, &PlaneHostVtable) -> R) -> R {
        mint(None, None, None, &self.app, self.durable.arena(), f)
    }
}

#[cfg(test)]
#[path = "tests/mod_tests.rs"]
mod tests;

// ==== merged from busbar-substrate (W4.b P2 engine drain) ====
// THE NEUTRAL LLM-RUNTIME BUILD CARRIER (1.6.0 money-path Phase 3-4 C): the single-compiled `PlaneBuildInput`
// DTO `busbar-core`'s `appbuild` populates and hands to the LLM plane's `build_runtime` seam.
pub mod build_input;
// THE NEUTRAL READ-SIDE PROJECTION of a data-plane's routing tables (1.6.0 money-path Phase 3-4 B):
// the `EngineTablesView` trait + `LaneView` + the zero-plane `EMPTY_VIEW` the core scrape/discovery
// readers name so they need not move when the tables relocate into `busbar-llm`.
pub mod engine_view;
// The mTLS client-identity registry, the extra-root trust-anchor registry and the peer-certificate
// SPKI DER walk — PURE host-side TLS helpers (process-atomic registries + an RFC 5280 length-skip; no
// `App`, no engine, no FFI). They live here so the host egress chokepoint and the A2A plane both name
// one neutral home; core re-exports them under their historical `crate::plane_host::{identity,
// trust_anchor,spki}` paths.
pub mod identity;
// THE COMPOSITION-ROOT-OWNED EGRESS-TRUST SEAM (HOST-CAPS S3, DECISIONS #26): the `EgressTrustHost`
// trait naming client-identity / trust-anchor / peer-SPKI as ONE host capability, with a byte-for-byte
// pass-through impl and a composition-root install/get. Additive and DORMANT — no shipped call site
// consults it yet (W2 flips the egress chokepoint onto it).
pub mod egress_trust;
// `PlaneSlots` through any pointer to a slot holder (`Arc`, load guard, borrow), so a plane's slot
// readers can take `&impl PlaneSlots` instead of a concrete snapshot type without touching callers.
pub mod slots_through;
pub mod spki;
pub mod trust_anchor;

use crate::breaker::CanonicalSignal;
use crate::plane::approvals::Sealer;
use crate::plane::calllog::CallInput;
pub use crate::plane_host::build_input::{
    AffinityInput, AuthStyleInput, BreakerInput, ClientSettingsInput, FailoverInput, HealthInput,
    HealthModeInput, LaneInput, OnExhaustedInput, PlaneBuildInput, PoolInput, PoolMemberInput,
    TripInput, TripModeInput,
};
pub use crate::plane_host::engine_view::{
    EmptyEngineTablesView, EngineTablesView, LaneView, EMPTY_VIEW,
};
use crate::store::Unavailable;
use crate::trust::validate::{Lapsed, Standing};
use crate::trust::TrustState;
use busbar_contract::auth::{AuthPrincipal, IdentityRefusal};
use busbar_contract::records::{PlaneRequestCtx, VirtualKey};
use busbar_plugin::hot::{AdmissionId, Signal, StatusClass};

/// The outcome of a refusal-fidelity admit driven over the host `govern_admit_reason` seam.
#[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
pub enum GovAdmit {
    /// Admitted — the RAII grant is registered in the arena the caller passed.
    Admitted,
    /// A limit blocked — the RENDERED reason (byte-identical to the plane's own
    /// `format!("{blocked:?}")`) and the block's recovery floor in whole seconds.
    Blocked {
        /// The rendered reason bytes the host copied out (the exact `{blocked:?}` the plane surfaces).
        reason: String,
        /// The recovery floor in whole seconds (`0` when the block does not self-recover / never rolls).
        retry_after_secs: u64,
    },
}

/// The verdict of a request-admission gate fired over the host `gate_decide` seam.
#[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
pub enum GateOutcome {
    /// No gate objected (or none is attached) — the request proceeds.
    Proceed,
    /// A gate refused the request. Reconstructed from the `GateVerdictOut` header + the copied-out
    /// buffers, byte-identical to the in-process `GateVerdict::Reject`.
    Reject {
        /// The hook's refusal status, already clamped to the 4xx band by the gate.
        status: u16,
        /// The hook's own refusal message (empty on a fail-closed refusal).
        message: String,
        /// The transport/policy name, for the audit row and the log line (empty on a fail-closed refusal).
        hook: String,
    },
}

/// The verdict of a request-admission TRANSFORM (`prompt: rw` rewrite) chain fired over the host
/// `transform_over` seam — the TAP/observe-transform half of the hook surface, the twin of
/// [`GateOutcome`] for the rewrite pass. When no rewrite hook is attached the plane never calls the
/// seam (it guards on [`AdmissionHost::tap_attached`]), so the request/response path is BYTE-IDENTICAL
/// to a deployment with the seam absent: the tap is a no-op absent hooks.
#[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
pub enum TransformVerdict {
    /// The transform chain ran. `args_json` is the (possibly rewritten) payload the plane should send
    /// upstream; `applied` is `true` IFF a hook actually committed a rewrite (so the plane can keep
    /// its original bytes untouched — and therefore byte-identical — when no rewrite landed, even
    /// though a chain of purely-abstaining hooks fired). Reconstructed byte-for-byte from the same
    /// serde_json round-trip the gate seam uses (`preserve_order` OFF ⇒ a `Value` object is a
    /// sorted-stable `BTreeMap`).
    Proceed {
        /// Whether ANY hook in the chain committed a rewrite to the payload.
        applied: bool,
        /// The payload bytes to send upstream — the rewritten `arguments`/`params` when `applied`, or
        /// a faithful re-serialization of the original otherwise (the plane uses its own bytes then).
        args_json: Vec<u8>,
    },
    /// A `prompt: rw` gate REJECTED the request on the transform path (reject > rewrite > abstain).
    /// Same clamped/sanitized semantics as a decide-path reject, reconstructed identically to
    /// [`GateOutcome::Reject`].
    Reject {
        /// The hook's refusal status, already clamped to the 4xx band.
        status: u16,
        /// The hook's own refusal message (empty on a fail-closed refusal).
        message: String,
        /// The transport/policy name, for the audit row and the log line (empty on a fail-closed refusal).
        hook: String,
    },
}

/// What could be established about a presented bearer's RFC 8707 audience binding — the outcome of
/// the host `identity_audience_binding` pre-filter, for credentials busbar did not mint.
///
/// Relocated here from `busbar_kernel::auth::audience` so a plane reads the pre-filter verdict without
/// naming the core auth module; the binding JUDGEMENT (which reaches core's governance token prefix)
/// stays core behind [`EngineHost::identity_audience_binding`]. Core re-exports this at
/// `crate::auth::audience::Binding`, so its own callers and the enum's variants are unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AudienceBinding {
    /// A busbar-signed token. The real audience check happens in the verifier, which has the
    /// signature and the claims; the pre-filter must not pre-judge it.
    Deferred,
    /// A JWT whose `aud` includes the expected value. Not an admission — the chain still verifies it.
    Bound,
    /// A JWT whose `aud` does not include the expected value, or which carries no `aud` at all. Both
    /// are refused for the same reason: minted for someone else, or for nobody in particular.
    Mismatch,
    /// Not a JWT and not a busbar token: nothing to read. Refused.
    Opaque,
}

/// The raw wire outcome of a host-driven completion: the pipeline's HTTP status and body bytes,
/// for the plane to shape into its protocol's own result. Neutral — no axum `Response`, no `App`.
#[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
pub struct HostCompletion {
    /// The pipeline's HTTP status.
    pub status: u16,
    /// The pipeline's response body bytes (bounded by the `max_body_bytes` the caller passed).
    pub body: bytes::Bytes,
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE GAUNTLET SEAM — one shared request sequence every protocol plane rides.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The neutral per-request facts of ONE gauntlet traversal that the SHARED sequence
/// ([`run_gauntlet`]) reads and threads — the resolved identity, the destination the pre-admission
/// verify judges, and the correlation/timing a plane's stage-6 record joins on. Everything protocol-
/// or dialect-specific (the parsed body, the dialect handler, the wire framing, the plane's engine)
/// lives in the plane's own [`GauntletPlane`] value, NEVER here — so this names no plane type.
pub struct GauntletRequest<'a> {
    /// Stage 1 — the resolved caller identity/scope, threaded from the auth layer that ran upstream.
    pub gov: &'a busbar_contract::records::PlaneRequestCtx,
    /// The destination key the pre-admission `verify_destination` judges — a model for the LLM plane,
    /// a tool/server for the MCP plane. Opaque to the shared sequence; each plane spells its meaning.
    pub destination: &'a str,
    /// The per-request correlation id the plane's stage-6 audit record joins on (single-accounting).
    pub correlation_id: u64,
    /// The header-arrival epoch (whole seconds) the request was admitted at — the metering window base.
    pub charged_at: u64,
    /// The monotonic start instant for the request-duration metric.
    pub started: std::time::Instant,
}

/// The outcome of the pre-admission destination verification (stage 2).
pub enum VerifyOutcome {
    /// The destination is permitted; the sequence proceeds to the plane's `drive`.
    Proceed,
    /// The destination is refused. The plane returns its OWN already-finished, protocol-native
    /// response (metrics/webhook already emitted plane-side); [`run_gauntlet`] returns it verbatim,
    /// so refusal shaping stays byte-identical to the plane's in-place rejection.
    Refuse(axum::response::Response),
}

/// THE LOOP'S ANSWER SHAPE at the unified boundary (DECISIONS #28), plane-neutral.
///
/// When a rider runs on the kernel Teller loop (`busbar_kernel::teller::run_unit`), the loop returns
/// only the money/lifecycle `Ended`; the request's ANSWER bytes are read back out of the plane's own
/// `ctx.key`-keyed binding table (the admin template — `AdminUnitTable`). `PlaneAnswer` is what a
/// rider stashes into that table and the outer async handler serves. Two shapes, per #28:
///
/// - [`PlaneAnswer::Unary`] — buffered status + headers + body, crosses the sync channel and settles
///   at Encode on the final byte count (the admin cleanliness caller and every unary verb, including
///   an SSE body materialised after dispatch).
/// - [`PlaneAnswer::Live`] — a live body the outer handler serves directly, governed at admit
///   (auth/verify/approve/admit/audit ran unary), bypassing the Encode-emits-bytes path (the llm
///   RouteLeg emits this).
///
/// NEUTRAL BY CONSTRUCTION: nothing here names a plane, a dialect or a verb, and it lives in the
/// neutral substrate tier — NOT in `busbar-kernel`, which keeps naming zero planes and zero answer
/// shapes. It coexists with the shipped [`crate::plane_host`] `PlaneDispatch`-role carriers (#28): a
/// plane's arena (`DispatchScope`) rides its own loop value, so nothing in this shape carries it.
pub enum PlaneAnswer {
    /// Buffered: status, headers, body bytes. Settles at Encode on the final byte count.
    Unary(
        axum::http::StatusCode,
        axum::http::HeaderMap,
        axum::body::Bytes,
    ),
    /// A live body the outer async handler serves directly, governed at admit.
    Live(axum::response::Response),
}

impl PlaneAnswer {
    /// Materialise either shape into the one response the outer handler serves. `Unary` is rebuilt
    /// status-for-header-for-byte so a buffered answer serves byte-identically to the response the
    /// plane shaped; `Live` is handed through untouched.
    pub fn into_response(self) -> axum::response::Response {
        match self {
            PlaneAnswer::Unary(status, headers, body) => {
                let mut resp = axum::response::Response::new(axum::body::Body::from(body));
                *resp.status_mut() = status;
                *resp.headers_mut() = headers;
                resp
            }
            PlaneAnswer::Live(resp) => resp,
        }
    }
}

/// THE PLANE-NEUTRAL IN-FLIGHT ANSWER TABLE (DECISIONS #28), keyed by the unit's `ctx.key`.
///
/// The kernel Teller loop (`busbar_kernel::teller::run_unit`) returns only the money/lifecycle
/// `Ended`; a rider stashes its [`PlaneAnswer`] here at the step that produced it (Route, or a
/// pre-charge refusal) and the outer async handler reads it back by key AFTER the loop returns —
/// mirroring `AdminUnitTable` (the admin template, `admin_mount.rs`). NEUTRAL BY CONSTRUCTION: the
/// key is a bare `u64` (the raw `ctx.key`), so this names no plane, no dialect and no verb, and it
/// lives in the neutral substrate tier — every rider (mcp first, then a2a/voice/llm) reuses this ONE
/// table with zero new seam code.
#[derive(Default)]
pub struct PlaneInFlight {
    slots: std::sync::Mutex<std::collections::BTreeMap<u64, Option<PlaneAnswer>>>,
}

impl PlaneInFlight {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        PlaneInFlight::default()
    }

    /// Open a slot for a unit about to run. Idempotent; a re-open clears any prior answer.
    pub fn open(&self, key: u64) {
        self.slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, None);
    }

    /// Record the unit's answer, at the step that produced it.
    pub fn store(&self, key: u64, answer: PlaneAnswer) {
        self.slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, Some(answer));
    }

    /// Take the unit's answer out and forget the slot, after the loop returned. `None` if the unit
    /// produced no answer (a path that never reached the step that stores one).
    #[must_use]
    pub fn take(&self, key: u64) -> Option<PlaneAnswer> {
        self.slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&key)
            .flatten()
    }
}

/// A protocol plane's contribution to the shared gauntlet: the pre-admission destination check
/// (stage 2, sync) and the byte-identical engine that admits, routes, meters and finishes the
/// request (stages 4+5, async). The SHARED sequence ([`run_gauntlet`]) owns only stage 1 (identity,
/// already resolved and threaded via `req.gov`) and the stage-2→drive ORDER — verify strictly before
/// any charge, so nothing can reject an already-charged request. The sequence pulls NOTHING out of
/// `drive`: the plane's admission/route/metering/finish stay inside it, byte-identical. Names are
/// neutral; a plane implements this in its own crate (`busbar-mcp`/`busbar-a2a`) or in core (the LLM
/// native plane) identically — they are siblings on this one seam.
#[async_trait::async_trait]
pub trait GauntletPlane: Send + Sync {
    /// STAGE 2 — pre-admission destination verification. Sync; runs BEFORE `drive`. `Proceed` clears
    /// the request to admission; `Refuse` carries the plane's OWN finished, protocol-native rejection.
    fn verify_destination(&self, req: &GauntletRequest<'_>) -> VerifyOutcome;

    /// STAGES 4+5 — the plane's OWN engine: budget-admission, route/failover, egress, and the plane's
    /// own metering, returning the (possibly streaming) response. Byte-identical to the plane's
    /// in-place dispatch. Takes `self: Box<Self>` so the plane moves its owned per-request payload
    /// (body/parsed form/grant) into the engine; object-safe, so `run_gauntlet` drives it as `dyn`.
    async fn drive(self: Box<Self>, req: GauntletRequest<'_>) -> axum::response::Response;

    /// THIS PLANE'S CAPABILITY KEY, for the composition-tier host-selection seam
    /// ([`register_gauntlet_runner`]). `None` (the DEFAULT) means "run me on the substrate loop,
    /// exactly as today" — so with nothing overridden and nothing registered, every path is
    /// byte-identical to the shipped release. A plane opts onto the unified kernel loop by returning
    /// its key AND the composition root registering a runner under it (an oracle-gated flip, #29).
    /// NEUTRAL: the trait names no plane; each plane spells its own key, and the seam only ever
    /// compares strings.
    fn capability_key(&self) -> Option<&str> {
        None
    }
}

/// The successful OPEN-PASS ADMISSION result of the session gate in [`run_gauntlet_session`] — the request cleared the verify-before-
/// charge gate. Carries the per-request `correlation_id` so a SESSION opener ([`run_gauntlet_session`])
/// can join its own later durable/audit rows on it. A one-shot [`run_gauntlet`] discards it and proceeds
/// straight to `drive`; a session opener returns it to the plane, which then reserves/binds/opens its
/// live carrier AFTER (nothing charged before the gate cleared).
#[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admitted {
    /// The per-request correlation id the caller threads into its stage-6 / durable-session record.
    pub correlation_id: u64,
}

// THE SUBSTRATE TELLER LOOP IS GONE (W2.b, DECISIONS #28). The gauntlet's old seat on that loop — the
// `GauntletAdapter` (a pass-through `TellerPlane`), `gauntlet_unit`, and the `admit_open` open-pass gate —
// was deleted with `busbar-substrate/src/teller/`. Every shipped plane now rides the UNIFIED
// `busbar_kernel::teller` loop via a registered runner on the host-selection seam below; the fallback for
// an unregistered/test plane is the inline verify-then-drive in `run_gauntlet[_session]`, byte-identical
// to what that adapter loop produced (it wrapped nothing).

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE COMPOSITION-TIER HOST-SELECTION SEAM (loop unification, DECISIONS #28).
//
// A per-capability-keyed registry of KERNEL-LOOP runners the composition root installs at boot
// (mirrors the admin-mount-seam, busbar-core/src/admin/seam.rs). The kernel loop lives in
// `busbar-kernel`, which this tier does not depend on, so the runners are FN-POINTERS root injects.
// The gauntlet free fns below consult the registry by the request's plane capability key: if a
// runner is registered, route to it; UNSET (the default) runs today's substrate loop, byte-identical.
// NEUTRAL: the seam names no plane — it is a `&str`-keyed table, exactly as `AdminUnitTable` is
// `ctx.key`-keyed. Per-plane flip = registering that one plane's runner, oracle-gated (#29).
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// A kernel-loop one-shot runner, as the composition root injects it: the kernel-loop twin of
/// [`run_gauntlet`], erased to a fn-pointer so this tier need not name `busbar-kernel`.
pub type GauntletRunner = for<'a> fn(
    GauntletRequest<'a>,
    Box<dyn GauntletPlane + 'a>,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = axum::response::Response> + Send + 'a>,
>;

/// A kernel-loop session runner, the kernel-loop twin of [`run_gauntlet_session`].
pub type SessionRunner = for<'a> fn(
    GauntletRequest<'a>,
    Box<dyn GauntletPlane + 'a>,
) -> Result<Admitted, axum::response::Response>;

static ONE_SHOT_RUNNERS: std::sync::RwLock<
    std::collections::BTreeMap<&'static str, GauntletRunner>,
> = std::sync::RwLock::new(std::collections::BTreeMap::new());

static SESSION_RUNNERS: std::sync::RwLock<std::collections::BTreeMap<&'static str, SessionRunner>> =
    std::sync::RwLock::new(std::collections::BTreeMap::new());

/// Register a kernel-loop one-shot runner for a plane capability key. Composition root only, at boot.
/// Last-write-wins and idempotent. Registering a key is the per-plane FLIP onto the unified loop.
pub fn register_gauntlet_runner(key: &'static str, runner: GauntletRunner) {
    ONE_SHOT_RUNNERS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(key, runner);
}

/// Register a kernel-loop session runner for a plane capability key. Composition root only, at boot.
pub fn register_session_runner(key: &'static str, runner: SessionRunner) {
    SESSION_RUNNERS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(key, runner);
}

/// Whether a one-shot kernel-loop runner is registered for this capability key — i.e. whether that
/// plane has been FLIPPED onto the unified kernel loop. The read-side twin of
/// [`register_gauntlet_runner`], for a composition-root boot assertion or a per-plane cutover
/// regression test. NEUTRAL: a bare `&str` lookup that names no plane.
#[must_use]
pub fn gauntlet_runner_registered(key: &str) -> bool {
    one_shot_runner(key).is_some()
}

/// Whether a SESSION kernel-loop runner is registered for this capability key — i.e. whether that
/// session plane (voice/streaming) has been FLIPPED onto the unified kernel loop's session admit. The
/// read-side twin of [`register_session_runner`], for a composition-root boot assertion or a per-plane
/// cutover regression test. NEUTRAL: a bare `&str` lookup that names no plane.
#[must_use]
pub fn session_runner_registered(key: &str) -> bool {
    session_runner(key).is_some()
}

fn one_shot_runner(key: &str) -> Option<GauntletRunner> {
    ONE_SHOT_RUNNERS
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(key)
        .copied()
}

fn session_runner(key: &str) -> Option<SessionRunner> {
    SESSION_RUNNERS
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(key)
        .copied()
}

/// THE SHARED GAUNTLET SEQUENCE — the ONE request path every protocol plane rides. It consults the
/// host-selection seam first: a plane whose capability key has a kernel-loop runner registered rides
/// the UNIFIED `busbar_kernel::teller` loop; every other plane (a not-yet-flipped or test plane) runs
/// the inline verify-then-`drive` fallback below, byte-identical to the deleted substrate Teller loop
/// this seam used to ride (that loop wrapped nothing — see the fallback comment).
/// Stage 1 identity is already resolved (threaded via `req.gov`); the path runs the plane's
/// `verify_destination` at Verify, in the correct PRE-ADMISSION position, and only if it proceeds the
/// plane's `drive` at Route (its own byte-identical engine + metering). Returns the plane's (possibly
/// streaming) response verbatim. The plane owns admission/route/metering/finish; the loop owns solely
/// the order (nothing may reject after a charge) — so all planes enforce that invariant in ONE place.
pub async fn run_gauntlet(
    req: GauntletRequest<'_>,
    plane: Box<dyn GauntletPlane + '_>,
) -> axum::response::Response {
    let selected = plane.capability_key().and_then(one_shot_runner);
    if let Some(runner) = selected {
        return runner(req, plane).await;
    }
    // NO kernel-loop runner registered for this key. With W2.b every shipped plane is flipped onto the
    // unified kernel loop, so this arm is the DEFAULT only for a plane not (yet) flipped or a test
    // plane. It runs the plane's OWN two-stage sequence inline — verify STRICTLY before drive — which
    // is BYTE-IDENTICAL to the (now-deleted) substrate Teller loop the gauntlet used to ride: that loop
    // proceeded every step, opened an empty hold, settled nothing, and returned the plane's `drive`
    // response (or its own pre-charge refusal) verbatim. The loop wrapped nothing, so inlining it
    // removes only the redundant loop, not any behaviour (the kernel-vs-substrate shadow-compare proved
    // the two produced identical bytes before the substrate loop was removed).
    match plane.verify_destination(&req) {
        VerifyOutcome::Refuse(resp) => resp,
        VerifyOutcome::Proceed => plane.drive(req).await,
    }
}

/// THE SESSION SIBLING of [`run_gauntlet`] — the OPEN-PASS admission for a live, session-oriented plane
/// (voice/duplex) that has no one-shot `drive`-shaped Response to return. It runs the SAME
/// verify-STRICTLY-before-charge gate (a registered kernel-loop session runner, else the inline
/// fallback) and returns the [`Admitted`] result instead of
/// driving a request: the plane's own reserve/bind/open + socket bind proceed only on `Ok`, so a `Refuse`
/// costs ZERO bytes and ZERO charge (nothing opened before the gate cleared). Distinct from
/// [`run_gauntlet`] (one Response) but a TRUE sibling — they share the one verify-before-charge gate, so
/// a refactor can neither inline nor foreclose this opener, and both enforce that one order.
///
/// Synchronous: the admission gate is `verify_destination` (sync), so a session opener (a sync
/// `begin_session`) calls this directly — there is no async `drive` leg on the session path.
///
/// (`result_large_err`: the `Err` is the plane's OWN finished refusal `Response`, carried BY VALUE so
/// refusal shaping stays byte-identical to [`run_gauntlet`]'s verbatim return — boxing it would diverge
/// the two siblings on the type they carry a refusal in.)
#[allow(clippy::result_large_err)]
pub fn run_gauntlet_session(
    req: GauntletRequest<'_>,
    plane: Box<dyn GauntletPlane + '_>,
) -> Result<Admitted, axum::response::Response> {
    let selected = plane.capability_key().and_then(session_runner);
    if let Some(runner) = selected {
        return runner(req, plane);
    }
    // NO kernel-loop session runner registered for this key — the inline open-pass admit, BYTE-IDENTICAL
    // to the (now-deleted) substrate `admit_open`: it ran the SAME verify-STRICTLY-before-charge gate
    // through the substrate Teller's `open_unit` over a pass-through adapter that opened an empty hold
    // and settled nothing, returning `Admitted` (the request's own correlation) on a pass or the plane's
    // OWN finished refusal verbatim. Inlining removes only the redundant loop: on `Refuse` NOTHING is
    // opened (zero bytes, zero charge); on `Proceed` the caller opens its own carrier next.
    match plane.verify_destination(&req) {
        VerifyOutcome::Refuse(resp) => Err(resp),
        VerifyOutcome::Proceed => Ok(Admitted {
            correlation_id: req.correlation_id,
        }),
    }
}

/// The `plane_slots` companion key under which a plane's ALWAYS-PRESENT per-generation runtime object
/// is carried — DERIVED from the plane's own decl `key` by the neutral `"<key>:runtime"` convention,
/// so core spells no plane token. It is deliberately distinct from the plane's config-conditional
/// dispatch slot (carried under the bare decl key): the runtime bundle exists on every generation
/// whereas the dispatch slot is absent when the plane's config block is unspecified, so folding them
/// onto one key would change the bare key's presence semantics (and the dispatch table `build_dispatch`
/// derives from it). Named by both core's `appbuild` (which composes the slot) and the owning plane
/// (which reads it back through [`EngineHost::plane_slot`]) — each passes its decl key and gets the
/// SAME interned `&'static str`, so it lives in the neutral substrate rather than either crate.
///
/// Interned process-lifetime (leaked once per distinct key, bounded by the plane count) so the
/// companion key is a stable `&'static str` fit for the `plane_slots` map's key type without either
/// caller holding a hard-coded literal.
pub fn runtime_slot_key(plane_key: &str) -> &'static str {
    static INTERNED: std::sync::Mutex<std::collections::BTreeMap<String, &'static str>> =
        std::sync::Mutex::new(std::collections::BTreeMap::new());
    let composed = format!("{plane_key}:runtime");
    let mut interned = INTERNED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(k) = interned.get(&composed) {
        return k;
    }
    let leaked: &'static str = Box::leak(composed.clone().into_boxed_str());
    interned.insert(composed, leaked);
    leaked
}

/// A source of freshly live-bound hosts: each call returns a host reading the current snapshot,
/// so a config swap between calls is seen. Handed to transports that re-mint per frame.
pub type LiveHostFactory = std::sync::Arc<dyn Fn() -> std::sync::Arc<dyn EngineHost> + Send + Sync>;

// ─────────────────────────────────────────────────────────────────────────────────────────────
// OPAQUE GOVERNANCE HANDLES (App-retype WEDGE 2) — the neutral carrier tokens a plane HOLDS on its
// per-request sink so the sink's field types stop naming `busbar_kernel::governance::GovState` /
// `busbar_kernel::cost::CostModel` / `busbar_kernel::governance::AdmitGrant`. Each wraps an
// `Arc<dyn Any + Send + Sync>` the host minted over the concrete engine value; the plane never
// introspects it — it hands [`GovHandle`]/[`CostHandle`] BACK to the metering seams
// ([`EngineHost::meter_ledger`]/[`EngineHost::meter_series`]), which downcast host-side. This keeps
// the byte-identical `sink.gov`/`sink.cost` the plane minted (a custom test cost, the live app cost —
// whichever the sink was built from), NOT a re-read of the host snapshot.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// An OPAQUE, cheaply-cloned (one `Arc` bump) handle to the deployment's governance state — minted
/// host-side ([`EngineHost::governance`]) and consumed host-side ([`EngineHost::meter_ledger`] /
/// [`EngineHost::meter_series`]). The plane holds it on its per-request sink WITHOUT naming
/// `busbar_kernel::governance::GovState`.
#[derive(Clone)]
pub struct GovHandle(pub Arc<dyn std::any::Any + Send + Sync>);

/// The cost-model twin of [`GovHandle`] — an opaque handle to a resolved `CostModel`. KERNEL-SIDE
/// ONLY: it rides inside a [`MeterPin`] and no plane-facing signature names it (#43).
#[derive(Clone)]
pub struct CostHandle(pub Arc<dyn std::any::Any + Send + Sync>);

/// THE METER PIN — what a plane holds on its per-request sink so its counts land against the
/// governance state AND the rate card that were in force when the request was admitted. OPAQUE: the
/// fields are private and only the kernel's host pins a card ([`BudgetHost::meter_pin`]), so a plane
/// carries its request's pricing context without naming a cost or price type (#43: a plane is
/// PRICING-BLIND; #71: its money obligation is one raw count per class). The plane hands the pin BACK
/// to the metering seams ([`BudgetHost::meter_ledger`], [`BudgetHost::rate_headroom`],
/// [`BudgetHost::budget_state`], [`BudgetHost::meter_series`]), which read it kernel-side. A plane
/// calls [`BudgetHost::meter_series`] UNCONDITIONALLY with the counts it observed (#43: no branch, no
/// knowledge of billing state) — #42's billing-off posture is the VIEW's job (the served figure reads
/// zero), not the write's; nothing kernel-side gates the row on the pinned card any more (that gate,
/// `meter_series_billed`, was dead code with no production caller after d09c2e0b0 and is gone).
///
/// A plane-side host (a test double) pins NO card: its pin answers the no-card posture everywhere.
#[derive(Clone)]
pub struct MeterPin {
    gov: GovHandle,
    cost: CostHandle,
}

impl MeterPin {
    /// Pin `gov` and the card `cost` names. Kernel-side; a TEST that hand-builds a card pins it here.
    #[cfg(any(test, feature = "test-support"))]
    pub fn new(gov: GovHandle, cost: CostHandle) -> Self {
        MeterPin { gov, cost }
    }

    /// The governance handle the pin carries — what [`BudgetHost::meter_series`] takes.
    pub fn gov(&self) -> &GovHandle {
        &self.gov
    }
}

/// An opaque handle to a governance ADMISSION grant (`AdmitGrant`), held DROP-ONLY on a plane's
/// per-request sink so the admission's in-flight concurrency holds release when the last sink clone
/// drops. The plane never introspects it; it exists purely so its `Drop` (on the last clone) releases
/// the gauges — byte-identical to the sink's current `Option<Arc<busbar_kernel::governance::AdmitGrant>>`.
#[derive(Clone)]
pub struct AdmitHandle(pub Arc<dyn std::any::Any + Send + Sync>);

/// BRAKE (audit D): the BREAKER-family slice of the host seam, split off `EngineHost` as a supertrait
/// so the circuit-breaker admission/settle/record cluster stays a cohesive, bounded ABI rather than
/// dissolving into the ~30-method god-trait. Groups the five `(pool, lane)` breaker seams a plane's
/// dispatch/failover legs drive: win a probe ([`breaker_admit`](Self::breaker_admit)), fold a leg's
/// outcome ([`breaker_settle`](Self::breaker_settle)), the in-place record fallbacks
/// ([`breaker_record_success`](Self::breaker_record_success) /
/// [`breaker_record_signal`](Self::breaker_record_signal)), and the cooldown read
/// ([`breaker_retry_after_secs`](Self::breaker_retry_after_secs)). PURE STRUCTURAL: every method keeps
/// its exact signature and same-dispatch body; a plane that names `EngineHost` still calls these
/// through the inherited supertrait bound.
pub trait BreakerHost: Send + Sync {
    /// WIN ONE `(pool, lane)` breaker probe through the host `breaker_admit` seam, leaving the
    /// settle-capable admission REGISTERED in `scope`'s arena and returning the POD [`AdmissionId`] —
    /// or the store's own [`Unavailable`] refusal. Identical to
    /// `busbar_kernel::plane_host::breaker::breaker_admit_over`.
    fn breaker_admit(
        &self,
        scope: &DispatchScope,
        pool: &[u8],
        lane: u32,
    ) -> Result<AdmissionId, Unavailable>;

    /// Fold a leg's classified outcome through the host `breaker_settle` seam over `admission` (looked
    /// up in `scope`'s arena). `Ok` means the live admission was found and settled; a `Gone` means it
    /// was already settled — the caller falls back to an in-place record. Byte-identical disposition
    /// to the plane's own `record_signal`/`record_success`.
    fn breaker_settle(
        &self,
        scope: &DispatchScope,
        admission: AdmissionId,
        signal: &Signal,
    ) -> StatusClass;

    /// Record a SUCCESS against the `(pool, lane)` breaker cell in place — the fallback a settle leg
    /// takes when no arena owns the probe (or a multi-round leg whose probe was already settled).
    /// Identical to the plane's own `PlaneBreakers::record_success`.
    fn breaker_record_success(&self, pool: &str, lane: usize);

    /// Record a canonical failure signal against the `(pool, lane)` breaker cell in place — the
    /// fallback twin of [`breaker_record_success`](Self::breaker_record_success). Identical to the
    /// plane's own `PlaneBreakers::record_signal`.
    fn breaker_record_signal(&self, pool: &str, lane: usize, sig: &CanonicalSignal);

    /// The seconds until the `(pool, lane)` breaker cell's cooldown expires — the honest `Retry-After`
    /// for a refused pooled dispatch, read PER MEMBER so a pool whose members trip independently
    /// answers with the soonest. Identical to the plane's own `PlaneBreakers::retry_after_secs`; a
    /// pure read, so it needs no `HostCtx`.
    fn breaker_retry_after_secs(&self, pool: &str, lane: usize) -> u64;
}

/// BRAKE (audit D): the LANE/POOL-family slice of the host seam, split off `EngineHost` as a supertrait
/// so the lane-runtime + pool-membership + probe-default cluster stays a cohesive, bounded ABI. Groups
/// the five seams a plane's routing/health machinery reads: the neutral breaker/lane store view
/// ([`lane_store`](Self::lane_store)), the two process-wide active-probe fallbacks
/// ([`default_probe_interval_secs`](Self::default_probe_interval_secs) /
/// [`default_probe_timeout_secs`](Self::default_probe_timeout_secs)), and the failover-pool membership
/// resolvers ([`pool_members_repeatable`](Self::pool_members_repeatable) /
/// [`plane_pool_members`](Self::plane_pool_members)). PURE STRUCTURAL: signatures and bodies are
/// unchanged; a plane that names `EngineHost` reaches these through the inherited supertrait bound.
pub trait LanePoolHost: Send + Sync {
    /// The breaker/lane store this deployment routes through, as the NEUTRAL
    /// [`busbar_kernel::store::LaneRuntime`](crate::store::LaneRuntime) view — the seam the engine's
    /// `app.store` reads (select/health/pipeline lane admit/settle/snapshot) resolve to WITHOUT naming
    /// core's `state::App`. A pure borrow of the bound snapshot's store, no `HostCtx`; the returned
    /// `&dyn LaneRuntime` shares the live in-memory breaker engine, identical to `&*App::store`.
    ///
    /// WEDGE 2 (App-retype): additive — the transitional seam the wedge-3 `app.store → host.lane_store()`
    /// flip targets. The `LaneRuntime` trait already lives in substrate (wedge 1), so this names no core type.
    fn lane_store(&self) -> &dyn crate::store::LaneRuntime;

    /// The process-wide active-probe INTERVAL fallback (whole seconds) a lane with no
    /// `health.interval_secs` inherits — the host-read form of `busbar_kernel::limits::default_probe_interval_secs`.
    /// A pure read of the live limits registry, no `HostCtx`; byte-identical to that free fn.
    ///
    /// WEDGE 2 (App-retype): additive — the seam the wedge-3 `health.rs` probe-spawn flip targets. The
    /// limits fns read core's runtime `LIMITS` global, so they CANNOT relocate to substrate by-identity;
    /// this host seam is the neutral home instead.
    fn default_probe_interval_secs(&self) -> u64;

    /// The process-wide active-probe TIMEOUT fallback (whole seconds) a lane with no `health.timeout_secs`
    /// inherits — the host-read twin of [`default_probe_interval_secs`](Self::default_probe_interval_secs).
    /// Byte-identical to `busbar_kernel::limits::default_probe_timeout_secs`.
    fn default_probe_timeout_secs(&self) -> u64;

    /// The `(pool_name, members, repeatable)` of the failover pool `member` belongs to, off the BOUND
    /// snapshot; `None` when `member` is un-pooled. `repeatable` is the pool's `repeatable:` operation
    /// list (what `CandidatePoolCfg::repeatability` consults) — the extra tuple element that
    /// distinguishes this seam from the 2-tuple [`plane_pool_members`](Self::plane_pool_members).
    /// Identical to scanning the deployment's repeatable-carrying pool map.
    fn pool_members_repeatable(&self, member: &str) -> Option<(String, Vec<String>, Vec<String>)>;

    /// The `(pool_name, members)` of the failover pool `member` belongs to on the plane identified by
    /// the opaque registry `plane_key`, off the BOUND snapshot; `None` when `member` is un-pooled. The
    /// member-selection walk derives each candidate's lane from the member's position in the returned
    /// list, so name + members is the whole seam. Identical to scanning the plane's pool map.
    fn plane_pool_members(&self, plane_key: &str, member: &str) -> Option<(String, Vec<String>)>;
}

/// An OPAQUE handle to ONE open host-owned reserve-then-settle cost lease, minted by
/// [`MeteringHost::cost_reserve`] and handed back to [`MeteringHost::cost_settle`] /
/// [`cost_settled`](MeteringHost::cost_settled) / [`cost_close`](MeteringHost::cost_close). The
/// reserve/settled/cap money state lives HOST-side behind this id; only the `u64` handle crosses the
/// seam. Substrate-native (not the frozen hot-ABI POD) so the neutral seam stays independent of the
/// C-ABI, though the two are structurally the same `u64` handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CostLeaseId(pub u64);

impl CostLeaseId {
    /// The reserved sentinel a REFUSED reserve reads as — never a live lease (ids are minted `≥ 1`).
    pub const NONE: CostLeaseId = CostLeaseId(0);
}

/// The post-settle state [`MeteringHost::cost_settle`] reads back — the neutral twin of the hot-ABI
/// `CostSettleOut.exhausted` flag. A live carrier reads `exhausted` after each settle and HARD-CLOSES
/// the instant it is set (`settled ≥ cap`), the one thing post-hoc metering structurally cannot do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettleOutcome {
    /// Whether the caller's budget is now DRY (`settled ≥ cap`) — the carrier must hard-close.
    pub exhausted: bool,
}

/// THE KERNEL'S PRICING SIDE of a live carrier — the reserve-then-settle cost lease and the rate card
/// that prices each increment. KERNEL-INTERNAL (#43: "a plane plugin NEVER sees its rate card or
/// fees"): it is NOT a supertrait of [`EngineHost`], so no plane-side host implements it and no plane
/// names it. A plane meters a live carrier through the kernel's count-only
/// [`SessionAccount`](session_meter::SessionAccount), which prices nothing (Q21b); what drives this
/// trait is the hot-ABI cost slots.
///
/// The lease legs DEFAULT to the kernel's own host-owned `CostHold` registry ([`cost_host`]) — the SAME
/// registry the hot-ABI `cost_reserve`/`cost_settle` slots fill, so every lease is one ledger. An
/// implementor supplies the pricing. Money-denominated end to end in `u128` nanodollars (1e-9 USD);
/// this is a plain Rust trait, not the frozen hot FFI, so it carries `u128` without narrowing.
pub trait MeteringHost: Send + Sync {
    /// OPEN a reserve-then-settle cost lease over ALREADY-PRICED nanodollars and return its opaque
    /// [`CostLeaseId`]. `estimate_nanos` is the coarse over-estimate debited up front, `fee_nanos` the
    /// once-per-lease flat session fee (`0` = none), and `cap_nanos` the TRUE budget ceiling exhaustion
    /// is judged against: `None` leaves the lease UNCAPPED (never exhausts); `Some(0)` is a REFUSE-ALL
    /// cap, DENIED at the door — the method returns `None` and the session must fail closed (never
    /// open). Any other `Some(cap)` opens a live lease.
    fn cost_reserve(
        &self,
        estimate_nanos: u128,
        fee_nanos: u128,
        cap_nanos: Option<u128>,
    ) -> Option<CostLeaseId> {
        cost_host::reserve_lease(estimate_nanos, fee_nanos, cap_nanos).map(CostLeaseId)
    }

    /// ACCRUE one EXACT already-priced increment (`exact_nanos`) against the open lease `lease` and read
    /// back the post-settle [`SettleOutcome`]. The lease STAYS open after a settle — a live carrier keeps
    /// settling increments until it hard-closes. `None` iff `lease` names no open lease (unknown /
    /// already-closed / the [`CostLeaseId::NONE`] sentinel); on `None` the caller fails CLOSED and
    /// hard-closes the carrier, exactly as it would on `exhausted`.
    fn cost_settle(&self, lease: CostLeaseId, exact_nanos: u128) -> Option<SettleOutcome> {
        cost_host::settle_lease(lease.0, exact_nanos).map(|exhausted| SettleOutcome { exhausted })
    }

    /// The total nanodollars SETTLED so far against `lease` — the audit tap. `None` for an unknown /
    /// already-closed lease.
    fn cost_settled(&self, lease: CostLeaseId) -> Option<u128> {
        cost_host::settled_of(lease.0)
    }

    /// CLOSE and forget the lease `lease`, returning its finalize()'d ledgered total (the exact settled
    /// sum — never the coarse reserve). `None` for an unknown / already-closed lease. Idempotent: a
    /// second close reads `None`. Bounds the registry so a finished carrier's lease does not leak.
    fn cost_close(&self, lease: CostLeaseId) -> Option<u128> {
        cost_host::close_lease(lease.0)
    }

    /// PRICE a turn's neutral [`billing::Usage`](crate::billing::Usage) counts for `model` into
    /// nanodollars via the deployment's rate card — the SAME `CostModel` arithmetic the LLM
    /// enforcement/derive path uses (a new ENTRY POINT over the same function).
    ///
    /// Semantics mirror the host's per-model rate lookup exactly:
    /// - no rate card configured ⇒ `Some(0)` (pricing off — every model prices at 0, as core does);
    /// - card present, `model` priced ⇒ `Some(nanos)`;
    /// - card present, `model` UNKNOWN ⇒ `None` — the caller FAILS CLOSED (an unpriced passthrough model
    ///   must not meter as free).
    fn price_usage(&self, model: &str, usage: &crate::billing::Usage) -> Option<u128>;
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// CAPABILITY SLICES (M4 god-trait split) — the residual flat host seam, cut into cohesive capability
// supertraits so a plane depends ONLY on the slices it uses. `EngineHost` is the SUM (a supertrait of
// every slice), so an existing `Arc<dyn EngineHost>` caller is unaffected — it still reaches every
// method through the inherited bound — while a plane that needs a narrower capability (a voice/bytes
// port that must NOT name LLM-only `synthesize_completion`) can take `&dyn SliceX` instead. PURELY
// STRUCTURAL: every method keeps its exact signature, doc and same-dispatch body; nothing moves in the
// wire/ABI/money plane. The single `EngineHostImpl` (busbar-core) implements each slice.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The CLOCK slice: the host wall-clock reads a plane's timing/window arithmetic needs, in whole
/// seconds and milliseconds. Split off `EngineHost` as a supertrait; a plane that only needs the
/// clock can take `&dyn ClockHost`.
pub trait ClockHost: Send + Sync {
    /// Read the host wall clock in whole SECONDS through the `clock_now` seam — the host-driven form
    /// of a plane's in-place seconds clock. Identical to `busbar_kernel::plane_host::clock_now_secs_over`.
    fn clock_now_secs(&self) -> u64;

    /// Read the host wall clock in MILLISECONDS through the `clock_now` seam — the host-driven form of
    /// a plane's in-place millis clock. Identical to `busbar_kernel::plane_host::clock_now_ms_over`.
    fn clock_now_ms(&self) -> u64;
}

/// The TELEMETRY slice: the plane-labelled metric emits a plane fires to close a request out and to
/// count its dispatch/failover/translation events, plus the `pool_label` cardinality bound every emit
/// path runs first. Split off `EngineHost` as a supertrait; each emit is snapshot-scoped, no `HostCtx`.
pub trait TelemetryHost: Send + Sync {
    /// Stamp the plane-labelled request-completion metric family for a MOUNTED plane through the host.
    /// A neutral trait seam: the plane hands its own `(plane, ingress_protocol, pool, outcome, seconds)`
    /// and the host records the completion, so the plane never names core's engine snapshot to close a
    /// request out. Identical to `busbar_kernel::telemetry::request_finished` over the bound snapshot.
    fn request_finished(
        &self,
        plane: &str,
        ingress_protocol: &str,
        pool: &str,
        outcome: &'static str,
        seconds: f64,
    );

    /// Count ONE dispatch ATTEMPT on `(pool_label, lane)` — the `busbar_upstream_attempts_total`
    /// upstream-attempt metric — through the host, so the engine emits it without naming core's
    /// telemetry module. `pool_label` is the bounded metric label (a named pool, or the routed model
    /// name for the default `""` cell); `lane` is the lane index the host resolves the `lane` label
    /// from off the bound snapshot. A pure snapshot-scoped metric emit, no `HostCtx`; identical to
    /// `busbar_kernel::telemetry::upstream_attempt` over the bound snapshot.
    fn telemetry_upstream_attempt(&self, pool_label: &str, lane: usize);

    /// Count ONE classified upstream FAILURE on `(pool_label, lane)` by `disposition` — the
    /// `busbar_upstream_failures_total` metric — through the host. The telemetry twin of
    /// [`telemetry_upstream_attempt`](Self::telemetry_upstream_attempt); identical to
    /// `busbar_kernel::telemetry::upstream_failure` over the bound snapshot.
    fn telemetry_upstream_failure(&self, pool_label: &str, lane: usize, disposition: &'static str);

    /// Count ONE logical Closed→Open breaker TRIP on `(pool_label, lane)` — the
    /// `busbar_breaker_trips_total` metric — through the host. Identical to
    /// `busbar_kernel::telemetry::breaker_trip` over the bound snapshot.
    fn telemetry_breaker_trip(&self, pool_label: &str, lane: usize);

    /// Count ONE FAILOVER event on `pool_label` by `reason` — the `busbar_failovers_total` metric —
    /// through the host. Identical to `busbar_kernel::telemetry::failover` over the bound snapshot.
    fn telemetry_failover(&self, pool_label: &str, reason: &'static str);

    /// Count ONE cross-protocol TRANSLATION hop `from → to` — the `busbar_translations_total`
    /// metric — through the host. Both names come from the fixed protocol vocabulary, so the emit is
    /// snapshot-independent; identical to `busbar_kernel::telemetry::translation`.
    fn telemetry_translation(&self, from: &str, to: &str);

    /// Map a client-supplied model/name string to the BOUNDED `pool` metric label through the host:
    /// the string verbatim when it names a configured pool or by-model lane, else the fixed
    /// `"unresolved"` sentinel. Bounds the Prometheus label cardinality on every finish/webhook path.
    /// Identical to `busbar_kernel::ingress::pool_label` over the bound snapshot; the returned slice
    /// borrows `model` (or a `'static` sentinel), independent of the host.
    fn pool_label<'a>(&self, model: &'a str) -> &'a str;
}

/// The JOURNAL slice: the durable admin-audit / call-log emits a plane writes as a side effect of the
/// mutation it records. All fire-and-forget (a store miss never fails the recorded action). Split off
/// `EngineHost` as a supertrait.
pub trait JournalHost: Send + Sync {
    /// Emit ONE hostless admin-audit record `(action, resource, outcome, principal)` to the shared
    /// admin audit log. Fire-and-forget, loudly: a store write failure NEVER fails the mutation it
    /// records. Identical to `busbar_kernel::plane::auditlog::emit_admin_hostless_now` — this seam needs
    /// no `HostCtx`, so it is a plain forward to that engine (which stays unchanged in core).
    fn audit_emit(&self, action: &str, resource: &str, outcome: &str, principal: &str);

    /// Record ONE admin-audit event `(action, resource, outcome, principal)` through the IN-PROCESS
    /// ADMIN RING (`busbar_kernel::admin::audit::AUDIT::record_by`), which seals it into the retained ring
    /// AND cascades the SAME record onto the durable hostless journal seam. Distinct from
    /// [`audit_emit`](Self::audit_emit) (durable-only): this is the seam the DATA-plane egress
    /// audit-and-allow path (a dropped cross-dialect control) writes through, so the record lands in the
    /// in-process ring the egress audit-trail assertions read. `outcome` is a fixed vocabulary literal.
    ///
    /// WEDGE 3 (App-retype): the neutral home of the engine's `AUDIT.record_by(...)` reach.
    fn audit_record(&self, action: &str, resource: &str, outcome: &'static str, principal: &str);

    /// Emit ONE per-call record through the durable MCP call-log engine. The transient `HostCtx` the
    /// chain seam needs is minted INTERNALLY (a fresh per-call arena over the live engine — the append
    /// registers no host handle, so the arena choice is immaterial). Identical to
    /// `busbar_kernel::calllog::emit`.
    fn call_log_emit(&self, principal: &str, input: CallInput);

    /// The DEFERRED-SITE twin of [`call_log_emit`](Self::call_log_emit): emit through the
    /// HOSTLESS call-log path, for a client-leg site that has no `HostCtx` to open. Identical to
    /// `busbar_kernel::calllog::emit_hostless`.
    fn call_log_emit_hostless(&self, principal: &str, input: CallInput);
}

/// The MOUNT slice: the pure mount-table reads that shape an arrival's dialect and its pre-collapse
/// fallback error. Split off `EngineHost` as a supertrait; both are pure snapshot reads, no `HostCtx`.
pub trait MountHost: Send + Sync {
    /// The mount-aware dialect an answer to `path` is SHAPED in — the host-driven form of
    /// `busbar_kernel::ingress::native::envelope_dialect(App::planes.ingress_of(path))`. A pure snapshot
    /// mount-table read, no `HostCtx`.
    ///
    /// WEDGE 3 (App-retype — THE FLIP): the seam core's `ArrivalHost` impl reads instead of the dropped
    /// `ArrivalPayload::app`; the neutral `ArrivalPayload` now carries only the host, so this mount read
    /// crosses the host seam like every other.
    fn arrival_envelope_dialect(&self, path: &str) -> &'static str;

    /// The pre-collapse fallback error SHAPE by `path` — the host-driven form of
    /// `busbar_kernel::fallback_error_response(&App::planes, path, status, kind, message)`. Renders the
    /// unmatched-path/404 envelope in the dialect the deployment mounted `path` under; a pure snapshot
    /// mount-table read, no `HostCtx`. The twin of [`arrival_envelope_dialect`](Self::arrival_envelope_dialect).
    fn arrival_fallback_error(
        &self,
        path: &str,
        status: axum::http::StatusCode,
        kind: &str,
        message: &str,
    ) -> axum::response::Response;
}

/// The REGISTRY slice: the per-generation registry/snapshot reads a plane pulls off the bound (or
/// live) snapshot — its type-erased runtime slot, its type-erased defs, the request-id counter, the
/// neutral secret resolver, and the host-held card-signing key. Split off `EngineHost` as a supertrait.
pub trait RegistryHost: Send + Sync {
    /// Stamp the NEXT per-request correlation id — one relaxed `fetch_add` on the host-owned counter.
    /// Identical to `busbar_kernel::state::App::next_request_id` (the counter is boot-seeded and carried
    /// across config swaps, so the value is engine-snapshot independent).
    fn next_request_id(&self) -> u64;

    /// The plane's type-erased runtime object off the BOUND snapshot (the one this host was minted
    /// over), owned (an `Arc` clone) so it outlives the call. `None` when the plane contributed no
    /// slot under `key` this generation. Identical to `busbar_kernel::state::App::plane_slot(key)`
    /// cloned — a pure `plane_slots` map read, no `HostCtx` (mirrors [`next_request_id`]).
    ///
    /// [`next_request_id`]: RegistryHost::next_request_id
    fn plane_slot(&self, key: &str) -> Option<Arc<dyn std::any::Any + Send + Sync>>;

    /// The plane's slot off the CURRENT snapshot — re-reads the LIVE handle so a config swap AFTER
    /// this host was minted is seen (the dispatch-time re-validation / per-round revocation / watch
    /// loops depend on this). Falls back to the bound snapshot for a snapshot-only mint (one built
    /// without a live handle). A pure map read, no `HostCtx`.
    fn plane_slot_live(&self, key: &str) -> Option<Arc<dyn std::any::Any + Send + Sync>>;

    /// The deployment's NEUTRAL secret resolver, behind the `busbar_contract::secret::SecretResolve` seam, so a
    /// plane mints a delegation credential (and loads its outbound TLS PEM) WITHOUT naming the
    /// engine's concrete `SecretResolver`. A pure snapshot read of `App::secret_resolver`, no
    /// `HostCtx`; the returned `Arc<dyn SecretResolve>` shares the live resolver (built-ins plus any
    /// wired `kind: secret` plugin), fail-closed exactly as core resolution.
    fn secret_resolver(&self) -> Arc<dyn busbar_contract::secret::SecretResolve>;

    /// Sign a plane-framed agent-card signing input, returning the 64-byte Ed25519 signature (None
    /// when this deployment holds no card-signing key). The card subkey is derived and held HOST-side;
    /// only the bytes to sign cross in and only the signature crosses out — no key material reaches the
    /// plane. Mints its transient HostCtx internally over a fresh per-call DispatchScope, drives the
    /// slot synchronously, returns owned bytes — no HostCtx crosses an `.await`.
    fn subkey_sign(&self, signing_input: &[u8]) -> Option<[u8; 64]>;

    /// The deployment's type-erased plane definitions (`Arc<dyn Any + Send + Sync>` holding the
    /// per-plane config object the owning plane downcasts), off the BOUND snapshot — the
    /// `App::agent_defs` field that is NOT a `plane_slots` entry. Owned (an `Arc` clone) so it
    /// outlives the call; a pure snapshot read, no `HostCtx` (mirrors [`secret_resolver`](Self::secret_resolver)).
    fn plane_defs(&self) -> Arc<dyn std::any::Any + Send + Sync>;
}

/// The HOOK/CONFIG-FACADE slice (App-retype WEDGE 2d): the residual `busbar-llm` request-path reads off
/// the resolved hook/config facades — the rewrite/tap/gate chains, the routing policy, the requested-
/// signal bitmask and the group-membership walk. Each is a pure borrow of the bound snapshot tied to
/// `&self`, no `HostCtx`. Split off `EngineHost` as a supertrait; every borrow is byte-identical to the
/// `App::X` field read the wedge-3 flip targets.
pub trait HookConfigHost: Send + Sync {
    /// Whether `caller_group` sits within (any ancestor of) one of `hook_groups` — the group-membership
    /// walk a hook's `groups:` filter consults, resolved against this deployment's group registry.
    /// Identical to `busbar_kernel::config::caller_in_hook_groups(caller_group, hook_groups, &App::groups_registry)`;
    /// a pure tree walk over the bound snapshot's registry, no `HostCtx`.
    ///
    /// WEDGE 2 (App-retype): additive — the seam the wedge-3 `pipeline.rs` flip targets. Folding the
    /// `&App::groups_registry` argument HOST-side means the engine reads group membership without naming
    /// `busbar_kernel::config` or `App::groups_registry`.
    fn caller_in_hook_groups(&self, caller_group: Option<&str>, hook_groups: &[String]) -> bool;

    /// This pool's resolved REWRITE chain `(timeout, policy)` — the phase-1 transform hooks fired for
    /// requests routed to `pool`, empty (the default) ⇒ no pool rewrites. Byte-identical to
    /// `busbar_kernel::state::App::pool_rewrites(pool)`; a pure keyed map read, no `HostCtx`. The tuple is
    /// purely neutral (`Duration`, the [`RoutingPolicy`](busbar_contract::hooks::RoutingPolicy) trait object — api).
    fn pool_rewrites(
        &self,
        pool: &str,
    ) -> &[(
        std::time::Duration,
        std::sync::Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )];

    /// The GLOBAL (all-pools) rewrite chain `(timeout, policy)` fired in the phase-1 transform pass
    /// BEFORE any pool rewrites — the borrow of `App::rewrite_hooks`. Empty (the default) ⇒ no globals.
    /// Same neutral tuple shape as [`pool_rewrites`](Self::pool_rewrites).
    fn rewrite_hooks(
        &self,
    ) -> &[(
        std::time::Duration,
        std::sync::Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )];

    /// Whether ANY registered hook holds a prompt-CONTENT grant (`prompt: ro`/`rw`) this generation —
    /// the deployment gate that decides whether the request IR is built for the hook seam. A single
    /// bool load of `App::any_content_hook`, byte-identical; `false` (the default) is the whole
    /// zero-cost-when-off property.
    fn any_content_hook(&self) -> bool;

    /// A hook was handed a unit's content (and the caller's identity, when `identity`): leave the
    /// one access amendment the kernel's own gate and rewrite seams leave, on the node journal.
    /// `principal` is whose content it was; `op` the ingress label — data, never branched on.
    /// PROVIDED, so a plane's own hook call sites record through the same seam as the kernel's.
    fn hook_read(&self, name: &str, principal: Option<&str>, op: &str, identity: bool) {
        crate::audit::amend::hook_read(name, principal, op, identity);
    }

    /// The GLOBAL request-stage `kind: tap` observers — the borrow of `App::tap_hooks`. Each
    /// [`TapEntry`](crate::hooks::TapEntry) is a neutral `(deadline, prompt-grant, transport, groups)`
    /// tuple. Held BY REF across the forward await-loop (the tap-fire pass reads it after each hop), so
    /// the borrow is deliberately tied to the stable host `&self`, not a per-call temporary.
    fn tap_hooks(&self) -> &[crate::hooks::TapEntry];

    /// The RESPONSE-stage tap observers — the borrow of `App::tap_hooks_response`. Same
    /// [`TapEntry`](crate::hooks::TapEntry) shape as [`tap_hooks`](Self::tap_hooks); fired once the
    /// upstream response outcome is known.
    fn tap_hooks_response(&self) -> &[crate::hooks::TapEntry];

    /// The ROUTING-stage tap observers — the borrow of `App::tap_hooks_routing`. Fired per failover hop
    /// with the routing/attempt projection; same [`TapEntry`](crate::hooks::TapEntry) shape.
    fn tap_hooks_routing(&self) -> &[crate::hooks::TapEntry];

    /// The CANDIDATE-stage tap observers — the borrow of `App::tap_hooks_candidate`. Fired once the
    /// decision reconcile has produced the final candidate set; same [`TapEntry`](crate::hooks::TapEntry)
    /// shape.
    fn tap_hooks_candidate(&self) -> &[crate::hooks::TapEntry];

    /// This pool's resolved DECISION GATES `(priority, policy)` in config order — the borrow of
    /// `App::pool_gates(pool)`. Empty ⇒ no pool gates. The [`ResolvedPolicy`](crate::hooks::ResolvedPolicy)
    /// carrier is already neutral substrate; a pure keyed map read, no `HostCtx`.
    fn pool_gates(&self, pool: &str) -> &[(u16, crate::hooks::ResolvedPolicy)];

    /// The GLOBAL decision gates `(priority, policy)` fired alongside the pool gates in the phase-2
    /// reconcile — the borrow of `App::global_gates`. Empty (the default) ⇒ the phase-2 pass is skipped.
    /// Same neutral `(u16, ResolvedPolicy)` shape as [`pool_gates`](Self::pool_gates).
    fn global_gates(&self) -> &[(u16, crate::hooks::ResolvedPolicy)];

    /// This pool's resolved routing POLICY, or `None` for the zero-cost weighted/SWRR default — the
    /// borrow of `App::pool_policy(pool)`. The [`ResolvedPolicy`](crate::hooks::ResolvedPolicy) is
    /// neutral substrate; a pure keyed map read, no `HostCtx`.
    fn pool_policy(&self, pool: &str) -> Option<&crate::hooks::ResolvedPolicy>;

    /// The config generation's declared-signal bitmask — the borrow of `App::requested_signals`. A
    /// single load of the neutral [`RequestedSignals`](crate::hooks::RequestedSignals) newtype the
    /// candidate-signal loop gates on (`requested.is_empty()` / `requested.wants(sig)`); the all-zero
    /// default short-circuits the whole loop. Byte-identical to the field read.
    fn requested_signals(&self) -> &crate::hooks::RequestedSignals;
}

/// The BUDGET/METERING slice: the money-path seams a plane drives — COUNTS in, VERDICTS out. The
/// governance handle and [`MeterPin`] mints, the record-usage / record-metering accruals, the
/// reserve-then-charge meter, and the pure headroom/budget projections (a live carrier's
/// [`SessionAccount`](session_meter::SessionAccount) is built over them). No method names a cost or price type: pricing is the kernel's
/// ([`MeteringHost`], #43), so a plane-side host implements this slice without naming one. Split off
/// `EngineHost` as a supertrait; the accrual seams read the pin kernel-side, no `HostCtx`.
pub trait BudgetHost: Send + Sync {
    /// Whether governance is configured for this deployment. Identical to
    /// `busbar_kernel::state::App::governance.is_some()`.
    fn governance_enabled(&self) -> bool;

    /// Record ONE metered, attributed event through the host `meter_charge` seam over `scope`'s arena,
    /// billed to `caller` — the request's middleware-resolved context, carried INTO the mint (DEC-SERVE
    /// G1b); `usage` supplies the counts and the `(model, provider)` words, never the key. The
    /// transient `HostCtx` is minted over `scope` and consumed SYNCHRONOUSLY inside the call.
    /// Fire-and-forget: a store miss is not surfaced, exactly as the in-place `record_metering` was.
    fn meter_charge(
        &self,
        scope: &DispatchScope,
        caller: &PlaneRequestCtx,
        usage: &busbar_plugin::hot::Usage,
    );

    /// The per-caller RATE HEADROOM (min fraction of remaining request/token budget across the key's
    /// chain, `None` when unconstrained) — the host-driven form of
    /// `gov.rate_headroom(&app.cost, key, pool, now)` over the governance state and card `pin` carries
    /// (a pure observation, no cell mutation). No `HostCtx`. `key` is the already-neutral
    /// [`VirtualKey`](busbar_contract::records::VirtualKey) (api).
    fn rate_headroom(
        &self,
        pin: &MeterPin,
        key: &busbar_contract::records::VirtualKey,
        pool: Option<&str>,
        now: u64,
    ) -> Option<f64>;

    /// The HOOK-seam budget projection for `key`: `{bucket_id, spend_at_current_rate, remaining, window}`
    /// per chain bucket, derived fresh from the token ledger × the card `pin` carries — the host-driven
    /// form of `gov.budget_state(&app.cost, key, now)`. Returns the neutral
    /// [`BudgetBucketState`](busbar_contract::hooks::BudgetBucketState) vec (empty when the key has no chain). No
    /// `HostCtx`.
    fn budget_state(
        &self,
        pin: &MeterPin,
        key: &busbar_contract::records::VirtualKey,
        now: u64,
    ) -> Vec<busbar_contract::hooks::BudgetBucketState>;

    /// Mint the OPAQUE [`GovHandle`] for this deployment's governance state — `Some` iff governance is
    /// configured. One `Arc` bump, no `HostCtx`. Byte-identical to cloning `App::governance`.
    fn governance(&self) -> Option<GovHandle>;

    /// PIN this request's metering context — `Some` iff governance is configured. The plane holds the
    /// pin on its per-request sink and hands it back to the metering seams. The kernel's host pins its
    /// bound snapshot's card; a plane-side host keeps this default, which pins NO card (every card read
    /// through the pin answers the no-card posture).
    fn meter_pin(&self) -> Option<MeterPin> {
        let cost = CostHandle(Arc::new(()));
        self.governance().map(|gov| MeterPin { gov, cost })
    }

    /// The pre-admission pricing guard's VERDICT: does a PRESENT rate card leave `model` unpriced?
    /// `false` for every name when no card is configured (there is no card to miss). A verdict, not a
    /// rate: the plane fails the request closed on `true` and never learns a figure.
    fn cost_model_unpriced(&self, model: &str) -> bool;

    /// LEDGER one delivered response's tier-split counts against the key's budget chain — the
    /// host-driven form of `sink.gov.record_usage(&sink.cost, key, pool, model, tokens, now)` over the
    /// governance state and card `pin` carries. A no-op on an all-zero tier, exactly as
    /// `record_usage`. No `HostCtx`.
    fn meter_ledger(
        &self,
        pin: &MeterPin,
        key: &busbar_contract::records::VirtualKey,
        pool: &str,
        model: &str,
        usage: &crate::billing::Usage,
        now: u64,
    );

    /// Record one delivered response's RAW consumption into the per-(key, bucket, model, provider)
    /// metering series — the host-driven form of
    /// `sink.gov.record_metering(key_id, model, provider, usage, now)`. `gov` is the opaque handle the
    /// sink minted; the host downcasts it and drives the SAME write-behind accrual (a zero-token
    /// response still counts its request). No `HostCtx`.
    fn meter_series(
        &self,
        gov: &GovHandle,
        key_id: &str,
        model: &str,
        provider: &str,
        usage: Option<&crate::billing::TokenUsage>,
        now: u64,
    );
}

/// The IDENTITY/TRUST slice: inbound identity resolution + the trust/approval seams around it — the
/// audience pre-filter, the auth-chain admit, the standing re-ask, the ask-state sealer derivation, the
/// drift quarantine settle, the one-time approval redeem, and the test-only token verifier. Split off
/// `EngineHost` as a supertrait. `#[async_trait]` because [`identity_admit`](Self::identity_admit) is
/// the one async method (it awaits a `spawn_blocking` join over the host auth chain).
#[async_trait::async_trait]
pub trait IdentityHost: Send + Sync {
    /// Settle a drift disposition for `subject` through the host `drift_quarantine` seam, pulling the
    /// demotion store host-side. Returns whether the slot answered `Ok`; the settle is
    /// fire-and-forget, so a non-`Ok` is a durability miss, not a refusal. Identical to
    /// `busbar_kernel::plane_host::trust::quarantine_settle_over`.
    fn quarantine_settle(&self, subject: &str, state: TrustState) -> bool;

    /// Redeem a one-time approval against the shared spent-approval ledger the host pulls, spending
    /// against the seal's own `expires_at` and the caller's `now`. `true` iff this is the FIRST
    /// redemption; `false` when already spent OR the durable ledger could not answer (fail-closed).
    /// Identical to `busbar_kernel::plane_host::trust::approval_redeem_q`.
    fn approval_redeem(&self, nonce: &str, expires_at: u64, now: u64) -> bool;

    /// TEST-ONLY raw-token → resolved `VirtualKey` resolution over this deployment's governance state
    /// (the data-plane boundary: no audience). The host-driven form of
    /// `App::governance.and_then(|g| g.verify_token(token, now, None))`, for the test paths that
    /// exercise the routing-policy seam WITHOUT building a full `PlaneRequestCtx` (production always
    /// threads a resolved key, so this never runs there). Gated to test / `test-support` builds so no
    /// production binary carries a raw-token verifier on the neutral seam.
    ///
    /// DEFAULT `None` (resolves nothing): the method exists only when THIS crate's `test-support` is
    /// on, and a downstream implementor cannot see that feature — cargo may unify it on through some
    /// other crate's dev-deps. A default lets an implementor compile either way; a host that actually
    /// verifies tokens overrides it (item 115).
    #[cfg(any(test, feature = "test-support"))]
    fn verify_token_test(&self, token: &str) -> Option<Arc<busbar_contract::records::VirtualKey>> {
        let _ = token;
        None
    }

    /// Establish what can be established about a presented bearer's RFC 8707 audience binding against
    /// `expected_aud` — the fail-closed pre-filter a plane runs BEFORE the auth chain, for credentials
    /// busbar did not mint. A pure judgement (it reaches only core's governance token prefix, no live
    /// engine state), so it needs no `HostCtx`. Identical to `busbar_kernel::auth::audience::inspect_bearer`.
    fn identity_audience_binding(&self, token: &str, expected_aud: &str) -> AudienceBinding;

    /// Resolve INBOUND data-plane identity: run the configured auth chain + the ONE verdict resolution
    /// over the caller's OWN wire credential and the live governance state, returning the resolved
    /// `(AuthPrincipal, PlaneRequestCtx)` or the specific [`IdentityRefusal`]. Identical to
    /// `busbar_kernel::plane_host::identity_admit_over`.
    ///
    /// The ONE async method: the core impl awaits a `spawn_blocking` that mints AND consumes the
    /// `HostCtx` INSIDE the blocking closure, so the `!Send` pointer never crosses this `.await` and
    /// the future stays `Send`. Fail-closed: a join panic maps to [`IdentityRefusal::Denied`].
    async fn identity_admit(
        &self,
        token: Option<String>,
        audience: String,
        resource: String,
    ) -> Result<(AuthPrincipal, PlaneRequestCtx), IdentityRefusal>;

    /// RE-ASK a [`Standing`] permission against the LIVE governance registry: hand back the principal
    /// AS IT IS NOW, or the [`Lapsed`] reason it no longer stands. Injects the host's `GovState`
    /// (through the `GovResolve` seam) INTERNALLY, so the plane holds only the `Standing`. Identical to
    /// `Standing::still_permitted(app.governance, live, now)`.
    fn principal_standing(
        &self,
        standing: &Standing,
        live_gen: u64,
        now: u64,
    ) -> Result<Option<Arc<VirtualKey>>, Lapsed>;

    /// Derive this deployment's ask-state [`Sealer`] from governance's fleet-shared signing secret,
    /// WITHOUT the raw secret crossing to the plane. `None` when governance is disabled. Identical to
    /// `busbar_kernel::plane::approvals::ask_state_sealer(app.governance)` — the derivation stays core
    /// behind this seam.
    fn ask_state_sealer(&self) -> Option<Sealer>;
}

/// The ADMISSION slice: the request-admission gauntlet seams — the gate decision + presence pre-filter,
/// the governance admit-reason, the destination guard, the budget-admission door, the audience-bound
/// mount read, and the post-admission/not-charged finishes. Split off `EngineHost` as a supertrait.
pub trait AdmissionHost: Send + Sync {
    /// Fire the operator's REQUEST-ADMISSION hook gates over the host `gate_decide` seam and
    /// reconstruct the [`GateOutcome`]. Identical to `busbar_kernel::plane_host::gate_decide_over`:
    /// same reconstructed facts, same key identity, same gate decision. Drives the ASYNC gate on a
    /// fresh runtime, so it MUST be called from a BLOCKING thread (`spawn_blocking`).
    ///
    /// `plane_key` is the opaque registry key (the plane's stable decl key) the host resolves the
    /// gate set and the `ingress_protocol` label from. `key` is the caller's resolved `(id, name)`;
    /// `session_id` is the caller's session, `Some` only when non-empty.
    #[allow(clippy::too_many_arguments)]
    fn gate_decide(
        &self,
        plane_key: &str,
        container: &str,
        request_id: u64,
        tool: &str,
        args_json: &[u8],
        key: Option<(&str, &str)>,
        session_id: Option<&str>,
    ) -> GateOutcome;

    /// Cheap presence pre-filter: is any request-admission hook gate attached to `container` on the
    /// plane identified by the opaque registry `plane_key` (the plane's stable decl key)? Lets a plane
    /// skip the blocking `gate_decide` hop when nothing is attached. Identical to
    /// `App::plane_gates(plane_key).contains_key(container)`.
    fn gate_attached(&self, plane_key: &str, container: &str) -> bool;

    /// Cheap presence pre-filter for the TAP/TRANSFORM half: is any `prompt: rw` rewrite hook attached
    /// to `container` on the plane identified by the opaque registry `plane_key`? Lets a plane skip the
    /// blocking `transform_over` hop — and stay BYTE-IDENTICAL to a build without the seam — when
    /// nothing is attached. Identical to `App::plane_rewrites(plane_key).get(container).is_some()`.
    ///
    /// The presence check is the whole zero-cost guarantee: absent a rewrite hook a plane never
    /// serializes the payload, never spawns the blocking hop, and never touches its own bytes.
    fn tap_attached(&self, plane_key: &str, container: &str) -> bool;

    /// Fire the operator's REQUEST-ADMISSION TRANSFORM (`<section>.hooks:` `prompt: rw`) chain over the
    /// host `transform_over` seam and reconstruct the [`TransformVerdict`] — the TAP/observe-transform
    /// twin of [`gate_decide`](Self::gate_decide). The host re-selects the rewrite chain by
    /// `(plane_key, container)` (the Seam-B inversion: the plane body names no core hook symbol), builds
    /// the SAME `InvokeReq` projection the gate builds from `(tool, args_json)`, runs each hook's
    /// `transform` in priority order (each seeing the prior's output — a true transform chain), and
    /// returns the rewritten payload or a reject. Drives the ASYNC hooks on a fresh runtime, so it MUST
    /// be called from a BLOCKING thread (`spawn_blocking`), exactly like `gate_decide`.
    ///
    /// `plane_key`/`container`/`request_id`/`tool`/`args_json`/`key`/`session_id` carry the identical
    /// meaning they do on [`gate_decide`](Self::gate_decide).
    #[allow(clippy::too_many_arguments)]
    fn transform_over(
        &self,
        plane_key: &str,
        container: &str,
        request_id: u64,
        tool: &str,
        args_json: &[u8],
        key: Option<(&str, &str)>,
        session_id: Option<&str>,
    ) -> TransformVerdict;

    /// Admit one unit of work for `caller` (the request's middleware-resolved context, DEC-SERVE G1b)
    /// over the host `govern_admit_reason` seam, REGISTERING the RAII grant in `scope`'s arena on
    /// success and returning the RENDERED refusal reason on a blocked limit.
    /// Identical to `busbar_kernel::plane_host::govern_admit_reason_over`.
    fn govern_admit_reason(
        &self,
        scope: &DispatchScope,
        caller: &PlaneRequestCtx,
        pool: &[u8],
    ) -> GovAdmit;

    /// STAGE 2 pre-admission DESTINATION guard through the host: the pool ACL, the fallback-pool ACL,
    /// and the all-or-nothing unpriced-model gate. `Ok(())` admits; `Err` is the already-finished,
    /// protocol-native rejection response (finished via the not-charged terminal). Identical to
    /// `busbar_kernel::ingress::destination_guard` over the bound snapshot + `gov` scope.
    fn destination_guard(
        &self,
        gov: &PlaneRequestCtx,
        proto: &'static str,
        pool: &str,
        started: std::time::Instant,
        charged_at: u64,
    ) -> Result<(), Box<axum::response::Response>>;

    /// STAGE 3–4 budget-admission door: charge the chain buckets for one request under `gov` on
    /// `pool`, returning the ADMISSION grant (as the opaque [`AdmitHandle`] the sink holds Drop-only)
    /// and any budget DOWNGRADE re-pool, or the already-finished not-charged rejection. Identical to
    /// `busbar_kernel::ingress::admission_door` over the bound snapshot; the returned `AdmitHandle`
    /// wraps the SAME `AdmitGrant` the in-place door produced, so `.is_some()` (charged?) and the
    /// gauge-releasing `Drop` are byte-identical. No `HostCtx` on this path.
    ///
    /// WEDGE 2 (App-retype): additive — the seam the wedge-3 `native_ingress::drive` flip targets
    /// (a host is already minted there). The `AdmitGrant`→[`AdmitHandle`] carrier-field retype
    /// (`response_body.rs` / `native_ingress.rs`) rides the same wedge-3 governance flip.
    fn admission_door(
        &self,
        gov: &PlaneRequestCtx,
        proto: &'static str,
        pool: &str,
        started: std::time::Instant,
        charged_at: u64,
    ) -> Result<(Option<AdmitHandle>, Option<String>), Box<axum::response::Response>>;

    /// THE SAME DOOR, WITHOUT THE TERMINAL — the check-and-charge on its own.
    ///
    /// [`admission_door`](Self::admission_door) is exactly this call followed by
    /// `finish_rejected` on the refusing arm, which is right for a caller whose refusal ends there
    /// and wrong for one whose terminal is a step of its own: posting the refusal at the door and
    /// then posting it again at the terminal would put two links on one unit's chain. So a plane
    /// that owns an Audit step takes this one and hands the refusal — bytes, not a posted record —
    /// to that step, and a unit posts exactly one link whichever way it ended.
    ///
    /// Identical to `busbar_kernel::ingress::admit_check` over the bound snapshot: the same buckets,
    /// the same charge, the same downgrade re-pool, and on the refusing arm the same
    /// protocol-native bytes the door would have finished. The label the terminal records those
    /// bytes under is [`pool_label`](EngineHost::pool_label) of the same `pool`, which is what the
    /// door computes for itself before it finishes.
    fn admission_check(
        &self,
        gov: &PlaneRequestCtx,
        proto: &'static str,
        pool: &str,
        charged_at: u64,
    ) -> Result<(Option<AdmitHandle>, Option<String>), Box<axum::response::Response>>;

    /// POST-ADMISSION finish through the host: emit the per-request metric family + request-log
    /// webhook and, on a NON-2xx outcome, REFUND the flat per-request fee IFF it actually landed at
    /// admission (`charged`). Identical to `busbar_kernel::ingress::finish_admitted` over the bound
    /// snapshot + `gov` scope.
    #[allow(clippy::too_many_arguments)]
    fn finish_admitted(
        &self,
        gov: &PlaneRequestCtx,
        ingress_protocol: &str,
        pool: &str,
        started: std::time::Instant,
        charged_at: u64,
        resp: axum::response::Response,
        charged: bool,
    ) -> axum::response::Response;

    /// NOT-CHARGED (pre-charge turn-away) finish through the host: emit metrics + the webhook with NO
    /// refund, for a request rejected BEFORE the admission charge ever ran (governance guard denial or
    /// a pre-routing failure). Identical to `busbar_kernel::ingress::finish_rejected` over the bound
    /// snapshot + `gov` scope.
    #[allow(clippy::too_many_arguments)]
    fn finish_rejected(
        &self,
        gov: &PlaneRequestCtx,
        ingress_protocol: &str,
        pool: &str,
        started: std::time::Instant,
        charged_at: u64,
        resp: axum::response::Response,
    ) -> axum::response::Response;

    /// Whether the plane identified by the opaque registry `plane_key` is mounted under an
    /// AUDIENCE-BOUND door — the deployment gate a request path reads before it trusts an inbound
    /// audience claim. Identical to
    /// `App::planes.mount_of(plane_key).and_then(|m| App::planes.admission_for(m)).is_some()`. A pure
    /// snapshot read, no `HostCtx`.
    fn plane_audience_bound(&self, plane_key: &str) -> bool;
}

/// The COMPLETION slice — LLM-ONLY. The single seam that drives a non-streaming chat completion through
/// the resolved ingress pipeline. Split off `EngineHost` as a supertrait SPECIFICALLY so a non-LLM plane
/// (a voice/bytes port) is NOT forced to name it: such a plane takes the slices it uses and never sees
/// this one. `#[async_trait]` because [`synthesize_completion`](Self::synthesize_completion) is async.
#[async_trait::async_trait]
pub trait CompletionHost: Send + Sync {
    /// Synthesize ONE non-streaming chat completion by driving `body` through the ENTIRE resolved
    /// ingress pipeline (governance → pools → breaker/failover → metering → request log) under `gov`,
    /// on the operator's declared `model`, and return the raw wire outcome. The dialect the request is
    /// driven as is NEUTRAL to this seam: the host resolves it from the registry's residual-default
    /// chat protocol (`None` — no chat dialect installed — surfaces as an error, not a hard-coded
    /// identity), so MCP's `sampling/complete` bridge names no LLM dialect to reach a completion.
    ///
    /// The ONE async method beside [`IdentityHost::identity_admit`] — but simpler:
    /// the host drives a NATIVE core async fn (no C-ABI slot, no `spawn_blocking`), so this only
    /// `.await`s it. No `HostCtx` crosses the `.await`; the future is `Send`. `max_body_bytes`
    /// bounds the response body read.
    async fn synthesize_completion(
        &self,
        gov: &busbar_contract::records::PlaneRequestCtx,
        model: &str,
        body: bytes::Bytes,
        max_body_bytes: usize,
    ) -> Result<HostCompletion, String>;
}

/// The neutral HOST seam a plane calls to reach the engine's host-owned capabilities.
///
/// A plane holds an `Arc<dyn EngineHost>` (minted core-side over the live engine) and calls these
/// typed methods rather than naming `busbar_kernel::plane_host::*_over(&App, …)`. Each method reaches
/// the SAME host vtable slot the in-core veneer drives, so the value is identical — this is a
/// same-dispatch relocation of the reach, not a new behaviour.
///
/// `Send + Sync` because a plane carries the handle across `.await` and between threads (e.g. into a
/// `spawn_blocking` breaker leg). That is sound precisely because no method exposes the `!Send`
/// `HostCtx`: each mints it internally, uses it synchronously, and drops it before returning.
///
/// ## M4 — `EngineHost` is the SUM of the capability slices
///
/// The residual flat method set has been cut into cohesive capability SUPERTRAITS
/// ([`ClockHost`], [`TelemetryHost`], [`JournalHost`], [`MountHost`], [`RegistryHost`],
/// [`HookConfigHost`], [`BudgetHost`], [`IdentityHost`], [`AdmissionHost`], [`CompletionHost`]),
/// alongside the earlier braking slices ([`BreakerHost`], [`LanePoolHost`]). Every slice is
/// PLANE-FACING and pricing-blind; the kernel's pricing ([`MeteringHost`]) is deliberately NOT one of
/// them, so a plane-side host implements the whole sum without naming a cost or price type (#43).
/// `EngineHost` now declares NO methods of its own beyond the provided [`run_gauntlet`](Self::run_gauntlet)
/// ergonomic entry — it is the SUM (a supertrait bound of every slice). An existing
/// `Arc<dyn EngineHost>` caller is unaffected (it still reaches every method through the inherited
/// bound); a plane that needs a narrower capability takes `&dyn SliceX` and depends only on what it
/// uses — a voice/bytes port never names LLM-only [`CompletionHost::synthesize_completion`].
///
/// `#[async_trait]` is inherited via the async slices; `EngineHost` itself carries only the provided
/// `run_gauntlet` future, so the attribute leaves it a thin sum.
#[async_trait::async_trait]
pub trait EngineHost:
    BreakerHost
    + LanePoolHost
    + ClockHost
    + TelemetryHost
    + JournalHost
    + MountHost
    + RegistryHost
    + HookConfigHost
    + BudgetHost
    + IdentityHost
    + AdmissionHost
    + CompletionHost
    + Send
    + Sync
{
    // The cross-protocol translation seam's global-fallback max-output-tokens and effort→budget-table
    // reads are GONE from this neutral host trait: they are LLM-plane vocabulary, so the engine now
    // reads them off the LLM plane's own per-generation runtime (`NativeRuntime`) rather than through a
    // neutral `PlaneHost` method over `App`. See busbar-llm `engine/wire.rs`.

    /// Run one request through THE shared gauntlet sequence ([`run_gauntlet`]) — the ergonomic entry
    /// for a plane that already holds an `Arc<dyn EngineHost>`. A PROVIDED method: it delegates to the
    /// free [`run_gauntlet`] (which needs no host — the sequence is verify→drive over the plane), so
    /// every host impl shares one body and core's own callers can use the free fn directly.
    async fn run_gauntlet<'a>(
        &self,
        req: GauntletRequest<'a>,
        plane: Box<dyn GauntletPlane + 'a>,
    ) -> axum::response::Response {
        run_gauntlet(req, plane).await
    }
}

/// Compile-time witness for the M4 god-trait split: any `EngineHost` implementor IS every capability
/// slice. If a future edit dropped any supertrait bound (or an impl stopped satisfying it), this stops
/// compiling — so `EngineHost` cannot silently cease to equal the SUM of its slices (the families
/// cannot re-dissolve back into the flat god-trait).
const _: () = {
    fn _assert_engine_host_is_sum_of_slices<T: EngineHost + ?Sized>() {
        fn _needs_breaker<U: BreakerHost + ?Sized>() {}
        fn _needs_lane_pool<U: LanePoolHost + ?Sized>() {}
        fn _needs_clock<U: ClockHost + ?Sized>() {}
        fn _needs_telemetry<U: TelemetryHost + ?Sized>() {}
        fn _needs_journal<U: JournalHost + ?Sized>() {}
        fn _needs_mount<U: MountHost + ?Sized>() {}
        fn _needs_registry<U: RegistryHost + ?Sized>() {}
        fn _needs_hook_config<U: HookConfigHost + ?Sized>() {}
        fn _needs_budget<U: BudgetHost + ?Sized>() {}
        fn _needs_identity<U: IdentityHost + ?Sized>() {}
        fn _needs_admission<U: AdmissionHost + ?Sized>() {}
        fn _needs_completion<U: CompletionHost + ?Sized>() {}
        _needs_breaker::<T>();
        _needs_lane_pool::<T>();
        _needs_clock::<T>();
        _needs_telemetry::<T>();
        _needs_journal::<T>();
        _needs_mount::<T>();
        _needs_registry::<T>();
        _needs_hook_config::<T>();
        _needs_budget::<T>();
        _needs_identity::<T>();
        _needs_admission::<T>();
        _needs_completion::<T>();
    }
};

/// THE NEUTRAL TYPE-ERASED SLOT-READ SEAM the core-owned `PlaneDecl` callbacks that today force a
/// `&busbar_kernel::state::App` are neutralised over — so a plane's `on_swap` / `registry_contains` /
/// `retain_verify_gates` hook reads its own per-generation runtime object off the snapshot WITHOUT
/// the callback fn-pointer signature naming a core type. Core `impl`s it for `App` as a thin delegate
/// to the inherent `App::plane_slot`; an EXTRACTED plane reaches only [`Self::plane_slot`] and
/// stays neutral. [`Self::as_any`] is the recovery hatch an in-core plane twin uses to downcast back
/// to its concrete snapshot for a field that does not live in `plane_slots` (`agent_defs`); an
/// extracted plane never calls it.
pub trait PlaneSlots {
    /// The plane's type-erased runtime object for THIS generation, keyed by the plane's decl key —
    /// a pure `plane_slots` map read, borrowed (mirrors the inherent `App::plane_slot`).
    fn plane_slot(&self, key: &str) -> Option<&Arc<dyn std::any::Any + Send + Sync>>;

    /// Recover the concrete engine snapshot as `&dyn Any` — the hatch an in-core plane twin downcasts
    /// through to reach the snapshot fields that are not `plane_slots` entries. An extracted plane
    /// never names a concrete type through this, so it never calls it.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// THE NEUTRAL `&mut` GATE-REBUILD SINK the core-owned `PlaneDecl::reresolve_gates` callback is
/// neutralised over — the config-swap re-resolution of a plane's per-registration hook gates, moved
/// behind a trait so the fn-pointer signature names no `&mut busbar_kernel::state::App`. A `PlaneSlots`
/// (its supertrait) so the plane can read its own registry object off the same `&mut` receiver before
/// it writes the resolved gates back. The resolve-and-store is ONE method (rather than the spec's
/// `resolve` + `set` pair) because the resolved gate map value type is core-owned
/// (`Vec<(u16, busbar_kernel::hooks::ResolvedPolicy)>`) and cannot be named in this crate — so the map
/// never crosses the seam; it is built and stored entirely core-side, keyed by `plane_key`.
pub trait ContainerGateSink: PlaneSlots {
    /// Resolve `containers` (each `(name, its-own-hooks)`) unioned with `section_hooks` against this
    /// snapshot's hook registry, and store the resolved per-container gates under the opaque registry
    /// `plane_key` (the plane's stable decl key) in the generic `App::plane_gates` map. Byte-identical
    /// to the old inline `next.plane_gates.insert(plane_key, next.resolve_container_gates(...))`.
    fn reresolve_container_gates(
        &mut self,
        plane_key: &str,
        containers: &[(&str, &[String])],
        section_hooks: &[String],
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// D3 WITNESS — the gauntlet siblings COEXIST and share ONE `admit_open` gate. (That `begin_session`
// actually CALLS `run_gauntlet_session` at its call site is pinned in busbar-voice's topology tests.)
// ─────────────────────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
#[path = "tests/gauntlet_session_tests.rs"]
mod gauntlet_session_tests;

#[cfg(test)]
#[path = "tests/plane_answer_tests.rs"]
mod plane_answer_tests;
