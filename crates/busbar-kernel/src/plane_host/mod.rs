// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plane_host` — the HOST side of the plane ABI: the construction point + lifecycle arena the
//! capability fan-out fills in.
//!
//! The HOT-lane ABI ([`busbar_contract::abi::hot`]) defines the `#[repr(C)] PlaneHostVtable` — the inbound
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
// `busbar_kernel::plane_host` and are re-exported here — core's egress chokepoint names the
// same `crate::plane_host::{identity, trust_anchor}` paths as before. The peer-SPKI DER walk's
// walk is the connector's (`busbar_core_connector::tls::spki`): the connector owns pinning, and the
// engine reads the computed pin off its secured stream.
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
use busbar_contract::abi::hot::host::{HostCtx, HostGeneration, PlaneHostVtable};
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
    // `state` and `generation` are locals, dropped only after this tail call returns.
    f(host, &vtable)
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
        (status == busbar_contract::abi::hot::StatusClass::Ok).then_some(out)
    })
}

// The refusal-fidelity admit outcome is a pure POD naming only `busbar_contract::abi::hot` + std, so it now
// lives in the substrate beside the neutral `EngineHost` seam; core re-exports it so every in-core
// caller (`govern_admit_reason_over`, a2a) is unchanged.

/// Admit one unit of work over the host [`govern_admit_reason`](vtable) seam, REGISTERING the RAII
/// grant in `scope`'s arena on success and returning the RENDERED refusal reason on a blocked limit —
/// a SAFE wrapper that keeps the `#[repr(C)]` [`GovRefusal`](busbar_contract::abi::hot::GovRefusal) out-param
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
    let mut out = core::mem::MaybeUninit::<busbar_contract::abi::hot::GovRefusal>::uninit();
    let decision = mint(
        None,
        HostCaller::of(Some(caller)),
        None,
        app,
        scope,
        |hctx, vt| {
            let facts = busbar_contract::abi::hot::Facts::new(0, 0, 0, 0, 0, pool);
            (vt.govern_admit_reason
                .expect("govern_admit_reason is a wired slot"))(
                hctx,
                &*facts as *const busbar_contract::abi::hot::Facts,
                reason_buf.as_mut_ptr(),
                reason_buf.len(),
                std::ptr::from_mut(&mut out),
            )
        },
    );
    if decision == busbar_contract::abi::hot::Decision::Admit {
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
/// the `#[repr(C)]` [`IdentityAdmitted`](busbar_contract::abi::hot::IdentityAdmitted) out-param read and the
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
            let query = busbar_contract::abi::hot::IdentityQuery {
                size: core::mem::size_of::<busbar_contract::abi::hot::IdentityQuery>() as u32,
                version: busbar_contract::abi::hot::POD_VERSION,
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
            let mut out =
                core::mem::MaybeUninit::<busbar_contract::abi::hot::IdentityAdmitted>::uninit();
            let status = (vt.identity_admit.expect("identity_admit is a wired slot"))(
                hctx,
                &query as *const busbar_contract::abi::hot::IdentityQuery,
                std::ptr::from_mut(&mut out),
            );
            if status != busbar_contract::abi::hot::StatusClass::Ok {
                // A null query is impossible here (we pass a live POD); a runtime that will not start /
                // a caught panic fails closed to a refusal, never an admit.
                return Err(crate::auth::IdentityRefusal::Denied);
            }
            // SAFETY: the `Ok` status published the out-param (init-only-on-Ok).
            let admitted = unsafe { out.assume_init() };
            match admitted.outcome {
                busbar_contract::abi::hot::IdentityOutcome::Admitted => {
                    // Consume the opaque handle to recover the EXACT resolved (principal, gov). A handle
                    // that vanished (double-consume / eviction) fails closed to a refusal.
                    identity_admit::take(admitted.identity)
                        .ok_or(crate::auth::IdentityRefusal::Denied)
                }
                busbar_contract::abi::hot::IdentityOutcome::Denied => {
                    Err(crate::auth::IdentityRefusal::Denied)
                }
                busbar_contract::abi::hot::IdentityOutcome::NoGrant => {
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

/// `EngineHost::breaker_settle` through the `breaker_settle` slot (HOT; leaves with it).
pub(crate) fn breaker_settle_over(
    app: &App,
    scope: &DispatchScope,
    admission: busbar_contract::abi::hot::AdmissionId,
    signal: &busbar_contract::abi::hot::Signal,
) -> busbar_contract::abi::hot::StatusClass {
    // SAME dispatch as the in-place `with_borrowed_host` settle the plane's sync leg drove: mint
    // the transient `HostCtx` over the caller's arena, fold the leg through the `breaker_settle`
    // slot, and return the class — the raw host pointer never escapes the call.
    with_borrowed_host(app, scope, |host, vt| {
        (vt.breaker_settle.expect("breaker_settle is a wired slot"))(
            host,
            admission,
            signal as *const busbar_contract::abi::hot::Signal,
        )
    })
}

/// `EngineHost::call_log_emit` through a fresh dispatch scope (HOT; leaves with it).
pub(crate) fn call_log_emit_over(
    app: &App,
    principal: &str,
    input: busbar_kernel::plane::calllog::CallInput,
) {
    // Mint a fresh per-call arena over the live engine and drive the chain seam SYNCHRONOUSLY — the
    // `HostCtx` never escapes the call. A chain append registers no host handle, so which arena
    // reclaims is immaterial.
    with_dispatch_scope(app, |host, _| crate::calllog::emit(host, principal, input));
}

/// `EngineHost::meter_charge` through the `meter_charge` slot (HOT; leaves with it).
pub(crate) fn meter_charge_over(
    app: &App,
    scope: &DispatchScope,
    caller: &busbar_contract::records::PlaneRequestCtx,
    usage: &busbar_contract::abi::hot::Usage,
) {
    // Mint the transient `HostCtx` over the caller's arena CARRYING the middleware-resolved
    // `caller` (DEC-SERVE G1b — the host bills that key, never the `Usage` tail's), fire the
    // `meter_charge` slot, and drop the host pointer without letting it escape. Fire-and-forget.
    let caller = HostCaller::of(Some(caller));
    mint(None, caller, None, app, scope, |host, vt| {
        let _ = (vt.meter_charge.expect("meter_charge is a wired slot"))(
            host,
            usage as *const busbar_contract::abi::hot::Usage,
        );
    });
}

/// `EngineHost::approval_redeem` through the `approval_redeem_q` slot (HOT; leaves with it).
pub(crate) fn approval_redeem_over(app: &App, nonce: &str, expires_at: u64, now: u64) -> bool {
    // A fresh per-call arena backs the borrow; the redemption registers no host handle, so which
    // arena reclaims is immaterial. The `ApprovalQuery` is built HERE so the plane passes only the
    // nonce/expiry/now — it never names the `#[repr(C)]` POD or the `SpentTokenLedger`.
    let scope = DispatchScope::new();
    with_borrowed_host(app, &scope, |host, _vt| {
        let query = busbar_contract::abi::hot::ApprovalQuery {
            size: core::mem::size_of::<busbar_contract::abi::hot::ApprovalQuery>() as u32,
            version: busbar_contract::abi::hot::POD_VERSION,
            _reserved: 0,
            scope: 0,
            _reserved2: 0,
            expires_at,
            now,
            key_ptr: nonce.as_ptr(),
            key_len: nonce.len(),
        };
        trust::approval_redeem_q(
            host,
            &query as *const busbar_contract::abi::hot::ApprovalQuery,
        ) == busbar_contract::abi::hot::StatusClass::Ok
    })
}

/// Fire the operator's REQUEST-ADMISSION hook gates over the wired [`gate_decide`](vtable) seam and
/// reconstruct the [`GateOutcome`] — so an MCP/A2A plane body admits a request through its
/// `tools.hooks:` / `agents.hooks:` gates without ever naming `crate::hooks::gate::decide` or holding the
/// resolved `ResolvedPolicy` set (the host owns and re-selects it by `(plane_key, container)`). A SAFE
/// wrapper that keeps the `#[repr(C)]` [`GateVerdictOut`](busbar_contract::abi::hot::GateVerdictOut) out-param
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
    let mut out = core::mem::MaybeUninit::<busbar_contract::abi::hot::GateVerdictOut>::uninit();
    let (key_id, key_name) = key.unwrap_or(("", ""));
    let sid = session_id.unwrap_or("");
    let scope = DispatchScope::new();
    let status = with_borrowed_host(app, &scope, |hctx, vt| {
        let subject = busbar_contract::abi::hot::GateSubjectRef {
            size: core::mem::size_of::<busbar_contract::abi::hot::GateSubjectRef>() as u32,
            version: busbar_contract::abi::hot::POD_VERSION,
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
            &subject as *const busbar_contract::abi::hot::GateSubjectRef,
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
    if status == busbar_contract::abi::hot::StatusClass::Ok && v.proceed != 0 {
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

    /// Run `f` synchronously with a materialized [`HostCtx`] + host vtable, INSIDE the blocking body.
    /// The [`HostGeneration`] opens HERE (on the blocking thread the closure actually runs on —
    /// `HostGeneration` is thread-local, so opening it back on the async task's thread in
    /// [`new`](Self::new) would mint a stamp that is never live on the thread that checks it) and
    /// drops when this call returns.
    pub fn with_host<R>(&self, f: impl FnOnce(HostCtx, &PlaneHostVtable) -> R) -> R {
        mint(None, None, None, &self.app, &self.scope, f)
    }
}

#[cfg(test)]
#[path = "tests/mod_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/residual_tests.rs"]
mod residual_tests;

// ==== merged from busbar-substrate (W4.b P2 engine drain) ====
// The mTLS client-identity registry and the extra-root trust-anchor registry — process-atomic
// registries the HOT egress resolves its refs against; they go with it.
pub mod identity;
pub mod trust_anchor;

// The host capability vocabulary (`EngineHost` and its slices, `PlaneSlots`, the gauntlet) is
// `crate::plane::host`'s; re-exported here for the plane_host files and the legacy plane crates
// until they are deleted.
pub use crate::plane::host::*;

pub use crate::plane::host_impl::{
    engine_host, engine_host_from_handle, engine_host_value, live_host_factory, live_standing,
    standing_over, transform_over_over, EngineHostImpl,
};
