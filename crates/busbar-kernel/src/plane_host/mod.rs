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
    ) -> Result<busbar_contract::abi::hot::AdmissionId, busbar_kernel::store::Unavailable> {
        breaker::breaker_admit_over(&self.app, scope, pool, lane)
    }

    fn breaker_settle(
        &self,
        scope: &DispatchScope,
        admission: busbar_contract::abi::hot::AdmissionId,
        signal: &busbar_contract::abi::hot::Signal,
    ) -> busbar_contract::abi::hot::StatusClass {
        // SAME dispatch as the in-place `with_borrowed_host` settle the plane's sync leg drove: mint
        // the transient `HostCtx` over the caller's arena, fold the leg through the `breaker_settle`
        // slot, and return the class — the raw host pointer never escapes the call.
        with_borrowed_host(&self.app, scope, |host, vt| {
            (vt.breaker_settle.expect("breaker_settle is a wired slot"))(
                host,
                admission,
                signal as *const busbar_contract::abi::hot::Signal,
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
        sig: &busbar_contract::upstream::CanonicalSignal,
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
// host implements it and no plane names it. The pricing is this host's: its bound snapshot's rate card.
impl busbar_kernel::plane_host::MeteringHost for EngineHostImpl {
    fn price_usage(&self, model: &str, usage: &busbar_contract::billing::Usage) -> Option<u128> {
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
        crate::audit::auditlog::emit_admin_hostless_now(action, resource, outcome, principal);
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

    fn plane_gates_of(
        &self,
        plane_key: &str,
        container: &str,
    ) -> Vec<(u16, busbar_kernel::hooks::ResolvedPolicy)> {
        // The set the previous release's gate seam fired, as resolved (`gate::decide` orders it).
        self.app
            .plane_gates(plane_key)
            .and_then(|m| m.get(container))
            .cloned()
            .unwrap_or_default()
    }

    fn plane_rewrites_of(
        &self,
        plane_key: &str,
        container: &str,
    ) -> Vec<(
        std::time::Duration,
        Arc<dyn busbar_contract::hooks::RoutingPolicy>,
    )> {
        self.app
            .plane_rewrites(plane_key)
            .and_then(|m| m.get(container))
            .cloned()
            .unwrap_or_default()
    }

    fn gate_scan(&self) -> Option<(Arc<busbar_kernel::session::SessionStore>, u64)> {
        self.app
            .incremental_scan
            .then(|| (Arc::clone(&self.app.session_store), self.app.config_version))
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
        usage: &busbar_contract::abi::hot::Usage,
    ) {
        // Mint the transient `HostCtx` over the caller's arena CARRYING the middleware-resolved
        // `caller` (DEC-SERVE G1b — the host bills that key, never the `Usage` tail's), fire the
        // `meter_charge` slot, and drop the host pointer without letting it escape. Fire-and-forget.
        let caller = HostCaller::of(Some(caller));
        mint(None, caller, None, &self.app, scope, |host, vt| {
            let _ = (vt.meter_charge.expect("meter_charge is a wired slot"))(
                host,
                usage as *const busbar_contract::abi::hot::Usage,
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
        usage: &busbar_contract::billing::Usage,
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

    fn meter_refund_fee(
        &self,
        pin: &busbar_kernel::plane_host::MeterPin,
        key: &busbar_contract::records::VirtualKey,
        pool: &str,
        plane: &str,
        fee_unit: &str,
        now: u64,
    ) {
        // The refund primitive reads a plane-qualified pool: the plane names the fee lane, the pool
        // the buckets the count reached.
        if let Some((g, c)) = pin_models(pin) {
            let pool = format!("{plane}{}{pool}", crate::governance::PLANE_LANE_SEP);
            g.refund_fee_unit(&c, key, &pool, now, fee_unit);
        }
    }

    fn meter_series(
        &self,
        gov: &busbar_kernel::plane_host::GovHandle,
        key_id: &str,
        model: &str,
        provider: &str,
        usage: Option<&busbar_contract::billing::TokenUsage>,
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
        charged: Option<&busbar_kernel::plane_host::AdmitHandle>,
    ) -> axum::response::Response {
        // The handle is the grant `admission_check`/`admission_door` wrapped: its charge is what a
        // non-2xx end refunds.
        let grant = charged.and_then(|h| h.0.downcast_ref::<crate::governance::AdmitGrant>());
        crate::ingress::finish_admitted(
            &self.app,
            gov,
            ingress_protocol,
            pool,
            started,
            charged_at,
            resp,
            grant.map(crate::governance::AdmitGrant::charge),
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
        _gov: &busbar_contract::records::PlaneRequestCtx,
        _model: &str,
        _body: bytes::Bytes,
        _max_body_bytes: usize,
    ) -> Result<
        busbar_kernel::plane_host::HostCompletion,
        busbar_kernel::plane_host::CompletionRefusal,
    > {
        // No linked plane installs a resolved-completion synthesizer (the seam left with the engine
        // that installed it), so there is no dialect to drive: the caller gets the neutral refusal
        // and words it in its own vocabulary.
        Err(busbar_kernel::plane_host::CompletionRefusal::NotInstalled)
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

/// THE LIVE RE-RESOLUTION a door unit's entitlement asks through (`entitlement.check`, ARCHITECT
/// round 4 Q-L3B-SURFACES (a)): an admitted principal re-resolved against the CURRENT snapshot's
/// governance registry (a registry key, by id) and `role_bindings` (a role-bound key), exactly as
/// [`EngineHost::principal_standing`] judges a long-lived response's frame. `None` when it no longer
/// stands; a deployment with governance off stands as admitted.
#[must_use]
pub fn live_standing(
    handle: std::sync::Arc<crate::state::AppHandle>,
) -> crate::host_services::Standing {
    std::sync::Arc::new(move |admitted, now| {
        let app = handle.load();
        standing_in(&app, admitted, now)
    })
}

/// [`live_standing`] over one fixed generation `app` (a composition with no live handle).
#[must_use]
pub fn standing_over(app: std::sync::Arc<crate::state::App>) -> crate::host_services::Standing {
    std::sync::Arc::new(move |admitted, now| standing_in(&app, admitted, now))
}

/// `admitted` as it stands in `app` at `now`.
fn standing_in(
    app: &crate::state::App,
    admitted: &Arc<busbar_contract::records::VirtualKey>,
    now: u64,
) -> Option<Arc<busbar_contract::records::VirtualKey>> {
    let resolve = crate::governance::LiveResolve {
        governance: app.governance.as_deref(),
        role_bindings: &app.role_bindings,
    };
    let standing = busbar_kernel::trust::validate::Standing::opened(
        Some(admitted),
        busbar_kernel::trust::validate::Snapshot::Watching,
        std::time::Duration::MAX,
    );
    match standing.still_permitted(
        Some(&resolve as &dyn busbar_kernel::trust::validate::GovResolve),
        0,
        now,
    ) {
        Ok(Some(live)) => Some(live),
        Ok(None) => Some(Arc::clone(admitted)),
        Err(_) => None,
    }
}

// The request-admission gate verdict is a pure POD naming only `busbar_contract::abi::hot` + std, so it now
// lives in the substrate beside the neutral `EngineHost` seam; core re-exports it so every in-core
// caller (`gate_decide_over`, a2a) is unchanged.

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
        let facts = busbar_contract::ir::invoke::InvokeReq {
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
/// [`IrFacts`]: busbar_contract::ir::facts::IrFacts
fn build_invoke_rewrite_request<'a>(
    facts: &'a dyn busbar_contract::ir::facts::IrFacts,
    ingress_protocol: &'a str,
    request_id: u64,
) -> busbar_contract::hooks::RoutingRequest<'a> {
    use busbar_contract::ir::facts::Slot;
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
        crate::hooks::content_capped(busbar_contract::hooks::PromptProjection { system, messages });
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
        session: None,
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
