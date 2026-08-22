// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The GOVERNANCE family of the plane host-vtable, wired over core's REAL primitives:
//! `govern_admit` (admission + the RAII [`AdmitGrant`](crate::governance::AdmitGrant) registered in
//! the dispatch arena), `meter_charge` (the money-scalar settlement + the write-behind metering
//! time-series), and `auth_resolve` (a credential REF → a host-side reference, never plaintext).
//!
//! These are the BODIES the three vtable slots delegate to. Each vtable fn owns the boundary
//! discipline (recover the [`HostState`] first, run inside `catch_unwind`, fail-closed, write any
//! out-param only on `Ok`); this module owns the translation from the borrowed `#[repr(C)]` POD to
//! the real core primitive and back.
//!
//! ## What is faithful today, and what is Phase 2
//!
//! The hot PODs the plane hands back ([`Facts`], [`Usage`], [`AuthQuery`]) carry the SHAPE of a
//! request but not yet the resolved core identity (the real [`VirtualKey`](busbar_api::VirtualKey),
//! the `(key_id, model, provider)` metering attribution, the credential-store lookup). So each fn
//! here drives the real primitive as far as is cleanly additive — the budget gate, the RAII grant,
//! the `try_admit` chain engine, the `CostBreakdown` "parts add up" invariant, the write-behind
//! metering accrual, the `AuthPrincipal` — and marks the identity-resolution wiring with a clear
//! `// Phase 2:` note. Nothing here is called by the engine yet (the module is ADDITIVE).

use super::HostState;
use crate::governance::AdmitGrant;
use crate::plane::cost::{CostAmount, CostBreakdown, CostComponent};
use busbar_plugin::hot::{
    AuthQuery, AuthResolved, Decision, Facts, MeterOutcome, Usage, UsageComponent, POD_VERSION,
};

/// Nanodollars per micro-currency unit — the projection from a [`Usage`]'s `unit_cost_micros` money
/// scalar into the engine's nanodollar ledger unit ([`CostAmount`]). Mirrors `cost::NANOS_PER_MICRO`
/// (a private const there); duplicated as a local so this module takes no new pub surface on `cost`.
const NANOS_PER_MICRO: u128 = 1_000;

/// Default bounded lifetime stamped onto a resolved credential reference until the real
/// credential-store lookup (Phase 2) supplies the mint's true expiry.
const DEFAULT_AUTH_TTL_SECS: u64 = 300;

/// The unattributed model/provider a metering row is recorded under until Phase 2 resolves the real
/// attribution from the request. Kept explicit (not `""`) so a stray row is legible in the store.
const MODEL_UNATTRIBUTED: &str = "plane:unattributed";
const PROVIDER_UNATTRIBUTED: &str = "plane:unattributed";

// ─────────────────────────────────────────────────────────────────────────────────────────────
// govern_admit — REAL admission over `crate::governance`, RAII grant registered in the arena.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The real admission decision over a borrowed [`Facts`]. On `Admit` the RAII
/// [`AdmitGrant`](crate::governance::AdmitGrant) obtained from the governance engine is REGISTERED in
/// the dispatch arena, so its release runs on scope-drop no matter how the dispatch future ends (the
/// §4 leak keystone). Called from inside the slot's `catch_unwind`; the caller maps a panic to
/// `Deny`, so this stays fail-closed by construction.
pub(super) fn admit(state: &HostState, facts: &Facts) -> Decision {
    // The budget gate the Facts POD encodes: the caller's remaining budget MUST cover the requested
    // units. This is enforced regardless of whether the node runs the full `GovState` limit engine.
    if facts.budget_remaining < facts.tokens {
        return Decision::Deny;
    }
    // Obtain the RAII admission grant from the real engine (an EMPTY grant when governance is
    // disabled or the resolved chain has no concurrent caps; a real gauge-holding grant otherwise),
    // then register it so the arena reclaims it on scope-drop.
    let grant = match grant_for(state, facts) {
        Ok(g) => g,
        Err(()) => return Decision::Deny, // a blocked chain limit (or a missing group) denies.
    };
    state.scope.register_admission(Box::new(grant));
    Decision::Admit
}

/// Drive the real `GovState::try_admit` limit engine and hand back its RAII grant.
///
/// `Ok(grant)` = admitted (the grant holds every concurrent gauge the chain took); `Err(())` = a
/// chain limit blocked. When governance is disabled this is an enforcement no-op (matching an empty
/// `GovCtx { key: None }`) that still returns a real — empty — grant so the arena path is uniform.
fn grant_for(state: &HostState, facts: &Facts) -> Result<AdmitGrant, ()> {
    let Some(gov) = state.app.governance.as_ref() else {
        return Ok(AdmitGrant::default());
    };
    let pool = borrowed_str(facts.pool_name_ptr, facts.pool_name_len);
    // Phase 2: resolve the caller's REAL `VirtualKey` (id / group / enforcement chain) from the
    // request identity so the grant carries the chain's concurrent gauges. The `Facts` POD carries
    // no key handle today, so the limit engine is driven with an ungrouped key synthesized from the
    // tenant id — an unlimited 1-bucket chain that admits and returns an empty grant, exercising the
    // real `try_admit` path end to end.
    let key = synth_key(facts.tenant_id);
    let now = crate::store::now_ms() / 1_000;
    gov.try_admit(state.app.cost.as_ref(), &key, &pool, now)
        .map_err(|_| ())
}

/// A minimal ungrouped [`VirtualKey`](busbar_api::VirtualKey) synthesized from a tenant id — the
/// Phase-2 seam for real key resolution (see [`grant_for`]).
fn synth_key(tenant_id: u64) -> busbar_api::VirtualKey {
    let id = format!("plane:tenant:{tenant_id}");
    busbar_api::VirtualKey {
        generation_hash: format!("plane:gen:{tenant_id}"),
        name: id.clone(),
        id,
        allowed_scopes: None,
        enabled: true,
        created_at: 0,
        group: None, // ungrouped → an unlimited 1-bucket chain (no caps) in `try_admit`.
        labels: std::collections::BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// meter_charge — the money-scalar settlement + the write-behind metering time-series.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Charge a borrowed [`Usage`] through the real metering path. Computes the neutral money scalar
/// (`amount × unit_cost_micros`, projected to nanodollars) and validates it through the real
/// [`CostBreakdown`] "parts add up" invariant, then accrues the usage into the write-behind metering
/// time-series. A malformed breakdown REFUSES the charge (fail-closed). Called from inside the slot's
/// `catch_unwind`; a panic maps to `Rejected`.
pub(super) fn charge(state: &HostState, usage: &Usage) -> MeterOutcome {
    // The neutral money scalar this usage settles, in nanodollars (the engine's ledger unit).
    let micros = u128::from(usage.amount).saturating_mul(u128::from(usage.unit_cost_micros));
    let amount = CostAmount(micros.saturating_mul(NANOS_PER_MICRO));
    // Validate through the real `CostBreakdown`: a single opaque-component line (breakdowns are
    // sparse, so a zero charge carries no component). A breakdown that cannot be constructed — the
    // parts do not add up — refuses the charge rather than ledgering an untrustworthy split.
    let components = if amount == CostAmount::ZERO {
        Vec::new()
    } else {
        vec![CostComponent::top(component_label(usage.component), amount)]
    };
    if CostBreakdown::new(amount, components).is_err() {
        return MeterOutcome::Rejected;
    }
    // Accrue into the real write-behind metering time-series when governance is enabled.
    // Phase 2: attribute to the resolved `(key_id, model, provider)` and fold the settled money
    // scalar into the budget ledger via a `CostHold`. Today the usage is recorded against a synthetic
    // attribution derived from the admission id, so the accrual path is exercised end to end.
    if let Some(gov) = state.app.governance.as_ref() {
        let key_id = format!("plane:admission:{}", usage.admission.0);
        let token_usage = token_usage_for(usage);
        let now = crate::store::now_ms() / 1_000;
        gov.record_metering(
            &key_id,
            MODEL_UNATTRIBUTED,
            PROVIDER_UNATTRIBUTED,
            token_usage.as_ref(),
            now,
        );
    }
    MeterOutcome::Charged
}

/// Project a [`Usage`] onto a [`TokenUsage`](crate::billing::TokenUsage) — the shape metering
/// accrual counts — only when the component is `Tokens`. Other components (bytes / frames / queries)
/// record a request with no token counts (`None`), which is faithful: the metering time-series counts
/// tokens, and Phase 2 adds the per-component projections.
fn token_usage_for(usage: &Usage) -> Option<crate::billing::TokenUsage> {
    match usage.component {
        UsageComponent::Tokens => Some(crate::billing::TokenUsage {
            input: usage.amount,
            ..Default::default()
        }),
        UsageComponent::Bytes | UsageComponent::Frames | UsageComponent::Queries => None,
    }
}

/// The opaque, protocol-blind label for a usage component's cost line (never interpreted by core).
fn component_label(component: UsageComponent) -> &'static str {
    match component {
        UsageComponent::Tokens => "tokens",
        UsageComponent::Bytes => "bytes",
        UsageComponent::Frames => "frames",
        UsageComponent::Queries => "queries",
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// auth_resolve — a credential REF → a host-side reference (NEVER plaintext).
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Resolve a borrowed [`AuthQuery`] to an [`AuthResolved`], or `None` to refuse. A query naming no
/// credential (`credential_ref == 0`) has nothing to resolve and is refused. Establishes the caller
/// principal through the real [`AuthPrincipal`](crate::auth::AuthPrincipal) primitive and hands back
/// an OPAQUE host-side reference with a bounded expiry — never a secret. Called from inside the slot's
/// `catch_unwind`, which writes the out-param only on the `Ok`/`Some` path.
pub(super) fn resolve_auth(_state: &HostState, query: &AuthQuery) -> Option<AuthResolved> {
    if query.credential_ref == 0 {
        return None;
    }
    // Phase 2: look the credential REF up against the host credential store / auth middleware to mint
    // a real short-lived host-side reference and its true expiry. Today the principal is established
    // via the real `AuthPrincipal` primitive (anonymous unless the query's audience scopes it) and
    // the resolved handle is derived from the query ref with a bounded default TTL.
    let audience = borrowed_str(query.audience_ptr, query.audience_len);
    let principal = if audience.is_empty() {
        crate::auth::AuthPrincipal(None)
    } else {
        crate::auth::AuthPrincipal(Some(crate::auth::Principal::from_id(audience)))
    };
    // Exercise the real primitive (attribution handle) — the seam a Phase-2 lookup resolves through.
    let _actor_id = principal.actor_id();
    let now = crate::store::now_ms() / 1_000;
    Some(AuthResolved {
        size: core::mem::size_of::<AuthResolved>() as u32,
        version: POD_VERSION,
        _reserved: 0,
        _reserved2: 0,
        // The resolved host-side reference is opaque; echoing the query ref is the faithful minimal
        // (Phase 2 mints a distinct short-lived handle). It is NEVER a secret either way.
        resolved_ref: query.credential_ref,
        expires_unix: now.saturating_add(DEFAULT_AUTH_TTL_SECS),
    })
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Shared POD helpers.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Read a borrowed `(ptr, len)` byte range from a POD into an owned `String` (lossy on non-UTF-8). A
/// null pointer or zero length reads as empty — the ABI's "not present" encoding for a borrowed field.
fn borrowed_str(ptr: *const u8, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        return String::new();
    }
    // SAFETY: per the ABI borrow discipline a non-null `(ptr, len)` is a live, initialized byte range
    // for the duration of the host call (see the POD field docs on `Facts`/`AuthQuery`).
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf8_lossy(bytes).into_owned()
}
