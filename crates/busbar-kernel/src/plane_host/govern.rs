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
//! ## Whose identity
//!
//! The hot PODs the plane hands back ([`Facts`], [`Usage`], [`AuthQuery`]) carry the SHAPE of a
//! request, never who it is for: admission and billing resolve the caller from the handle the HOST
//! minted ([`HostState`]'s caller, stamped from the auth middleware's context — DEC-SERVE G1/G1b),
//! so an identity word a plane writes into a POD tail is never read as a key.

use super::HostState;
use crate::governance::{AdmitGrant, LimitBlocked};
use crate::plane::cost::{CostAmount, CostBreakdown, CostComponent};
use busbar_plugin::hot::{
    AuthQuery, AuthResolved, Decision, Facts, MeterOutcome, Usage, UsageComponent, POD_VERSION,
};
use busbar_plugin::read_sized_field;

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

/// THE SYNTHETIC ADMISSION KEY (DEC-SERVE G1b): the ungrouped key a mint with NO caller admits as —
/// `plane:tenant:<Facts.tenant_id>`. Never a key a plane named: a `Facts` identity tail is not read.
pub(super) const SYNTH_TENANT_KEY: &str = "plane:tenant:";

/// THE SYNTHETIC BILLING KEY (DEC-SERVE G1b): the key a mint with NO caller bills —
/// `plane:admission:<Usage.admission>`. Never a key a plane named: a `Usage` key id is not read.
pub(super) const SYNTH_ADMISSION_KEY: &str = "plane:admission:";

// ─────────────────────────────────────────────────────────────────────────────────────────────
// govern_admit — REAL admission over `crate::governance`, RAII grant registered in the arena.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The real admission decision over a borrowed [`Facts`]. On `Admit` the RAII
/// [`AdmitGrant`](crate::governance::AdmitGrant) obtained from the governance engine is REGISTERED in
/// the dispatch arena, so its release runs on scope-drop no matter how the dispatch future ends (the
/// leak keystone). Called from inside the slot's `catch_unwind`; the caller maps a panic to
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
    grant_for_blocked(state, facts).map_err(|_| ())
}

/// [`grant_for`] WITHOUT discarding the block reason: `Err` carries the real
/// [`LimitBlocked`](crate::governance::LimitBlocked) the chain engine yielded, so the refusal-fidelity
/// admit ([`admit_reason`]) can render it for an operator instead of collapsing it to a bare `Deny`.
/// The admit path itself is byte-for-byte [`grant_for`]'s — same identity resolution, same `try_admit`
/// over the same clock — so `grant_for`'s `Err(())` and this `Err(blocked)` name the SAME block.
fn grant_for_blocked(state: &HostState, facts: &Facts) -> Result<AdmitGrant, LimitBlocked> {
    let Some(gov) = state.app.governance.as_ref() else {
        return Ok(AdmitGrant::default());
    };
    let pool = borrowed_str(facts.pool_name_ptr, facts.pool_name_len);
    // WHO IS ADMITTED (DEC-SERVE G1b, #65/#40): the caller the minter stamped from the auth context —
    // its real key, whose `id` + `group` are all `try_admit`/`chain_for` read — never an identity
    // the plane wrote in the `Facts` tail. No caller: the named synthetic ungrouped key.
    let synth;
    let key = match &state.caller {
        Some(caller) => caller.key(),
        None => {
            synth = virtual_key(format!("{SYNTH_TENANT_KEY}{}", facts.tenant_id), None);
            &synth
        }
    };
    let now = busbar_kernel::store::now_ms() / 1_000;
    gov.try_admit(state.app.cost.as_ref(), key, &pool, now)
}

/// A blocked admission carried out of [`admit_reason`]: the RENDERED reason (the exact
/// `format!("{blocked:?}")` bytes the mcp budget-refusal surfaces today) plus the block's recovery
/// floor in whole seconds. Kept as an owned `String` on the cold refusal path only.
pub(super) struct GovBlocked {
    /// The rendered reason bytes the host copies into the caller's `reason_buf`.
    pub(super) reason: String,
    /// The recovery floor in whole seconds (`0` when the block does not self-recover / never rolls).
    pub(super) retry_after_secs: u64,
}

/// The refusal-fidelity analogue of [`admit`]: identical admit behaviour (the budget-POD gate, then
/// the real `try_admit` chain, REGISTERING the RAII grant in the dispatch arena on success), but a
/// blocked limit returns the RENDERED [`GovBlocked`] reason instead of a bare `Deny`. `Ok(())` =
/// admitted (grant registered); `Err(blocked)` = refused with the reason to surface. Called from
/// inside the slot's `catch_unwind`, so a panic maps to `Deny` upstream and this stays fail-closed.
pub(super) fn admit_reason(state: &HostState, facts: &Facts) -> Result<(), GovBlocked> {
    // The budget gate the Facts POD encodes has no chain-limit reason to render (it is the POD's own
    // pre-chain refusal), so a gate block carries an empty reason + no recovery floor. `charge_round`
    // never trips it (its Facts carry tokens = budget = 0); the chain below is the sole decider there.
    if facts.budget_remaining < facts.tokens {
        return Err(GovBlocked {
            reason: String::new(),
            retry_after_secs: 0,
        });
    }
    match grant_for_blocked(state, facts) {
        Ok(grant) => {
            state.scope.register_admission(Box::new(grant));
            Ok(())
        }
        Err(blocked) => {
            // The recovery floor a windowed-limit block knows; a `total` window never rolls and a
            // missing/disabled group does not self-recover, so both carry `0`.
            let retry_after_secs = match &blocked {
                LimitBlocked::Limit { retry_after, .. } => retry_after.unwrap_or(0),
                LimitBlocked::Disabled(_) | LimitBlocked::MissingGroup(_) => 0,
            };
            // BYTE-IDENTICAL to the mcp `charge_round`'s current `Err(format!("{blocked:?}"))`: the
            // plane cannot hold `LimitBlocked` post-flip, so the host renders the SAME Debug bytes.
            Err(GovBlocked {
                reason: format!("{blocked:?}"),
                retry_after_secs,
            })
        }
    }
}

/// Build the minimal [`VirtualKey`](busbar_contract::records::VirtualKey) `chain_for` reads: `id` + `group`. Every
/// other field is an inert default the enforcement chain never consults.
fn virtual_key(id: String, group: Option<String>) -> busbar_contract::records::VirtualKey {
    busbar_contract::records::VirtualKey {
        generation_hash: String::new(),
        name: id.clone(),
        id,
        allowed_scopes: None,
        enabled: true,
        created_at: 0,
        group,
        labels: std::collections::BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
        ..Default::default()
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
    // The plane FILLS this struct, so `component` is a plane-chosen byte. Decode it through the
    // checked carrier BEFORE anything dispatches on it: a byte this build does not name has no
    // defensible cost line and no defensible token projection, so the charge is REFUSED rather than
    // billed against a guess (and the bare enum is never materialized, so there is no UB to reach).
    let Some(component) = usage.component.component() else {
        return MeterOutcome::Rejected;
    };
    // The neutral money scalar this usage settles, in nanodollars (the engine's ledger unit).
    let micros = u128::from(usage.amount).saturating_mul(u128::from(usage.unit_cost_micros));
    let amount = CostAmount(micros.saturating_mul(NANOS_PER_MICRO));
    // Validate through the real `CostBreakdown`: a single opaque-component line (breakdowns are
    // sparse, so a zero charge carries no component). A breakdown that cannot be constructed — the
    // parts do not add up — refuses the charge rather than ledgering an untrustworthy split.
    let components = if amount == CostAmount::ZERO {
        Vec::new()
    } else {
        vec![CostComponent::top(component_label(component), amount)]
    };
    if CostBreakdown::new(amount, components).is_err() {
        return MeterOutcome::Rejected;
    }
    // Accrue into the real write-behind metering time-series when governance is enabled, against the
    // minted caller's key and the tail's `(model, provider)` — the EXACT row the in-process meter
    // records (proven by `charge_over_usage_matches_record_metering`).
    // THE LEDGER WRITE IS UNCONDITIONAL (DECISION #43, owner ruling 2026-09-22: "planes always
    // ledger"). The plane's counts are appended whether or not a `rate_card:` is configured: the card
    // decides only whether a READ can turn counts into money (#42 — billing off means the money VIEW
    // reads 0), never whether the write happens. A write gated on the card is a ledger that knows about
    // money, which #43/#71/#77(3) rule out. (This used to be `if state.app.cost.pricing_enabled()`,
    // which left a billing-off deployment with no record of what its planes did.)
    if let Some(gov) = state.app.governance.as_ref() {
        // WHO PAYS (DEC-SERVE G1/G1b, #65/#40): the caller the minter stamped from the auth context
        // is the ONLY key billed — the `Usage` tail's key id is never read as a key, so a plane that
        // forges one bills its real caller, never the victim. No caller: the named synthetic key.
        let synth;
        let key = match &state.caller {
            Some(caller) => caller.key(),
            None => {
                synth = virtual_key(format!("{SYNTH_ADMISSION_KEY}{}", usage.admission.0), None);
                &synth
            }
        };
        let (model, provider) = resolved_attribution(usage).unwrap_or_else(|| {
            (
                MODEL_UNATTRIBUTED.to_string(),
                PROVIDER_UNATTRIBUTED.to_string(),
            )
        });
        let token_usage = token_usage_for(component, usage.amount);
        let now = busbar_kernel::store::now_ms() / 1_000;
        gov.record_metering(&key.id, &model, &provider, token_usage.as_ref(), now);
        // ITEM 123 (#71): the keyed-unit tail — every class the plane counted, reserved and open —
        // lands in the enforcement ledger VERBATIM for the attributed key; the card prices it.
        // SAFETY: `usage` is the live POD this slot was handed; the decode reads the tail only
        // when the sender's advertised `size` proves it was written.
        let units = unsafe { busbar_plugin::hot::decode_usage_units(usage) };
        if !units.is_empty() {
            gov.record_usage(&state.app.cost, key, "", &model, &units, now);
        }
    }
    MeterOutcome::Charged
}

/// Read the `(model, provider)` words off the [`Usage`] attribution tail, or `None` when the tail is
/// absent (an older sender, per the sized-struct guard) or names no key — the pre-enrichment row. The
/// tail's key id is read only as that presence marker, NEVER as the key billed (DEC-SERVE G1b).
fn resolved_attribution(usage: &Usage) -> Option<(String, String)> {
    let key_ptr = read_sized_field!(usage, usage.size, Usage, key_id_ptr)?;
    let key_len = read_sized_field!(usage, usage.size, Usage, key_id_len)?;
    if key_ptr.is_null() || key_len == 0 {
        return None;
    }
    let model = match (
        read_sized_field!(usage, usage.size, Usage, model_ptr),
        read_sized_field!(usage, usage.size, Usage, model_len),
    ) {
        (Some(ptr), Some(len)) => borrowed_str(ptr, len),
        _ => String::new(),
    };
    let provider = match (
        read_sized_field!(usage, usage.size, Usage, provider_ptr),
        read_sized_field!(usage, usage.size, Usage, provider_len),
    ) {
        (Some(ptr), Some(len)) => borrowed_str(ptr, len),
        _ => String::new(),
    };
    Some((model, provider))
}

/// Project a [`Usage`] onto a [`TokenUsage`](crate::billing::TokenUsage) — the shape metering
/// accrual counts — only when the component is `Tokens`. Other components (bytes / frames / queries)
/// record a request with no token counts (`None`), which is faithful: the metering time-series counts
/// tokens, and Phase 2 adds the per-component projections.
fn token_usage_for(component: UsageComponent, amount: u64) -> Option<crate::billing::TokenUsage> {
    match component {
        UsageComponent::Tokens => Some(crate::billing::TokenUsage {
            input: amount,
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
    // Establish the caller principal through the real `AuthPrincipal` primitive (anonymous unless the
    // query's audience scopes it) — the seam a Phase-2 credential-store lookup resolves through.
    let audience = borrowed_str(query.audience_ptr, query.audience_len);
    let principal = if audience.is_empty() {
        crate::auth::AuthPrincipal(None)
    } else {
        crate::auth::AuthPrincipal(Some(crate::auth::Principal::from_id(audience.clone())))
    };
    let _actor_id = principal.actor_id();
    let now = busbar_kernel::store::now_ms() / 1_000;
    let expires_unix = now.saturating_add(DEFAULT_AUTH_TTL_SECS);
    // MINT a fresh, short-lived, host-owned credential reference (the CLUSTER-3 (d) decision: a NEW
    // per-hop `resolved_ref`, DISTINCT from the input `credential_ref`; the host owns its expiry). The
    // resolved PLAINTEXT stays host-side in `super::creds` — the plane gets back only the opaque ref,
    // which it carries to `egress_open` where the host reads the secret back and injects it. Phase 2:
    // the real host credential store resolves `(credential_ref, audience)` to the provider secret; the
    // host-derived placeholder here keeps the plaintext off the plane while that lookup is wired.
    let secret = format!("hostcred:{}:{}", query.credential_ref, audience).into_bytes();
    // FFI-F5: BIND the mint to the destination the plane named (`audience`), so `egress_open` injects
    // this secret ONLY on a hop to that destination — never a plane-chosen attacker host.
    let resolved_ref = super::creds::mint(secret, audience, expires_unix, now);
    Some(AuthResolved {
        size: core::mem::size_of::<AuthResolved>() as u32,
        version: POD_VERSION,
        _reserved: 0,
        _reserved2: 0,
        // An OPAQUE host-side reference (NEVER a secret): a fresh mint, distinct from the input ref.
        resolved_ref,
        expires_unix,
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

#[cfg(test)]
#[path = "tests/govern_tests.rs"]
mod tests;
