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
    // Resolve the caller's admission identity from the `Facts` tail: `try_admit`/`chain_for` read
    // ONLY the key's `id` (its attribution `total` bucket) and its `group` (the enforcement chain up
    // the parent tree), so a `VirtualKey` reconstructed from just those two fields drives the SAME
    // chain the in-process budget plane enforces (proven by `admit_over_facts_matches_try_admit`).
    // When the tail is absent (an older sender, or a caller with no resolved identity) fall back to
    // the ungrouped key synthesized from the tenant id — the pre-enrichment behaviour.
    let key = resolved_key(facts).unwrap_or_else(|| synth_key(facts.tenant_id));
    let now = crate::store::now_ms() / 1_000;
    gov.try_admit(state.app.cost.as_ref(), &key, &pool, now)
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

/// Reconstruct the caller's [`VirtualKey`](busbar_api::VirtualKey) from the [`Facts`] identity tail,
/// or `None` when the tail is absent (an older sender, per the sized-struct guard) or carries no key
/// id. Only the fields `try_admit`/`chain_for` actually read are populated — `id` (the attribution
/// bucket) and `group` (the enforcement chain) — so the reconstructed key drives the identical chain
/// resolution; every other field is an inert default `chain_for` never consults.
fn resolved_key(facts: &Facts) -> Option<busbar_api::VirtualKey> {
    let id_ptr = read_sized_field!(facts, Facts, identity_id_ptr)?;
    let id_len = read_sized_field!(facts, Facts, identity_id_len)?;
    let id = borrowed_str(id_ptr, id_len);
    if id.is_empty() {
        return None; // no resolved identity → the synth fallback (pre-enrichment behaviour).
    }
    // The group is optional even when an id is present: a null/empty range is an UNGROUPED key (an
    // unlimited 1-bucket chain), exactly as `key.group == None` resolves in `chain_for`.
    let group = match (
        read_sized_field!(facts, Facts, group_ptr),
        read_sized_field!(facts, Facts, group_len),
    ) {
        (Some(ptr), Some(len)) if !ptr.is_null() && len != 0 => Some(borrowed_str(ptr, len)),
        _ => None,
    };
    Some(virtual_key(id, group))
}

/// A minimal ungrouped [`VirtualKey`](busbar_api::VirtualKey) synthesized from a tenant id — the
/// fallback when the [`Facts`] identity tail is absent (see [`grant_for`]).
fn synth_key(tenant_id: u64) -> busbar_api::VirtualKey {
    virtual_key(format!("plane:tenant:{tenant_id}"), None)
}

/// Build the minimal [`VirtualKey`](busbar_api::VirtualKey) `chain_for` reads: `id` + `group`. Every
/// other field is an inert default the enforcement chain never consults.
fn virtual_key(id: String, group: Option<String>) -> busbar_api::VirtualKey {
    busbar_api::VirtualKey {
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
    // Accrue into the real write-behind metering time-series when governance is enabled. When the
    // `Usage` attribution tail is present the row is recorded against the EXACT `(key_id, model,
    // provider)` the in-process meter would (proven by `charge_over_usage_matches_record_metering`);
    // when it is absent the row falls back to the synthetic attribution derived from the admission id,
    // the pre-enrichment behaviour.
    if let Some(gov) = state.app.governance.as_ref() {
        let attribution = resolved_attribution(usage);
        // The synthetic fallback key id, materialized here so it outlives the borrow below.
        let synth_key_id = format!("plane:admission:{}", usage.admission.0);
        let (key_id, model, provider) = match attribution.as_ref() {
            Some((k, m, p)) => (k.as_str(), m.as_str(), p.as_str()),
            None => (
                synth_key_id.as_str(),
                MODEL_UNATTRIBUTED,
                PROVIDER_UNATTRIBUTED,
            ),
        };
        let token_usage = token_usage_for(usage);
        let now = crate::store::now_ms() / 1_000;
        gov.record_metering(key_id, model, provider, token_usage.as_ref(), now);
    }
    MeterOutcome::Charged
}

/// Resolve the metering attribution `(key_id, model, provider)` from the [`Usage`] tail, or `None`
/// when the tail is absent (an older sender, per the sized-struct guard) or carries no key id. The
/// three words are exactly `record_metering`'s `(key_id, model, provider)` — so a present tail records
/// the identical row the in-process meter does.
fn resolved_attribution(usage: &Usage) -> Option<(String, String, String)> {
    let key_ptr = read_sized_field!(usage, Usage, key_id_ptr)?;
    let key_len = read_sized_field!(usage, Usage, key_id_len)?;
    let key_id = borrowed_str(key_ptr, key_len);
    if key_id.is_empty() {
        return None; // no resolved attribution → the synthetic fallback (pre-enrichment behaviour).
    }
    let model = match (
        read_sized_field!(usage, Usage, model_ptr),
        read_sized_field!(usage, Usage, model_len),
    ) {
        (Some(ptr), Some(len)) => borrowed_str(ptr, len),
        _ => String::new(),
    };
    let provider = match (
        read_sized_field!(usage, Usage, provider_ptr),
        read_sized_field!(usage, Usage, provider_len),
    ) {
        (Some(ptr), Some(len)) => borrowed_str(ptr, len),
        _ => String::new(),
    };
    Some((key_id, model, provider))
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
    // Establish the caller principal through the real `AuthPrincipal` primitive (anonymous unless the
    // query's audience scopes it) — the seam a Phase-2 credential-store lookup resolves through.
    let audience = borrowed_str(query.audience_ptr, query.audience_len);
    let principal = if audience.is_empty() {
        crate::auth::AuthPrincipal(None)
    } else {
        crate::auth::AuthPrincipal(Some(crate::auth::Principal::from_id(audience.clone())))
    };
    let _actor_id = principal.actor_id();
    let now = crate::store::now_ms() / 1_000;
    let expires_unix = now.saturating_add(DEFAULT_AUTH_TTL_SECS);
    // MINT a fresh, short-lived, host-owned credential reference (the CLUSTER-3 (d) decision: a NEW
    // per-hop `resolved_ref`, DISTINCT from the input `credential_ref`; the host owns its expiry). The
    // resolved PLAINTEXT stays host-side in `super::creds` — the plane gets back only the opaque ref,
    // which it carries to `egress_open` where the host reads the secret back and injects it. Phase 2:
    // the real host credential store resolves `(credential_ref, audience)` to the provider secret; the
    // host-derived placeholder here keeps the plaintext off the plane while that lookup is wired.
    let secret = format!("hostcred:{}:{}", query.credential_ref, audience).into_bytes();
    let resolved_ref = super::creds::mint(secret, expires_unix);
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
mod tests {
    use crate::plane_host::with_dispatch_scope;
    use busbar_plugin::hot::{
        AdmissionId, Decision, Facts, GovRefusal, MeterOutcome, Usage, UsageComponent,
    };
    use core::mem::MaybeUninit;
    use std::sync::Arc;

    /// A cost model with ONE budget group (`name`, `cap` cents on the total window, no parent) and a
    /// 1c flat fee — so `cap` requests fit before the group's total-window bucket blocks. Mirrors the
    /// governance suite's `group_cost`, inlined here to keep this module's tests self-contained.
    fn group_cost(name: &str, cap: i64) -> crate::cost::CostModel {
        use crate::config::groups::{LimitCfg, LimitMetric, LimitWindow};
        let mut groups = std::collections::BTreeMap::new();
        groups.insert(
            name.to_string(),
            crate::config::GroupCfg {
                parent: None,
                enabled: true,
                limits: vec![LimitCfg {
                    metric: LimitMetric::Budget,
                    amount: u64::try_from(cap).unwrap_or(0),
                    per: Some(LimitWindow::Total),
                    scope: None,
                    on_exhaust: None,
                    downgrade_to: None,
                }],
                ..Default::default()
            },
        );
        crate::cost::CostModel::resolve_parts(None, 1, &groups)
    }

    /// Like [`group_cost`] but the single group is FROZEN (`enabled: false`), so every request
    /// charging through it is rejected with [`LimitBlocked::Disabled`].
    fn disabled_group_cost(name: &str) -> crate::cost::CostModel {
        use crate::config::groups::{LimitCfg, LimitMetric, LimitWindow};
        let mut groups = std::collections::BTreeMap::new();
        groups.insert(
            name.to_string(),
            crate::config::GroupCfg {
                parent: None,
                enabled: false,
                limits: vec![LimitCfg {
                    metric: LimitMetric::Budget,
                    amount: 100,
                    per: Some(LimitWindow::Total),
                    scope: None,
                    on_exhaust: None,
                    downgrade_to: None,
                }],
                ..Default::default()
            },
        );
        crate::cost::CostModel::resolve_parts(None, 1, &groups)
    }

    /// The minimal [`VirtualKey`](busbar_api::VirtualKey) `try_admit`/`chain_for` read — `id` + `group`
    /// — so a direct `try_admit` and the host `govern_admit_reason` drive the identical chain.
    fn test_key(id: &str, group: Option<&str>) -> busbar_api::VirtualKey {
        busbar_api::VirtualKey {
            generation_hash: String::new(),
            name: id.to_string(),
            id: id.to_string(),
            allowed_scopes: None,
            enabled: true,
            created_at: 0,
            group: group.map(str::to_string),
            labels: std::collections::BTreeMap::new(),
            expires_at: None,
            deleted_at: None,
            revision: 0,
            ..Default::default()
        }
    }

    fn gov() -> Arc<crate::governance::GovState> {
        Arc::new(
            crate::governance::GovState::new(Arc::new(crate::governance::MemoryStore::new()), None)
                .expect("memory store constructs"),
        )
    }

    /// THE GOVERN FAITHFULNESS PROOF: driving `govern_admit` over a [`Facts`] carrying the caller's
    /// REAL `(key_id, group)` admits against the EXACT SAME budget bucket the plane's own
    /// `try_admit(&real_key, pool)` charges — the govern analogue of the breaker's
    /// `settle_through_host_matches_direct_record_signal`. A group with a 5c total cap at 1c/request
    /// fits exactly 5 admissions; 3 taken directly through the real key leave exactly 2 for the host
    /// path (proving they share the `group:<name>@total` bucket, not two disjoint buckets).
    #[test]
    fn admit_over_facts_matches_try_admit() {
        let gov = gov();
        let cost = group_cost("team", 5); // 5c cap, 1c/request → 5 requests fit
        let now = crate::store::now_ms() / 1_000;
        // The real key the plane would resolve: `chain_for` reads only `id` + `group`.
        let key = busbar_api::VirtualKey {
            generation_hash: String::new(),
            name: "k".to_string(),
            id: "vk_faithful_admit".to_string(),
            allowed_scopes: None,
            enabled: true,
            created_at: 0,
            group: Some("team".to_string()),
            labels: std::collections::BTreeMap::new(),
            expires_at: None,
            deleted_at: None,
            revision: 0,
            ..Default::default()
        };
        // DIRECT: take 3 of the 5 through the real `try_admit`, exactly as `charge_round` does.
        for _ in 0..3 {
            assert!(
                gov.try_admit(&cost, &key, "pool-x", now).is_ok(),
                "the real key admits under the cap"
            );
        }
        // HOST: admit through the vtable over a Facts carrying the SAME (id, group). Exactly 2 fit.
        let app = crate::test_support::TestApp::new()
            .governance(Arc::clone(&gov))
            .cost(group_cost("team", 5))
            .build();
        let admitted = with_dispatch_scope(&app, |host, vt| {
            let mut n = 0;
            for _ in 0..4 {
                let facts = Facts::with_attribution(
                    1,
                    1_000,
                    0,
                    0,
                    0,
                    b"pool-x",
                    key.id.as_bytes(),
                    Some(b"team"),
                );
                if (vt.govern_admit.unwrap())(host, &*facts as *const Facts) == Decision::Admit {
                    n += 1;
                }
            }
            n
        });
        assert_eq!(
            admitted, 2,
            "3 direct + 2 host = the 5-request cap; the host path shares the real key's group bucket"
        );
    }

    /// A [`Facts`] WITHOUT the identity tail (`Facts::new`) still admits against the synthesized
    /// ungrouped key — the pre-enrichment fallback is unchanged, so the enrichment is behavior-additive.
    #[test]
    fn admit_without_identity_falls_back_to_synth() {
        let gov = gov();
        let app = crate::test_support::TestApp::new()
            .governance(gov)
            .cost(group_cost("team", 1))
            .build();
        with_dispatch_scope(&app, |host, vt| {
            // No attribution → synth ungrouped key → the unlimited 1-bucket chain admits.
            let facts = Facts::new(1, 1_000, 42, 0, 0, b"pool-x");
            assert_eq!(
                (vt.govern_admit.unwrap())(host, &*facts as *const Facts),
                Decision::Admit
            );
        });
    }

    /// THE GOVERN-REFUSAL FAITHFULNESS PROOF (the govern analogue of the breaker's
    /// `settle_through_host_matches_direct_record_signal`): for every blocked-limit shape, driving the
    /// host `govern_admit_reason` slot yields the SAME `Decision::Deny` AND the SAME rendered reason
    /// bytes as the direct `try_admit(...)`→`format!("{blocked:?}")` the mcp `charge_round` returns
    /// today — the byte-identity Option A rests on. Covers `MissingGroup`, `Disabled`, and an
    /// exhausted `Limit{..}`.
    #[test]
    fn govern_admit_reason_reason_bytes_match_direct_try_admit() {
        // Run ONE blocked shape over a SHARED gov: drain `drain` requests, capture the direct block's
        // `{blocked:?}`, then drive the host slot over an identical cost + Facts and compare.
        fn faithful_case(
            make_cost: &dyn Fn() -> crate::cost::CostModel,
            key_group: Option<&str>,
            facts_group: Option<&[u8]>,
            drain: usize,
        ) {
            let pool = "pool-x";
            let key = test_key("vk_reason", key_group);
            let gov = gov();
            let cost = make_cost();
            let now = crate::store::now_ms() / 1_000;
            // Exhaust the budget for the Limit case (a no-op for MissingGroup/Disabled, drain = 0).
            for _ in 0..drain {
                let _ = gov.try_admit(&cost, &key, pool, now);
            }
            // DIRECT: the exact `LimitBlocked` the mcp `charge_round` renders today.
            let blocked = gov
                .try_admit(&cost, &key, pool, now)
                .expect_err("this shape must block");
            let expected = format!("{blocked:?}");

            // HOST: drive the slot over the SAME gov (shared drained state) + an identical cost.
            let app = crate::test_support::TestApp::new()
                .governance(Arc::clone(&gov))
                .cost(make_cost())
                .build();
            with_dispatch_scope(&app, |host, vt| {
                let facts = Facts::with_attribution(
                    0,
                    0,
                    0,
                    0,
                    0,
                    pool.as_bytes(),
                    key.id.as_bytes(),
                    facts_group,
                );
                let mut buf = [0u8; 512];
                let mut out = MaybeUninit::<GovRefusal>::uninit();
                let decision = (vt.govern_admit_reason.unwrap())(
                    host,
                    &*facts as *const Facts,
                    buf.as_mut_ptr(),
                    buf.len(),
                    std::ptr::from_mut(&mut out),
                );
                assert_eq!(decision, Decision::Deny, "a blocked limit denies");
                // SAFETY: the host always initializes `out`.
                let refusal = unsafe { out.assume_init() };
                assert!(
                    refusal.reason_len <= buf.len(),
                    "written length fits the buffer"
                );
                let actual = String::from_utf8_lossy(&buf[..refusal.reason_len]).into_owned();
                assert_eq!(
                    actual, expected,
                    "host-rendered reason must be byte-identical to the direct {{blocked:?}}"
                );
            });
        }

        // MissingGroup: the key names a group the cost model does not have.
        faithful_case(&|| group_cost("team", 5), Some("ghost"), Some(b"ghost"), 0);
        // Disabled: the key's group is frozen (`enabled: false`).
        faithful_case(
            &|| disabled_group_cost("frozen"),
            Some("frozen"),
            Some(b"frozen"),
            0,
        );
        // Limit: a 5c total cap at 1c/request → the 6th request blocks after draining 5.
        faithful_case(&|| group_cost("team", 5), Some("team"), Some(b"team"), 5);
    }

    /// A live admit through `govern_admit_reason` returns `Admit`, leaves `reason_len == 0`, and
    /// registers the RAII grant in the arena exactly as `govern_admit` does.
    #[test]
    fn govern_admit_reason_admits_and_registers_grant() {
        let gov = gov();
        let app = crate::test_support::TestApp::new()
            .governance(gov)
            .cost(group_cost("team", 5))
            .build();
        with_dispatch_scope(&app, |host, vt| {
            let facts = Facts::with_attribution(0, 0, 0, 0, 0, b"pool-x", b"vk_ok", Some(b"team"));
            let mut buf = [0u8; 64];
            let mut out = MaybeUninit::<GovRefusal>::uninit();
            let decision = (vt.govern_admit_reason.unwrap())(
                host,
                &*facts as *const Facts,
                buf.as_mut_ptr(),
                buf.len(),
                std::ptr::from_mut(&mut out),
            );
            assert_eq!(decision, Decision::Admit, "under the cap → admit");
            // SAFETY: the host always initializes `out`.
            assert_eq!(
                unsafe { out.assume_init() }.reason_len,
                0,
                "an admit renders no reason"
            );
            // SAFETY: live HostState from `with_dispatch_scope`.
            let state: &crate::plane_host::HostState = unsafe { crate::plane_host::recover(host) };
            assert_eq!(
                state.scope.registered(),
                1,
                "the RAII grant is registered in the arena"
            );
        });
    }

    /// THE METER FAITHFULNESS PROOF: charging a [`Usage`] carrying the REAL `(key_id, model, provider)`
    /// records the EXACT metering row the plane's own `record_metering(key_id, model, provider, ..)`
    /// does — so a direct record and a host charge COALESCE into ONE `(key_id, bucket, model,
    /// provider)` cell rather than two. A wrong attribution would leave two distinct cells.
    #[test]
    fn charge_over_usage_matches_record_metering() {
        let gov = gov();
        let now = crate::store::now_ms() / 1_000;
        // DIRECT: the plane's own metering row.
        gov.record_metering(
            "vk_faithful_meter",
            "tool:fs",
            "plane:mcp",
            Some(&crate::billing::TokenUsage {
                input: 100,
                ..Default::default()
            }),
            now,
        );
        // HOST: charge a Usage carrying the SAME (key_id, model, provider).
        let app = crate::test_support::TestApp::new()
            .governance(Arc::clone(&gov))
            .build();
        with_dispatch_scope(&app, |host, vt| {
            let usage = Usage::with_attribution(
                UsageComponent::Tokens,
                100,
                1,
                AdmissionId(7),
                b"vk_faithful_meter",
                b"tool:fs",
                b"plane:mcp",
            );
            assert_eq!(
                (vt.meter_charge.unwrap())(host, &*usage as *const Usage),
                MeterOutcome::Charged
            );
        });
        // The two accruals coalesced into ONE cell (same attribution key) with summed counts.
        let (cells, counts) = gov.pending_metering_totals();
        assert_eq!(
            cells, 1,
            "direct + host recorded the SAME (key_id, model, provider) cell"
        );
        assert_eq!(counts.requests, 2, "both accruals counted");
        assert_eq!(
            counts.tokens_input, 200,
            "100 direct + 100 host input tokens"
        );
    }

    /// A [`Usage`] WITHOUT the attribution tail (`Usage::charge`) still records against the synthetic
    /// admission-derived attribution — the pre-enrichment fallback is unchanged.
    #[test]
    fn charge_without_attribution_falls_back_to_synth() {
        let gov = gov();
        let app = crate::test_support::TestApp::new()
            .governance(Arc::clone(&gov))
            .build();
        with_dispatch_scope(&app, |host, vt| {
            let usage = Usage::charge(UsageComponent::Tokens, 10, 1, AdmissionId(99));
            assert_eq!(
                (vt.meter_charge.unwrap())(host, &*usage as *const Usage),
                MeterOutcome::Charged
            );
        });
        let (cells, counts) = gov.pending_metering_totals();
        assert_eq!(cells, 1, "one synthetic cell recorded");
        assert_eq!(counts.requests, 1);
        // The synthetic key is `plane:admission:99`, distinct from any real id.
    }
}
