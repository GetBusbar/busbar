// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The GOVERNANCE family of the plane host, over core's REAL primitives: the refusal-fidelity
//! admission (the RAII [`AdmitGrant`](crate::governance::AdmitGrant) registered in the dispatch
//! arena) and the metering charge (the write-behind metering time-series and the keyed-unit ledger).
//!
//! These are the BODIES the host's [`AdmissionHost`](super::AdmissionHost) and
//! [`BudgetHost`](super::BudgetHost) methods call; the caller owns the panic boundary.
//!
//! ## Whose identity
//!
//! What a plane hands over ([`MeterUsage`](super::MeterUsage), a pool name) carries the SHAPE of a
//! request, never who it is for: admission and billing resolve the caller from the [`HostState`]
//! the HOST built ([`HostState`]'s caller, stamped from the auth middleware's context — DEC-SERVE
//! G1/G1b).

use super::{HostState, MeterUsage, UsageComponent};
use crate::governance::{AdmitGrant, LimitBlocked};

/// The unattributed model/provider a metering row is recorded under until Phase 2 resolves the real
/// attribution from the request. Kept explicit (not `""`) so a stray row is legible in the store.
const MODEL_UNATTRIBUTED: &str = "plane:unattributed";
const PROVIDER_UNATTRIBUTED: &str = "plane:unattributed";

/// THE SYNTHETIC ADMISSION KEY (DEC-SERVE G1b): the ungrouped key an admission with NO caller admits
/// as — `plane:tenant:<tenant>`, the tenant being [`UNNAMED_TENANT`]. Never a key a plane named.
pub(super) const SYNTH_TENANT_KEY: &str = "plane:tenant:";

/// The tenant an admission with no caller is keyed under: no plane names one.
const UNNAMED_TENANT: u64 = 0;

/// THE SYNTHETIC BILLING KEY (DEC-SERVE G1b): the key a charge with NO caller bills —
/// `plane:admission:<MeterUsage.admission>`. Never a key a plane named.
pub(super) const SYNTH_ADMISSION_KEY: &str = "plane:admission:";

/// Drive the real `GovState::try_admit` limit engine for `pool` and hand back its RAII grant, or the
/// real [`LimitBlocked`](crate::governance::LimitBlocked) the chain engine yielded. When governance
/// is disabled this is an enforcement no-op that still returns a real — empty — grant so the arena
/// path is uniform.
fn grant_for_blocked(state: &HostState, pool: &[u8]) -> Result<AdmitGrant, LimitBlocked> {
    let Some(gov) = state.app.governance.as_ref() else {
        return Ok(AdmitGrant::default());
    };
    let pool = String::from_utf8_lossy(pool);
    // WHO IS ADMITTED (DEC-SERVE G1b, #65/#40): the caller stamped from the auth context — its real
    // key, whose `id` + `group` are all `try_admit`/`chain_for` read. No caller: the named synthetic
    // ungrouped key.
    let synth;
    let key = match &state.caller {
        Some(caller) => caller.key(),
        None => {
            synth = virtual_key(format!("{SYNTH_TENANT_KEY}{UNNAMED_TENANT}"), None);
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
    /// The rendered reason bytes.
    pub(super) reason: String,
    /// The recovery floor in whole seconds (`0` when the block does not self-recover / never rolls).
    pub(super) retry_after_secs: u64,
}

/// Admit one unit of work on `pool`: the real `try_admit` chain, REGISTERING the RAII grant in the
/// dispatch arena on success; a blocked limit returns the RENDERED [`GovBlocked`] reason. `Ok(())` =
/// admitted (grant registered); `Err(blocked)` = refused with the reason to surface.
pub(super) fn admit_reason(state: &HostState, pool: &[u8]) -> Result<(), GovBlocked> {
    match grant_for_blocked(state, pool) {
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
            // BYTE-IDENTICAL to the mcp `charge_round`'s `Err(format!("{blocked:?}"))`: the plane
            // cannot hold `LimitBlocked`, so the host renders the SAME Debug bytes.
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
// meter_charge — the write-behind metering time-series + the keyed-unit ledger.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Charge a [`MeterUsage`] through the real metering path: accrue its COUNTS into the write-behind
/// metering time-series. A plane names counts, never a price (#43/#71; the plane-side
/// `unit_cost_micros` price was retired by KERNEL<>PLUGINS step 16, item 577), so nothing is priced
/// here.
pub(super) fn charge(state: &HostState, usage: &MeterUsage) {
    // THE LEDGER WRITE IS UNCONDITIONAL (DECISION #43, owner ruling 2026-09-22: "planes always
    // ledger"). The plane's counts are appended whether or not a `rate_card:` is configured: the card
    // decides only whether a READ can turn counts into money (#42 — billing off means the money VIEW
    // reads 0), never whether the write happens.
    if let Some(gov) = state.app.governance.as_ref() {
        // WHO PAYS (DEC-SERVE G1/G1b, #65/#40): the caller stamped from the auth context is the ONLY
        // key billed. No caller: the named synthetic key.
        let synth;
        let key = match &state.caller {
            Some(caller) => caller.key(),
            None => {
                synth = virtual_key(format!("{SYNTH_ADMISSION_KEY}{}", usage.admission.0), None);
                &synth
            }
        };
        let (model, provider) = match &usage.attribution {
            Some(a) => (a.model.to_string(), a.provider.to_string()),
            None => (
                MODEL_UNATTRIBUTED.to_string(),
                PROVIDER_UNATTRIBUTED.to_string(),
            ),
        };
        let token_usage = token_usage_for(usage.component, usage.amount);
        let now = busbar_kernel::store::now_ms() / 1_000;
        gov.record_metering(&key.id, &model, &provider, token_usage.as_ref(), now);
        // ITEM 123 (#71): every class the plane counted, reserved and open, lands in the enforcement
        // ledger VERBATIM for the attributed key; the card prices it.
        if !usage.units.is_empty() {
            gov.record_usage(&state.app.cost, key, "", &model, usage.units, now);
        }
    }
}

/// Project a usage onto a [`TokenUsage`](crate::billing::TokenUsage) — the shape metering accrual
/// counts — only when the component is `Tokens`. Other components (bytes / frames / queries) record a
/// request with no token counts (`None`), which is faithful: the metering time-series counts tokens.
fn token_usage_for(component: UsageComponent, amount: u64) -> Option<crate::billing::TokenUsage> {
    match component {
        UsageComponent::Tokens => Some(crate::billing::TokenUsage {
            input: amount,
            ..Default::default()
        }),
        UsageComponent::Bytes | UsageComponent::Frames | UsageComponent::Queries => None,
    }
}

#[cfg(test)]
#[path = "tests/govern_tests.rs"]
mod tests;
