// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::records::{PlaneDisposition, PlaneRecordRef, RecordStore};
use serde::{Deserialize, Serialize};

const KIND: &str = "busbar.admin-adjust-action.v1";

/// Safe durable projection. The explanation is hashed, never stored as public free text.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    operation_id: String,
    actor: String,
    target: String,
    fingerprint: String,
    reason_hash: String,
    effect: String,
    status: u16,
}

fn answer(receipt: &Receipt) -> Result<AdminAnswer, GovernanceError> {
    let mut response = super::super::json_answer(
        serde_json::to_vec(&serde_json::json!({
            "operation_id": receipt.operation_id,
            "operation": "adjust",
            "actor": receipt.actor,
            "target": receipt.target,
            "fingerprint": receipt.fingerprint,
            "reason_hash": receipt.reason_hash,
            "effect": receipt.effect,
            "applied": receipt.effect == "applied",
            "retry": "same_action_only",
            "recovery": if receipt.effect == "unknown" { "reconcile_ledger_recovery" } else { "receipt" },
            "count_scale": busbar_contract::count::COUNT_SCALE
        }))
        .map_err(|_| GovernanceError::Store)?,
    );
    response.status = receipt.status;
    response
        .headers
        .push(("x-busbar-adjust-effect".into(), receipt.effect.clone()));
    Ok(response)
}

fn keep(store: &dyn RecordStore, receipt: &Receipt, now: u64) -> Result<(), GovernanceError> {
    let body = serde_json::to_vec(receipt).map_err(|_| GovernanceError::Store)?;
    store
        .upsert_plane_record(PlaneRecordRef {
            kind: KIND,
            id: &receipt.operation_id,
            parent: Some(&receipt.actor),
            seq: 0,
            ts: now,
            // Action identities are not recycled by the ten-minute credential replay sweep.
            disposition: PlaneDisposition::Active,
            body: &body,
        })
        .map_err(|_| GovernanceError::Store)
}

/// The header selects an additive exact-Count profile. A token is claimed permanently before
/// the effect. Crash/settlement loss leaves an unknown receipt; it never authorizes another delta.
pub(crate) fn adjust_request(
    unit: &super::super::AdminRequest,
    body: &[u8],
    scope: busbar_contract::authz::Scope,
    actor: &str,
    store: Option<&super::super::bound::ReplayStore>,
    pool_known: &dyn Fn(&str) -> bool,
    adjuster: &UsageAdjuster,
) -> Result<AdminAnswer, GovernanceError> {
    if scope != busbar_contract::authz::Scope::Full {
        return Err(GovernanceError::Validation);
    }
    let keys: Vec<_> = unit
        .headers
        .iter()
        .filter(|(name, _)| name == "idempotency-key")
        .collect();
    let Some((_, action)) = keys.first() else {
        return adjust_effect(body, scope, pool_known, adjuster);
    };
    if keys.len() != 1
        || action.is_empty()
        || action.len() > 128
        || !action.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(GovernanceError::Validation);
    }
    let store = store.and_then(|get| get()).ok_or(GovernanceError::Store)?;
    let operation_id = busbar_contract::redacted::sha256_hex(
        format!("adjust:{}:{actor}:{}:{action}", actor.len(), action.len()).as_bytes(),
    );
    let fingerprint = busbar_contract::redacted::sha256_hex(body);
    let read = || -> Result<Option<Receipt>, GovernanceError> {
        store
            .get_plane_record(KIND, &operation_id)
            .map_err(|_| GovernanceError::Store)?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| GovernanceError::Store))
            .transpose()
    };
    let replay = |receipt: Receipt| {
        if receipt.actor != actor || receipt.fingerprint != fingerprint {
            return Ok(super::super::error_answer_with_message(
                409,
                "idempotency_mismatch",
                "Idempotency-Key is bound to different exact request bytes",
            ));
        }
        answer(&receipt)
    };
    if let Some(receipt) = read()? {
        return replay(receipt);
    }
    let mut correction = parse_correction(body, pool_known, true)?;
    correction.action_id = Some(operation_id.clone());
    let doc: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| GovernanceError::Validation)?;
    let reason = doc["reason"].as_str().ok_or(GovernanceError::Validation)?;
    let mut receipt = Receipt {
        operation_id: operation_id.clone(),
        actor: actor.into(),
        target: correction.key.clone(),
        fingerprint: fingerprint.clone(),
        reason_hash: busbar_contract::redacted::sha256_hex(reason.as_bytes()),
        effect: "unknown".into(),
        status: 409,
    };
    if !store
        .redeem_plane_token(KIND, &operation_id, u64::MAX, unit.at)
        .map_err(|_| GovernanceError::Store)?
    {
        if let Some(receipt) = read()? {
            return replay(receipt);
        }
        // The claim may have crashed before persisting its binding. No effect may be retried.
        let mut response = super::super::json_answer(serde_json::to_vec(&serde_json::json!({
            "error": { "code": "action_in_flight", "message": "The action is in flight or requires recovery" },
            "operation_id": operation_id, "effect": "unknown", "recovery": "reconcile_ledger_recovery"
        })).map_err(|_| GovernanceError::Store)?);
        response.status = 409;
        response
            .headers
            .push(("x-busbar-adjust-effect".into(), "unknown".into()));
        return Ok(response);
    }
    keep(&*store, &receipt, unit.at)?;
    match apply_correction(correction, adjuster) {
        Ok(applied) if applied.status == 200 => {
            receipt.effect = "applied".into();
            receipt.status = 200;
        }
        Ok(refused) => {
            receipt.effect = "not_applied".into();
            receipt.status = refused.status;
        }
        Err(
            GovernanceError::NotFound | GovernanceError::Validation | GovernanceError::Conflict,
        ) => {
            receipt.effect = "not_applied".into();
            receipt.status = 400;
        }
        Err(GovernanceError::Store) => {}
    }
    if keep(&*store, &receipt, unit.at).is_err() {
        // The effect is known in this process, even if receipt settlement needs reconciliation.
        // Subsequent processes see the pre-effect unknown receipt and cannot apply twice.
        let mut response = answer(&receipt)?;
        response
            .headers
            .push(("x-busbar-receipt-durable".into(), "false".into()));
        return Ok(response);
    }
    answer(&receipt)
}

#[cfg(test)]
#[path = "tests/adjust_action_tests.rs"]
mod tests;
