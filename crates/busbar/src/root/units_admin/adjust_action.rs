// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::Secret;
use busbar_kernel::persistence::scoped::{ClaimOutcome, Outcome, ScopedStore};
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

async fn keep(store: &ScopedStore, receipt: &Receipt) -> Result<(), GovernanceError> {
    let body = serde_json::to_vec(receipt).map_err(|_| GovernanceError::Store)?;
    match store
        .put(KIND, receipt.operation_id.as_bytes(), Secret::new(body))
        .await
    {
        Ok(Outcome::Applied) => Ok(()),
        // Unconfirmed native writes retain their exact candidate in CoreStore.
        // Never run the additive effect before the unknown binding is durable.
        _ => Err(GovernanceError::Store),
    }
}

async fn read(store: &ScopedStore, operation_id: &str) -> Result<Option<Receipt>, GovernanceError> {
    store
        .get(KIND, operation_id.as_bytes())
        .await
        .map_err(|_| GovernanceError::Store)?
        .map(|bytes| {
            serde_json::from_slice(bytes.expose(&busbar_kernel::seal::lend()))
                .map_err(|_| GovernanceError::Store)
        })
        .transpose()
}

/// The header selects an additive exact-Count profile. A token is claimed permanently before
/// the effect. Crash/settlement loss leaves an unknown receipt; it never authorizes another delta.
pub(crate) async fn adjust_request(
    unit: &super::super::AdminRequest,
    body: &[u8],
    scope: busbar_contract::authz::Scope,
    actor: &str,
    store: Option<&super::super::bound::ReplayStore>,
    pool_known: &(dyn Fn(&str) -> bool + Sync),
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
        return adjust_effect(body, scope, pool_known, adjuster).await;
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
    if let Some(receipt) = read(&store, &operation_id).await? {
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
    let claimed = store
        .redeem(KIND, &operation_id, u64::MAX)
        .await
        .map_err(|_| GovernanceError::Store)?;
    if !matches!(claimed, ClaimOutcome::Claimed) {
        if let Some(receipt) = read(&store, &operation_id).await? {
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
    keep(&store, &receipt).await?;
    match apply_correction(correction, adjuster).await {
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
    if keep(&store, &receipt).await.is_err() {
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

#[cfg(test)]
#[path = "tests/adjust_staging_tests.rs"]
mod staging_tests;
