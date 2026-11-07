// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Restart settlement uses captured host facts and the privileged recovery lane. It never
//! recreates a request admission, reservation, or fee, and never reuses an unverified audit pass.

use busbar_contract::caps::{Abort, OriginKind, Outcome, ReasonCode, UnitKey};
use busbar_contract::records::{RecordStoreError, RecordStoreResult};
use busbar_kernel::governance::unit_checkpoint::UnitCheckpoint;
use busbar_kernel::governance::unit_checkpoint_store::UnitCheckpointEvidence;
use busbar_kernel_audit::{
    Audit as _, AuditInputs, Controls, FinishClass, HookApplied, HookHead, OpClassId, OutcomeFacts,
    Subject, Usage, UsageLine, What,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

use super::{Durability, AUDIT_RING};

/// Captured only by NodeEndPost from the actual unit and its pinned host state. The outer
/// unit.accrued signature binds these facts to the admitted money snapshot and original identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunningAudit {
    pub incarnation: u64,
    pub principal: String,
    pub op_class: String,
    pub origin: String,
    pub parent: Option<u64>,
    pub wall: u64,
    pub mono: u64,
    pub destination: Option<String>,
    pub rate_card: Option<[u8; 20]>,
    pub policy_epoch: u64,
    pub hooks: Vec<(String, String, bool)>,
}

fn error(message: impl ToString) -> RecordStoreError {
    RecordStoreError(message.to_string())
}

/// A live terminal cannot retire its money head ahead of the root's one fixed audit line.
/// Returning an error keeps the exact terminal raw operation IDs for the next flush or restart.
pub(super) async fn confirm(
    book: &Arc<Mutex<Durability>>,
    evidence: &UnitCheckpointEvidence,
    snapshot: &UnitCheckpoint,
) -> RecordStoreResult<()> {
    let facts: RunningAudit = serde_json::from_slice(
        snapshot
            .audit
            .as_deref()
            .ok_or_else(|| error("terminal unit lacks captured admission audit facts"))?,
    )
    .map_err(error)?;
    if let Some(audit) = evidence
        .find_audit(snapshot.unit, facts.incarnation)
        .await?
    {
        if audit.subject != Subject::PrincipalId(snapshot.principal.clone())
            || audit.what.op_class.as_str() != facts.op_class
        {
            return Err(error("terminal unit's sealed audit identity differs"));
        }
        let keys = super::keyset_of(&book.lock().unwrap_or_else(|p| p.into_inner()).record);
        let key = audit
            .key_id
            .as_deref()
            .and_then(|id| keys.get(id))
            .ok_or_else(|| error("terminal unit audit is unsigned"))?;
        busbar_kernel_audit::AuditChain::verify_signature(&audit, key).map_err(error)?;
        return Ok(());
    }
    Err(error("terminal unit awaits its sealed audit line"))
}

pub(super) async fn recover(
    book: &Arc<Mutex<Durability>>,
    evidence: &UnitCheckpointEvidence,
    snapshot: &UnitCheckpoint,
) -> RecordStoreResult<()> {
    let Some(encoded) = &snapshot.audit else {
        return Err(error(
            "running money checkpoint lacks captured admission audit facts",
        ));
    };
    let facts: RunningAudit = serde_json::from_slice(encoded).map_err(error)?;
    if facts.principal != snapshot.principal || facts.op_class.is_empty() {
        return Err(error(
            "running money audit identity differs from its admitted principal",
        ));
    }
    if let Some(audit) = evidence
        .find_audit(snapshot.unit, facts.incarnation)
        .await?
    {
        if audit.subject != Subject::PrincipalId(snapshot.principal.clone())
            || audit.what.op_class.as_str() != facts.op_class
        {
            return Err(error(
                "recovered unit identity already has different audit facts",
            ));
        }
        let keys = super::keyset_of(&book.lock().unwrap_or_else(|p| p.into_inner()).record);
        let key = audit
            .key_id
            .as_deref()
            .and_then(|id| keys.get(id))
            .ok_or_else(|| error("recovered unit audit is unsigned"))?;
        busbar_kernel_audit::AuditChain::verify_signature(&audit, key).map_err(error)?;

        return Ok(());
    }
    if let Some(pending) = evidence.pending_audit(snapshot.unit, facts.incarnation) {
        if pending.subject != Subject::PrincipalId(snapshot.principal.clone())
            || pending.what.op_class.as_str() != facts.op_class
        {
            return Err(error("pending recovered audit identity differs"));
        }
        evidence.append_audit(pending.clone()).await?;
        publish(book, pending);
        return Ok(());
    }
    let parent = facts.parent.map(UnitKey::new);
    let origin = match facts.origin.as_str() {
        "client" => OriginKind::Client,
        "provider" => OriginKind::Provider,
        "tick" => OriginKind::Tick,
        "arrival" => OriginKind::Arrival,
        "handshake" => OriginKind::Handshake,
        "bootstrap" => OriginKind::Bootstrap,
        "nested" => OriginKind::Nested {
            parent: parent.ok_or_else(|| error("nested checkpoint lacks parent"))?,
        },
        "delivery" => OriginKind::Delivery {
            parent: parent.ok_or_else(|| error("delivery checkpoint lacks parent"))?,
        },
        _ => return Err(error("unknown checkpoint origin")),
    };
    let hooks: Vec<_> = facts
        .hooks
        .into_iter()
        .map(|(hook, head, failed)| {
            Ok(HookApplied {
                hook,
                head: HookHead::from_tag(&head)
                    .ok_or_else(|| error("unknown checkpoint hook head"))?,
                failed,
            })
        })
        .collect::<RecordStoreResult<_>>()?;
    let lines = snapshot
        .units
        .iter()
        .filter(|(_, count)| !count.is_zero())
        .map(|(class, count)| {
            Ok(UsageLine {
                class: busbar_kernel::Registration::meter_class(class)
                    .ok_or_else(|| error(format!("unregistered recovered meter class {class}")))?,
                quantity: *count,
                source: busbar_contract::caps::QuantitySource::Count,
                estimated: false,
            })
        })
        .collect::<RecordStoreResult<Vec<_>>>()?;
    let kernel = busbar_kernel::teller::Kernel::new();
    let outcome = Outcome::Aborted(Abort::Kernel {
        reason: ReasonCode::Drain,
    });
    let inputs = AuditInputs {
        subject: Subject::PrincipalId(snapshot.principal.clone()),
        what: What {
            unit_key: UnitKey::new(snapshot.unit),
            incarnation: facts.incarnation,
            op_class: OpClassId::new(facts.op_class),
            destination: facts.destination,
            parent,
            pre_hook_head: None,
            post_hook_head: None,
        },
        wall: facts.wall,
        mono: facts.mono,
        origin: kernel.origin(origin),
        outcome: OutcomeFacts {
            unit_end: outcome,
            step: outcome.step(),
            finish: FinishClass::Partial,
            hook_failed: hooks.iter().any(|hook| hook.failed),
            emission_delta: 0,
            stale_policy: false,
        },
        usage: Usage {
            lines,
            tier_bp: 10_000,
            fee_count: 0,
            rate_card_version: facts.rate_card,
            bucket_chain_ref: String::new(),
        },
        controls: Controls {
            policy_epoch: facts.policy_epoch,
            hooks_applied: hooks,
            ..Controls::default()
        },
        correlation_label: None,
    };
    let record = {
        let mut book = book.lock().unwrap_or_else(|p| p.into_inner());
        book.record
            .seal(inputs, &busbar_kernel::teller::verb_audit_pass(&kernel))
    };
    evidence.append_audit(record.clone()).await?;
    publish(book, record);
    Ok(())
}

fn publish(book: &Arc<Mutex<Durability>>, record: busbar_kernel_audit::AuditRecord) {
    let mut book = book.lock().unwrap_or_else(|p| p.into_inner());
    if record.key_id.is_some() && book.audit_signed_from.is_none() {
        book.audit_signed_from = Some(record.seq);
    }
    if !book
        .audit_records
        .iter()
        .any(|existing| existing == &record)
    {
        book.audit_records.push(record);
        if book.audit_records.len() > AUDIT_RING {
            book.audit_records.remove(0);
        }
    }
}
