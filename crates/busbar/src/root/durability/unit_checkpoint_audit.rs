// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Restart settlement uses captured host facts and the privileged recovery lane. It never
//! recreates a request admission, reservation, or fee, and never reuses an unverified audit pass.

use busbar_contract::caps::{Abort, OriginKind, Outcome, ReasonCode, StepName, UnitKey};
use busbar_contract::records::{RecordStoreError, RecordStoreResult};
use busbar_kernel::governance::unit_checkpoint::UnitCheckpoint;
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

fn find_record(
    book: &Arc<Mutex<Durability>>,
    unit: u64,
    incarnation: u64,
) -> RecordStoreResult<
    Option<(
        busbar_kernel_wal::JournalRecord,
        busbar_kernel_audit::AuditRecord,
    )>,
> {
    fn find(
        records: Vec<busbar_kernel_wal::JournalRecord>,
        unit: u64,
        incarnation: u64,
    ) -> RecordStoreResult<
        Option<(
            busbar_kernel_wal::JournalRecord,
            busbar_kernel_audit::AuditRecord,
        )>,
    > {
        for record in records {
            if let Some(audit) = super::decode_audit(&record).map_err(error)? {
                if audit.what.unit_key.get() == unit && audit.what.incarnation == incarnation {
                    return Ok(Some((record, audit)));
                }
            }
        }
        Ok(None)
    }
    // The bounded live journal tail handles the usual terminal ACK without scanning history.
    let recent = book
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .journal
        .replay()
        .map_err(error)?
        .map_err(error)?;
    if let Some(found) = find(recent, unit, incarnation)? {
        return Ok(Some(found));
    }
    // Crash recovery and old pending terminals prove identity against retained Store records.
    let chain = book.lock().unwrap_or_else(|p| p.into_inner()).chain_at();
    let chain = chain.read().map_err(error)?.map_err(error)?;
    find(chain, unit, incarnation)
}

/// A live terminal cannot retire its money head ahead of the root's one fixed audit line.
/// Returning an error keeps the exact terminal raw operation IDs for the next flush or restart.
pub(super) fn confirm(
    book: &Arc<Mutex<Durability>>,
    snapshot: &UnitCheckpoint,
) -> RecordStoreResult<()> {
    let facts: RunningAudit = serde_json::from_slice(
        snapshot
            .audit
            .as_deref()
            .ok_or_else(|| error("terminal unit lacks captured admission audit facts"))?,
    )
    .map_err(error)?;
    if let Some((record, audit)) = find_record(book, snapshot.unit, facts.incarnation)? {
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
        let lane = book
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .lane()
            .cloned()
            .ok_or_else(|| error("terminal audit has no Store lane"))?;
        if !lane.drain(super::store_chain::ACK_DEADLINE) {
            return Err(error("terminal unit audit awaits Store custody"));
        }
        return super::store_chain::confirm_record_bytes(
            lane.calls().as_ref(),
            &busbar_kernel_wal::Record::new(record.node, record.node_seq, record.encode()),
        )
        .map_err(error);
    }
    Err(error("terminal unit awaits its sealed audit line"))
}

pub(super) fn recover(
    book: &Arc<Mutex<Durability>>,
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
    if let Some((record, audit)) = find_record(book, snapshot.unit, facts.incarnation)? {
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
        let lane = book
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .lane()
            .cloned()
            .ok_or_else(|| error("recovered audit has no Store lane"))?;
        if !lane.drain(super::store_chain::ACK_DEADLINE) {
            return Err(error(
                "recovered unit audit is still awaiting Store custody",
            ));
        }
        super::store_chain::confirm_record_bytes(
            lane.calls().as_ref(),
            &busbar_kernel_wal::Record::new(record.node, record.node_seq, record.encode()),
        )
        .map_err(error)?;
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
    let lane = {
        let mut book = book.lock().unwrap_or_else(|p| p.into_inner());
        let record = book
            .record
            .seal(inputs, &busbar_kernel::teller::verb_audit_pass(&kernel));
        let entry = super::audit_entry(&record).map_err(error)?;
        book.journal
            .append(&kernel.durability_token(), StepName::Audit, &[entry])
            .map_err(|_| error("recovered unit audit awaits Store custody"))?;
        if record.key_id.is_some() && book.audit_signed_from.is_none() {
            book.audit_signed_from = Some(record.seq);
        }
        book.audit_records.push(record);
        if book.audit_records.len() > AUDIT_RING {
            book.audit_records.remove(0);
        }
        book.lane()
            .cloned()
            .ok_or_else(|| error("recovered audit has no Store lane"))?
    };
    if !lane.drain(super::store_chain::ACK_DEADLINE) {
        return Err(error("recovered unit audit has not reached Store custody"));
    }
    Ok(())
}
