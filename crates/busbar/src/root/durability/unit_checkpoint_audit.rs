// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Restart settlement uses captured host facts and the privileged recovery lane. It never
//! recreates a request admission, reservation, or fee, and never reuses an unverified audit pass.

use busbar_contract::caps::{Abort, OriginKind, Outcome, ReasonCode, UnitKey};
use busbar_contract::records::{RecordStoreError, RecordStoreResult};
use busbar_kernel::governance::unit_checkpoint::UnitCheckpoint;
use busbar_kernel::governance::unit_checkpoint_store::UnitCheckpointEvidence;
use busbar_kernel::persistence::journal::runtime::Carried;
use busbar_kernel_audit::{
    AuditInputs, Controls, FinishClass, HookApplied, HookHead, OpClassId, OutcomeFacts, Subject,
    Usage, UsageLine, What,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

use super::Durability;

/// Captured only by NodeEndPost from the actual unit and its pinned host state. The outer
/// unit.accrued signature binds these facts to the admitted money snapshot and original identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunningAudit {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_identity: Option<SelectedAuditIdentity>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SelectedAuditIdentity {
    pub node: u64,
    pub boot_nonce: [u8; 16],
    pub user: Option<String>,
    pub labels: Vec<(String, String)>,
}

fn error(message: impl ToString) -> RecordStoreError {
    RecordStoreError(message.to_string())
}

fn selected_billing(
    snapshot: &UnitCheckpoint,
) -> RecordStoreResult<Option<busbar_kernel_audit::record::billing::PartitionedBillingV1>> {
    if snapshot.partitions.is_none() {
        return Ok(None);
    }
    let view = busbar_kernel::governance::unit_checkpoint::partitions::ValidatedSelectedCheckpoint::try_from(snapshot)?;
    crate::root::selected_report::selected_billing(&view)
        .map(Some)
        .map_err(error)
}

fn selected_matches(
    snapshot: &UnitCheckpoint,
    facts: &RunningAudit,
    audit: &busbar_kernel_audit::AuditRecord,
) -> RecordStoreResult<()> {
    let Some(expected) = selected_billing(snapshot)? else {
        return Ok(());
    };
    let identity = facts
        .selected_identity
        .as_ref()
        .ok_or_else(|| error("selected checkpoint lacks original audit identity"))?;
    let labels: Vec<_> = audit
        .unit
        .records
        .labels
        .iter()
        .map(|(key, value)| (key.to_string(), value.clone()))
        .collect();
    if audit.node != identity.node
        || audit.unit.boot_nonce != identity.boot_nonce
        || audit.what.unit_key.get() != snapshot.unit
        || audit.what.incarnation != facts.incarnation
        || audit.wall != facts.wall
        || audit.mono != facts.mono
        || audit.unit.records.user != identity.user
        || labels != identity.labels
        || audit.unit.billing.as_ref() != Some(&expected)
        || !audit.usage.lines.is_empty()
        || audit.usage.fee_count != expected.fee_count()
        || audit.usage.rate_card_version != facts.rate_card
    {
        return Err(error(
            "selected audit differs from exact captured terminal evidence",
        ));
    }
    Ok(())
}

/// A live terminal cannot retire its money head ahead of the root's one fixed audit line.
/// Returning an error keeps the exact terminal raw operation IDs for the next flush or restart.
pub(super) async fn confirm(
    book: &Arc<Mutex<Durability>>,
    evidence: &UnitCheckpointEvidence,
    snapshot: &UnitCheckpoint,
    hint: Option<Carried>,
) -> RecordStoreResult<()> {
    let facts: RunningAudit = busbar_contract::json::parse(
        snapshot
            .audit
            .as_deref()
            .ok_or_else(|| error("terminal unit lacks captured admission audit facts"))?,
    )
    .map_err(error)?;
    // A line this process sealed is read once, by the evidence carried from its seal
    // (SHUTDOWN-HANG F1a); only a unit with no hint takes the journal scan.
    let found = match hint {
        Some(line) => {
            let audit = evidence.find_audit_at(line).await?;
            if audit.what.unit_key.get() != snapshot.unit
                || audit.what.incarnation != facts.incarnation
            {
                return Err(error("terminal unit's audit hint names another unit"));
            }
            Some(audit)
        }
        None => evidence
            .find_audit(snapshot.unit, facts.incarnation)
            .await?
            .map(|(_, audit)| audit),
    };
    if let Some(audit) = found {
        selected_matches(snapshot, &facts, &audit)?;
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
    let facts: RunningAudit = busbar_contract::json::parse(encoded).map_err(error)?;
    if facts.principal != snapshot.principal || facts.op_class.is_empty() {
        return Err(error(
            "running money audit identity differs from its admitted principal",
        ));
    }
    if let Some((_node_seq, audit)) = evidence
        .find_audit(snapshot.unit, facts.incarnation)
        .await?
    {
        selected_matches(snapshot, &facts, &audit)?;
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
    if let Some((_node_seq, pending)) = evidence.pending_audit(snapshot.unit, facts.incarnation) {
        selected_matches(snapshot, &facts, &pending)?;
        if pending.subject != Subject::PrincipalId(snapshot.principal.clone())
            || pending.what.op_class.as_str() != facts.op_class
        {
            return Err(error("pending recovered audit identity differs"));
        }
        let node_seq = evidence.append_audit(pending.clone()).await?;
        publish(book, pending, node_seq);
        return Ok(());
    }
    let billing = selected_billing(snapshot)?;
    if billing.is_some() && facts.selected_identity.is_none() {
        return Err(error(
            "selected recovery lacks captured node, boot and record identity",
        ));
    }
    let captured_node = facts
        .selected_identity
        .as_ref()
        .map(|identity| identity.node);
    let current_node = book.lock().unwrap_or_else(|p| p.into_inner()).record.node();
    if billing.is_some() && captured_node != Some(current_node) {
        return Err(error("selected recovery belongs to another node"));
    }
    let fee_count = billing.as_ref().map_or(0, |billing| billing.fee_count());
    let records = facts
        .selected_identity
        .as_ref()
        .filter(|_| billing.is_some())
        .map(|identity| busbar_kernel_audit::RecordFacts {
            user: identity.user.clone(),
            labels: identity
                .labels
                .iter()
                .map(|(key, value)| (Arc::<str>::from(key.as_str()), value.clone()))
                .collect(),
        })
        .unwrap_or_default();
    let boot_nonce = facts
        .selected_identity
        .as_ref()
        .filter(|_| billing.is_some())
        .map_or([0; 16], |identity| identity.boot_nonce);
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
            fee_count,
            rate_card_version: facts.rate_card,
            bucket_chain_ref: String::new(),
        },
        controls: Controls {
            policy_epoch: facts.policy_epoch,
            hooks_applied: hooks,
            ..Controls::default()
        },
        correlation_label: None,
        // A recovered unit ran in a predecessor process: its nonce is not this one's, so none is
        // sealed (no unit id), and its pool was not checkpointed.
        unit: busbar_kernel_audit::UnitFacts {
            billing,
            boot_nonce,
            records,
            attribution: busbar_kernel_audit::attribution(
                &snapshot.group,
                "",
                snapshot.provider.as_deref().unwrap_or_default(),
            ),
            ..busbar_kernel_audit::UnitFacts::at(facts.wall.saturating_mul(1_000))
        },
    };
    // Today's order is kept (SEALING-FIX §3.5): link under the lock, append outside it, then
    // publish. The line is hashed before the lock and dated under it, just before `link`.
    let node = book.lock().unwrap_or_else(|p| p.into_inner()).record.node();
    let prepared = busbar_kernel_audit::AuditChain::prepare(inputs, node);
    let record = {
        let mut book = book.lock().unwrap_or_else(|p| p.into_inner());
        let linked_ms = busbar_kernel::store::now_ms();
        let linked = book.record.link(
            prepared,
            linked_ms,
            &busbar_kernel::teller::verb_audit_pass(&kernel),
        );
        book.record.advance(&linked);
        linked.into_record()
    };
    let node_seq = evidence.append_audit(record.clone()).await?;
    publish(book, record, node_seq);
    Ok(())
}

/// Push the recovered line to the ring once, and publish it to the notary's head cell only now
/// that `append_audit` succeeded, never moving the head back (SEALING-FIX §3.5).
fn publish(book: &Arc<Mutex<Durability>>, record: busbar_kernel_audit::AuditRecord, node_seq: u64) {
    let mut book = book.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(fp) = busbar_kernel_audit::Fingerprint::from_hex(&record.hash) {
        book.head
            .publish_max(&busbar_kernel::persistence::journal::head_cell::Head {
                seq: record.seq,
                node_seq,
                fp: fp.0,
                wall_ms: record.linked_ms,
            });
    }
    if record.key_id.is_some() && book.audit_signed_from.is_none() {
        book.audit_signed_from = Some(record.seq);
    }
    book.audit_ring.push_unique(record);
}
