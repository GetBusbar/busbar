// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Map the final captured checkpoint into signed audit evidence without repricing its facts.
use busbar_kernel::governance::unit_checkpoint::partitions as raw;
use busbar_kernel_audit::record::billing as audit;

pub(crate) fn selected_billing(
    view: &raw::ValidatedSelectedCheckpoint<'_>,
) -> Result<audit::PartitionedBillingV1, String> {
    let projection = view.project().map_err(|e| e.to_string())?;
    let source = view.usage();
    let fee_state = match &projection.fee {
        raw::CapturedFee::NotOwner { .. } => audit::FeeState::NotOwner,
        raw::CapturedFee::PendingOwner { .. } => return Err("selected fee is still pending".into()),
        raw::CapturedFee::ResolvedOwner {
            result: raw::FeeResult::Charged,
            ..
        } => audit::FeeState::Charged,
        raw::CapturedFee::ResolvedOwner {
            result: raw::FeeResult::Refunded,
            ..
        } => audit::FeeState::Refunded,
        raw::CapturedFee::RecoveredUnknown { .. } => audit::FeeState::Unknown,
    };
    let disposition = match projection.disposition {
        raw::Disposition::Running => {
            return Err("running checkpoint is not a terminal audit".into())
        }
        raw::Disposition::End => audit::BillingDisposition::End,
        raw::Disposition::Failed => audit::BillingDisposition::Failed,
        raw::Disposition::Cancel { reason } => {
            audit::BillingDisposition::Cancel(reason.as_str().to_owned())
        }
        raw::Disposition::RecoveredRunning => audit::BillingDisposition::RecoveredRunning,
    };
    let mut partitions = Vec::with_capacity(projection.partitions.len());
    for part in &projection.partitions {
        let (scope, kind, original) = match part.scope {
            raw::PartitionScope::Session => (
                audit::PartitionScope::Session,
                audit::TargetKind::Session,
                source
                    .session
                    .as_ref()
                    .ok_or("projected session has no source")?,
            ),
            raw::PartitionScope::Attempt {
                preparation,
                dispatch,
            } => {
                let attempt = source
                    .attempts
                    .iter()
                    .find(|a| a.preparation == preparation)
                    .ok_or("projected preparation has no source")?;
                if attempt.dispatch != dispatch {
                    return Err("projected dispatch changed identity".into());
                }
                let kind = match attempt.kind {
                    raw::TargetKind::Model => audit::TargetKind::Model,
                    raw::TargetKind::Registration => audit::TargetKind::Registration,
                };
                (
                    audit::PartitionScope::Attempt {
                        preparation,
                        dispatch,
                    },
                    kind,
                    &attempt.usage,
                )
            }
        };
        if original
            .classes
            .keys()
            .any(|name| !part.classes.contains_key(name))
        {
            return Err("class projection lost source facts".into());
        }
        let mut classes = std::collections::BTreeMap::new();
        for (name, value) in &part.classes {
            if !source.declared_classes.contains(name) {
                return Err("projected undeclared class".into());
            }
            // Projection includes every class owned by this scope. Absence of a raw report is
            // unknown, including a preparation that never sent; it is not a known zero.
            let unknown = raw::ClassFacts::default();
            let original = original.classes.get(name).unwrap_or(&unknown);
            classes.insert(
                name.as_str().to_owned(),
                audit::BillingClass {
                    reported: original.reported,
                    floor: original.floor,
                    estimated: original.estimated,
                    selected: value.selected.map(quantity),
                    billed: value.billed.map(quantity),
                    rate_high_water: value.rate_high_water,
                },
            );
        }
        partitions.push(audit::BillingPartition {
            scope,
            kind,
            // The signed audit record owns its names: one copy of each, as before.
            instance: part.identity.instance.as_str().to_owned(),
            lane: part.identity.lane.as_str().to_owned(),
            provider: part.identity.provider.as_deref().map(str::to_owned),
            selected_pool: part.identity.selected_pool.as_deref().map(str::to_owned),
            resource: part.identity.resource.as_deref().map(str::to_owned),
            transport: part.transport.map(|t| match t {
                raw::Transport::Prepared => audit::Transport::Prepared,
                raw::Transport::Committed => audit::Transport::Committed,
                raw::Transport::NoSend => audit::Transport::NoSend,
            }),
            finality: match part.finality {
                raw::Finality::Live => return Err("live source finality cannot be frozen".into()),
                raw::Finality::Complete => audit::Finality::Complete,
                raw::Finality::Partial => audit::Finality::Partial,
                raw::Finality::Unknown => audit::Finality::Unknown,
            },
            classes,
        });
    }
    let basis = projection.fee.basis();
    audit::PartitionedBillingV1::new(audit::BillingFacts {
        revision: projection.common.revision,
        request_pool: projection.common.request_pool.as_str().to_owned(),
        routing_generation: projection.common.routing_generation,
        era: era(projection.common.era),
        session_origin: audit::SessionOrigin {
            instance: projection.session_origin.instance.as_str().to_owned(),
            lane: projection.session_origin.lane.as_str().to_owned(),
            provider: projection
                .session_origin
                .provider
                .as_deref()
                .map(str::to_owned),
        },
        logical_request: match projection.logical_request.map(|m| m.identity) {
            None => audit::LogicalRequest::None,
            Some(raw::LogicalMeterIdentity::HostOrigin) => audit::LogicalRequest::HostOrigin,
            Some(raw::LogicalMeterIdentity::DeliveredPreparation(n)) => {
                audit::LogicalRequest::DeliveredPreparation(n)
            }
        },
        fee: audit::LogicalFee {
            state: fee_state,
            lane: basis.lane.clone(),
            era: era(basis.era),
        },
        disposition,
        far_end_answered: source.far_end_answered,
        caller_bytes_committed: source.caller_bytes_committed,
        final_target: source.final_target,
        partitions,
    })
    .map_err(|e| e.to_string())
}

fn era(value: busbar_kernel_ledger::cost::RawRateEra) -> audit::BillingEra {
    audit::BillingEra {
        effective_from: value.effective_from,
        entry_id: value.entry_id.map(|id| id.0),
    }
}
fn quantity(value: raw::SelectedQuantity) -> audit::SelectedQuantity {
    audit::SelectedQuantity {
        count: value.count,
        source: match value.source {
            raw::UsageSource::Reported => audit::UsageSource::Reported,
            raw::UsageSource::Floor => audit::UsageSource::Floor,
            raw::UsageSource::Estimated => audit::UsageSource::Estimated,
        },
    }
}
