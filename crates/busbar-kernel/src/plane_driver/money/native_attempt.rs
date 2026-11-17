// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Linear input to the selected-resource governor. Selection and preparation minting remain
//! private to the money consumer; configuration metadata alone cannot authorize an attempt.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::governance::unit_checkpoint::partitions::{AttemptPartition, Finality, Transport};
use crate::governance::unit_checkpoint::UnitCheckpoint;
use crate::plane_driver::port_egress::SelectedWalkAttempt;
use crate::plane_driver::port_session::{PreparedExchange, RequestDeclaration};
use crate::plane_driver::request_admission::AdmittedRequest;

/// The book-accepted complete checkpoint is the runtime's single factual source as well.
/// Live selection/rate authority is separate and is never reconstructed from these facts.
pub(super) struct NativeMoney {
    accepted: Arc<UnitCheckpoint>,
    declaration: Option<RequestDeclaration>,
}

impl NativeMoney {
    /// Factual reader fixtures carry no live task/selection authority.
    #[cfg(test)]
    pub(super) fn from_accepted(accepted: Arc<UnitCheckpoint>) -> Self {
        Self {
            accepted,
            declaration: None,
        }
    }

    pub(super) fn admitted(accepted: Arc<UnitCheckpoint>, declaration: RequestDeclaration) -> Self {
        Self {
            accepted,
            declaration: Some(declaration),
        }
    }

    pub(super) fn checkpoint(&self) -> &Arc<UnitCheckpoint> {
        &self.accepted
    }
}

/// The original money service and admitted request, issued only after selected initial custody.
/// Runtime keeps this with the same allocation; there is no numeric-unit lookup constructor.
pub struct NativeRequestMoney {
    pub(super) money: Arc<super::PlaneMoney>,
    pub(super) request: AdmittedRequest,
}

impl NativeRequestMoney {
    pub fn request(&self) -> &AdmittedRequest {
        &self.request
    }
}
use busbar_plugin_abi::records::RecErr;
use busbar_ports::codec::fallback_usage::{
    AttemptEnd, AttemptState, AttemptUsage, Completeness, Declaration, UsageSource,
};

/// One prepared exchange under an actual request admission.
///
/// The governor moves this value through reservation, commit and refusal. It never copies the
/// request admission or reconstructs the exchange from its descriptive fields. In particular,
/// a refusal returns this same value only after releasing its own provisional rate cells.
///
/// There is deliberately no public or crate-wide constructor: the native money consumer must
/// check the live invocation, original Open identity and selected member before minting it.
/// Until that producer is integrated this input cannot activate selected-attempt dispatch.
pub(crate) struct PreparedRateAttempt {
    request: AdmittedRequest,
    selected: SelectedWalkAttempt,
    physical_classes: Box<[Box<str>]>,
    // Retain the whole validated preparation: its exchange cannot be paired with another
    // target/ordinal or a separately copied estimate/echo view.
    _prepared: PreparedExchange,
}

impl PreparedRateAttempt {
    /// The authenticated request payer captured by the original monetary admission.
    pub(crate) fn key_id(&self) -> &str {
        &self.request.key().id
    }

    pub(crate) fn instance(&self) -> &str {
        self.request.context().instance()
    }

    /// Absent only when the selected-policy resolver produces no resource rule rows.
    pub(crate) fn resource(&self) -> Option<&str> {
        self.selected.resource()
    }

    /// The frozen, validated physical class set; aggregates must not overlap its classes.
    pub(crate) fn physical_classes(&self) -> &[Box<str>] {
        &self.physical_classes
    }

    /// Original verified payer/credential restrictions, route domain and live money authority.
    /// Current-policy resolution must not rebuild these facts from a key id.
    pub(crate) fn receipt(&self) -> &AdmittedRequest {
        &self.request
    }

    /// Actual take-once selected member, bound to the same walk as the admitted request.
    pub(crate) fn selection(&self) -> &SelectedWalkAttempt {
        &self.selected
    }
}

impl std::fmt::Debug for PreparedRateAttempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedRateAttempt")
            .finish_non_exhaustive()
    }
}

/// A whole accepted factual update, still private until the money/checkpoint owner publishes it.
/// This does not mint live selection authority, perform rate effects or select a money table.
struct StagedAttemptFacts {
    partition: AttemptPartition,
    rounded: bool,
}

fn stage_attempt_facts(
    before: &AttemptPartition,
    physical_classes: &BTreeSet<String>,
    declaration: Declaration<'_>,
    reports: &[AttemptUsage<'_>],
    end: Option<AttemptEnd>,
) -> Result<StagedAttemptFacts, RecErr> {
    if before.preparation == 0
        || !before.dispatch.is_some_and(|dispatch| dispatch != 0)
        || before.transport != Transport::Committed
        || before.finality != Finality::Live
        || physical_classes
            .iter()
            .any(|class| !declaration.is_attempt_class(class))
        || before
            .usage
            .classes
            .keys()
            .any(|class| !declaration.is_attempt_class(class))
    {
        return Err(RecErr::Size);
    }
    let state = AttemptState {
        attempt: before.preparation,
        exchange: 0,
        sealed: false,
    };
    let mut partition = before.clone();
    let mut rounded = false;
    for report in reports {
        declaration.validate_attempt_usage(state, *report)?;
        let (count, was_rounded) =
            super::super::usage::scaled(report.amount, report.scale).ok_or(RecErr::Size)?;
        rounded |= was_rounded;
        let facts = partition
            .usage
            .classes
            .entry(report.class.to_owned())
            .or_default();
        match report.source {
            UsageSource::Reported => facts.reported = Some(count),
            UsageSource::Floor => facts.floor = Some(count),
            UsageSource::Estimated => facts.estimated = Some(count),
        }
        if physical_classes.contains(report.class) {
            if let Some(selected) = facts.selected() {
                facts.rate_high_water = facts.rate_high_water.max(selected.count);
            }
        }
    }
    if let Some(end) = end {
        let reported: Vec<&str> = partition
            .usage
            .classes
            .iter()
            .filter_map(|(class, facts)| facts.reported.is_some().then_some(class.as_str()))
            .collect();
        declaration.validate_attempt_end(state, end, &reported)?;
        partition.finality = match end.completeness {
            Completeness::Complete => Finality::Complete,
            Completeness::Partial => Finality::Partial,
            Completeness::Unknown => Finality::Unknown,
        };
    }
    Ok(StagedAttemptFacts { partition, rounded })
}

#[cfg(test)]
#[path = "native_attempt_tests.rs"]
mod tests;
