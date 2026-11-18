// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Linear input to the selected-resource governor. Selection and preparation minting remain
//! private to the money consumer; configuration metadata alone cannot authorize an attempt.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::governance::unit_checkpoint::partitions::{
    AttemptPartition, Disposition, Finality, TargetKind, Transport, UsagePartition,
};
use crate::governance::unit_checkpoint::UnitCheckpoint;
use crate::plane_driver::port_egress::SelectedWalkAttempt;
use crate::plane_driver::port_session::{PreparedExchange, RequestDeclaration};
use crate::plane_driver::port_upstream::TargetIdentity;
use crate::plane_driver::request_admission::AdmittedRequest;

#[derive(Debug)]
pub(crate) enum NativeAttemptError {
    Unavailable,
    Binding,
    Custody,
    /// The answer's usage records were refused (the session reports BadRecords).
    Usage,
    /// The rate owner refused the observation or the seal.
    Rate,
}

/// The book-accepted complete checkpoint is the runtime's single factual source as well.
/// Live selection/rate authority is separate and is never reconstructed from these facts.
pub(super) struct NativeMoney {
    pub(super) terminal: Arc<super::native_terminal::TerminalSlot>,
    pub(super) work: Option<super::super::usage::Ending>,
    accepted: Arc<UnitCheckpoint>,
    /// Incurred facts remain owned here if publishing their successor was refused.
    unpublished: Option<Arc<UnitCheckpoint>>,
    declaration: Option<RequestDeclaration>,
}

impl NativeMoney {
    /// Factual reader fixtures carry no live task/selection authority.
    #[cfg(test)]
    pub(super) fn from_accepted(accepted: Arc<UnitCheckpoint>) -> Self {
        Self {
            terminal: super::native_terminal::TerminalSlot::new(&accepted),
            work: None,
            accepted,
            unpublished: None,
            declaration: None,
        }
    }

    pub(super) fn admitted(accepted: Arc<UnitCheckpoint>, declaration: RequestDeclaration) -> Self {
        Self {
            terminal: super::native_terminal::TerminalSlot::new(&accepted),
            work: None,
            accepted,
            unpublished: None,
            declaration: Some(declaration),
        }
    }

    pub(super) fn checkpoint(&self) -> &Arc<UnitCheckpoint> {
        self.unpublished.as_ref().unwrap_or(&self.accepted)
    }

    pub(super) fn accepted_revision(&self) -> u64 {
        self.accepted.revision
    }

    pub(super) fn publish_incurred(
        &mut self,
        gov: &crate::governance::GovState,
        snapshot: UnitCheckpoint,
    ) -> Result<(), NativeAttemptError> {
        match gov.stage_selected_checkpoint(snapshot.clone(), Some(self.accepted.revision)) {
            Ok(accepted) => {
                self.accepted = accepted;
                self.unpublished = None;
                Ok(())
            }
            Err(_) => {
                self.unpublished = Some(Arc::new(snapshot));
                Err(NativeAttemptError::Custody)
            }
        }
    }
}

/// The original money service and admitted request, issued only after selected initial custody.
/// Runtime keeps this with the same allocation; there is no numeric-unit lookup constructor.
pub struct NativeRequestMoney {
    pub(super) terminal: Arc<super::native_terminal::TerminalSlot>,
    pub(super) money: Arc<super::PlaneMoney>,
    pub(super) request: AdmittedRequest,
}

impl NativeRequestMoney {
    pub(super) fn capture_checkpoint_facts(
        &self,
        snapshot: &mut UnitCheckpoint,
    ) -> Result<(), NativeAttemptError> {
        snapshot.audit = Some(
            self.money
                .post
                .checkpoint_facts(self.request.unit())
                .ok_or_else(|| NativeAttemptError::Custody)?,
        );
        Ok(())
    }

    pub fn request(&self) -> &AdmittedRequest {
        &self.request
    }

    /// Consume both actual producer proofs while checking the original still-live money Open.
    /// Prepared estimates remain in the owned exchange; they are never incurred quantity facts.
    pub(crate) fn prepare(
        &self,
        selected: SelectedWalkAttempt,
        prepared: PreparedExchange,
    ) -> Result<PreparedRateAttempt, NativeAttemptError> {
        if !self.request.accepts_walk(selected.walk())
            || !member_granted(
                self.request.member_grants(),
                selected.pool(),
                selected.qualified_member(),
            )
            || selected.target() != prepared.target()
            || selected.preparation() != prepared.attempt()
        {
            return Err(NativeAttemptError::Binding);
        }
        let mut all = self.money.shard(self.request.unit());
        let open = all
            .get_mut(&self.request.unit())
            .ok_or(NativeAttemptError::Unavailable)?;
        self.check_open(open)?;
        let native = open
            .native
            .as_mut()
            .ok_or(NativeAttemptError::Unavailable)?;
        if native.unpublished.is_some() {
            return Err(NativeAttemptError::Unavailable);
        }
        if !native
            .declaration
            .as_ref()
            .is_some_and(|declaration| declaration.accepts(&prepared))
        {
            return Err(NativeAttemptError::Binding);
        }
        let before = &native.accepted;
        let mut snapshot = before.as_ref().clone();
        self.capture_checkpoint_facts(&mut snapshot)?;
        let parts = snapshot
            .partitions
            .as_mut()
            .ok_or(NativeAttemptError::Binding)?;
        if parts.disposition != Disposition::Running
            || !preparation_follows(parts.attempt_limit, &parts.attempts, prepared.attempt())
            || parts.routing_generation
                != self
                    .request
                    .context()
                    .generation()
                    .routing_generation()
                    .ok_or(NativeAttemptError::Binding)?
                    .get()
        {
            return Err(NativeAttemptError::Binding);
        }
        let physical_classes: Box<[Box<str>]> = prepared
            .declaration()
            .physical_classes()
            .map(Box::<str>::from)
            .collect();
        // The same set as the checkpoint's (as the owned set comparison judged it): each declared
        // class is in the checkpoint's set, and each of the checkpoint's is declared.
        if !physical_classes
            .iter()
            .all(|class| parts.physical_classes.contains(&**class))
            || !parts
                .physical_classes
                .iter()
                .all(|held| physical_classes.iter().any(|class| **class == **held))
        {
            return Err(NativeAttemptError::Binding);
        }
        parts.attempts.push(AttemptPartition {
            preparation: selected.preparation(),
            dispatch: None,
            kind: match selected.target().identity {
                TargetIdentity::Registration => TargetKind::Registration,
                TargetIdentity::Model { .. } => TargetKind::Model,
            },
            instance: self.request.context().instance().to_owned(),
            selected_pool: partition_pool(&self.request, selected.pool()),
            resource: selected.resource().map(str::to_owned),
            usage: UsagePartition {
                lane: selected.qualified_member().to_owned(),
                provider: (!selected.provider().is_empty()).then(|| selected.provider().to_owned()),
                classes: BTreeMap::new(),
            },
            transport: Transport::Prepared,
            finality: Finality::Live,
        });
        let accepted = self
            .money
            .gov
            .stage_selected_checkpoint(snapshot, Some(before.revision))
            .map_err(|_| NativeAttemptError::Custody)?;
        native.accepted = accepted;
        Ok(PreparedRateAttempt {
            request: self.request.clone(),
            selected,
            physical_classes,
            _prepared: prepared,
        })
    }

    /// A quota/eligibility refusal consumes the original preparation without creating a dispatch.
    /// Minute-expired provisional reservations instead return this same token for re-admission.
    pub(crate) fn no_send(&self, prepared: PreparedRateAttempt) -> Result<(), NativeAttemptError> {
        // The token is spent here, on every path, after the shard guard of the check is released.
        let result = self.no_send_checked(&prepared);
        drop(prepared);
        result
    }

    fn no_send_checked(&self, prepared: &PreparedRateAttempt) -> Result<(), NativeAttemptError> {
        let mut all = self.money.shard(self.request.unit());
        let open = all
            .get_mut(&self.request.unit())
            .ok_or(NativeAttemptError::Unavailable)?;
        self.check_open_identity(open)?;
        if !prepared.request.matches_money_identity(
            &self.money.book,
            &open.identity,
            open.grant.as_ref().ok_or(NativeAttemptError::Unavailable)?,
        ) {
            return Err(NativeAttemptError::Binding);
        }
        let native = open
            .native
            .as_mut()
            .ok_or(NativeAttemptError::Unavailable)?;
        let mut snapshot = native.checkpoint().as_ref().clone();
        let attempt = snapshot
            .partitions
            .as_mut()
            .and_then(|parts| parts.attempts.last_mut())
            .ok_or(NativeAttemptError::Binding)?;
        if attempt.preparation != prepared.selected.preparation()
            || attempt.transport != Transport::Prepared
            || attempt.finality != Finality::Live
        {
            return Err(NativeAttemptError::Binding);
        }
        attempt.transport = Transport::NoSend;
        attempt.finality = Finality::Unknown;
        native.publish_incurred(&self.money.gov, snapshot)
    }

    fn check_open(&self, open: &super::Open) -> Result<(), NativeAttemptError> {
        self.check_open_identity(open)?;
        if !self.request.is_live() {
            return Err(NativeAttemptError::Unavailable);
        }
        Ok(())
    }

    pub(super) fn check_open_identity(&self, open: &super::Open) -> Result<(), NativeAttemptError> {
        if open.finished
            || open.ledgered
            || open.abandoned
            || !self.request.matches_money_identity(
                &self.money.book,
                &open.identity,
                open.grant.as_ref().ok_or(NativeAttemptError::Unavailable)?,
            )
            || !self.request.matches_governance(&self.money.gov)
        {
            return Err(NativeAttemptError::Unavailable);
        }
        Ok(())
    }
}

#[path = "native_live.rs"]
mod live;
#[path = "native_session.rs"]
mod session;
#[cfg(test)]
use live::effective_tokens;
pub(crate) use live::{NativeAttempt, NativeCommitError};

fn preparation_follows(limit: u32, attempts: &[AttemptPartition], preparation: u32) -> bool {
    preparation != 0
        && preparation <= limit
        && attempts
            .last()
            .is_none_or(|prior| prior.preparation < preparation && prior.finality != Finality::Live)
}

fn member_granted(grants: &BTreeMap<String, Vec<String>>, pool: &str, member: &str) -> bool {
    grants
        .get(pool)
        .is_some_and(|members| members.iter().any(|held| held == member))
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
/// The sole mint consumes the live walk and Task preparation through NativeRequestMoney;
/// descriptive metadata alone cannot construct this value or authorize a transport handoff.
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

    pub(crate) fn route(&self) -> u32 {
        self._prepared.route()
    }

    pub(crate) fn original_route(
        &self,
    ) -> Option<&crate::plane_driver::route_identity::OriginalPlaneRoute> {
        self._prepared.original_route()
    }

    pub(crate) fn exchange(&self) -> &crate::plane_driver::port_session::UpExchange {
        self._prepared.exchange()
    }

    pub(crate) fn data(&self) -> Option<&Arc<crate::auth::native_data::NativeDataPending>> {
        self._prepared.data()
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
        let mut reported = smallvec::SmallVec::<[&str; 8]>::new();
        reported.extend(
            partition
                .usage
                .classes
                .iter()
                .filter_map(|(class, facts)| facts.reported.is_some().then_some(class.as_str())),
        );
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

/// The pool a selected attempt partition records: an instance-qualified identity
/// (`instance\u{1f}pool`, required by the partition rule of ddd61a377f), never an internal walk
/// key (request_admission: "Operator domain is distinct from the internal walk key"). Every walk
/// key is internal: a seat walks its own pool under the bare instance (`SeatPool::of`), a catalog
/// pool under a length-framed key (`provider_catalog::walk_key`). An attempt in the request's own
/// walk records the request's own qualified pool (`instance\u{1f}domain`). Any other walk key is
/// recorded as it is, and the partition rule judges it.
fn partition_pool(request: &AdmittedRequest, walk_pool: &str) -> String {
    if request.walk_key() == Some(walk_pool) {
        request.pool().to_owned()
    } else {
        walk_pool.to_owned()
    }
}
