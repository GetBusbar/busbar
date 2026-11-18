// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The selected unit's factual custody and its one monetary projection. Deserializing these
//! facts never creates a live selection, rate reservation, admission or fee participation.

use std::collections::{BTreeMap, BTreeSet};

use busbar_contract::kept::Text;
use busbar_contract::Count;
use serde::{Deserialize, Serialize};

use super::{RecordStoreError, RecordStoreResult, UnitCheckpoint, UnitTarget};
use busbar_kernel_ledger::cost::RawRateEra;

pub const MAX_PREPARATIONS: usize = 256;
pub const MAX_CLASSES: usize = 64;
pub const MAX_TARGETS: usize = 64;
pub const MAX_IDENTITY_BYTES: usize = 4096;
pub const MAX_AUDIT_BYTES: usize = 1024 * 1024;
pub const MAX_TERMINAL_EVENTS: usize = 1024;
pub const MAX_CHECKPOINT_BYTES: usize = 16 * 1024 * 1024;

mod decode;
mod fee;
pub(crate) use decode::check_encoded;
pub use fee::{CapturedFee, FeeBasis, FeeResult, SelectedFeeCompletion};

/// An invalid partition: its message is a fixed word of the program, so nothing is allocated.
fn invalid(message: &'static str) -> RecordStoreError {
    RecordStoreError::fixed(message)
}

/// The selected unit's stored usage custody. Every name in it is shared text ([`Text`]): it is
/// written and read as the same string it always was (the stored bytes do not change), and a
/// copy of the record (each accepted update starts from one) copies no name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionedUsageV1 {
    pub version: u8,
    pub request_pool: Text,
    pub routing_generation: u64,
    pub attempt_limit: u32,
    pub declared_classes: BTreeSet<Text>,
    pub attempt_classes: BTreeSet<Text>,
    pub physical_classes: BTreeSet<Text>,
    pub session_origin: SessionOrigin,
    pub fee: CapturedFee,
    pub session: Option<UsagePartition>,
    pub attempts: Vec<AttemptPartition>,
    pub far_end_answered: bool,
    pub caller_bytes_committed: bool,
    pub disposition: Disposition,
    /// The host's delivered preparation ordinal, never a dispatch ordinal or vector offset.
    pub final_target: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionOrigin {
    pub instance: Text,
    pub lane: Text,
    pub provider: Option<Text>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsagePartition {
    pub lane: Text,
    pub provider: Option<Text>,
    pub classes: BTreeMap<Text, ClassFacts>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassFacts {
    pub reported: Option<Count>,
    pub floor: Option<Count>,
    pub estimated: Option<Count>,
    pub rate_high_water: Count,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptPartition {
    pub preparation: u32,
    pub dispatch: Option<u32>,
    pub kind: TargetKind,
    pub instance: Text,
    pub selected_pool: Text,
    pub resource: Option<Text>,
    pub usage: UsagePartition,
    pub transport: Transport,
    pub finality: Finality,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Model,
    Registration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Prepared,
    Committed,
    NoSend,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Finality {
    Live,
    Complete,
    Partial,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Running,
    End,
    Failed,
    Cancel { reason: Text },
    RecoveredRunning,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageSource {
    Reported,
    Floor,
    Estimated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedQuantity {
    pub count: Count,
    pub source: UsageSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PartitionScope {
    Session,
    Attempt {
        preparation: u32,
        dispatch: Option<u32>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartitionIdentity {
    pub lane: Text,
    pub provider: Option<Text>,
    pub instance: Text,
    pub selected_pool: Option<Text>,
    pub resource: Option<Text>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectedClass {
    pub selected: Option<SelectedQuantity>,
    pub billed: Option<SelectedQuantity>,
    pub rate_high_water: Count,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectedPartition {
    pub scope: PartitionScope,
    pub identity: PartitionIdentity,
    pub transport: Option<Transport>,
    pub finality: Finality,
    pub classes: BTreeMap<Text, ProjectedClass>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogicalMeterIdentity {
    HostOrigin,
    DeliveredPreparation(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalMeter {
    pub identity: LogicalMeterIdentity,
    pub lane: Text,
    pub provider: Option<Text>,
}

#[derive(Clone, Debug)]
pub struct ProjectedCommon {
    pub id: [u8; 16],
    pub revision: u64,
    pub unit: u64,
    pub principal: String,
    pub group: String,
    pub arrived: u64,
    pub era: RawRateEra,
    pub targets: Vec<UnitTarget>,
    pub request_pool: Text,
    pub routing_generation: u64,
}

#[derive(Clone, Debug)]
pub struct UsageProjection {
    pub common: ProjectedCommon,
    pub partitions: Vec<ProjectedPartition>,
    pub logical_request: Option<LogicalMeter>,
    pub disposition: Disposition,
    pub fee: CapturedFee,
    pub session_origin: SessionOrigin,
}

/// A borrowed complete snapshot: readers cannot override its disposition or common context.
pub struct ValidatedSelectedCheckpoint<'a> {
    snapshot: &'a UnitCheckpoint,
    usage: &'a PartitionedUsageV1,
}

impl<'a> TryFrom<&'a UnitCheckpoint> for ValidatedSelectedCheckpoint<'a> {
    type Error = RecordStoreError;

    fn try_from(snapshot: &'a UnitCheckpoint) -> Result<Self, Self::Error> {
        snapshot.validate()?;
        let usage = snapshot
            .partitions
            .as_ref()
            .ok_or_else(|| invalid("a legacy checkpoint has no selected partition view"))?;
        Ok(Self { snapshot, usage })
    }
}

impl ClassFacts {
    pub(crate) fn selected(&self) -> Option<SelectedQuantity> {
        self.billable().or_else(|| {
            self.estimated.map(|count| SelectedQuantity {
                count,
                source: UsageSource::Estimated,
            })
        })
    }

    fn billable(&self) -> Option<SelectedQuantity> {
        self.reported
            .map(|count| SelectedQuantity {
                count,
                source: UsageSource::Reported,
            })
            .or_else(|| {
                self.floor.map(|count| SelectedQuantity {
                    count,
                    source: UsageSource::Floor,
                })
            })
    }

    fn follows(&self, before: &Self) -> bool {
        self.rate_high_water >= before.rate_high_water
            && (before.reported.is_none() || self.reported.is_some())
            && (before.floor.is_none() || self.floor.is_some())
            && (before.estimated.is_none() || self.estimated.is_some())
    }
}

impl ProjectedPartition {
    /// The partition's billed classes with a count that is not zero, as the ledger's owned map
    /// keys them.
    pub fn billed_counts(&self) -> BTreeMap<String, Count> {
        self.classes
            .iter()
            .filter_map(|(class, facts)| {
                facts
                    .billed
                    .filter(|quantity| !quantity.count.is_zero())
                    .map(|quantity| (class.as_str().to_owned(), quantity.count))
            })
            .collect()
    }

    /// Whether [`Self::billed_counts`] would hold anything: some class is billed a count that is
    /// not zero. It reads the classes where they lie and builds no map.
    pub fn has_bill(&self) -> bool {
        self.classes.values().any(|facts| {
            facts
                .billed
                .is_some_and(|quantity| !quantity.count.is_zero())
        })
    }
}

impl UsageProjection {
    /// Same-lane attempts merge only for raw accounting and one final rounding operation.
    pub fn billed_by_lane(&self) -> RecordStoreResult<BTreeMap<String, BTreeMap<String, Count>>> {
        let mut lanes = BTreeMap::<String, BTreeMap<String, Count>>::new();
        for partition in &self.partitions {
            for (class, count) in partition.billed_counts() {
                let total = lanes
                    .entry(partition.identity.lane.as_str().to_owned())
                    .or_default()
                    .entry(class)
                    .or_default();
                *total = total
                    .checked_add(count)
                    .map_err(|_| invalid("selected lane quantity overflow"))?;
            }
        }
        Ok(lanes)
    }
}

impl ValidatedSelectedCheckpoint<'_> {
    pub fn usage(&self) -> &PartitionedUsageV1 {
        self.usage
    }
    pub fn snapshot(&self) -> &UnitCheckpoint {
        self.snapshot
    }
    pub fn project(&self) -> RecordStoreResult<UsageProjection> {
        let snapshot = self.snapshot;
        let usage = self.usage;
        let eligible = match usage.disposition {
            Disposition::Failed => false,
            Disposition::Cancel { .. } => usage.far_end_answered && usage.caller_bytes_committed,
            Disposition::Running | Disposition::End | Disposition::RecoveredRunning => true,
        };
        // One partition's classes, projected over the class names it is read under: each name is
        // the record's own shared text, and the names are walked where they lie (the session's
        // are the declared classes less the attempt classes, read without making that set).
        fn project_classes<'c>(
            raw: &UsagePartition,
            classes: impl Iterator<Item = &'c Text>,
            billed: bool,
        ) -> BTreeMap<Text, ProjectedClass> {
            classes
                .map(|name| {
                    let facts = raw.classes.get(name).cloned().unwrap_or_default();
                    (
                        name.clone(),
                        ProjectedClass {
                            selected: facts.selected(),
                            billed: billed.then(|| facts.billable()).flatten(),
                            rate_high_water: facts.rate_high_water,
                        },
                    )
                })
                .collect()
        }
        let mut partitions =
            Vec::with_capacity(usage.attempts.len() + usize::from(usage.session.is_some()));
        for attempt in &usage.attempts {
            partitions.push(ProjectedPartition {
                scope: PartitionScope::Attempt {
                    preparation: attempt.preparation,
                    dispatch: attempt.dispatch,
                },
                identity: PartitionIdentity {
                    lane: attempt.usage.lane.clone(),
                    provider: attempt.usage.provider.clone(),
                    instance: attempt.instance.clone(),
                    selected_pool: Some(attempt.selected_pool.clone()),
                    resource: attempt.resource.clone(),
                },
                transport: Some(attempt.transport),
                finality: attempt.finality,
                classes: project_classes(
                    &attempt.usage,
                    usage.attempt_classes.iter(),
                    attempt.transport == Transport::Committed && eligible,
                ),
            });
        }
        if let Some(session) = &usage.session {
            partitions.push(ProjectedPartition {
                scope: PartitionScope::Session,
                identity: PartitionIdentity {
                    lane: session.lane.clone(),
                    provider: session.provider.clone(),
                    instance: usage.session_origin.instance.clone(),
                    selected_pool: None,
                    resource: None,
                },
                transport: None,
                finality: match usage.disposition {
                    Disposition::Running => Finality::Live,
                    Disposition::End => Finality::Complete,
                    Disposition::RecoveredRunning => Finality::Unknown,
                    _ => Finality::Partial,
                },
                classes: project_classes(
                    session,
                    usage.declared_classes.difference(&usage.attempt_classes),
                    eligible,
                ),
            });
        }
        let logical_request = if !snapshot.metered {
            None
        } else if let Some(preparation) = usage.final_target {
            let attempt = usage
                .attempts
                .iter()
                .find(|a| a.preparation == preparation)
                .ok_or_else(|| invalid("selected final preparation is missing"))?;
            Some(LogicalMeter {
                identity: LogicalMeterIdentity::DeliveredPreparation(preparation),
                lane: attempt.usage.lane.clone(),
                provider: attempt.usage.provider.clone(),
            })
        } else {
            Some(LogicalMeter {
                identity: LogicalMeterIdentity::HostOrigin,
                lane: usage.session_origin.lane.clone(),
                provider: usage.session_origin.provider.clone(),
            })
        };
        let projection = UsageProjection {
            common: ProjectedCommon {
                id: snapshot.id,
                revision: snapshot.revision,
                unit: snapshot.unit,
                principal: snapshot.principal.clone(),
                group: snapshot.group.clone(),
                arrived: snapshot.arrived,
                era: snapshot.era(),
                targets: snapshot.targets.clone(),
                request_pool: usage.request_pool.clone(),
                routing_generation: usage.routing_generation,
            },
            partitions,
            logical_request,
            disposition: usage.disposition.clone(),
            fee: usage.fee.clone(),
            session_origin: usage.session_origin.clone(),
        };
        projection.billed_by_lane()?;
        Ok(projection)
    }
}

fn identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_IDENTITY_BYTES && !value.contains('\0')
}

fn optional_identity(value: Option<&str>) -> bool {
    value.is_none_or(identity)
}

fn class_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b':'))
}

fn in_instance(lane: &str, instance: &str) -> bool {
    identity(lane)
        && lane
            .split_once('\u{1f}')
            .is_some_and(|(owner, subject)| owner == instance && !subject.contains('\u{1f}'))
}

/// `allowed` says whether a class name may appear in this partition: asked of the record's own
/// sets where they lie, so no set is made to ask it.
fn validate_classes(
    raw: &UsagePartition,
    allowed: impl Fn(&Text) -> bool,
    physical: &BTreeSet<Text>,
) -> RecordStoreResult<()> {
    if raw.classes.len() > MAX_CLASSES || !optional_identity(raw.provider.as_deref()) {
        return Err(invalid("selected usage identity or class bound is invalid"));
    }
    for (class, facts) in &raw.classes {
        if !allowed(class)
            || facts.rate_high_water.is_negative()
            || [facts.reported, facts.floor, facts.estimated]
                .into_iter()
                .flatten()
                .any(|n| n.is_negative())
            || (physical.contains(class)
                && facts
                    .selected()
                    .is_some_and(|quantity| quantity.count > facts.rate_high_water))
        {
            return Err(invalid(
                "selected usage class, quantity or high water is invalid",
            ));
        }
    }
    Ok(())
}

impl PartitionedUsageV1 {
    /// Conservative encoded upper bound before the first dispatch. It covers the complete
    /// declared attempt universe, Count text, JSON escaping and byte-array recovery payloads.
    /// The aggregate byte limit can refuse combinations below the individual dimension caps.
    pub fn preflight_terminal_bound(&self, targets: usize) -> RecordStoreResult<()> {
        let attempts = self.attempt_limit as usize;
        let classes = self.declared_classes.len();
        if attempts == 0
            || attempts > MAX_PREPARATIONS
            || classes > MAX_CLASSES
            || targets > MAX_TARGETS
        {
            return Err(invalid(
                "selected terminal preflight dimensions exceed their bounds",
            ));
        }
        // Every non-class string may JSON-escape to six bytes per input byte. A Count's signed
        // exact decimal spelling fits in 48 bytes. Event payloads serialize bytes as up to four
        // characters; plain/dated and whole/chunk custody each retain their original quantities.
        let text = MAX_IDENTITY_BYTES * 6;
        let class = 64 + 48 + 32;
        let raw = (attempts + 1) * (text * 5 + classes * (class + 4 * 48));
        let budget = targets * (attempts + 1) * (text + classes * class) * 16;
        let metering = (attempts + 3) * (text * 5 + classes * class) * 4;
        let overhead =
            MAX_AUDIT_BYTES * 4 + targets * (text * 2 + 128) + MAX_TERMINAL_EVENTS * 1024;
        let bytes = raw
            .checked_add(budget)
            .and_then(|n| n.checked_add(metering))
            .and_then(|n| n.checked_add(overhead))
            .ok_or_else(|| invalid("selected terminal preflight size overflow"))?;
        if bytes > MAX_CHECKPOINT_BYTES {
            return Err(invalid(
                "complete selected terminal custody cannot fit its byte bound",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        if self.version != 1
            || snapshot.measurement.is_some()
            || !snapshot.lane.is_empty()
            || snapshot.provider.is_some()
            || !snapshot.units.is_empty()
            || self.attempt_limit == 0
            || self.attempt_limit as usize > MAX_PREPARATIONS
            || self.attempts.len() > self.attempt_limit as usize
            || self.declared_classes.len() > MAX_CLASSES
            || self.declared_classes.iter().any(|name| !class_name(name))
            || !self.attempt_classes.is_subset(&self.declared_classes)
            || !self.physical_classes.is_subset(&self.attempt_classes)
            || !identity(&self.request_pool)
            || !identity(&self.session_origin.instance)
            || !in_instance(&self.session_origin.lane, &self.session_origin.instance)
            || !self.session_origin.lane.ends_with('\u{1f}')
            || self.session_origin.provider.is_some()
            || !optional_identity(self.fee.basis().lane.as_deref())
            || (self.fee.pending() && snapshot.terminal.is_some())
            || snapshot.targets.len() > MAX_TARGETS
            || snapshot.targets.iter().any(|target| {
                !identity(&target.bucket) || !optional_identity(target.group.as_deref())
            })
            || snapshot
                .targets
                .windows(2)
                .any(|pair| (&pair[0].bucket, pair[0].window) >= (&pair[1].bucket, pair[1].window))
            || !identity(&snapshot.principal)
            || snapshot.group.len() > MAX_IDENTITY_BYTES
            || snapshot
                .audit
                .as_ref()
                .is_some_and(|audit| audit.len() > MAX_AUDIT_BYTES)
            || snapshot
                .terminal
                .as_ref()
                .is_some_and(|events| events.len() > MAX_TERMINAL_EVENTS)
            || snapshot.ended == matches!(self.disposition, Disposition::Running)
        {
            return Err(invalid(
                "invalid selected checkpoint representation or bound",
            ));
        }
        if let Disposition::Cancel { reason } = &self.disposition {
            if !identity(reason) {
                return Err(invalid("selected cancellation lacks a valid reason"));
            }
        }
        if let Some(session) = &self.session {
            if session.lane != self.session_origin.lane
                || session.provider != self.session_origin.provider
            {
                return Err(invalid("session usage changed its original host identity"));
            }
            // The session's classes are the declared classes less the attempt classes.
            validate_classes(
                session,
                |class| {
                    self.declared_classes.contains(class) && !self.attempt_classes.contains(class)
                },
                &BTreeSet::new(),
            )?;
        }
        let mut preparation = 0;
        let mut dispatch = 0;
        for attempt in &self.attempts {
            if attempt.preparation <= preparation
                || attempt.preparation > self.attempt_limit
                || !identity(&attempt.instance)
                || !in_instance(&attempt.usage.lane, &attempt.instance)
                || !in_instance(&attempt.selected_pool, &attempt.instance)
                || !optional_identity(attempt.resource.as_deref())
                || (snapshot.ended && attempt.finality == Finality::Live)
                || (attempt.transport == Transport::Committed) != attempt.dispatch.is_some()
            {
                return Err(invalid(
                    "invalid selected attempt identity, order or transport",
                ));
            }
            preparation = attempt.preparation;
            if let Some(ordinal) = attempt.dispatch {
                dispatch += 1;
                if ordinal != dispatch {
                    return Err(invalid("selected dispatch ordinals are not consecutive"));
                }
            }
            validate_classes(
                &attempt.usage,
                |class| self.attempt_classes.contains(class),
                &self.physical_classes,
            )?;
            if attempt.finality == Finality::Complete
                && (attempt.transport != Transport::Committed
                    || self.physical_classes.iter().any(|class| {
                        attempt
                            .usage
                            .classes
                            .get(class)
                            .is_none_or(|facts| facts.reported.is_none())
                    }))
            {
                return Err(invalid(
                    "selected complete usage lacks explicit reported coverage",
                ));
            }
        }
        if self.final_target.is_some_and(|preparation| {
            !self.attempts.iter().any(|attempt| {
                attempt.preparation == preparation
                    && attempt.transport == Transport::Committed
                    && attempt.dispatch.is_some()
            })
        }) {
            return Err(invalid(
                "selected final target is not a committed preparation",
            ));
        }
        check_size(snapshot)?;
        Ok(())
    }

    /// Restore only captured facts; a process-local rate cell or live dispatch is never recreated.
    pub(super) fn recover_running(&mut self) {
        self.fee.recover();
        if self.disposition == Disposition::Running {
            self.disposition = Disposition::RecoveredRunning;
            for attempt in &mut self.attempts {
                if attempt.finality == Finality::Live {
                    attempt.finality = Finality::Unknown;
                }
            }
        }
    }
}

/// An ordered replacement cannot erase accepted source evidence or rebind attribution.
pub fn validate_successor(
    before: &UnitCheckpoint,
    after: &UnitCheckpoint,
) -> RecordStoreResult<()> {
    after.validate()?;
    let (Some(old), Some(new)) = (&before.partitions, &after.partitions) else {
        return Err(invalid(
            "a selected checkpoint cannot change representation",
        ));
    };
    let mut comparable_old = old.clone();
    if old.fee.pending() && before.terminal.is_none() && new.fee.follows(&old.fee) {
        comparable_old.fee = new.fee.clone();
    }
    if before.id != after.id
        || before.unit != after.unit
        || before.principal != after.principal
        || before.group != after.group
        || before.arrived != after.arrived
        || before.era_at != after.era_at
        || before.era_entry != after.era_entry
        || before.targets != after.targets
        || old.request_pool != new.request_pool
        || old.routing_generation != new.routing_generation
        || old.attempt_limit != new.attempt_limit
        || old.declared_classes != new.declared_classes
        || old.attempt_classes != new.attempt_classes
        || old.physical_classes != new.physical_classes
        || old.session_origin != new.session_origin
        || !new.fee.follows(&old.fee)
        || (old.far_end_answered && !new.far_end_answered)
        || (old.caller_bytes_committed && !new.caller_bytes_committed)
        || (old.final_target.is_some() && old.final_target != new.final_target)
        || (before.ended
            && (&comparable_old != new
                || before.metered != after.metered
                || before.audit != after.audit
                || before.unread != after.unread
                || !after.ended
                || (before.terminal.is_some() && before.terminal != after.terminal)))
        || old.attempts.len() > new.attempts.len()
    {
        return Err(invalid(
            "selected checkpoint replacement changes immutable custody",
        ));
    }
    let classes_follow = |old: &UsagePartition, new: &UsagePartition| {
        old.lane == new.lane
            && old.provider == new.provider
            && old.classes.iter().all(|(class, facts)| {
                new.classes
                    .get(class)
                    .is_some_and(|next| next.follows(facts))
            })
    };
    if old.session.as_ref().is_some_and(|session| {
        new.session
            .as_ref()
            .is_none_or(|next| !classes_follow(session, next))
    }) {
        return Err(invalid("selected session source evidence was erased"));
    }
    for (old, new) in old.attempts.iter().zip(&new.attempts) {
        if old.preparation != new.preparation
            || old.kind != new.kind
            || old.instance != new.instance
            || old.selected_pool != new.selected_pool
            || old.resource != new.resource
            || !classes_follow(&old.usage, &new.usage)
            || (old.transport != Transport::Prepared && old.transport != new.transport)
            || (old.dispatch.is_some() && old.dispatch != new.dispatch)
            || (old.finality != Finality::Live && old != new)
        {
            return Err(invalid(
                "selected attempt changed after its identity or finality was fixed",
            ));
        }
    }
    Ok(())
}

struct ByteBound(usize);
impl std::io::Write for ByteBound {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|n| *n <= MAX_CHECKPOINT_BYTES)
            .ok_or_else(|| std::io::Error::other("selected checkpoint exceeds byte bound"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn check_size(snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
    busbar_contract::json::to_writer(ByteBound(0), snapshot)
        .map_err(|_| invalid("selected checkpoint exceeds its encoded byte bound"))
}
