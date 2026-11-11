// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Host-attributed raw measurements. Plugins supply indexed cumulative quantities;
//! identity, operation lineage, accounting targets and the rate era stay in the host.
use crate::governance::{
    unit_checkpoint::{UnitCheckpoint, UnitTarget},
    GovState,
};
use busbar_contract::{caps::KernelSeal, services::Caller, Count};
use busbar_kernel_ledger::cost::{measurement_lane, RawRateEra};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub const MAX_CLASSES: usize = 64;
pub const MAX_REVISIONS: usize = 4096;
pub const MAX_OPERATIONS: usize = 256;
const MAX_TEXT: usize = 1024;
const MAX_CLASS_TEXT: usize = 256;
pub(crate) const MAX_EVIDENCE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Origin {
    Request {
        principal: String,
        group: String,
        targets: Vec<UnitTarget>,
        unit: u64,
    },
    System,
}

/// Constructed by the root from original authenticated admission, or explicitly
/// as system work. Never deserialized from a plugin answer or inferred from TLS.
#[derive(Clone)]
pub struct MeasurementContext {
    origin: Origin,
    arrived: u64,
    era: RawRateEra,
}
impl MeasurementContext {
    #[allow(clippy::too_many_arguments)]
    pub fn request(
        _seal: &KernelSeal,
        unit: u64,
        principal: String,
        group: String,
        targets: Vec<UnitTarget>,
        arrived: u64,
        era: RawRateEra,
    ) -> Result<Self, Refusal> {
        if unit == 0
            || principal.is_empty()
            || principal.len() > MAX_TEXT
            || group.len() > MAX_TEXT
            || targets.len() > 64
            || targets.iter().any(|t| {
                t.bucket.is_empty()
                    || t.bucket.len() > MAX_TEXT
                    || t.group.as_ref().is_some_and(|g| g.len() > MAX_TEXT)
            })
        {
            return Err(Refusal::Malformed);
        }
        let mut names = std::collections::BTreeSet::new();
        if targets.iter().any(|t| !names.insert((&t.bucket, t.window))) {
            return Err(Refusal::Malformed);
        }
        Ok(Self {
            origin: Origin::Request {
                principal,
                group,
                targets,
                unit,
            },
            arrived,
            era,
        })
    }
    pub fn system(_seal: &KernelSeal, arrived: u64, era: RawRateEra) -> Self {
        Self {
            origin: Origin::System,
            arrived,
            era,
        }
    }
}

/// The root copies this from the admitted immutable Statement and validated Caller.
pub struct MeasurementBinding {
    pub caller: Caller,
    pub statement_digest: [u8; 32],
    pub classes: Vec<String>,
}

/// Signed as measurement.accrued, separately from unit admission evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementEvidence {
    version: u32,
    plugin_kind: String,
    namespace: String,
    statement_digest: [u8; 32],
    classes: Vec<String>,
    origin: Origin,
    slot: u32,
    /// The accepted cumulative snapshot's revision; zero means no report.
    reported_revision: u64,
}
impl MeasurementEvidence {
    pub(crate) fn validate(&self, snapshot: &UnitCheckpoint) -> Result<(), Refusal> {
        if snapshot.id == [0; 16]
            || snapshot
                .units
                .values()
                .any(|count| !count.fits_a_64_bit_column())
            || self.version != 1
            || self.namespace.is_empty()
            || self.namespace.len() > MAX_TEXT
            || ![
                "auth",
                "store",
                "secret",
                "export",
                "hook",
                "transport",
                "plane",
            ]
            .contains(&self.plugin_kind.as_str())
            || self.statement_digest == [0; 32]
            || self.classes.is_empty()
            || self.classes.len() > MAX_CLASSES
            || self
                .classes
                .iter()
                .any(|name| name.is_empty() || name.len() > MAX_CLASS_TEXT)
            || self
                .classes
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.classes.len()
            || self.reported_revision == 0
            || self.reported_revision > MAX_REVISIONS as u64
            || snapshot.audit.is_some()
            || snapshot.metered
            || snapshot.provider.is_some()
            || snapshot.lane != measurement_lane(&self.plugin_kind, &self.namespace)
            || snapshot
                .units
                .keys()
                .any(|name| !self.classes.contains(name))
        {
            return Err(Refusal::Malformed);
        }
        match &self.origin {
            Origin::Request {
                principal,
                group,
                targets,
                unit,
            } => {
                if *unit == 0
                    || principal.is_empty()
                    || principal.len() > MAX_TEXT
                    || group.len() > MAX_TEXT
                    || targets.len() > MAX_CLASSES
                    || targets.iter().any(|target| {
                        target.bucket.len() > MAX_TEXT
                            || target
                                .group
                                .as_ref()
                                .is_some_and(|group| group.len() > MAX_TEXT)
                    })
                    || snapshot.unit != *unit
                    || &snapshot.principal != principal
                    || &snapshot.group != group
                    || &snapshot.targets != targets
                {
                    return Err(Refusal::Conflict);
                }
            }
            Origin::System => {
                if snapshot.unit != 0
                    || !snapshot.targets.is_empty()
                    || !snapshot.group.is_empty()
                    || snapshot.principal != system_identity(&self.plugin_kind, &self.namespace)
                {
                    return Err(Refusal::Conflict);
                }
            }
        }
        Ok(())
    }
}
fn system_identity(kind: &str, namespace: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"busbar/system-measurement/v1\0");
    for part in [kind, namespace] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    format!("system-measurement:{}", hex::encode(digest.finalize()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Unavailable,
    Malformed,
    Conflict,
}

/// Capacity remains occupied until the existing durable flusher has settled it.
/// Retrying/cancelling an invocation must retain its same Operation, not reserve again.
pub struct MeasurementRuntime {
    gov: Arc<GovState>,
    capacity: usize,
    operations: Mutex<HashMap<[u8; 16], Arc<MeasurementOperation>>>,
}
impl MeasurementRuntime {
    pub fn new(
        _seal: &KernelSeal,
        gov: Arc<GovState>,
        capacity: usize,
    ) -> Result<Arc<Self>, Refusal> {
        if capacity == 0 || capacity > MAX_OPERATIONS {
            return Err(Refusal::Malformed);
        }
        let mut operations = HashMap::new();
        operations
            .try_reserve(capacity)
            .map_err(|_| Refusal::Unavailable)?;
        Ok(Arc::new(Self {
            gov,
            capacity,
            operations: Mutex::new(operations),
        }))
    }
    /// Called before any plugin work. Both count cells and replay fingerprints are
    /// reserved now, not allocated or dropped after the plugin has done work.
    pub fn reserve(
        &self,
        _seal: &KernelSeal,
        binding: MeasurementBinding,
        context: &MeasurementContext,
        slot: u32,
    ) -> Result<Arc<MeasurementOperation>, Refusal> {
        if !self.gov.unit_checkpoints_enabled() {
            return Err(Refusal::Unavailable);
        }
        let mut operations = self.operations.lock().unwrap_or_else(|p| p.into_inner());
        operations.retain(|_, operation| !operation.settled());
        if operations.len() >= self.capacity {
            return Err(Refusal::Unavailable);
        }
        let namespace = binding.caller.namespace().to_string();
        if namespace.is_empty()
            || namespace.len() > MAX_TEXT
            || binding.statement_digest == [0; 32]
            || binding.classes.is_empty()
            || binding.classes.len() > MAX_CLASSES
            || binding
                .classes
                .iter()
                .any(|c| c.is_empty() || c.len() > MAX_CLASS_TEXT)
            || binding
                .classes
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != binding.classes.len()
        {
            return Err(Refusal::Malformed);
        }
        let mut history = Vec::new();
        history
            .try_reserve_exact(MAX_REVISIONS)
            .map_err(|_| Refusal::Unavailable)?;
        let units = binding
            .classes
            .iter()
            .map(|name| (name.clone(), Count::ZERO))
            .collect();
        let plugin_kind = binding.caller.kind().word().to_owned();
        let (principal, group, targets, unit) = match &context.origin {
            Origin::Request {
                principal,
                group,
                targets,
                unit,
            } => (principal.clone(), group.clone(), targets.clone(), *unit),
            Origin::System => (
                system_identity(&plugin_kind, &namespace),
                String::new(),
                Vec::new(),
                0,
            ),
        };
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|_| Refusal::Unavailable)?;
        if id == [0; 16] || operations.contains_key(&id) {
            return Err(Refusal::Unavailable);
        }
        let snapshot = UnitCheckpoint {
            id,
            revision: 0,
            unit,
            principal,
            group,
            arrived: context.arrived,
            lane: measurement_lane(&plugin_kind, &namespace),
            provider: None,
            era_at: context.era.effective_from,
            era_entry: context.era.entry_id.map(|id| id.0),
            units,
            targets,
            metered: false,
            ended: false,
            terminal: None,
            audit: None,
            measurement: Some(MeasurementEvidence {
                version: 1,
                plugin_kind,
                namespace,
                statement_digest: binding.statement_digest,
                classes: binding.classes,
                origin: context.origin.clone(),
                slot,
                reported_revision: 0,
            }),
        };
        let operation = Arc::new(MeasurementOperation {
            gov: self.gov.clone(),
            id,
            state: Mutex::new(State {
                snapshot: Some(snapshot),
                observed: 0,
                history,
                released: false,
                handed_off: 0,
            }),
        });
        operations.insert(id, operation.clone());
        Ok(operation)
    }
    pub fn pending(&self) -> usize {
        self.operations
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .filter(|op| !op.settled())
            .count()
    }
}
struct State {
    snapshot: Option<UnitCheckpoint>,
    observed: u64,
    history: Vec<[u8; 32]>,
    released: bool,
    handed_off: usize,
}
/// Opaque host operation lineage. It exposes no account, price, budget or scope setter.
pub struct MeasurementOperation {
    gov: Arc<GovState>,
    id: [u8; 16],
    state: Mutex<State>,
}
impl MeasurementOperation {
    pub fn revision(&self) -> u64 {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.released || state.history.len() == MAX_REVISIONS {
            0
        } else {
            state.history.len() as u64 + 1
        }
    }
    /// Pure bounded staging: no Store operation, no callback, no price lookup.
    pub fn capture(
        &self,
        revision: u64,
        counts: impl IntoIterator<Item = (u32, Count)>,
    ) -> Result<(), Refusal> {
        let mut incoming = [(0u32, Count::ZERO); MAX_CLASSES];
        let mut length = 0;
        let mut mask = 0u64;
        for (index, count) in counts {
            if length == MAX_CLASSES
                || index as usize >= MAX_CLASSES
                || mask & (1u64 << index) != 0
                || count.is_negative()
                || !count.fits_a_64_bit_column()
            {
                return Err(Refusal::Malformed);
            }
            mask |= 1u64 << index;
            incoming[length] = (index, count);
            length += 1;
        }
        if revision == 0 || revision > MAX_REVISIONS as u64 {
            return Err(Refusal::Malformed);
        }
        incoming[..length].sort_unstable_by_key(|(index, _)| *index);
        let mut hash = Sha256::new();
        hash.update(b"busbar/measurement-snapshot/v1\0");
        for (index, count) in &incoming[..length] {
            hash.update(index.to_be_bytes());
            hash.update(count.micros().to_be_bytes());
        }
        let hash: [u8; 32] = hash.finalize().into();
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(previous) = state.history.get(revision as usize - 1) {
            return if previous == &hash {
                Ok(())
            } else {
                Err(Refusal::Conflict)
            };
        }
        if state.released || revision != state.history.len() as u64 + 1 {
            return Err(Refusal::Conflict);
        }
        let snapshot = state.snapshot.as_mut().ok_or(Refusal::Conflict)?;
        let evidence = snapshot.measurement.as_mut().ok_or(Refusal::Conflict)?;
        // Validate the whole batch before changing any accepted cell.
        for (index, count) in &incoming[..length] {
            let name = evidence
                .classes
                .get(*index as usize)
                .ok_or(Refusal::Malformed)?;
            if snapshot.units.get(name).is_none_or(|old| count < old) {
                return Err(Refusal::Conflict);
            }
        }
        for (index, count) in &incoming[..length] {
            let name = &evidence.classes[*index as usize];
            *snapshot.units.get_mut(name).expect("reserved class cell") = *count;
        }
        evidence.reported_revision = revision;
        state.observed |= mask;
        state.history.push(hash);
        Ok(())
    }
    /// Called only after invocation capacity/leases are released, also on cancel/failure.
    /// The existing host flusher owns every accepted count from this point onward.
    pub fn released(&self, terminal: bool) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.released {
            return;
        }
        if state.history.is_empty() {
            if terminal {
                state.released = true;
                state.snapshot = None;
            }
            return;
        }
        if !terminal && state.handed_off == state.history.len() {
            return;
        }
        // The retained original is independent of the flusher's owned snapshot.
        // A later report cannot mutate a pending native commit or its evidence.
        let mut snapshot = state
            .snapshot
            .as_ref()
            .expect("unreleased snapshot")
            .clone();
        let observed = state.observed;
        let classes = &snapshot
            .measurement
            .as_ref()
            .expect("measurement evidence")
            .classes;
        snapshot.units.retain(|class, _| {
            classes
                .iter()
                .position(|name| name == class)
                .is_some_and(|index| observed & (1u64 << index) != 0)
        });
        if !self.gov.unit_checkpoints_enabled() {
            return;
        }
        if terminal {
            self.gov.finish_unit_checkpoint(snapshot);
            state.released = true;
            state.snapshot = None;
        } else {
            self.gov.stage_unit_checkpoint(snapshot);
        }
        state.handed_off = state.history.len();
    }
    fn settled(&self) -> bool {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.released && !self.gov.unit_checkpoint_pending(&self.id)
    }
}

#[cfg(test)]
mod tests;
