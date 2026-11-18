// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Process-lifetime phase cells. Raw histogram queues and caller-owned output are not retained
//! here. Allocation failure is fatal; fixed-capacity admission refusal is a counted observation.

use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64 as HealthCounter};
use std::sync::TryLockError;

/// Request telemetry captures refused, by `reason` (DES-337 catalogue).
pub(crate) const TELEMETRY_REQUEST_CAPTURE_REFUSALS_TOTAL: &str =
    "busbar_telemetry_request_capture_refusals_total";
/// Request telemetry store cells, by `state` (DES-337 catalogue).
pub(crate) const TELEMETRY_REQUEST_CELLS: &str = "busbar_telemetry_request_cells";
/// Bytes reserved by the request telemetry store (DES-337 catalogue).
pub(crate) const TELEMETRY_REQUEST_RESERVED_BYTES: &str = "busbar_telemetry_request_reserved_bytes";

const LABELS: [&str; 4] = ["plane", "phase", "pool", "ingress_protocol"];
const OUTCOMES: [&str; 5] = ["ok", "exhausted", "client_error", "error", ""];
const LOSS: [&str; 6] = [
    "invalid_duration",
    "integer_overflow",
    "series_capacity",
    "boot_nonce_unavailable",
    "histogram_capacity",
    "unregistered_labels",
];
const CAPACITY: usize = 8192;
const MIB: usize = 1024 * 1024;
const TARGET_CHARGE: usize = 64;

// Static dispatch avoids touching thread banks or a registration mutex when recording.
static BANK_TARGETS: [OnceLock<Histogram>; CAPACITY] = [const { OnceLock::new() }; CAPACITY];
static STORE: OnceLock<Arc<RequestStore>> = OnceLock::new();
static UNAVAILABLE: HealthCounter = HealthCounter::new(0);

pub(crate) fn process() -> &'static Arc<RequestStore> {
    STORE.get_or_init(|| Arc::new(RequestStore::new(true)))
}

pub(crate) fn unavailable() {
    saturating_increment(&UNAVAILABLE);
}

fn saturating_increment(counter: &HealthCounter) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
}

fn reserved<T>(capacity: usize) -> Vec<T> {
    let mut values = Vec::new();
    if values.try_reserve_exact(capacity).is_err() {
        std::process::abort();
    }
    values
}

fn filled<T>(capacity: usize, mut make: impl FnMut() -> T) -> Vec<T> {
    let mut values = reserved(capacity);
    values.extend((0..capacity).map(|_| make()));
    values
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
struct Labels {
    bytes: [[u8; 256]; 4],
    lengths: [u16; 4],
}

impl Labels {
    fn value(&self, index: usize) -> &str {
        std::str::from_utf8(&self.bytes[index][..usize::from(self.lengths[index])])
            .expect("metadata copies validated UTF-8 strings")
    }

    fn key(&self) -> Key {
        Key::from_parts(
            crate::telemetry::REQUEST_PHASE_DURATION,
            LABELS
                .iter()
                .enumerate()
                .map(|(i, name)| metrics::Label::new(*name, self.value(i).to_owned()))
                .collect::<Vec<_>>(),
        )
    }
}

struct Parsed {
    labels: Labels,
    outcome: usize,
    order: u16,
}

fn parse<'a>(labels: impl IntoIterator<Item = (&'a str, &'a str)>) -> Option<Parsed> {
    let mut result = Parsed {
        labels: Labels {
            bytes: [[0; 256]; 4],
            lengths: [0; 4],
        },
        outcome: 4,
        order: 0,
    };
    let mut seen = 0u8;
    for (count, (name, value)) in labels.into_iter().enumerate() {
        let index = if name == "outcome" {
            4
        } else {
            LABELS.iter().position(|key| *key == name)?
        };
        if count >= 5 || seen & (1 << index) != 0 {
            return None;
        }
        seen |= 1 << index;
        result.order |= (u16::try_from(index).expect("five label indices") + 1) << (count * 3);
        if index == 4 {
            result.outcome = OUTCOMES[..4]
                .iter()
                .position(|outcome| *outcome == value)
                .unwrap_or(4);
        } else {
            if value.len() > 256 || value.trim().is_empty() || value.chars().any(char::is_control) {
                return None;
            }
            result.labels.bytes[index][..value.len()].copy_from_slice(value.as_bytes());
            result.labels.lengths[index] =
                u16::try_from(value.len()).expect("label is at most 256 bytes");
        }
    }
    if seen & 15 != 15
        || !matches!(
            result.labels.value(1),
            "LlmProducerDrive" | "MountedResponseReady"
        )
    {
        return None;
    }
    Some(result)
}

#[derive(Clone, Default)]
struct Cell {
    distribution: RequestDistribution,
    observed: bool,
}

struct State {
    cells: Vec<Cell>,
    index: Vec<usize>,
    dropped: [u64; 6],
}

struct Captured {
    index: usize,
    distribution: RequestDistribution,
}

struct RequestCore {
    labels: Vec<OnceLock<Labels>>,
    state: Mutex<State>,
    workspace: Mutex<Vec<Captured>>,
    busy: [HealthCounter; 2],
    active: AtomicBool,
    production: bool,
    nonce: Option<&'static str>,
}

impl RequestCore {
    fn enabled(&self) -> bool {
        if self.production {
            super::super::enabled()
        } else {
            self.active.load(Ordering::Relaxed)
        }
    }

    fn refused(&self, reason: usize) {
        if !self.enabled() {
            return;
        }
        let mut state = lock(&self.state);
        state.dropped[reason] = state.dropped[reason].saturating_add(1);
    }
}

struct PhaseTarget {
    core: Arc<RequestCore>,
    cell: usize,
    outcome: usize,
}

impl HistogramFn for PhaseTarget {
    fn record(&self, value: f64) {
        if !self.core.enabled() {
            return;
        }
        let mut state = lock(&self.core.state);
        let error = if self.core.nonce.is_none() {
            Some(3)
        } else {
            let cell = &mut state.cells[self.cell];
            cell.observed = true;
            cell.distribution.add(value, OUTCOMES[self.outcome]).err()
        };
        if let Some(reason) = error {
            state.dropped[reason] = state.dropped[reason].saturating_add(1);
        }
    }
}

struct RefusalTarget {
    core: Arc<RequestCore>,
    reason: usize,
}
impl HistogramFn for RefusalTarget {
    fn record(&self, _: f64) {
        self.core.refused(self.reason);
    }
}

struct Binding {
    cell: usize,
    outcome: usize,
    order: u16,
    slot: u32,
}

pub(crate) struct RequestStore {
    core: Arc<RequestCore>,
    targets: Vec<[Arc<PhaseTarget>; 5]>,
    refusals: [Arc<RefusalTarget>; 6],
    bindings: Mutex<Vec<Binding>>,
    reserved_bytes: usize,
}

impl RequestStore {
    #[cfg(test)]
    pub(super) fn seed(&self, key: &Key, distribution: RequestDistribution) {
        let parsed = parse(key.labels().map(|label| (label.key(), label.value()))).unwrap();
        let cell = self.cell(&parsed).unwrap();
        lock(&self.core.state).cells[cell] = Cell {
            distribution,
            observed: true,
        };
    }

    pub(super) fn new(production: bool) -> Self {
        Self::with_nonce(production, process_boot_nonce())
    }

    fn with_nonce(production: bool, nonce: Option<&'static str>) -> Self {
        let labels = filled(CAPACITY, OnceLock::new);
        let cells = filled(CAPACITY, Cell::default);
        let index = reserved(CAPACITY);
        let workspace = reserved(CAPACITY);
        let bindings = reserved(CAPACITY);
        let metadata_bytes = labels.capacity() * std::mem::size_of::<OnceLock<Labels>>()
            + cells.capacity() * std::mem::size_of::<Cell>();
        let workspace_bytes = workspace.capacity() * std::mem::size_of::<Captured>();
        let index_bytes = index.capacity() * std::mem::size_of::<usize>();
        let binding_bytes = bindings.capacity() * std::mem::size_of::<Binding>();
        let core = Arc::new(RequestCore {
            labels,
            state: Mutex::new(State {
                cells,
                index,
                dropped: [0; 6],
            }),
            workspace: Mutex::new(workspace),
            busy: std::array::from_fn(|_| HealthCounter::new(0)),
            active: AtomicBool::new(true),
            production,
            nonce,
        });
        let mut targets = reserved(CAPACITY);
        for cell in 0..CAPACITY {
            targets.push(std::array::from_fn(|outcome| {
                Arc::new(PhaseTarget {
                    core: Arc::clone(&core),
                    cell,
                    outcome,
                })
            }));
        }
        let refusals = std::array::from_fn(|reason| {
            Arc::new(RefusalTarget {
                core: Arc::clone(&core),
                reason,
            })
        });
        let target_bytes = CAPACITY * 5 * TARGET_CHARGE
            + 6 * TARGET_CHARGE
            + targets.capacity() * std::mem::size_of::<[Arc<PhaseTarget>; 5]>()
            + index_bytes;
        // Conservative charged Arc headers/alignment, fixed dispatch, descriptors, binding index,
        // and construction scratch. Allocator bookkeeping and caller outputs are excluded.
        let control_bytes = std::mem::size_of::<Self>()
            + std::mem::size_of::<RequestCore>()
            + 128
            + std::mem::size_of_val(&BANK_TARGETS)
            + binding_bytes
            + CAPACITY * 256;
        if !(metadata_bytes <= 16 * MIB
            && target_bytes <= 4 * MIB
            && workspace_bytes <= 4 * MIB
            && control_bytes <= 8 * MIB)
        {
            std::process::abort();
        }
        Self {
            core,
            targets,
            refusals,
            bindings: Mutex::new(bindings),
            reserved_bytes: metadata_bytes + target_bytes + workspace_bytes + control_bytes,
        }
    }

    fn cell(&self, parsed: &Parsed) -> Result<usize, usize> {
        let mut state = lock(&self.core.state);
        let position = state.index.binary_search_by(|index| {
            self.core.labels[*index]
                .get()
                .expect("published metadata")
                .cmp(&parsed.labels)
        });
        match position {
            Ok(position) => Ok(state.index[position]),
            Err(position) => {
                let cell = state.index.len();
                if cell == CAPACITY {
                    return Err(2);
                }
                assert!(
                    self.core.labels[cell].set(parsed.labels.clone()).is_ok(),
                    "cell metadata is published once"
                );
                state.index.insert(position, cell);
                Ok(cell)
            }
        }
    }

    fn target(&self, cell: usize, outcome: usize) -> Histogram {
        Histogram::from_arc(Arc::clone(&self.targets[cell][outcome]))
    }

    pub(super) fn register<'a>(
        &self,
        labels: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Histogram {
        let Some(parsed) = parse(labels) else {
            return Histogram::from_arc(Arc::clone(&self.refusals[5]));
        };
        match self.cell(&parsed) {
            Ok(cell) => self.target(cell, parsed.outcome),
            Err(reason) => Histogram::from_arc(Arc::clone(&self.refusals[reason])),
        }
    }

    fn capture<R>(
        &self,
        consume: impl FnOnce(&[Captured], [u64; 6], usize, u64, u64) -> R,
    ) -> Option<R> {
        let mut workspace = match self.core.workspace.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
            Err(TryLockError::WouldBlock) => {
                saturating_increment(&self.core.busy[0]);
                return None;
            }
        };
        let state = match self.core.state.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
            Err(TryLockError::WouldBlock) => {
                saturating_increment(&self.core.busy[1]);
                return None;
            }
        };
        workspace.clear();
        for (index, cell) in state.cells[..state.index.len()].iter().enumerate() {
            if cell.observed {
                workspace.push(Captured {
                    index,
                    distribution: cell.distribution.clone(),
                });
            }
        }
        let dropped = state.dropped;
        let reserved = state.index.len();
        let Some(captured_at) = unix_millis(SystemTime::now()).filter(|time| *time != 0) else {
            if self.core.production {
                unavailable();
            }
            return None;
        };
        let Some((_, uptime)) = process_generation() else {
            if self.core.production {
                unavailable();
            }
            return None;
        };
        drop(state);
        workspace.sort_by(|a, b| {
            self.core.labels[a.index]
                .get()
                .cmp(&self.core.labels[b.index].get())
        });
        Some(consume(&workspace, dropped, reserved, captured_at, uptime))
    }

    pub(super) fn snapshot(&self, limit: usize) -> Option<RequestSnapshot> {
        self.snapshot_with_scope(limit, &mut None).ok().flatten()
    }

    pub(super) fn snapshot_with_scope(
        &self,
        limit: usize,
        scope: &mut Option<CaptureScope>,
    ) -> Result<Option<RequestSnapshot>, OutputError> {
        let Some(nonce) = self.core.nonce else {
            if self.core.production {
                unavailable();
            }
            return Ok(None);
        };
        self.capture(|rows, dropped, _, captured_at_unix_ms, uptime_ms| {
            let count = limit.min(32).min(rows.len());
            if let Some(scope) = scope {
                let mut bound = output::Bound::default();
                bound.add(nonce.len())?;
                bound.vector::<RequestIdentity>(count)?;
                for row in &rows[..count] {
                    let labels = self.core.labels[row.index]
                        .get()
                        .expect("captured metadata");
                    for index in 0..4 {
                        bound.add(labels.value(index).len())?;
                    }
                }
                bound.reserve(scope)?;
            }
            Ok(RequestSnapshot {
                process_boot_nonce: nonce.to_owned(),
                uptime_ms,
                captured_at_unix_ms,
                omitted_identities: u64::try_from(rows.len() - count).expect("8192 bounded rows"),
                dropped,
                identities: rows[..count]
                    .iter()
                    .map(|row| {
                        let labels = self.core.labels[row.index]
                            .get()
                            .expect("captured metadata");
                        let d = &row.distribution;
                        RequestIdentity {
                            plane: labels.value(0).to_owned(),
                            phase: labels.value(1).to_owned(),
                            pool: labels.value(2).to_owned(),
                            ingress_protocol: labels.value(3).to_owned(),
                            count: d.count,
                            errors: d.errors,
                            client_errors: d.client_errors,
                            sum_us: d.sum_us,
                            bins: d.bins,
                        }
                    })
                    .collect(),
            })
        })
        .transpose()
    }

    #[cfg(test)]
    pub(super) fn put(&self, out: &mut Building) -> Option<()> {
        self.put_with_scope(out, &mut None).ok().flatten()
    }

    pub(super) fn put_with_scope(
        &self,
        out: &mut Building,
        scope: &mut Option<CaptureScope>,
    ) -> Result<Option<()>, OutputError> {
        self.capture(|rows, dropped, reserved, _, _| {
            if let Some(nonce) = self.core.nonce {
                for row in rows {
                    let labels = self.core.labels[row.index]
                        .get()
                        .expect("captured metadata");
                    if let Some(scope) = scope {
                        // Preflight the entire phase row before even constructing its temporary
                        // Key/label lists. `put` below remains the shared projection algorithm.
                        for name in [
                            REQUEST_COUNT,
                            REQUEST_SUM,
                            REQUEST_ERRORS,
                            REQUEST_CLIENT_ERRORS,
                        ]
                        .into_iter()
                        .chain(std::iter::repeat_n(REQUEST_BIN, 16))
                        {
                            let labels = ["plane", "phase", "pool", "ingress_protocol"]
                                .into_iter()
                                .enumerate()
                                .map(|(i, name)| (name, labels.value(i)))
                                .chain([
                                    ("process_boot_nonce", nonce),
                                    ("upper_bound_ms", "120000"),
                                ]);
                            output::series_labels(scope, name, labels, 1)?;
                        }
                    }
                    row.distribution.put(out, &labels.key(), nonce);
                }
            }
            if let Some(scope) = scope {
                // Six loss families, two cell states, reserved storage and three busy reasons.
                for _ in 0..12 {
                    output::series_labels(
                        scope,
                        TELEMETRY_REQUEST_CAPTURE_REFUSALS_TOTAL,
                        [("reason", "source_unavailable")].into_iter(),
                        1,
                    )?;
                }
            }
            for (reason, count) in LOSS.iter().zip(dropped) {
                if count != 0 {
                    put(
                        out,
                        SCRAPE_KIND_COUNTER,
                        &Key::from_parts(
                            crate::telemetry::REQUEST_PHASE_DROPPED,
                            vec![metrics::Label::new("reason", *reason)],
                        ),
                        vec![("", None, count.to_string())],
                    );
                }
            }
            for (state, value) in [("reserved", reserved), ("observed", rows.len())] {
                put(
                    out,
                    SCRAPE_KIND_GAUGE,
                    &Key::from_parts(
                        TELEMETRY_REQUEST_CELLS,
                        vec![metrics::Label::new("state", state)],
                    ),
                    vec![("", None, value.to_string())],
                );
            }
            put(
                out,
                SCRAPE_KIND_GAUGE,
                &Key::from_name(TELEMETRY_REQUEST_RESERVED_BYTES),
                vec![("", None, self.reserved_bytes.to_string())],
            );
            for (reason, count) in [
                ("workspace_busy", self.core.busy[0].load(Ordering::Relaxed)),
                ("state_busy", self.core.busy[1].load(Ordering::Relaxed)),
                (
                    "source_unavailable",
                    if self.core.production {
                        UNAVAILABLE.load(Ordering::Relaxed)
                    } else {
                        0
                    },
                ),
            ] {
                put(
                    out,
                    SCRAPE_KIND_COUNTER,
                    &Key::from_parts(
                        TELEMETRY_REQUEST_CAPTURE_REFUSALS_TOTAL,
                        vec![metrics::Label::new("reason", reason)],
                    ),
                    vec![("", None, count.to_string())],
                );
            }
            Ok(())
        })
        .transpose()
    }
}

#[cfg(test)]
pub(crate) fn with_workspace_held<R>(operation: impl FnOnce() -> R) -> R {
    let _workspace = lock(&process().core.workspace);
    operation()
}

#[cfg(test)]
#[path = "../tests/request_store_tests.rs"]
pub(super) mod tests;

pub(crate) fn bank_target(slot: usize) -> Option<&'static Histogram> {
    BANK_TARGETS.get(slot)?.get()
}

pub(crate) fn refused(reason: usize) {
    if !super::super::enabled() {
        return;
    }
    process().core.refused(reason);
}

pub(crate) fn intern_bank(labels: &[(&str, &str)]) -> Result<u32, usize> {
    let parsed = parse(labels.iter().copied()).ok_or(5usize)?;
    let store = process();
    let mut bindings = lock(&store.bindings);
    if let Some(binding) = bindings.iter().find(|binding| {
        binding.outcome == parsed.outcome
            && binding.order == parsed.order
            && store.core.labels[binding.cell].get() == Some(&parsed.labels)
    }) {
        return Ok(binding.slot);
    }
    let mut descs = crate::telemetry::registry()
        .hists
        .descs
        .write()
        .unwrap_or_else(PoisonError::into_inner);
    if descs.len() == CAPACITY {
        return Err(4);
    }
    let cell = store.cell(&parsed)?;
    let target = store.target(cell, parsed.outcome);
    let slot = u32::try_from(descs.len()).expect("histogram slots bounded to 8192");
    let handle = OnceLock::new();
    assert!(handle.set(target.clone()).is_ok());
    descs.push(Arc::new(crate::telemetry::SlotDesc {
        name: crate::telemetry::REQUEST_PHASE_DURATION,
        labels: Vec::new(),
        handle,
        flushed: std::sync::atomic::AtomicU64::new(0),
        retired: std::sync::atomic::AtomicU64::new(0),
    }));
    assert!(
        BANK_TARGETS[slot as usize].set(target).is_ok(),
        "phase bank ID is published once"
    );
    bindings.push(Binding {
        cell,
        outcome: parsed.outcome,
        order: parsed.order,
        slot,
    });
    Ok(slot)
}
