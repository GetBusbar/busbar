// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Process-local selected-resource rates. These ephemeral cells never enter the money ledger.
//! RPM is reserved until handoff; TPM observes high-water usage and explicit uncertainty.

use std::collections::BTreeMap;
#[cfg(any(test, feature = "test-support"))]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLockWriteGuard};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use busbar_contract::Count;
use busbar_plugin_abi::fallback_usage::class_text;
use foldhash::HashMap;

use super::selected_policy::ResolvedSelectedRules;
use super::sharded::Sharded;
use crate::plane_driver::PreparedRateAttempt;

const CELL_CAPACITY: usize = 262_144;
const MAX_RULES: usize = 32;
const MAX_CLASSES: usize = 64;
const MINUTE_MS: u64 = 60_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RateMetric {
    Requests,
    Tokens,
}

#[derive(Clone, Debug)]
pub(crate) struct RateTerms {
    // Shared with the current policy and the resolved request: a hold clones the handles, never the text.
    pub(crate) group_id: Arc<str>,
    pub(crate) rule_id: Arc<str>,
    pub(crate) key_id: Arc<str>,
    pub(crate) instance: Arc<str>,
    pub(crate) resource: Arc<str>,
    pub(crate) metric: RateMetric,
    pub(crate) threshold: u64,
    pub(crate) policy_revision: u64,
    pub(crate) activated_minute: u64,
}

impl RateTerms {
    fn scope_key(&self) -> String {
        let parts = [
            self.group_id.as_ref(),
            self.rule_id.as_ref(),
            self.key_id.as_ref(),
            self.instance.as_ref(),
            self.resource.as_ref(),
        ];
        let capacity = 1 + parts
            .iter()
            .map(|part| part.len() + decimal_digits(part.len()) + 1)
            .sum::<usize>();
        let mut key = String::with_capacity(capacity);
        for part in parts {
            // Infallible: fmt::Write into a String only grows it, within the capacity reserved above.
            let _ = std::fmt::Write::write_fmt(&mut key, format_args!("{}", part.len()));
            key.push(':');
            key.push_str(part);
        }
        key.push(match self.metric {
            RateMetric::Requests => 'r',
            RateMetric::Tokens => 't',
        });
        key
    }

    fn valid(&self) -> bool {
        [
            self.group_id.as_ref(),
            self.rule_id.as_ref(),
            self.key_id.as_ref(),
            self.instance.as_ref(),
            self.resource.as_ref(),
        ]
        .iter()
        .all(|s| !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control))
    }
}

/// The number of decimal digits `n` is written with (`0` has one).
fn decimal_digits(n: usize) -> usize {
    n.checked_ilog10().map_or(1, |digits| digits as usize + 1)
}

#[derive(Clone, Debug)]
pub(crate) struct RateSnapshot {
    pub(crate) rule: RateTerms,
    pub(crate) process_epoch: [u8; 16],
    pub(crate) window_start_ms: u64,
    pub(crate) window_end_ms: u64,
    pub(crate) provisional_requests: u64,
    pub(crate) committed_requests: u64,
    pub(crate) known_tokens: Count,
    pub(crate) uncertain: bool,
    pub(crate) exhausted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RateRefusalKind {
    Rpm,
    Tpm,
    Uncertain,
    ExhaustedArithmetic,
    StateCapacity,
    InvalidBinding,
    ExpiredReservation,
    ClockUnavailable,
}

#[derive(Debug)]
pub(crate) struct RateRefusal {
    pub(crate) kind: RateRefusalKind,
    pub(crate) snapshots: Vec<RateSnapshot>,
}

impl RateRefusal {
    fn bare(kind: RateRefusalKind) -> Self {
        Self {
            kind,
            snapshots: Vec::new(),
        }
    }
}

/// Owns the original preparation only after any provisional charges have been released.
#[derive(Debug)]
pub(crate) struct RateRejected {
    pub(crate) reason: RateRefusal,
    pub(crate) prepared: PreparedRateAttempt,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct EffectiveToken<'a> {
    pub(crate) class: &'a str,
    pub(crate) quantity: Option<Count>,
    pub(crate) authoritative: bool,
}

/// One complete declaration-aligned view, after the money consumer selects each source.
pub(crate) struct EffectiveTokenView<'a>(pub(crate) Vec<EffectiveToken<'a>>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TokenCoverage {
    Complete,
    Partial,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RateObservationError {
    InvalidView,
    Incomplete,
    Arithmetic,
    Sealed,
}

#[derive(Debug)]
pub(crate) struct RateFinalSnapshot {
    pub(crate) rules: Vec<RateSnapshot>,
    pub(crate) highwater: Vec<(Box<str>, Count)>,
}

struct RateClock {
    epoch: [u8; 16],
    boot_ms: Option<u64>,
    started: Instant,
    #[cfg(any(test, feature = "test-support"))]
    elapsed: Option<Arc<AtomicU64>>,
}

impl RateClock {
    fn new() -> Self {
        let started = Instant::now();
        let boot_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|n| u64::try_from(n.as_millis()).ok());
        Self {
            epoch: crate::snapshot::boot_nonce(),
            boot_ms,
            started,
            #[cfg(any(test, feature = "test-support"))]
            elapsed: None,
        }
    }

    fn minute(&self) -> Option<u64> {
        if self.epoch == [0; 16] {
            return None;
        }
        #[cfg(any(test, feature = "test-support"))]
        let elapsed = match &self.elapsed {
            Some(elapsed) => Some(elapsed.load(Ordering::Relaxed)),
            None => u64::try_from(self.started.elapsed().as_millis()).ok(),
        };
        #[cfg(not(any(test, feature = "test-support")))]
        let elapsed = u64::try_from(self.started.elapsed().as_millis()).ok();
        let minute = self.boot_ms?.checked_add(elapsed?)? / MINUTE_MS;
        minute.checked_add(1)?.checked_mul(MINUTE_MS)?;
        Some(minute)
    }
}

#[derive(Default)]
struct MinuteCell {
    provisional: u64,
    committed: u64,
    known: Count,
    exhausted: bool,
    references: usize,
    live_incomplete: u64,
    terminal_unknown_through: Option<u64>,
}

#[derive(Default)]
struct Scope {
    windows: BTreeMap<u64, MinuteCell>,
}

impl Scope {
    fn uncertain(&self, minute: u64) -> bool {
        self.windows.iter().any(|(&at, cell)| {
            (at < minute && cell.live_incomplete != 0)
                || cell
                    .terminal_unknown_through
                    .is_some_and(|through| through >= minute)
        })
    }
}

/// The write guards of the shards one hold's scopes live in (one per shard; eight inline).
type Locked<'a> = smallvec::SmallVec<[(usize, RwLockWriteGuard<'a, HashMap<String, Scope>>); 8]>;

/// One hold's captured scopes (at most MAX_RULES). A Vec: inline storage would grow every reservation
/// and the refusals that return one.
type Captures = Vec<Captured>;

struct Captured {
    terms: RateTerms,
    key: String,
    shard: usize,
}

impl Captured {
    fn map<'a, 'b>(&self, locks: &'b mut Locked<'a>) -> &'b mut HashMap<String, Scope> {
        &mut locks
            .iter_mut()
            .find(|(shard, _)| *shard == self.shard)
            .expect("captured shard is locked")
            .1
    }

    fn cell<'a, 'b>(&self, locks: &'b mut Locked<'a>, minute: u64) -> &'b mut MinuteCell {
        self.map(locks)
            .get_mut(&self.key)
            .and_then(|scope| scope.windows.get_mut(&minute))
            .expect("live rate guard retains its captured cell")
    }
}

/// The serving GovState retains this owner across policy reloads. No rate state is durable.
pub(crate) struct SelectedRates {
    cells: Sharded<Scope>,
    clock: RateClock,
    unavailable: AtomicBool,
    capacity: usize,
    leases: AtomicUsize,
    sweep_cursor: AtomicUsize,
}

impl super::GovState {
    pub(crate) fn selected_rates(&self) -> &Arc<SelectedRates> {
        &self.selected_rates
    }
}

impl SelectedRates {
    pub(super) fn new() -> Self {
        Self {
            cells: Sharded::new(),
            clock: RateClock::new(),
            unavailable: AtomicBool::new(false),
            capacity: CELL_CAPACITY,
            leases: AtomicUsize::new(0),
            sweep_cursor: AtomicUsize::new(0),
        }
    }

    /// A governor whose minute is `elapsed_ms / 60_000`, moved by the caller: B-RATE-HOLD's.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn stepped(started: Instant, elapsed_ms: Arc<AtomicU64>) -> Self {
        Self {
            cells: Sharded::new(),
            clock: RateClock {
                epoch: [1; 16],
                boot_ms: Some(0),
                started,
                elapsed: Some(elapsed_ms),
            },
            unavailable: AtomicBool::new(false),
            capacity: CELL_CAPACITY,
            leases: AtomicUsize::new(0),
            sweep_cursor: AtomicUsize::new(0),
        }
    }

    fn minute(&self) -> Result<u64, RateRefusal> {
        if !self.unavailable.load(Ordering::Acquire) {
            if let Some(minute) = self.clock.minute() {
                return Ok(minute);
            }
            self.unavailable.store(true, Ordering::Release);
        }
        Err(RateRefusal::bare(RateRefusalKind::ClockUnavailable))
    }

    /// Policy publication stamps activation on the same monotonic window clock as admission.
    pub(crate) fn activation_minute(&self) -> Result<u64, RateRefusal> {
        self.minute()
    }

    /// The rules' terms, built as `capture` takes them (no intermediate Vec).
    fn terms(
        resolved: &ResolvedSelectedRules,
    ) -> Result<impl ExactSizeIterator<Item = RateTerms> + '_, RateRefusal> {
        if resolved.rows().len() > MAX_RULES
            || (resolved.resource().is_none() && !resolved.rows().is_empty())
        {
            return Err(RateRefusal::bare(RateRefusalKind::InvalidBinding));
        }
        Ok(resolved.rows().iter().map(|row| RateTerms {
            group_id: Arc::clone(row.group_handle()),
            rule_id: Arc::clone(row.rule_handle()),
            key_id: Arc::clone(resolved.key_handle()),
            instance: Arc::clone(resolved.instance_handle()),
            resource: resolved.resource_handle().cloned().unwrap_or_default(),
            metric: row.metric(),
            threshold: row.threshold(),
            policy_revision: row.policy_revision(),
            activated_minute: row.activated_minute(),
        }))
    }

    pub(crate) fn reserve(
        self: &Arc<Self>,
        resolved: &ResolvedSelectedRules,
        prepared: PreparedRateAttempt,
    ) -> Result<RateReservation, RateRejected> {
        if resolved.key_id() != prepared.key_id()
            || resolved.instance() != prepared.instance()
            || resolved.resource() != prepared.resource()
        {
            return Err(RateRejected {
                reason: RateRefusal::bare(RateRefusalKind::InvalidBinding),
                prepared,
            });
        }
        let result = Self::terms(resolved).and_then(|terms| {
            self.sweep_next();
            self.reserve_terms(terms, prepared.physical_classes())
        });
        match result {
            Ok(hold) => Ok(RateReservation { hold, prepared }),
            Err(reason) => Err(RateRejected { reason, prepared }),
        }
    }

    /// The current-policy resolver has already bound the authenticated caller and candidate.
    /// Missing rows yield no headroom facts; this never creates cells or reserves capacity.
    pub(crate) fn headroom(
        &self,
        resolved: &ResolvedSelectedRules,
    ) -> Result<Vec<RateSnapshot>, RateRefusal> {
        self.headroom_terms(Self::terms(resolved)?)
    }

    fn capture(
        &self,
        terms: impl IntoIterator<Item = RateTerms, IntoIter: ExactSizeIterator>,
    ) -> Result<Captures, RateRefusal> {
        let terms = terms.into_iter();
        if terms.len() > MAX_RULES {
            return Err(RateRefusal::bare(RateRefusalKind::InvalidBinding));
        }
        let mut captures = Captures::with_capacity(terms.len());
        for terms in terms {
            if !terms.valid() {
                return Err(RateRefusal::bare(RateRefusalKind::InvalidBinding));
            }
            let key = terms.scope_key();
            if captures.iter().any(|held| held.key == key) {
                return Err(RateRefusal::bare(RateRefusalKind::InvalidBinding));
            }
            captures.push(Captured {
                shard: self.cells.shard_index(&key),
                key,
                terms,
            });
        }
        Ok(captures)
    }

    fn lock(&self, captures: &[Captured]) -> Locked<'_> {
        let mut mask = captures
            .iter()
            .fold(0u64, |mask, row| mask | (1u64 << row.shard));
        let mut locks = Locked::new();
        while mask != 0 {
            let index = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            locks.push((index, self.cells.shard_at(index).write()));
        }
        locks
    }

    fn prune_scope(&self, map: &mut HashMap<String, Scope>, key: &str, minute: u64) {
        let Some(scope) = map.get_mut(key) else {
            return;
        };
        let before = scope.windows.len();
        scope.windows.retain(|&at, cell| {
            at >= minute
                || cell.references != 0
                || cell
                    .terminal_unknown_through
                    .is_some_and(|through| through >= minute)
        });
        let released = before - scope.windows.len();
        if scope.windows.is_empty() {
            map.remove(key);
        }
        // The last scope/key is physically removed before its last lease is returned.
        self.leases.fetch_sub(released, Ordering::AcqRel);
    }

    fn sweep_map(&self, map: &mut HashMap<String, Scope>, minute: u64) {
        let mut released = 0;
        map.retain(|_, scope| {
            let before = scope.windows.len();
            scope.windows.retain(|&at, cell| {
                at >= minute
                    || cell.references != 0
                    || cell
                        .terminal_unknown_through
                        .is_some_and(|through| through >= minute)
            });
            released += before - scope.windows.len();
            !scope.windows.is_empty()
        });
        self.leases.fetch_sub(released, Ordering::AcqRel);
    }

    fn sweep_next(&self) {
        // A bounded rotating pass; capacity safety never relies on this pass making progress.
        let cursor = self.sweep_cursor.fetch_add(1, Ordering::Relaxed);
        if !cursor.is_multiple_of(64) {
            return;
        }
        if let Ok(minute) = self.minute() {
            let index = (cursor / 64) % super::GOV_SHARDS;
            self.sweep_map(&mut self.cells.shard_at(index).write(), minute);
        }
    }

    #[cfg(test)]
    fn sweep_all(&self) {
        let minute = self.minute().unwrap();
        for index in 0..super::GOV_SHARDS {
            self.sweep_map(&mut self.cells.shard_at(index).write(), minute);
        }
    }

    fn lease(&self, count: usize) -> bool {
        self.leases
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(count)
                    .filter(|total| *total <= self.capacity)
            })
            .is_ok()
    }

    fn snapshot(
        &self,
        row: &Captured,
        locks: &mut Locked<'_>,
        cell_minute: u64,
        now: u64,
    ) -> RateSnapshot {
        let scope = row.map(locks).get(&row.key);
        let cell = scope.and_then(|scope| scope.windows.get(&cell_minute));
        RateSnapshot {
            rule: row.terms.clone(),
            process_epoch: self.clock.epoch,
            window_start_ms: cell_minute * MINUTE_MS,
            window_end_ms: (cell_minute + 1) * MINUTE_MS,
            provisional_requests: cell.map_or(0, |cell| cell.provisional),
            committed_requests: cell.map_or(0, |cell| cell.committed),
            known_tokens: cell.map_or(Count::ZERO, |cell| cell.known),
            uncertain: scope.is_some_and(|scope| scope.uncertain(now)),
            exhausted: cell.is_some_and(|cell| cell.exhausted),
        }
    }

    fn blocked(
        &self,
        row: &Captured,
        locks: &mut Locked<'_>,
        minute: u64,
        reserve: bool,
    ) -> Option<RateRefusal> {
        let snapshot = self.snapshot(row, locks, minute, minute);
        let kind = if snapshot.exhausted {
            Some(RateRefusalKind::ExhaustedArithmetic)
        } else {
            match row.terms.metric {
                RateMetric::Requests if reserve => match snapshot
                    .committed_requests
                    .checked_add(snapshot.provisional_requests)
                    .and_then(|n| n.checked_add(1))
                {
                    None => Some(RateRefusalKind::ExhaustedArithmetic),
                    Some(total) if total > row.terms.threshold => Some(RateRefusalKind::Rpm),
                    Some(_) => None,
                },
                RateMetric::Tokens if snapshot.uncertain => Some(RateRefusalKind::Uncertain),
                RateMetric::Tokens
                    if snapshot.known_tokens
                        >= Count::from_micros(i128::from(row.terms.threshold) * 1_000_000) =>
                {
                    Some(RateRefusalKind::Tpm)
                }
                _ => None,
            }
        };
        kind.map(|kind| RateRefusal {
            kind,
            snapshots: vec![snapshot],
        })
    }

    pub(crate) fn reserve_terms<C: AsRef<str>>(
        self: &Arc<Self>,
        terms: impl IntoIterator<Item = RateTerms, IntoIter: ExactSizeIterator>,
        classes: &[C],
    ) -> Result<RateHold, RateRefusal> {
        if classes.len() > MAX_CLASSES
            || classes.iter().enumerate().any(|(at, class)| {
                class_text(class.as_ref().as_bytes()).is_err()
                    || classes[..at]
                        .iter()
                        .any(|old| old.as_ref() == class.as_ref())
            })
        {
            return Err(RateRefusal::bare(RateRefusalKind::InvalidBinding));
        }
        let captures = self.capture(terms)?;
        let mut locks = self.lock(&captures);
        let minute = if captures.is_empty() {
            0
        } else {
            self.minute()?
        };
        let mut missing = 0;
        for row in &captures {
            self.prune_scope(row.map(&mut locks), &row.key, minute);
            if let Some(refusal) = self.blocked(row, &mut locks, minute, true) {
                return Err(refusal);
            }
            if let Some(cell) = row
                .map(&mut locks)
                .get(&row.key)
                .and_then(|s| s.windows.get(&minute))
            {
                if cell.references == usize::MAX {
                    return Err(RateRefusal::bare(RateRefusalKind::ExhaustedArithmetic));
                }
            } else {
                missing += 1;
            }
        }
        if !self.lease(missing) {
            return Err(RateRefusal::bare(RateRefusalKind::StateCapacity));
        }
        for row in &captures {
            let cell = row
                .map(&mut locks)
                .entry(row.key.clone())
                .or_default()
                .windows
                .entry(minute)
                .or_default();
            cell.references += 1;
            if row.terms.metric == RateMetric::Requests {
                cell.provisional += 1;
            }
        }
        drop(locks);
        Ok(RateHold {
            rates: self.clone(),
            captures,
            minute,
            phase: Phase::Reserved,
            classes: classes
                .iter()
                .map(|class| ClassHighwater {
                    class: class.as_ref().into(),
                    amount: Count::ZERO,
                    authoritative: false,
                })
                .collect(),
        })
    }

    fn headroom_terms(
        &self,
        terms: impl IntoIterator<Item = RateTerms, IntoIter: ExactSizeIterator>,
    ) -> Result<Vec<RateSnapshot>, RateRefusal> {
        let captures = self.capture(terms)?;
        if captures.is_empty() {
            return Ok(Vec::new());
        }
        let mut locks = self.lock(&captures);
        let minute = self.minute()?;
        Ok(captures
            .iter()
            .map(|row| {
                self.prune_scope(row.map(&mut locks), &row.key, minute);
                self.snapshot(row, &mut locks, minute, minute)
            })
            .collect())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Reserved,
    Committed,
    Finished,
}

struct ClassHighwater {
    class: Box<str>,
    amount: Count,
    authoritative: bool,
}

pub(crate) struct RateHold {
    rates: Arc<SelectedRates>,
    captures: Captures,
    minute: u64,
    phase: Phase,
    classes: Vec<ClassHighwater>,
}

impl RateHold {
    fn release_reserved(&mut self, locks: &mut Locked<'_>, now: u64) {
        for row in &self.captures {
            let cell = row.cell(locks, self.minute);
            if row.terms.metric == RateMetric::Requests {
                cell.provisional -= 1;
            }
            cell.references -= 1;
            self.rates.prune_scope(row.map(locks), &row.key, now);
        }
        self.phase = Phase::Finished;
    }

    pub(crate) fn commit(&mut self) -> Result<(), RateRefusal> {
        if self.phase != Phase::Reserved {
            return Err(RateRefusal::bare(RateRefusalKind::InvalidBinding));
        }
        if self.captures.is_empty() {
            self.phase = Phase::Committed;
            return Ok(());
        }
        let rates = self.rates.clone();
        let mut locks = rates.lock(&self.captures);
        let now = rates.minute();
        let refusal = match &now {
            Err(_) => Some(RateRefusal::bare(RateRefusalKind::ClockUnavailable)),
            Ok(now) if *now != self.minute => {
                Some(RateRefusal::bare(RateRefusalKind::ExpiredReservation))
            }
            Ok(now) => self.captures.iter().find_map(|row| {
                rates.blocked(row, &mut locks, *now, false).or_else(|| {
                    let cell = row.cell(&mut locks, self.minute);
                    let overflow = match row.terms.metric {
                        RateMetric::Requests => cell.committed == u64::MAX,
                        RateMetric::Tokens => cell.live_incomplete == u64::MAX,
                    };
                    overflow.then(|| RateRefusal::bare(RateRefusalKind::ExhaustedArithmetic))
                })
            }),
        };
        if let Some(refusal) = refusal {
            self.release_reserved(&mut locks, now.unwrap_or(self.minute));
            return Err(refusal);
        }
        for row in &self.captures {
            let cell = row.cell(&mut locks, self.minute);
            match row.terms.metric {
                RateMetric::Requests => {
                    cell.provisional -= 1;
                    cell.committed += 1;
                }
                RateMetric::Tokens => cell.live_incomplete += 1,
            }
        }
        self.phase = Phase::Committed;
        Ok(())
    }

    fn exhaust(&self, locks: &mut Locked<'_>) {
        for row in &self.captures {
            if row.terms.metric == RateMetric::Tokens {
                row.cell(locks, self.minute).exhausted = true;
            }
        }
    }

    pub(crate) fn observe(
        &mut self,
        view: &EffectiveTokenView<'_>,
    ) -> Result<(), RateObservationError> {
        if self.phase != Phase::Committed {
            return Err(RateObservationError::Sealed);
        }
        if view.0.len() != self.classes.len()
            || view.0.iter().enumerate().any(|(at, value)| {
                !self
                    .classes
                    .iter()
                    .any(|held| held.class.as_ref() == value.class)
                    || view.0[..at].iter().any(|other| other.class == value.class)
                    || value.quantity.is_some_and(Count::is_negative)
                    || (value.authoritative && value.quantity.is_none())
            })
        {
            return Err(RateObservationError::InvalidView);
        }
        let delta = Count::total(self.classes.iter().map(|held| {
            let quantity = view
                .0
                .iter()
                .find(|value| value.class == held.class.as_ref())
                .and_then(|value| value.quantity)
                .unwrap_or(Count::ZERO);
            // Both values are nonnegative; subtracting the smaller is exact and cannot overflow.
            quantity
                .max(held.amount)
                .checked_sub(held.amount)
                .expect("nonnegative high-water difference")
        }));
        let rates = self.rates.clone();
        let mut locks = rates.lock(&self.captures);
        let delta = match delta {
            Ok(delta) => delta,
            Err(_) => {
                self.exhaust(&mut locks);
                return Err(RateObservationError::Arithmetic);
            }
        };
        if self.captures.iter().any(|row| {
            row.terms.metric == RateMetric::Tokens
                && row
                    .cell(&mut locks, self.minute)
                    .known
                    .checked_add(delta)
                    .is_err()
        }) {
            self.exhaust(&mut locks);
            return Err(RateObservationError::Arithmetic);
        }
        for row in &self.captures {
            if row.terms.metric == RateMetric::Tokens {
                let cell = row.cell(&mut locks, self.minute);
                cell.known = cell
                    .known
                    .checked_add(delta)
                    .expect("all-row checked token addition");
            }
        }
        for held in &mut self.classes {
            let value = view
                .0
                .iter()
                .find(|value| value.class == held.class.as_ref())
                .expect("complete validated physical class view");
            held.amount = held.amount.max(value.quantity.unwrap_or(Count::ZERO));
            held.authoritative = value.authoritative;
        }
        Ok(())
    }

    pub(crate) fn finish(
        &mut self,
        coverage: TokenCoverage,
    ) -> Result<RateFinalSnapshot, RateObservationError> {
        if self.phase != Phase::Committed {
            return Err(RateObservationError::Sealed);
        }
        let invalid = coverage == TokenCoverage::Complete
            && self.classes.iter().any(|class| !class.authoritative);
        let unknown = invalid || coverage != TokenCoverage::Complete;
        let rates = self.rates.clone();
        let mut locks = rates.lock(&self.captures);
        // Clock failure latches the entire governor unavailable; it cannot reopen headroom.
        let now = rates.minute().unwrap_or(self.minute);
        for row in &self.captures {
            let cell = row.cell(&mut locks, self.minute);
            if row.terms.metric == RateMetric::Tokens {
                if unknown {
                    cell.terminal_unknown_through = Some(
                        cell.terminal_unknown_through
                            .map_or(now, |old| old.max(now)),
                    );
                }
                cell.live_incomplete -= 1;
            }
            cell.references -= 1;
        }
        let rules = self
            .captures
            .iter()
            .map(|row| rates.snapshot(row, &mut locks, self.minute, now))
            .collect();
        for row in &self.captures {
            rates.prune_scope(row.map(&mut locks), &row.key, now);
        }
        self.phase = Phase::Finished;
        if invalid {
            return Err(RateObservationError::Incomplete);
        }
        Ok(RateFinalSnapshot {
            rules,
            highwater: self
                .classes
                .iter()
                .map(|held| (held.class.clone(), held.amount))
                .collect(),
        })
    }
}

impl Drop for RateHold {
    fn drop(&mut self) {
        match self.phase {
            Phase::Reserved => {
                let rates = self.rates.clone();
                let mut locks = rates.lock(&self.captures);
                self.release_reserved(&mut locks, rates.minute().unwrap_or(self.minute));
            }
            Phase::Committed => {
                let _ = self.finish(TokenCoverage::Unknown);
            }
            Phase::Finished => {}
        }
    }
}

pub(crate) struct RateReservation {
    hold: RateHold,
    prepared: PreparedRateAttempt,
}

impl RateReservation {
    pub(crate) fn prepared(&self) -> &PreparedRateAttempt {
        &self.prepared
    }

    /// Releases the unsent hold before returning the original preparation for no-send
    /// finalization or a permitted retry within the same prepared partition.
    pub(crate) fn cancel(self) -> PreparedRateAttempt {
        let Self { hold, prepared } = self;
        drop(hold);
        prepared
    }

    pub(crate) fn try_commit(self) -> Result<CommittedRate, RateRejected> {
        let Self { mut hold, prepared } = self;
        match hold.commit() {
            Ok(()) => Ok(CommittedRate { hold, prepared }),
            Err(reason) => Err(RateRejected { reason, prepared }),
        }
    }
}

pub(crate) struct CommittedRate {
    hold: RateHold,
    prepared: PreparedRateAttempt,
}

impl CommittedRate {
    pub(crate) fn prepared(&self) -> &PreparedRateAttempt {
        &self.prepared
    }

    pub(crate) fn observe(
        &mut self,
        view: &EffectiveTokenView<'_>,
    ) -> Result<(), RateObservationError> {
        self.hold.observe(view)
    }

    pub(crate) fn seal(
        mut self,
        coverage: TokenCoverage,
    ) -> Result<RateFinalSnapshot, RateObservationError> {
        self.hold.finish(coverage)
    }
}

#[cfg(test)]
#[path = "selected_resource_tests.rs"]
mod tests;
