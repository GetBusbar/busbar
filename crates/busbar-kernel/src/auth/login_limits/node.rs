// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-NODE LIMITERS: source buckets, the global alarm, the per-method outage breaker, the
//! admin door and the audit gate. They are about this node's traffic and sit on the hot path, so
//! they live in memory; the per-account limiter, which protects the directory, is fleet-wide in the
//! core store (`super::account`). Every function takes `now` (Unix seconds) so tests drive time.

use std::collections::VecDeque;

use foldhash::HashMap;
use std::net::IpAddr;

use super::policy::{Limit, LoginLimitsPolicy};
use super::source::SourceBucket;

/// The most source buckets one node tracks (per table).
pub(crate) const MAX_TRACKED: usize = 65_536;

/// A failure reservation in the source table, settled after the plugin answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceTicket {
    ip: IpAddr,
    id: u64,
}

/// Why the source table refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceRefusal {
    /// The source's failure ceiling (or an aggregate's) is reached.
    Failures(SourceBucket),
    /// The source's submission rate is reached.
    Submissions(SourceBucket),
}

#[derive(Debug, Default)]
pub(crate) struct Bucket {
    /// (time, ticket id) of each failure, reservations included.
    pub(crate) failures: VecDeque<(u64, u64)>,
    /// Time of each submission in the last minute (base buckets only).
    pub(crate) submissions: VecDeque<u64>,
    /// When the bucket was last touched.
    pub(crate) touched: u64,
}

impl Bucket {
    pub(crate) fn prune(&mut self, now: u64, window: u64) {
        while self
            .failures
            .front()
            .is_some_and(|(t, _)| now.saturating_sub(*t) >= window)
        {
            self.failures.pop_front();
        }
        while self
            .submissions
            .front()
            .is_some_and(|t| now.saturating_sub(*t) >= 60)
        {
            self.submissions.pop_front();
        }
    }

    pub(crate) fn idle(&self) -> bool {
        self.failures.is_empty() && self.submissions.is_empty()
    }
}

/// The per-source failure and submission table.
#[derive(Debug, Default)]
pub(crate) struct SourceTable {
    pub(crate) buckets: HashMap<SourceBucket, Bucket>,
    next_id: u64,
}

impl SourceTable {
    /// Judge one submission from `ip` and, when admitted, reserve one failure unit in every bucket
    /// of its hierarchy. `tightened`: the global alarm is tripped (a quarter of the failures, a
    /// third of the submissions).
    pub(crate) fn reserve(
        &mut self,
        ip: IpAddr,
        policy: &LoginLimitsPolicy,
        tightened: bool,
        now: u64,
    ) -> Result<SourceTicket, SourceRefusal> {
        let p = policy.source;
        let window = p.failures.window_secs;
        let cut = |n: u32, by: u32| {
            if tightened {
                (n / by).max(1)
            } else {
                n
            }
        };
        let ceilings = [p.failures.max, p.aggregate_48, p.aggregate_32];
        let submissions = cut(p.submissions_per_minute, 3);
        self.make_room(now, window);
        for (i, b) in SourceBucket::hierarchy(ip).enumerate() {
            let bucket = self.buckets.entry(b).or_default();
            bucket.prune(now, window);
            bucket.touched = now;
            if i == 0 {
                if bucket.submissions.len() >= submissions as usize {
                    return Err(SourceRefusal::Submissions(b));
                }
                bucket.submissions.push_back(now);
            }
            if bucket.failures.len() >= cut(ceilings[i], 4) as usize {
                return Err(SourceRefusal::Failures(b));
            }
        }
        self.next_id = self.next_id.wrapping_add(1);
        let id = self.next_id;
        for b in SourceBucket::hierarchy(ip) {
            if let Some(bucket) = self.buckets.get_mut(&b) {
                bucket.failures.push_back((now, id));
            }
        }
        Ok(SourceTicket { ip, id })
    }

    /// Return a reservation: the attempt was not a failure.
    pub(crate) fn refund(&mut self, ticket: &SourceTicket) {
        for b in SourceBucket::hierarchy(ticket.ip) {
            if let Some(bucket) = self.buckets.get_mut(&b) {
                bucket.failures.retain(|(_, id)| *id != ticket.id);
            }
        }
    }

    /// Bound the table: drop idle buckets, then (still full) the least recently touched bucket
    /// that is not at a ceiling. A throttled bucket is never evicted while another can go. The
    /// sweep runs only when the table is full (`cold::auth::login`).
    fn make_room(&mut self, now: u64, window: u64) {
        if self.buckets.len() < MAX_TRACKED {
            return;
        }
        self.evict(now, window);
    }

    #[cfg(test)]
    pub(crate) fn tracked(&self) -> usize {
        self.buckets.len()
    }
}

/// THE GLOBAL ALARM: failures per minute on this node, as 60 one-second cells.
#[derive(Debug)]
pub(crate) struct GlobalAlarm {
    cells: [(u64, u32); 60],
    tripped: bool,
}

impl Default for GlobalAlarm {
    fn default() -> Self {
        Self {
            cells: [(0, 0); 60],
            tripped: false,
        }
    }
}

/// A change of the alarm's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AlarmChange {
    /// It tripped with this many failures in the last minute.
    Tripped(u32),
    /// It cleared.
    Cleared,
}

impl GlobalAlarm {
    fn rate(&self, now: u64) -> u32 {
        self.cells
            .iter()
            .filter(|(t, _)| now.saturating_sub(*t) < 60)
            .map(|(_, n)| *n)
            .sum()
    }

    /// Count one failure; `Some` when this one tripped the alarm.
    pub(crate) fn failure(&mut self, threshold: u32, now: u64) -> Option<AlarmChange> {
        let cell = &mut self.cells[(now % 60) as usize];
        if cell.0 != now {
            *cell = (now, 0);
        }
        cell.1 = cell.1.saturating_add(1);
        let rate = self.rate(now);
        if !self.tripped && rate >= threshold {
            self.tripped = true;
            return Some(AlarmChange::Tripped(rate));
        }
        None
    }

    /// Whether the alarm is tripped now; `Some(Cleared)` as it clears.
    pub(crate) fn poll(&mut self, threshold: u32, now: u64) -> (bool, Option<AlarmChange>) {
        if self.tripped && self.rate(now) < threshold {
            self.tripped = false;
            return (false, Some(AlarmChange::Cleared));
        }
        (self.tripped, None)
    }
}

/// THE PER-METHOD OUTAGE BREAKER: [`BREAKER_OUTAGES`] plugin outages within
/// [`BREAKER_WINDOW_SECS`] open it for [`BREAKER_OPEN_SECS`].
#[derive(Debug, Default)]
pub(crate) struct Breaker {
    outages: VecDeque<u64>,
    open_until: u64,
}

/// Outages that open the breaker.
pub const BREAKER_OUTAGES: usize = 5;
/// Their window, seconds.
const BREAKER_WINDOW_SECS: u64 = 60;
/// How long it stays open, seconds (also its `Retry-After`).
pub const BREAKER_OPEN_SECS: u64 = 30;

impl Breaker {
    /// Whether the method is held open now.
    pub(crate) fn open(&self, now: u64) -> bool {
        now < self.open_until
    }

    /// Count one plugin outage; `true` when this one opened the breaker.
    pub(crate) fn outage(&mut self, now: u64) -> bool {
        while self
            .outages
            .front()
            .is_some_and(|t| now.saturating_sub(*t) >= BREAKER_WINDOW_SECS)
        {
            self.outages.pop_front();
        }
        self.outages.push_back(now);
        if self.outages.len() >= BREAKER_OUTAGES && !self.open(now) {
            self.outages.clear();
            self.open_until = now + BREAKER_OPEN_SECS;
            return true;
        }
        false
    }
}

/// THE ADMIN DOOR: presented-and-refused credentials per source.
#[derive(Debug, Default)]
pub(crate) struct AdminTable {
    pub(crate) buckets: HashMap<SourceBucket, VecDeque<u64>>,
}

impl AdminTable {
    /// `Some(retry_after_secs)` when `ip` has spent its budget: the time until its oldest refusal
    /// leaves the window.
    pub(crate) fn throttled(&mut self, ip: IpAddr, limit: Limit, now: u64) -> Option<u64> {
        let bucket = self.buckets.get_mut(&SourceBucket::base(ip))?;
        while bucket
            .front()
            .is_some_and(|t| now.saturating_sub(*t) >= limit.window_secs)
        {
            bucket.pop_front();
        }
        if bucket.len() < limit.max as usize {
            return None;
        }
        let oldest = *bucket.front()?;
        Some((oldest + limit.window_secs).saturating_sub(now).max(1))
    }

    /// Count one refused credential from `ip`; `true` when it is the one that spent the budget
    /// (the first refusal of the window, which is audited).
    pub(crate) fn refused(&mut self, ip: IpAddr, limit: Limit, now: u64) -> bool {
        if self.buckets.len() >= MAX_TRACKED {
            self.evict(now, limit.window_secs);
        }
        let bucket = self.buckets.entry(SourceBucket::base(ip)).or_default();
        while bucket
            .front()
            .is_some_and(|t| now.saturating_sub(*t) >= limit.window_secs)
        {
            bucket.pop_front();
        }
        bucket.push_back(now);
        bucket.len() == limit.max as usize
    }
}

/// The global per-node budget of login audit records per minute.
const AUDIT_BUDGET_PER_MINUTE: u32 = 60;

/// THE AUDIT GATE: first record per (action, subject) per window, within a per-node budget; every
/// suppressed record is counted and summarised once its minute has passed.
#[derive(Debug, Default)]
pub(crate) struct AuditGate {
    /// action -> subject -> the window its record was written in.
    pub(crate) latches: HashMap<String, HashMap<String, u64>>,
    /// How many (action, subject) latches `latches` holds.
    pub(crate) latched: usize,
    minute: u64,
    spent: u32,
    suppressed: u64,
}

/// What the gate decided for one record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuditDecision {
    /// Write it.
    pub(crate) record: bool,
    /// A summary to write first: how many records the previous minutes suppressed.
    pub(crate) summary: Option<u64>,
}

impl AuditGate {
    /// Judge one record of `action` about `subject` under a latch of `window_secs`.
    pub(crate) fn admit(
        &mut self,
        action: &str,
        subject: &str,
        window_secs: u64,
        now: u64,
    ) -> AuditDecision {
        let minute = now / 60;
        let mut summary = None;
        if minute != self.minute {
            if self.suppressed > 0 {
                summary = Some(self.suppressed);
            }
            self.minute = minute;
            self.spent = 0;
            self.suppressed = 0;
        }
        let window = now / window_secs.max(1);
        let latched = self.latches.get(action).and_then(|s| s.get(subject)) == Some(&window);
        if latched || self.spent >= AUDIT_BUDGET_PER_MINUTE {
            self.suppressed = self.suppressed.saturating_add(1);
            return AuditDecision {
                record: false,
                summary,
            };
        }
        if self.latched >= MAX_TRACKED {
            self.evict(window);
        }
        match self
            .latches
            .get_mut(action)
            .and_then(|s| s.get_mut(subject))
        {
            Some(w) => *w = window,
            None => self.first_latch(action, subject, window),
        }
        self.spent += 1;
        AuditDecision {
            record: true,
            summary,
        }
    }
}

/// Consecutive account-throttled windows that make a sustained (targeted) throttle.
pub const SUSTAINED_WINDOWS: u32 = 4;

/// Tracks how many consecutive windows each account has been throttled in.
#[derive(Debug, Default)]
pub(crate) struct Sustained {
    pub(crate) accounts: HashMap<String, (u64, u32, bool)>,
}

impl Sustained {
    /// Note a throttle of `fingerprint`; `true` once it has been throttled in more than
    /// [`SUSTAINED_WINDOWS`] consecutive windows (once per window).
    pub(crate) fn throttled(&mut self, fingerprint: &str, window_secs: u64, now: u64) -> bool {
        let window = now / window_secs.max(1);
        if self.accounts.len() >= MAX_TRACKED {
            self.evict(window);
        }
        if !self.accounts.contains_key(fingerprint) {
            self.first_throttle(fingerprint, window);
        }
        let Some(entry) = self.accounts.get_mut(fingerprint) else {
            return false;
        };
        if entry.1 == 0 || window == entry.0 + 1 {
            entry.1 += 1;
            entry.2 = false;
        } else if window != entry.0 {
            entry.1 = 1;
            entry.2 = false;
        }
        entry.0 = window;
        if entry.1 > SUSTAINED_WINDOWS && !entry.2 {
            entry.2 = true;
            return true;
        }
        false
    }
}

#[cfg(test)]
#[path = "../tests/login_limits_node_tests.rs"]
mod tests;
