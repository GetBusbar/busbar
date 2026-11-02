//! The per-(pool, destination) circuit-breaker state machine.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

use crate::cfg::{BreakerCfg, TripMode};

/// Cell state encoding for the atomic `breaker_state` field. Kept as plain `u64` constants (not a

const ST_CLOSED: u64 = 0;
const ST_OPEN: u64 = 1;
const ST_HALF_OPEN: u64 = 2;

/// Bounded capacity of a cell's sliding outcome window (recent request outcomes feeding the

const OUTCOME_WINDOW_CAPACITY: usize = 1024;

/// FNV-1a 64-bit hash constants — used only to decorrelate simultaneous trips' jitter (see

const FNV1A_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV1A_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Lock a `std::sync::Mutex` without panicking on poison — a poisoned outcome-window or

fn lock_recover<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A bounded sliding window of recent outcomes (success/error), used to compute the error-rate trip
/// signal. Backed by a `VecDeque` so dropping the oldest entry at capacity is O(1).
#[derive(Debug, Clone)]
struct OutcomeWindow {
    /// `(timestamp_secs, is_error)` per outcome, oldest at the front.
    entries: std::collections::VecDeque<(u64, bool)>,
    capacity: usize,
}

impl OutcomeWindow {
    fn new(capacity: usize) -> Self {
        Self {
            entries: std::collections::VecDeque::new(),
            capacity,
        }
    }

    fn push(&mut self, ts: u64, is_error: bool) {
        if self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back((ts, is_error));
    }

    /// How many outcomes fall inside the window, and how many of those were errors — in ONE pass.

    fn outcomes_in_window(&self, now: u64, window_s: u64) -> (usize, usize) {
        let start = now.saturating_sub(window_s);
        let mut total = 0;
        let mut errors = 0;
        for (ts, is_error) in self.entries.iter() {
            if *ts >= start {
                total += 1;
                errors += usize::from(*is_error);
            }
        }
        (total, errors)
    }

    fn clear(&mut self) {
        self.entries.clear();
    }
}

/// One breaker cell: the FSM state for a single `(pool, destination)` pair.
pub struct BreakerCell {
    breaker_state: AtomicU64,
    streak: AtomicU32,
    cooldown_until: AtomicU64,
    probe_in_flight: AtomicBool,
    /// Monotonic single-flight probe generation, bumped each time a probe is WON (an Open→HalfOpen
    probe_epoch: AtomicU64,
    /// Lifetime error count on this cell. NOT reset by recovery (`cell_closed`) — mirrors the
    err: AtomicU64,
    outcome_window: Mutex<OutcomeWindow>,
    /// Serializes every transition that touches BOTH `breaker_state` and `cooldown_until` as a
    transition_lock: Mutex<()>,
}

impl Default for BreakerCell {
    fn default() -> Self {
        Self::new()
    }
}

impl BreakerCell {
    /// A fresh, Closed cell with an empty outcome window.
    pub fn new() -> Self {
        Self {
            breaker_state: AtomicU64::new(ST_CLOSED),
            streak: AtomicU32::new(0),
            cooldown_until: AtomicU64::new(0),
            probe_in_flight: AtomicBool::new(false),
            probe_epoch: AtomicU64::new(0),
            err: AtomicU64::new(0),
            outcome_window: Mutex::new(OutcomeWindow::new(OUTCOME_WINDOW_CAPACITY)),
            transition_lock: Mutex::new(()),
        }
    }

    /// Lifetime error count recorded against this cell (monotonic; not reset by recovery).
    pub fn err_count(&self) -> u64 {
        self.err.load(Ordering::Relaxed)
    }

    /// The consecutive-failure streak the escalating cooldown reads.
    pub fn streak(&self) -> u32 {
        self.streak.load(Ordering::Relaxed)
    }

    /// The raw cooldown deadline, in Unix seconds (0 when none is armed).
    pub fn cooldown_until(&self) -> u64 {
        self.cooldown_until.load(Ordering::Acquire)
    }

    /// The single-flight probe generation — the owner token the last probe winner holds.
    pub fn probe_epoch(&self) -> u64 {
        self.probe_epoch.load(Ordering::Acquire)
    }

    /// Whether a won recovery probe is still outstanding on this cell.
    pub fn probe_in_flight(&self) -> bool {
        self.probe_in_flight.load(Ordering::Acquire)
    }

    /// `(outcomes, errors)` recorded within `window_s` seconds of `now` — the error-rate trip

    pub fn outcomes_in_window(&self, now: u64, window_s: u64) -> (usize, usize) {
        lock_recover(&self.outcome_window).outcomes_in_window(now, window_s)
    }

    /// What survives a rebuild of this cell: its state and cooldown read as ONE pair under the

    pub fn snapshot(&self) -> CellSnapshot {
        let (state, cooldown_until) = {
            let _tx = lock_recover(&self.transition_lock);
            (
                self.breaker_state.load(Ordering::Acquire),
                self.cooldown_until.load(Ordering::Acquire),
            )
        };
        CellSnapshot {
            state,
            cooldown_until,
            streak: self.streak.load(Ordering::Relaxed),
            err: self.err.load(Ordering::Relaxed),
        }
    }

    /// Hold the transition lock, for a test that must park a transition at it.
    #[cfg(test)]
    pub(crate) fn transition_guard(&self) -> std::sync::MutexGuard<'_, ()> {
        lock_recover(&self.transition_lock)
    }

    /// Carry a [`Self::snapshot`] into this cell. A snapshot taken mid-probe restores as Open: the

    pub fn restore(&self, snap: CellSnapshot) {
        let _tx = lock_recover(&self.transition_lock);
        let state = if snap.state == ST_HALF_OPEN {
            ST_OPEN
        } else {
            snap.state
        };
        self.cooldown_until
            .store(snap.cooldown_until, Ordering::Release);
        self.breaker_state.store(state, Ordering::Release);
        self.probe_in_flight.store(false, Ordering::Release);
        self.streak.store(snap.streak, Ordering::Relaxed);
        self.err.store(snap.err, Ordering::Relaxed);
    }
}

/// A cell's persisted form (see [`BreakerCell::snapshot`]). `state` is the cell's own encoding —
/// `0` Closed, `1` Open, `2` HalfOpen — the value a persisted health snapshot has always carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CellSnapshot {
    /// The FSM state, in the cell's own encoding.
    pub state: u64,
    /// The cooldown deadline, in Unix seconds.
    pub cooldown_until: u64,
    /// The consecutive-failure streak.
    pub streak: u32,
    /// The lifetime error count.
    pub err: u64,
}

impl CellSnapshot {
    /// The verdict a cell [`BreakerCell::restore`]d from this snapshot would give at `now`, read

    pub fn verdict(&self, now: u64) -> BreakerVerdict {
        let state = if self.state == ST_HALF_OPEN {
            ST_OPEN
        } else {
            self.state
        };
        decode(state, self.cooldown_until, now)
    }
}

/// A cell's verdict from its state and cooldown, the one decoding [`BreakerCell::verdict`] and

fn decode(state: u64, until: u64, now: u64) -> BreakerVerdict {
    match state {
        ST_CLOSED => {
            if now >= until {
                BreakerVerdict::Ready
            } else {
                BreakerVerdict::Open { until }
            }
        }
        ST_OPEN => {
            if now >= until {
                BreakerVerdict::ProbeWinnable
            } else {
                BreakerVerdict::Open { until }
            }
        }
        ST_HALF_OPEN => BreakerVerdict::HalfOpen,

        _ => BreakerVerdict::Open { until: u64::MAX },
    }
}

/// Public FSM state, independent of any pending soft cooldown detail beyond `until`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Admitting normally.
    Closed,
    /// Suppressed until the cooldown deadline (Unix seconds).
    Open {
        /// The cooldown deadline, in Unix seconds.
        until: u64,
    },
    /// A single-flight recovery probe is in flight; no one else may dispatch.
    HalfOpen,
}

/// The decoded breaker situation for one cell at an instant — the output of the single
/// [`BreakerCell::verdict`] decoder. Read-only: `ProbeWinnable` reports that a probe COULD be won,
/// it does not win one ([`BreakerCell::acquire`] still owns that CAS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerVerdict {
    /// Closed and any pending soft cooldown has elapsed — admit without a probe.
    Ready,
    /// Suppressed: Open (or Closed still inside a soft cooldown) whose deadline has not elapsed.
    Open {
        /// The cooldown deadline, in Unix seconds.
        until: u64,
    },
    /// A peer holds the single-flight recovery probe — not winnable right now.
    HalfOpen,
    /// Expired-Open: a single-flight recovery probe could be won here (a mutating acquire is
    /// needed to actually win it).
    ProbeWinnable,
}

/// Why a probe acquisition was refused, decided by the same read that refused it.
///
/// A refusal has to carry its own reason: a caller that went back to the cell for one would be
/// reading a cell a peer may have moved in between, and could describe a refusal with a situation
/// that would have admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeniedBy {
    /// The cell is suppressed until the deadline — Open and still cooling, or Closed inside a
    /// lingering cooldown.
    Cooling {
        /// The cooldown deadline, in Unix seconds.
        until: u64,
    },
    /// The cell is HalfOpen: a peer holds the single-flight recovery probe.
    ProbeInFlight,
}

/// The outcome of a mutating probe-acquisition attempt ([`BreakerCell::acquire`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeAdmit {
    /// Refused, with the situation that refused it.
    Denied(DeniedBy),
    /// Admitted on a Closed-and-ready cell — a no-op CAS that won no probe; nothing to release.
    ReadyNoProbe,
    /// Won the single-flight recovery probe (Open→HalfOpen). Carries the owner-token epoch for a
    /// later owner-checked release.
    ProbeWon(u64),
}

/// What a recorded failure actually did to a cell ([`BreakerCell::record_failure`]).
///
/// The arm is decided under the cell's transition lock and reported from there, so a caller never
/// has to infer it from a state read taken before the call — a read a concurrent transition can
/// invalidate: a trip metric counts a fresh trip, and must not count a failed recovery probe's
/// reopen as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureEffect {
    /// A Closed cell reached its trip threshold and opened. The logical trip a metric counts.
    Tripped,
    /// A HalfOpen cell's recovery probe failed, so the cell reopened with a fresh cooldown. Not a
    /// fresh trip: the cell was already tripped.
    Reopened,
    /// A Closed cell stayed closed but was benched for a cooldown, below the trip threshold.
    Benched,
    /// Nothing changed: an already-Open cell, or a sub-threshold failure on a cell that does not
    /// bench below the threshold.
    Nothing,
}

impl FailureEffect {
    /// Whether this was a logical Closed→Open trip — the boolean a trip metric counts.
    pub fn tripped(self) -> bool {
        matches!(self, FailureEffect::Tripped)
    }
}

impl BreakerCell {
    /// THE single decoder of a cell's breaker situation. Read-only — no Open→HalfOpen transition,

    pub fn verdict(&self, now: u64) -> BreakerVerdict {
        let state = self.breaker_state.load(Ordering::Acquire);
        let until = self.cooldown_until.load(Ordering::Acquire);
        decode(state, until, now)
    }

    /// Side-effect-free readiness: would this cell admit a request right now, without stealing the

    pub fn ready(&self, now: u64) -> bool {
        matches!(
            self.verdict(now),
            BreakerVerdict::Ready | BreakerVerdict::ProbeWinnable
        )
    }

    /// The cell's current [`BreakerState`], for observability.
    pub fn state(&self) -> BreakerState {
        match self.breaker_state.load(Ordering::Acquire) {
            ST_CLOSED => BreakerState::Closed,
            ST_OPEN => BreakerState::Open {
                until: self.cooldown_until.load(Ordering::Acquire),
            },
            ST_HALF_OPEN => BreakerState::HalfOpen,
            _ => BreakerState::Closed,
        }
    }

    /// Evaluate the trip condition for a Closed → Open transition.
    fn should_trip(&self, now: u64, cfg: &BreakerCfg) -> bool {
        let window = lock_recover(&self.outcome_window);
        match cfg.trip.mode {
            TripMode::ErrorRate => {
                let (count, errors) = window.outcomes_in_window(now, cfg.trip.window_s);
                if count < cfg.trip.min_requests {
                    return false;
                }
                (errors as f64 / count as f64) >= cfg.trip.threshold
            }
            TripMode::Consecutive => self.streak.load(Ordering::Relaxed) >= cfg.trip.consecutive_n,
        }
    }

    /// Compute the escalating cooldown duration, with jitter and an optional requested-wait floor.

    pub fn compute_cooldown_with_retry_after(
        &self,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
        max_honored_retry_after_secs: u64,
    ) -> u64 {
        let streak = self.streak.load(Ordering::Relaxed);

        let mut duration = if streak == 0 {
            cfg.base_cooldown_secs
        } else {
            let shift = streak.min(63);
            let shifted = (cfg.base_cooldown_secs as u128) << shift;
            u64::try_from(shifted)
                .unwrap_or(u64::MAX)
                .min(cfg.max_cooldown_secs)
        };

        {
            let jitter_range = (duration / 10).max(1);
            let time_seed = now_time as u128;
            let cell_id = self as *const _ as *const () as usize as u128;
            let mut seed = FNV1A_OFFSET_BASIS as u128;
            for part in [time_seed, cell_id, streak as u128] {
                seed = (seed ^ part).wrapping_mul(FNV1A_PRIME as u128);
            }
            let jitter_seed = seed;

            let span = 2 * jitter_range as u128 + 1;
            let unbiased = (jitter_seed % span) as i64;
            let jitter = unbiased - jitter_range as i64;
            let jittered = if jitter >= 0 {
                duration.saturating_add(jitter as u64)
            } else {
                duration.saturating_sub(jitter.unsigned_abs())
            };

            let floor = (duration / 2).max(1).min(cfg.max_cooldown_secs);
            duration = jittered.clamp(floor, cfg.max_cooldown_secs);
        }

        match (cfg.honor_retry_after, retry_after) {
            (true, Some(ra)) => duration.max(ra.min(max_honored_retry_after_secs)),
            (false, Some(_)) | (true, None) | (false, None) => duration,
        }
    }

    /// `open` body, assuming the caller already holds `transition_lock` (used by the record paths

    fn open_locked(
        &self,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
        max_honored_retry_after_secs: u64,
    ) {
        let duration = self.compute_cooldown_with_retry_after(
            now_time,
            cfg,
            retry_after,
            max_honored_retry_after_secs,
        );

        self.cooldown_until
            .fetch_max(now_time.saturating_add(duration), Ordering::Release);
        self.breaker_state.store(ST_OPEN, Ordering::Release);

        self.probe_in_flight.store(false, Ordering::Release);
    }

    /// Transition the cell to Open with an escalated cooldown. Acquires the transition lock.
    pub fn open(
        &self,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
        max_honored_retry_after_secs: u64,
    ) {
        let _tx = lock_recover(&self.transition_lock);
        self.open_locked(now_time, cfg, retry_after, max_honored_retry_after_secs);
    }

    /// `close` body, assuming the caller already holds `transition_lock`.
    fn close_locked(&self) {
        self.streak.store(0, Ordering::Release);

        lock_recover(&self.outcome_window).clear();
        self.cooldown_until.store(0, Ordering::Release);
        self.breaker_state.store(ST_CLOSED, Ordering::Release);
        self.probe_in_flight.store(false, Ordering::Release);
    }

    /// Full recovery to Closed: reset streak/window, clear the cooldown, release the probe.
    pub fn close(&self) {
        let _tx = lock_recover(&self.transition_lock);
        self.close_locked();
    }

    /// Recovery close for an out-of-band health probe: closes the cell ONLY if no peer has since

    pub fn close_if_recoverable(&self, now: u64, observed_cooldown: u64) -> bool {
        let _tx = lock_recover(&self.transition_lock);
        if self.cooldown_until.load(Ordering::Acquire) > observed_cooldown {
            return false;
        }
        let suppressed = self.breaker_state.load(Ordering::Acquire) != ST_CLOSED
            || self.cooldown_until.load(Ordering::Acquire) > now;
        if suppressed {
            self.close_locked();
        }
        suppressed
    }

    /// Release an UNDISPATCHED single-flight probe (owner-checked): a strict no-op unless

    pub fn release_probe_owned(&self, owned_epoch: u64) {
        let _tx = lock_recover(&self.transition_lock);
        if self.probe_epoch.load(Ordering::Acquire) != owned_epoch {
            return;
        }
        let _ = self.breaker_state.compare_exchange(
            ST_HALF_OPEN,
            ST_OPEN,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        self.probe_in_flight.store(false, Ordering::Release);
    }

    /// The mutating probe-acquisition step, run only on the one destination a dispatch path

    pub fn acquire(&self, now: u64) -> ProbeAdmit {
        let _tx = lock_recover(&self.transition_lock);
        let until = self.cooldown_until.load(Ordering::Acquire);
        match self.breaker_state.load(Ordering::Acquire) {
            ST_CLOSED => {
                if now >= until {
                    ProbeAdmit::ReadyNoProbe
                } else {
                    ProbeAdmit::Denied(DeniedBy::Cooling { until })
                }
            }
            ST_OPEN => {
                if now < until {
                    return ProbeAdmit::Denied(DeniedBy::Cooling { until });
                }
                self.breaker_state.store(ST_HALF_OPEN, Ordering::Release);

                self.probe_epoch.fetch_add(1, Ordering::AcqRel);
                self.probe_in_flight.store(true, Ordering::Release);
                ProbeAdmit::ProbeWon(self.probe_epoch.load(Ordering::Acquire))
            }
            ST_HALF_OPEN => ProbeAdmit::Denied(DeniedBy::ProbeInFlight),

            _ => ProbeAdmit::Denied(DeniedBy::Cooling { until: u64::MAX }),
        }
    }

    /// Record a failure (transient or rate-limit — identical breaker handling) against the cell:

    pub fn record_failure(
        &self,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
        max_honored_retry_after_secs: u64,
    ) -> FailureEffect {
        lock_recover(&self.outcome_window).push(now_time, true);
        self.err.fetch_add(1, Ordering::Relaxed);

        let _tx = lock_recover(&self.transition_lock);
        match self.breaker_state.load(Ordering::Acquire) {
            ST_CLOSED => {
                self.streak.fetch_add(1, Ordering::Relaxed);
                if self.should_trip(now_time, cfg) {
                    self.open_locked(now_time, cfg, retry_after, max_honored_retry_after_secs);
                    FailureEffect::Tripped
                } else if !cfg.bench_below_trip_threshold {
                    if cfg.honor_retry_after {
                        if let Some(asked) = retry_after {
                            self.cooldown_until.fetch_max(
                                now_time.saturating_add(asked.min(max_honored_retry_after_secs)),
                                Ordering::Release,
                            );
                        }
                    }
                    FailureEffect::Nothing
                } else {
                    let duration = self.compute_cooldown_with_retry_after(
                        now_time,
                        cfg,
                        retry_after,
                        max_honored_retry_after_secs,
                    );
                    self.cooldown_until
                        .fetch_max(now_time.saturating_add(duration), Ordering::Release);
                    FailureEffect::Benched
                }
            }

            ST_HALF_OPEN => {
                self.streak.fetch_add(1, Ordering::Relaxed);
                self.open_locked(now_time, cfg, retry_after, max_honored_retry_after_secs);
                FailureEffect::Reopened
            }

            ST_OPEN => FailureEffect::Nothing,
            _ => FailureEffect::Nothing,
        }
    }

    /// Record a success against the cell: reset the streak (unless the cell is Open — see below),

    pub fn record_success(&self, now_time: u64) -> bool {
        if self.breaker_state.load(Ordering::Acquire) == ST_CLOSED
            && self.streak.load(Ordering::Acquire) == 0
        {
            lock_recover(&self.outcome_window).push(now_time, false);
            return false;
        }

        let _tx = lock_recover(&self.transition_lock);

        if self.breaker_state.load(Ordering::Acquire) != ST_OPEN {
            self.streak.store(0, Ordering::Release);
        }
        lock_recover(&self.outcome_window).push(now_time, false);
        if self
            .breaker_state
            .compare_exchange(ST_HALF_OPEN, ST_CLOSED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.close_locked();
            return true;
        }
        false
    }

    /// Trip this cell hard-down: a sticky cooldown of `hard_down_cooldown_secs`, unconditionally

    pub fn hard_down(&self, now_time: u64, hard_down_cooldown_secs: u64) -> bool {
        let _tx = lock_recover(&self.transition_lock);
        let was_closed = self.breaker_state.load(Ordering::Acquire) == ST_CLOSED;
        self.cooldown_until.store(
            now_time.saturating_add(hard_down_cooldown_secs),
            Ordering::Release,
        );
        self.breaker_state.store(ST_OPEN, Ordering::Release);
        self.probe_in_flight.store(false, Ordering::Release);
        was_closed
    }
}
