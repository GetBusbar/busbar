//! The per-(pool, destination) circuit-breaker state machine.
//!
//! Moved byte-identical from `busbar-core::store::in_memory::breaker` (1.5.5's
//! `crates/busbar-core/src/store/in_memory/breaker.rs`). The SWRR weighted-selection state and the
//! striped lifetime counters that lived alongside `BreakerCell` in the source belong to the EGRESS
//! unit (it owns the pool and picks among members) — they are intentionally not ported here; this
//! crate owns only the breaker's own fields: state, streak, cooldown, the single-flight probe, the
//! error counter, and the sliding outcome window.
//!
//! One structural simplification from the source: 1.5.5 had TWO cell shapes (`LaneState`'s
//! embedded default-cell fields, and a separate `BreakerCell` for named pools) unified behind a
//! `BreakerCellAccess` trait so the FSM logic could run against either without duplication. This
//! unit has exactly one destination-cell shape (every cell, including a lane's default `""` pool,
//! is a [`BreakerCell`]), so that trait collapses to inherent methods on one struct — the FSM
//! arithmetic itself (cooldown, jitter, the Retry-After floor, every state transition) is
//! unchanged.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

use crate::cfg::{BreakerCfg, TripMode};

/// Cell state encoding for the atomic `breaker_state` field. Kept as plain `u64` constants (not a
/// enum-backed atomic) exactly as in the source, so the encoding a persisted snapshot carries is
/// stable and CAS-able.
const ST_CLOSED: u64 = 0;
const ST_OPEN: u64 = 1;
const ST_HALF_OPEN: u64 = 2;

/// Bounded capacity of a cell's sliding outcome window (recent request outcomes feeding the
/// error-rate trip computation).
const OUTCOME_WINDOW_CAPACITY: usize = 1024;

/// FNV-1a 64-bit hash constants — used only to decorrelate simultaneous trips' jitter (see
/// [`compute_cooldown_with_retry_after`]), not for any identity or security property.
const FNV1A_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV1A_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Lock a `std::sync::Mutex` without panicking on poison — a poisoned outcome-window or
/// transition lock still protects a perfectly usable `VecDeque`/pair of atomics; refusing every
/// subsequent request because one panicked mid-critical-section would be a self-inflicted outage.
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

    fn count_in_window(&self, now: u64, window_s: u64) -> usize {
        let start = now.saturating_sub(window_s);
        self.entries.iter().filter(|(ts, _)| *ts >= start).count()
    }

    fn error_count_in_window(&self, now: u64, window_s: u64) -> usize {
        let start = now.saturating_sub(window_s);
        self.entries
            .iter()
            .filter(|(ts, is_error)| *ts >= start && *is_error)
            .count()
    }

    fn clear(&mut self) {
        self.entries.clear();
    }
}

/// One breaker cell: the FSM state for a single `(pool, destination)` pair.
pub struct BreakerCell {
    breaker_state: AtomicU64, // ST_CLOSED / ST_OPEN / ST_HALF_OPEN
    streak: AtomicU32,
    cooldown_until: AtomicU64,
    probe_in_flight: AtomicBool,
    /// Monotonic single-flight probe generation, bumped each time a probe is WON (an Open→HalfOpen
    /// CAS). The probe's owner token: the winner captures the post-bump value and passes it back to
    /// the owner-checked release, which reverts the cell only if the epoch still matches. Without
    /// this, a stalled release could revert a NEWER probe a different caller has since won.
    probe_epoch: AtomicU64,
    /// Lifetime error count on this cell. NOT reset by recovery (`cell_closed`) — mirrors the
    /// source, where this doubles as a public lifetime counter on the default cell.
    err: AtomicU64,
    outcome_window: Mutex<OutcomeWindow>,
    /// Serializes every transition that touches BOTH `breaker_state` and `cooldown_until` as a
    /// pair (trip, close, the Open→HalfOpen probe acquire). The hot read path
    /// ([`breaker_verdict`]) does not take this lock; only the comparatively rare transitions do.
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

/// The outcome of a mutating probe-acquisition attempt ([`BreakerCell::acquire`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeAdmit {
    /// Refused: HalfOpen with a peer's probe in flight, a still-cooling Open cell, or a Closed cell
    /// inside a lingering cooldown.
    Denied,
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
/// invalidate. Two different callers need two different facts out of the same event: a trip metric
/// counts a fresh trip, and the probe journal records a reopen.
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

    /// Whether this reopened a cell whose recovery probe failed — the event the probe journal
    /// records.
    pub fn reopened(self) -> bool {
        matches!(self, FailureEffect::Reopened)
    }
}

impl BreakerCell {
    /// THE single decoder of a cell's breaker situation. Read-only — no Open→HalfOpen transition,
    /// no probe CAS. Every "is the breaker open" question resolves here so the notions can never
    /// drift between the selection filter, observability, and the mutating admit path.
    pub fn verdict(&self, now: u64) -> BreakerVerdict {
        let until = self.cooldown_until.load(Ordering::Acquire);
        match self.breaker_state.load(Ordering::Acquire) {
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
            // Fails SAFE: an unrecognized encoding is never reachable under the atomic-sentinel
            // invariant this module maintains, but a never-elapsing Open denies admission rather
            // than panicking the caller.
            _ => BreakerVerdict::Open { until: u64::MAX },
        }
    }

    /// Side-effect-free readiness: would this cell admit a request right now, without stealing the
    /// single-flight recovery probe? `Ready` or `ProbeWinnable`; never `Open`/`HalfOpen`.
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
            _ => BreakerState::Closed, // fail benign on a total, side-effect-free read
        }
    }

    /// Evaluate the trip condition for a Closed → Open transition.
    fn should_trip(&self, now: u64, cfg: &BreakerCfg) -> bool {
        let window = lock_recover(&self.outcome_window);
        match cfg.trip.mode {
            TripMode::ErrorRate => {
                let count = window.count_in_window(now, cfg.trip.window_s);
                if count < cfg.trip.min_requests {
                    return false;
                }
                let errors = window.error_count_in_window(now, cfg.trip.window_s);
                (errors as f64 / count as f64) >= cfg.trip.threshold
            }
            TripMode::Consecutive => self.streak.load(Ordering::Relaxed) >= cfg.trip.consecutive_n,
        }
    }

    /// Compute the escalating cooldown duration, with jitter and an optional Retry-After floor.
    ///
    /// `streak == 0` gives `base_cooldown_secs`; otherwise `base << streak.min(63)` computed in
    /// u128 (a plain u64 `checked_shl` guards only the shift COUNT, not the value — an even base at
    /// `streak >= 63` would otherwise wrap to zero, giving a zero cooldown exactly when the lane is
    /// failing hardest), saturated to u64, then capped at `max_cooldown_secs`.
    ///
    /// ±10% jitter is then applied on EVERY trip, including the `streak == 0` base — a fleet of
    /// lanes tripping on the same base would otherwise get an identical cooldown and a synchronized
    /// thundering herd of half-open probes. The jitter seed mixes the wall clock, this cell's
    /// address, and the streak (FNV-1a) so lanes failing within nanoseconds of each other still
    /// decorrelate. The result is clamped to `[(duration/2).max(1), max_cooldown_secs]` — the
    /// `.max(1)` floor exists so `base_cooldown_secs == 1` can never jitter down to a zero cooldown
    /// (an instantly-re-admitting "tripped" cell).
    ///
    /// Finally, when `honor_retry_after` is set and the upstream sent a Retry-After, that value is a
    /// FLOOR under the computed cooldown (`duration.max(retry_after)`) — honored even past
    /// `max_cooldown_secs` (a legitimate upstream hint may exceed it) but clamped to
    /// `max_honored_retry_after_secs` so a hostile Retry-After cannot park a lane for millennia or
    /// overflow `now + duration`.
    pub fn compute_cooldown_with_retry_after(
        &self,
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
            let time_seed = crate::clock::unix_time_secs() as u128;
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
            duration = jittered.clamp((duration / 2).max(1), cfg.max_cooldown_secs);
        }

        match (cfg.honor_retry_after, retry_after) {
            (true, Some(ra)) => duration.max(ra.min(max_honored_retry_after_secs)),
            (false, Some(_)) | (true, None) | (false, None) => duration,
        }
    }

    /// `open` body, assuming the caller already holds `transition_lock` (used by the record paths
    /// that take the lock once and must not re-take a non-reentrant `std::sync::Mutex`).
    fn open_locked(
        &self,
        now_time: u64,
        cfg: &BreakerCfg,
        retry_after: Option<u64>,
        max_honored_retry_after_secs: u64,
    ) {
        let duration =
            self.compute_cooldown_with_retry_after(cfg, retry_after, max_honored_retry_after_secs);
        // saturating_add: `duration` may carry a server-supplied Retry-After (already clamped
        // above, but defense in depth) — never wrap `now + duration`, which would land
        // `cooldown_until` in the past and instantly re-ready a tripped cell.
        self.cooldown_until
            .store(now_time.saturating_add(duration), Ordering::Release);
        self.breaker_state.store(ST_OPEN, Ordering::Release);
        // Release any in-flight probe back to Open: a failed half-open probe routes here, and
        // without this the flag would stay true forever, permanently wedging the cell HalfOpen.
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
        // `err` is NOT zeroed: it is a lifetime counter, and the FSM itself never reads it
        // (`should_trip` keys off the outcome window and streak only).
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
    /// armed a STRICTER suppression than what the probe observed. `observed_cooldown` is the
    /// `cooldown_until` the probe's lock-free pre-filter read before dispatching. Returns whether
    /// the cell was actually closed.
    ///
    /// The race this closes: between the probe's pre-filter read and this call, a concurrent
    /// hard-down parks the cell Open with a FRESH sticky cooldown strictly later than anything the
    /// probe saw. An unconditional close would drop that just-armed cooldown and recover a lane the
    /// hard-down meant to keep suppressed.
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
    /// `owned_epoch` still equals the cell's current probe epoch — closing a stalled-release race
    /// where a late release could otherwise revert a NEWER probe a different caller has since won.
    /// Reverts HalfOpen → Open, leaving the (already-expired) cooldown intact so the next request
    /// can re-win the probe immediately, without escalating the cooldown for an outcome that was
    /// never recorded.
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
    /// actually chose. Closed honors any pending cooldown; an expired-cooldown Open cell
    /// transitions to HalfOpen and admits exactly one probe (a single CAS under the transition
    /// lock); HalfOpen admits nobody else.
    pub fn acquire(&self, now: u64) -> ProbeAdmit {
        match self.breaker_state.load(Ordering::Acquire) {
            ST_CLOSED => {
                if now >= self.cooldown_until.load(Ordering::Acquire) {
                    ProbeAdmit::ReadyNoProbe
                } else {
                    ProbeAdmit::Denied
                }
            }
            ST_OPEN => {
                let until = self.cooldown_until.load(Ordering::Acquire);
                if now < until {
                    return ProbeAdmit::Denied;
                }
                let _tx = lock_recover(&self.transition_lock);
                if self.breaker_state.load(Ordering::Acquire) != ST_OPEN
                    || now < self.cooldown_until.load(Ordering::Acquire)
                {
                    return ProbeAdmit::Denied;
                }
                if self
                    .breaker_state
                    .compare_exchange(ST_OPEN, ST_HALF_OPEN, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    // Bump the owner-token epoch BEFORE publishing the in-flight flag, still under
                    // the transition lock: no peer can win a newer probe while the cell is
                    // HalfOpen, so this is the exact epoch a later owner-checked release matches.
                    self.probe_epoch.fetch_add(1, Ordering::AcqRel);
                    self.probe_in_flight.store(true, Ordering::Release);
                    ProbeAdmit::ProbeWon(self.probe_epoch.load(Ordering::Acquire))
                } else {
                    ProbeAdmit::Denied
                }
            }
            ST_HALF_OPEN => ProbeAdmit::Denied,
            _ => ProbeAdmit::Denied, // fail safe on an unreachable encoding
        }
    }

    /// Record a failure (transient or rate-limit — identical breaker handling) against the cell:
    /// push the outcome, bump the error count and streak, then trip or extend the cooldown.
    ///
    /// Reports which arm it took, decided under the transition lock rather than from a state a
    /// caller read beforehand: between such a read and this call the cell can move, and a caller
    /// that guessed would journal a probe failure for a fresh trip, or miss one for a reopen it did
    /// not know it was doing.
    ///
    /// [`FailureEffect::tripped`] is the logical Closed→Open trip a trip metric counts. A
    /// HalfOpen→Open reopen (a failed recovery probe) is NOT a fresh trip — the cell was already
    /// tripped and is merely re-arming its cooldown — nor is an already-Open no-op.
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
                    // A degenerate single-member cell: there is no sibling to fail over to, so a
                    // sub-threshold failure benches nothing — it has not earned a cooldown. An
                    // upstream-requested Retry-After is still honored, but only for as long as it
                    // asked, not the escalating backoff a real trip earns.
                    if cfg.honor_retry_after {
                        if let Some(asked) = retry_after {
                            self.cooldown_until.store(
                                now_time.saturating_add(asked.min(max_honored_retry_after_secs)),
                                Ordering::Release,
                            );
                        }
                    }
                    FailureEffect::Nothing
                } else {
                    let duration = self.compute_cooldown_with_retry_after(
                        cfg,
                        retry_after,
                        max_honored_retry_after_secs,
                    );
                    self.cooldown_until
                        .store(now_time.saturating_add(duration), Ordering::Release);
                    FailureEffect::Benched
                }
            }
            // The probe failed → reopen. The cell was already tripped (Open) and won the half-open
            // probe; reopening re-arms the cooldown but is not a fresh Closed→Open trip.
            ST_HALF_OPEN => {
                self.streak.fetch_add(1, Ordering::Relaxed);
                self.open_locked(now_time, cfg, retry_after, max_honored_retry_after_secs);
                FailureEffect::Reopened
            }
            // Already Open: an intentional no-op. The cooldown is already armed; a failure while
            // Open does not re-escalate on every request during the cooldown.
            ST_OPEN => FailureEffect::Nothing,
            _ => FailureEffect::Nothing, // fail safe on an unreachable encoding
        }
    }

    /// Record a success against the cell: reset the streak (unless the cell is Open — see below),
    /// push the outcome, and — if this was the half-open probe — complete recovery to Closed.
    ///
    /// Returns `true` IFF this call won the HalfOpen→Closed recovery CAS.
    pub fn record_success(&self, now_time: u64) -> bool {
        // Fast path: the overwhelmingly common shape — a Closed cell with no failure streak. Only
        // the outcome needs recording.
        if self.breaker_state.load(Ordering::Acquire) == ST_CLOSED
            && self.streak.load(Ordering::Acquire) == 0
        {
            lock_recover(&self.outcome_window).push(now_time, false);
            return false;
        }

        let _tx = lock_recover(&self.transition_lock);
        // Reset the consecutive-failure streak on a success — but NOT while the cell is Open. A
        // success can land on an Open cell (e.g. a degraded fallback path recording against a cell
        // this dispatch didn't itself probe); the HalfOpen→Closed CAS below then fails (Open ≠
        // HalfOpen), so no recovery occurs, and an unconditional reset would still have wiped an
        // escalating streak the next failure ought to build on.
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
    /// (no trip-threshold check — a hard-down signal is definitive), releasing any in-flight probe.
    /// Returns `true` IFF this was a genuine fresh trip (the cell was Closed beforehand), so a
    /// caller can gate a trip-count metric on a LOGICAL trip rather than re-counting a persistently
    /// dead cell on every recovery-probe cycle.
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
