// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::Semaphore;

// Lower bound a hard-down sticky cooldown is asserted to exceed, in tests.
#[cfg(test)]
const COOLDOWN_TRANSIENT_SECS: u64 = 10;
// A hard-down fault (bad key / billing / hard quota) gets a long sticky cooldown and recovers via
// the half-open probe — NOT a permanent `dead` kill. A human likely has to fix the key, so fast
// re-probes are pointless; default 30 min. Now operator-tunable via `limits.hard_down_cooldown_secs`
// (threaded onto `HealthState`); this const is the DEFAULT (== the config default) and is retained
// only as the expected value in tests that exercise the default-configured store.
#[cfg(test)]
const HARD_DOWN_COOLDOWN_SECS: u64 = crate::config::DEFAULT_HARD_DOWN_COOLDOWN_SECS;

// Absolute ceiling on an UPSTREAM-supplied `Retry-After` we will honor as a cooldown floor. A
// server's hint can legitimately exceed the configured `max_cooldown_secs`, so we honor past the
// cap — but never past this ceiling (default 24h), so a hostile/buggy upstream sending a near-
// `u64::MAX` `Retry-After` cannot overflow `now + duration` (breaker bypass in release / panic in
// debug) or bench a lane for millennia. Now operator-tunable via `limits.max_honored_retry_after_secs`
// (threaded onto `HealthState`); this const is the DEFAULT, retained only for default-config tests.
#[cfg(test)]
const MAX_HONORED_RETRY_AFTER_SECS: u64 = crate::config::DEFAULT_MAX_HONORED_RETRY_AFTER_SECS;

// Breaker-state encoding for the per-cell `AtomicU64` (stored as u64 so it can be CAS'd).
const ST_CLOSED: u64 = 0;
const ST_OPEN: u64 = 1;
const ST_HALF_OPEN: u64 = 2;

/// Normalize a breaker state being RESTORED from a snapshot (or inherited by a sibling cell):
/// `ST_HALF_OPEN` becomes `ST_OPEN`. A restored HalfOpen cell has `probe_in_flight == false` (the
/// snapshot never carries it, and the restore path never sets it), and both `cell_ready_breaker` and
/// `cell_acquire_breaker` reject HalfOpen unconditionally — so the cell WEDGES: no dispatch can acquire
/// it and no probe outcome (`cell_open`/`cell_closed`) ever runs against it, benching that (pool, lane)
/// until an out-of-band `recover_lane` touches it (indefinitely when health probing is disabled).
/// Restoring `ST_OPEN` instead lets the restored (already-expired) cooldown drive a fresh probe
/// acquisition on the cell's first request.
fn restored_breaker_state(state: u64) -> u64 {
    if state == ST_HALF_OPEN {
        ST_OPEN
    } else {
        state
    }
}

// Bounded capacity of each cell's sliding outcome window (recent request outcomes for the
// error-rate trip computation).
const OUTCOME_WINDOW_CAPACITY: usize = 1024;

/// Lock a `std::sync::Mutex` on the production request path WITHOUT panicking on poison.
///
/// `.lock().unwrap()` panics if the mutex is poisoned (a thread panicked while holding the guard).
/// On the Tokio request path this is catastrophic and silent: one poisoned SWRR shard /
/// `outcome_window` / `dead_reason` mutex (or the `pool_cells` RwLock) would make EVERY subsequent
/// request that touches it panic
/// too — a poisoned-mutex DoS cascade. The data behind these mutexes is always still valid after a
/// poison (the critical sections only push to a bounded ring, mutate a small map, or swap a String),
/// so we recover the inner guard via `into_inner()` instead of propagating the poison. This keeps the
/// no-panic-on-request-path invariant: a single stray panic can never wedge the whole router.
fn lock_recover<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Poison-recovering shared READ acquire for an `RwLock` on the request path — the `RwLock`
/// analogue of [`lock_recover`]. A reader panic cannot leave inconsistent data behind the
/// `pool_cells` lock (readers only iterate), so recover the guard instead of cascading the poison.
fn read_recover<T>(m: &std::sync::RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    m.read().unwrap_or_else(|e| e.into_inner())
}

/// Poison-recovering exclusive WRITE acquire for an `RwLock` — used only on the rare lazy
/// cell-insert path. Same no-panic-on-request-path rationale as [`lock_recover`].
fn write_recover<T>(m: &std::sync::RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    m.write().unwrap_or_else(|e| e.into_inner())
}

// The production wall clock (`now`, `now_ms`) moved to the neutral substrate so the plane crates
// name it without reaching into busbar-core; re-exported here so every crate::store::{now, now_ms}
// caller is unchanged. The #[cfg(test)] test-clock below (TEST_NOW / now_for_test) stays in core —
// it owns the thread-local injection the in-core breaker/store tests drive, and now_for_test falls
// back to this re-exported now().
pub use busbar_substrate::store::{now, now_ms};

// Test-clock storage, THREAD-LOCAL.
//
// CRITICAL #1: these must NOT be function-local statics. A `static` declared inside a function body
// is scoped to that function, so `set_now_for_test` and `now_for_test` each declaring their own
// identically-named locals got INDEPENDENT storage — the injected time was never observed by
// `now_for_test` and every breaker timing test silently ran against the real wall clock.
//
// CRITICAL #2: they must be THREAD-LOCAL, not module-level statics. `cargo test` runs tests in
// parallel threads sharing one process; a single global clock means a unit test that froze time
// (e.g. set_now_for_test(1000)) would poison the clock for a concurrently-running forward
// integration test that records breaker cooldowns against the real wall clock. Per-thread storage
// isolates each test's injected time to its own thread while leaving real-time tests on real time.
#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static TEST_NOW: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static IN_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test helper to inject time for unit tests (this thread only).
#[allow(dead_code)]
#[cfg(any(test, feature = "test-support"))]
fn set_now_for_test(t: u64) {
    TEST_NOW.with(|c| c.set(t));
    IN_TEST.with(|c| c.set(true));
}

#[allow(dead_code)]
#[cfg(any(test, feature = "test-support"))]
fn now_for_test() -> u64 {
    // "Unset" is signalled SOLELY by the `IN_TEST` flag (set true by `set_now_for_test`), NOT by the
    // stored value. The old guard (`val != 0`) conflated a legitimately-injected instant of 0 with
    // "never set" and silently fell back to the wall clock — so `set_now_for_test(0)` (epoch / a
    // deliberately-pinned zero instant) was unmockable and any cooldown math anchored at 0 ran
    // against real time, a latent flake. With the flag as the sole gate, 0 is a legal mock instant.
    if IN_TEST.with(|c| c.get()) {
        TEST_NOW.with(|c| c.get())
    } else {
        now()
    }
}

// The neutral breaker-state taxonomy (`BreakerState`) moved to `busbar-substrate` so a plane crate
// names it without reaching into busbar-core; re-exported here so every `crate::store::BreakerState`
// caller is unchanged.
//
// ── Lane availability taxonomy ── relocated to `busbar-substrate` in Phase-B B1 (it travels with
// `failover::walk_with`, the neutral walk that carries it). Core re-exports the taxonomy and the two
// consumer-facing recovery floors so every `crate::store::…` name resolves unchanged;
// `PROBE_RETRY_FLOOR_MS` moved with its only reader (`recovery_hint_ms`) and stays substrate-private.
pub use busbar_substrate::store::{
    BreakerState, Unavailable, AT_CAPACITY_RECOVERY_FLOOR_MS, SHED_RETRY_FLOOR_MS,
};

// `Permit` (the RAII concurrency token) is neutral (pure `tokio::sync`, no config/serde coupling), so
// it now lives in the neutral `busbar_substrate::store` — the LLM plane's `walk` mints it and
// `LaneRuntime::try_admit` returns it, both naming the ONE type without the plane reaching into
// `busbar-core`. Re-exported here for core's own `crate::store::Permit` call sites (`Admit`, the
// `LaneRuntime` trait signatures, the FSM).
pub use busbar_substrate::store::Permit;

// App-retype WEDGE 1 (1.6.0): the `LaneRuntime` TRAIT and the three carriers its signatures name
// (`Admit`, `LaneSnapshot`, `LaneHealthSnapshot`, plus the latter's per-pool `PoolCellHealthSnapshot`)
// relocated DOWN to `busbar_substrate::store` so the LLM plane names the lane-runtime seam via the ABI
// instead of reaching into `busbar_core::store`. Re-exported here by-identity so the in-memory breaker
// engine's `impl LaneRuntime for HealthState`, `/stats`, the `/metrics` scrape, and the config-apply
// export/restore path resolve `crate::store::…` unchanged. `PoolCellHealthSnapshot` is re-exported
// `pub(crate)` to preserve its original core-private visibility (it is only ever named inside core).
pub use busbar_substrate::store::{Admit, LaneHealthSnapshot, LaneRuntime, LaneSnapshot};
pub(crate) use busbar_substrate::store::PoolCellHealthSnapshot;

mod in_memory;
pub use in_memory::*;

mod planes;
pub use planes::{PlaneBreakers, MAX_POOL_MEMBERS};
// `PlaneAdmission` is the RAII admission token the plane dispatch paths hand around; with BOTH
// planes compiled out nothing names it, so this re-export is unused in that config alone.
#[allow(unused_imports)]
pub(crate) use planes::Admission as PlaneAdmission;

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;
