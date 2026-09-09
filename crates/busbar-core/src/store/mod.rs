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
// name it without reaching into busbar-core.
//
// R5-store: the `crate::store::{now, now_ms}` re-export is DELETED and its ~110 call sites across
// twelve core modules name `busbar_substrate::store::{now, now_ms}` — the crate that defines it —
// instead. Core keeps a PRIVATE import, not a re-export: `now()` is still the fallback the
// #[cfg(test)] test-clock below (TEST_NOW / now_for_test) reads through, and that clock stays in
// core because it owns the thread-local injection the in-core breaker/store tests drive.
use busbar_substrate::store::now;

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

// ── THE NEUTRAL STORE VOCABULARY — the substrate's, and named from the substrate ─────────────────
//
// The breaker-state taxonomy (`BreakerState`), the lane-availability taxonomy (`Unavailable`), the
// `LaneRuntime` trait and the carriers its signatures name (`Admit`, `LaneSnapshot`, `Permit`) all
// relocated DOWN to `busbar_substrate::store` — Phase-B B1 for the taxonomies (they travel with
// `failover::walk_with`, the neutral walk that carries them), 1.6.0 App-retype WEDGE 1 for the
// lane-runtime seam — so a plane crate names them via the ABI without reaching into `busbar-core`.
//
// R5-store: none of them is RE-exported by core any more. The imports below are PRIVATE — they exist
// only so the in-memory breaker engine in `in_memory/` keeps its bare-name use through `use super::*`
// (`impl LaneRuntime for HealthState`, the FSM, the `/stats` and `/metrics` snapshot shapes). Every
// reader outside this module — `endpoints`, `metrics`, `failover`, `appbuild`, `plane_host`, and the
// one `busbar-llm` test — names `busbar_substrate::store::…`, the crate that defines them.
//
// Four names were dropped outright rather than repointed, having no reader at either the
// `crate::store::…` or the `busbar_core::store::…` path: `AT_CAPACITY_RECOVERY_FLOOR_MS` and
// `SHED_RETRY_FLOOR_MS` (their readers moved down with the taxonomy), and `LaneHealthSnapshot` and
// `PoolCellHealthSnapshot` (read only by `in_memory/`, which now imports them directly).
// `PROBE_RETRY_FLOOR_MS` moved earlier with its only reader, `recovery_hint_ms`, and is
// substrate-private.
use busbar_substrate::store::{
    Admit, BreakerState, LaneRuntime, LaneSnapshot, Permit, Unavailable,
};

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
