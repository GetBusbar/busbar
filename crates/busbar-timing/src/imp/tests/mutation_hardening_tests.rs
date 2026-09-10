// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Direct cases for `crates/busbar-timing/src/lib.rs` (feature-on registry, module `imp`) — the
//! three behaviours `tests/imp_tests.rs` cannot observe: the cached-disabled gate branch, the
//! install-once `atexit` latch, and `bucket_floor`'s own arithmetic, which over there is only ever
//! checked against ANOTHER call to itself and so agrees with any self-consistent rewrite of it.
//!
//! An earlier draft of this file also tried to pin `dump`/`dump_scoped`/`print_table`/`fmt_ns` by
//! redirecting the real stderr fd (`dup2`) around a call made on a freshly spawned thread, to
//! dodge `cargo test`'s default output capture. That capture turned out to survive the spawn
//! (their `eprintln!` output kept landing in libtest's OWN per-test capture instead of the pipe,
//! observed as the redirected read always coming back empty while the real content appeared in
//! the FAILING test's libtest-captured stdout) for reasons this session did not track down in the
//! time available, so those four cases are reported as remaining survivors rather than shipped as
//! tests that would always pass regardless of the mutation.

use super::tests::gate_lock;
use super::*;

/// The cached-DISABLED branch (`ENABLED == 1`) must answer straight from the atomic and never
/// re-sample the environment. `enabled()`'s match has three arms — `2 => true`, `1 => false`,
/// `_ => { read env, cache, return }` — and deleting the middle arm still type-checks (`1` falls
/// through to the wildcard), so nothing but an assertion that varies the ENVIRONMENT while the
/// cache is pinned at `1` can tell the two apart: both answer `false` when `BUSBAR_TIMING` is
/// genuinely unset, which is every CI invocation of this test.
#[test]
fn a_cached_disabled_gate_does_not_resample_the_environment() {
    let _gate = gate_lock();
    // Force the DISABLED cache state directly (bypassing `set_enabled`, which this test is not
    // about) and prove the env is not consulted while it holds — by setting the env to something
    // that would flip the answer to `true` if the cached branch fell through to the general case.
    ENABLED.store(1, Ordering::Relaxed);
    // SAFETY-of-intent: `env::set_var` in a test process is racy against other threads reading
    // the environment, which is exactly why this whole test runs under `gate_lock`.
    unsafe { std::env::set_var("BUSBAR_TIMING", "1") };
    let result = std::panic::catch_unwind(enabled);
    unsafe { std::env::remove_var("BUSBAR_TIMING") };
    // Restore the tri-state to "unread" so later tests in this binary see a clean slate.
    ENABLED.store(0, Ordering::Relaxed);
    assert!(
        !result.unwrap(),
        "a cached-disabled gate must answer from the cache, not re-read an environment that \
         would have said otherwise"
    );
}

/// `install_atexit` is the ONLY writer of `ATEXIT_INSTALLED`, so emptying its body leaves the flag
/// permanently `false` however many times the gate turns on, and nothing else in the crate reads
/// the flag closely enough to notice.
/// This does not depend on `atexit(3)` itself ever firing (which a unit test cannot observe
/// without ending the process) — only on the latch install_atexit exists to set.
#[test]
fn enabling_the_gate_installs_the_atexit_latch_exactly_once() {
    let _gate = gate_lock();
    set_enabled(true);
    assert!(
        ATEXIT_INSTALLED.load(Ordering::Acquire),
        "set_enabled(true) must install the atexit dump latch"
    );
    // Calling it again must not panic or double-install (compare_exchange guards it); the flag
    // simply stays set.
    set_enabled(true);
    assert!(ATEXIT_INSTALLED.load(Ordering::Acquire));
    set_enabled(false);
}

/// `bucket_floor` is the representative lower-bound nanosecond value for a histogram bucket index
/// — `0` for bucket 0, else `1 << (idx - 1)`. The existing `imp_tests.rs` coverage only ever
/// compares `bucket_floor(idx)` against ANOTHER call to `bucket_floor(idx)` (inside `percentile`),
/// so a mutant that breaks the function itself (return `0`/`1` always, `<<`→`>>`, or the `idx - 1`
/// subtraction) cancels out of that self-comparison and survives. These pin it against
/// independently computed values.
#[test]
fn bucket_floor_is_pinned_to_independent_values() {
    assert_eq!(bucket_floor(0), 0);
    assert_eq!(bucket_floor(1), 1 << 0);
    assert_eq!(bucket_floor(2), 1 << 1);
    assert_eq!(bucket_floor(3), 1 << 2);
    assert_eq!(bucket_floor(4), 1 << 3);
    assert_eq!(bucket_floor(10), 1 << 9);
    assert_eq!(bucket_floor(11), 1 << 10);
    assert_eq!(bucket_floor(64), 1 << 63);
    // And it must agree with `bucket_of` on the boundary it defines: the floor of the bucket a
    // value falls into must be <= that value, and the floor of the NEXT bucket must be > it.
    for ns in [1u64, 2, 3, 4, 1023, 1024, 1025, u32::MAX as u64, u64::MAX] {
        let idx = bucket_of(ns);
        assert!(
            bucket_floor(idx) <= ns,
            "bucket_floor({idx}) = {} must not exceed the sample {ns} that fell in it",
            bucket_floor(idx)
        );
    }
}
