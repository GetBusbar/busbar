// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-STDIO-RESPAWN (ABI-MIN3-INTERFACE §14): A CARRIER_STDIO child starts in `cwd`, is respawned at
//! 100/200/400/800 ms and trips on the 5th exit in 60 s.
//!
//! W1-K8A: the respawn and trip policy arm runs on the kernel's channel policy (`channels::respawn`,
//! IF §12.19). The other two clauses are relocated (re-checked 2026-11-16: the spawn and the pin check are not in
//! child_job.rs, they are on the branch already). TEST-VALUE pointers:
//!
//! - a CARRIER_STDIO child with `cwd` set starts there: `hostio::tests::an_admitted_program_runs_in_its_configured_working_directory`
//!   (crates/busbar-core-connector/src/tests/hostio_tests.rs:196, spawn in hostio.rs:724; it spawns /bin/pwd in the
//!   admitted directory and compares the output), with the cwd validation in the same file (:33-52);
//! - a `LocalProgram` pin without `cwd` is refused at config load: `upstreams::tests::local_program_needs_its_key_to_be_argv0_and_an_explicit_absolute_cwd`
//!   (crates/busbar-kernel/src/upstreams/tests.rs:145), and the pin is checked against the spawned path before the
//!   child exists in `channels::stdio_tests::a_local_program_pin_is_checked_against_the_spawned_path_before_the_child_exists`
//!   (crates/busbar-kernel/src/channels/stdio_tests.rs:162).

use std::time::{Duration, Instant};

use busbar_kernel::channels::respawn::{Respawn, Spawn, WINDOW};

#[test]
fn a_stdio_child_backs_off_then_trips() {
    let t0 = Instant::now();
    let mut channel = Respawn::new();
    let mut at = t0;
    for wait in [100u64, 200, 400, 800] {
        assert!(!channel.ended(at), "a child that exits at once");
        assert_eq!(channel.next(at), Spawn::After(Duration::from_millis(wait)));
        at += Duration::from_millis(wait);
        assert_eq!(channel.next(at), Spawn::Now, "respawned after {wait} ms");
    }
    assert!(at - t0 < WINDOW);
    assert!(
        channel.ended(at),
        "the 5th exit inside 60 s trips the channel"
    );
    assert_eq!(
        channel.next(at + WINDOW),
        Spawn::Tripped,
        "until the upstream is reconfigured"
    );
    channel.redeclared();
    assert_eq!(channel.next(at + WINDOW), Spawn::Now);
}
