// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-STDIO-RESPAWN (ABI-MIN3-INTERFACE §14): A CARRIER_STDIO child starts in `cwd`, is respawned at
//! 100/200/400/800 ms and trips on the 5th exit in 60 s.
//!
//! W1-K8A: the respawn and trip policy arm runs on the kernel's channel policy (`channels::respawn`,
//! IF §12.19). The spawn-in-`cwd` arm needs the connector's stdio carrier (W1-C1C) and stays ignored for it;
//! the `LocalProgram`-without-`cwd` refusal is K7's config load.

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

#[test]
#[ignore = "owner: W1-C1C"]
fn a_stdio_child_starts_in_its_cwd() {
    todo!("owner: W1-C1C (C-STDIO-RESPAWN cwd arm: the connector's stdio carrier)")
}
