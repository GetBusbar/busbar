// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-NEEDFUT-LATE (ABI-MIN3-INTERFACE §14): A `NeedFut` polled at step k and again only at k + 2 FAULTs
//! StaleHandle.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use crate::bridge_fixture::{self as fx, Status};

/// Inside one chain a combinator polls a `need::secret` future at step 0 (it writes its NEED) and lets the step
/// end. Polled again at step 1 it reads its own result; polled again only at step 2 (after another NEED made
/// step 1) it FAULTs StaleHandle and the chain is gone.
#[test]
fn a_late_poll_faults() {
    let instance = fx::instance();

    let mut chain = fx::parked(&instance, b"late-ok");
    let mut lease = fx::lease();
    assert_eq!(
        fx::resume_secret(&mut chain, b"one", &mut lease),
        Some(Status::OK),
        "the same future polled at k + 1 succeeds"
    );
    assert_eq!(fx::texts(&lease), [b"one".to_vec()]);
    drop(lease);

    let mut chain = fx::parked(&instance, b"late-stale");
    assert_eq!(
        fx::resume_secret(&mut chain, b"one", &mut fx::lease()),
        None,
        "step 1 makes its own NEED"
    );
    assert_eq!(
        fx::resume_secret(&mut chain, b"two", &mut fx::lease()),
        Some(Status::FAULT),
        "polled at k + 2: StaleHandle"
    );
    assert_eq!(fx::done(&instance, b"refuse-plain"), Status::REFUSED);
}
