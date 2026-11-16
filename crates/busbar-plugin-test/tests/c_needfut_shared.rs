// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-NEEDFUT-SHARED (ABI-MIN3-INTERFACE §14): A `NeedFut` shared across instances: B's poll FAULTs StaleHandle,
//! A's later poll gets A's value.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use crate::bridge_fixture::{self as fx, Status};

/// Two instances A and B of one image. A chain of A writes a `need::secret` NEED and parks the future in a
/// `static Mutex` (the single-flight shape). A resume of B's own chain polls it: FAULT StaleHandle, nothing of
/// B's results is read. A's later resume polls it at step + 1 and gets A's value.
#[test]
fn a_shared_needfut_faults_for_the_other_instance() {
    let a = fx::instance();
    let b = fx::instance();
    let mut chain_a = fx::parked(&a, b"share-a");
    let mut chain_b = fx::parked(&b, b"share-b");
    assert_eq!(
        fx::resume_secret(&mut chain_b, b"b-canary", &mut fx::lease()),
        Some(Status::FAULT),
        "B polled A's future: StaleHandle"
    );
    let mut lease = fx::lease();
    assert_eq!(
        fx::resume_secret(&mut chain_a, b"a-value", &mut lease),
        Some(Status::OK)
    );
    assert_eq!(fx::texts(&lease), [b"a-value".to_vec()], "A gets A's value");
}
