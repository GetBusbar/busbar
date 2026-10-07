// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core-connector/src/tls/trust.rs`.

use super::*;

/// The root's capability hands every answer to the guard behind it, deciding nothing itself, and
/// carries the wrap it was built with.
#[test]
fn the_guarded_seam_judges_by_the_guard_behind_it() {
    let judged = GuardedEgressTrust(
        busbar_kernel::egress::fixtures::private_refusing(&[]),
        Arc::new(crate::tls::engine::Layer),
    );
    let private: IpAddr = "10.0.0.5".parse().unwrap();
    let public: IpAddr = "93.184.216.34".parse().unwrap();
    assert!(judged.judge_answer("db.test", &[private], 0).is_err());
    assert_eq!(judged.judge_answer("api.test", &[public], 0), Ok(()));
    assert!(judged.secure_layer().is_some());
}
