// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/transport.rs` — the third axis.
//!
//! These are axis tests, not cell tests: what is being asserted is that the axis is a bounded label.
//! The kernel frames no codec cell (a plane reads its own far end through its door).

use crate::transport::*;

#[test]
fn names_are_stable_and_distinct() {
    let names: Vec<_> = Transport::ALL.iter().map(|t| t.name()).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "transport names must be unique");
    assert_eq!(Transport::Http.name(), "http");
}

// the per-plane leg-naming test MOVED to
// `crates/busbar/tests/plane_dispatch_cross_plane.rs`: it asserts `wire_format_names` for an agent plane against the REAL agent
// plane's declared wire formats, which needs the real roster registered — an integration-test
// target, never this `#[cfg(test)]` unit module (see that file's header).
