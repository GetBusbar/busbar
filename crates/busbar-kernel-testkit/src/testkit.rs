// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[path = "tests/neutral_protocols.rs"]
pub(crate) mod neutral_protocols;

pub static TEST_SEAM: crate::test_support::seam::TestPlaneSeam =
    crate::test_support::seam::TestPlaneSeam {
        name: "neutral-test-fallback",
        install,
        error_surface_driver: None,
        served_call: None,
        verify_gate: None,
    };

fn install() {
    crate::test_support::protocols::register_test_protocols(neutral_protocols::NEUTRAL_PROTOCOLS);
    crate::test_support::register_neutral_test_plane();
}
