// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S NEUTRAL TEST SEAM, for a test-support consumer that links no plane: the synthetic
//! protocol set the kernel's own test binary validates, routes and frames over
//! (`tests/neutral_protocols.rs`), and the neutral fallback plane that declares them as its
//! provider dialects (`test_support::register_neutral_test_plane`; ARCHITECT ruling 2026-10-16 D:
//! provider dialects are read off registered planes only). A consumer lists `busbar-kernel` in its
//! `test-linked` table and its generated loop installs this entry, as it installs a plane's.

#[path = "tests/neutral_protocols.rs"]
pub(crate) mod neutral_protocols;

/// The neutral seam's entry in a consumer's `test-linked` table.
pub static TEST_SEAM: crate::test_support::seam::TestPlaneSeam =
    crate::test_support::seam::TestPlaneSeam {
        name: "neutral-test-fallback",
        install,
        error_surface_driver: None,
        served_call: None,
        verify_gate: None,
    };

/// Register the synthetic protocols and the neutral fallback plane. Idempotent: both registrations
/// are per name.
fn install() {
    crate::test_support::protocols::register_test_protocols(neutral_protocols::NEUTRAL_PROTOCOLS);
    crate::test_support::register_neutral_test_plane();
}
