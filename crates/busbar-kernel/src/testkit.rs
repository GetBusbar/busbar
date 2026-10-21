// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S NEUTRAL TEST SEAM, for a test-support consumer that links no plane: the neutral
//! fallback plane (`test_support::register_neutral_test_plane`), which declares the synthetic
//! provider dialects a test lane names (`test_support::NEUTRAL_DIALECTS`; ARCHITECT ruling
//! 2026-10-16 D: provider dialects are read off registered planes only). The kernel holds no
//! protocol set: a plane resolves its own dialects (spec Part 1, Law 5). A consumer lists
//! `busbar-kernel` in its `test-linked` table and its generated loop installs this entry, as it
//! installs a plane's.

/// The neutral seam's entry in a consumer's `test-linked` table.
pub static TEST_SEAM: crate::test_support::seam::TestPlaneSeam =
    crate::test_support::seam::TestPlaneSeam {
        name: "neutral-test-fallback",
        install,
        error_surface_driver: None,
        served_call: None,
        verify_gate: None,
    };

/// Register the neutral fallback plane. Idempotent: the registration is per name.
fn install() {
    crate::test_support::register_neutral_test_plane();
}
