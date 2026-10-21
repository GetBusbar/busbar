// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S NEUTRAL TEST SEAM, for a test-support consumer that links no plane. The neutral
//! fallback plane, which declares the synthetic provider dialects a test lane names
//! (`test_support::NEUTRAL_DIALECTS`; ARCHITECT ruling 2026-10-16 D: provider dialects are read off
//! a plane's row only), is LENT, not installed: a test hands the neutral table
//! (`test_support::neutral_test_doors`) to what it drives, and a `TestApp` lent no table is lent
//! that one (status row 82, D2: the kernel holds no door table of its own). The kernel holds no
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

/// Nothing to install: the neutral fallback plane is not registered anywhere, it is lent by value
/// in the neutral table (`test_support::neutral_test_doors`) to every reader a test drives, and a
/// `TestApp` lent no other table reads that one.
fn install() {}
