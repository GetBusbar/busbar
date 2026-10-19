// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S NEUTRAL TEST SEAM, for a test-support consumer that links no plane: the neutral
//! fallback plane (`test_support::register_neutral_test_plane`; ARCHITECT ruling 2026-10-16 D:
//! provider dialects are read off registered planes only) and the synthetic provider dialect names
//! it declares, so a test lane names a provider protocol the boot accepts without naming a plane's
//! dialect. A consumer lists `busbar-kernel` in its `test-linked` table and its generated loop
//! installs this entry, as it installs a plane's.

/// THE SYNTHETIC PROVIDER DIALECTS the neutral test plane declares, in a fixed order. Names only:
/// the kernel holds no dialect (Q128 contract p11 finding 1), so a test that needs a provider
/// `protocol:` the boot accepts names one of these, and a dialect's behaviour is its plane's suite.
pub const NEUTRAL_TEST_DIALECTS: &[&str] = &[
    "proto-a", "proto-b", "proto-c", "proto-d", "proto-e", "proto-f",
];

/// The synthetic dialect a fixture names when it needs one and does not care which.
pub const NEUTRAL_TEST_DIALECT: &str = "proto-b";

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
