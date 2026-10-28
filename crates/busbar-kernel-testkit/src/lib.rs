// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S TEST FIXTURES, on the kernel's pub API. Each module is also mounted into the
//! kernel's own unit-test build by `#[path]`, so it names the kernel as `busbar_kernel` (the kernel
//! aliases itself under that name) and never as `crate`.

/// A process-wide limits posture for a test's duration, rolled back on drop.
pub mod limits;
/// The base data router's mounted surface for an App, as plain data.
pub mod routes;
