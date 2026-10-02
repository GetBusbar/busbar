// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PATH-MODEL ARRIVAL SIDE-REGISTRATION — a thin `busbar-core` veneer over the neutral
//! [`busbar_kernel::ingress::arrival`] table.
//!
//! The mechanism (the [`PathIngress`] fn-pointer type, the installed side-table, `install_path_ingress`,
//! `path_ingress_for`) RELOCATED DOWN to `busbar-substrate` so the extracted dialect crate names the
//! registration-pair type and its arrivals live there, calling core back through the neutral
//! `ArrivalHost` seam rather than core holding them. This module re-exports those
//! items at their historical `busbar_kernel::ingress::path_ingress::…` paths so the composition root and
//! the catch-all are unchanged, and adds the CORE-TEST seeding veneer around `path_ingress_for`.

// The registration-pair fn-pointer type + the composition root's one write, re-exported from the
// neutral substrate at their historical paths.
pub use busbar_kernel::ingress::arrival::{install_path_ingress, PathIngress};

// The catch-all resolves an arrival straight off the installed table (the composition root wrote it)
// or the test hook (`set_test_path_ingress`). Core's OWN `#[cfg(test)]` binary used to auto-seed the
// test hook here with the extracted dialects' `PATH_INGRESS` slice — the A6/HostCtx
// dev-dependency-cycle cleanup removed that (it named `busbar_llm` directly, which only type-checks
// with ONE `busbar_kernel` in the graph): a test that needs a real path-model arrival now registers
// it itself (`busbar_kernel::ingress::arrival::set_test_path_ingress(|| busbar_llm::PATH_INGRESS)`,
// idempotent, first-wins) from an integration-test target, exactly the posture an external
// `test-support` consumer already used — so this neutral source names no dialect crate under any
// build surface.
pub(crate) use busbar_kernel::ingress::arrival::path_ingress_for;
