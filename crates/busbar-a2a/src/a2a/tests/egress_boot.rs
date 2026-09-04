// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TEST-SCAFFOLDING: install the core-backed hostless-egress driver the composition root installs at
//! boot. The plane's own test binary (which links `busbar_core` only under `test-support`, the one
//! place it is nameable) has no `main` to do it, so the transport's `hop_spec` calls this once,
//! idempotently (first-wins `OnceLock` inside the substrate seam). It reaches core's
//! `CoreHostlessEgress` — the driver's only production implementation — as the plane's OWN test
//! dependency, so the name lives HERE, in this `tests/`-path file the neutral-purity lint excludes
//! (the twin of `envelope_boot.rs`), and out of every shipped source file. Mirrors the MCP leg's
//! identical `test_egress_boot`.

/// Bind core's `CoreHostlessEgress` into the substrate seam, idempotently.
pub(crate) fn install() {
    busbar_substrate::egress::seam::install_hostless_egress(
        &busbar_core::egress::seam::CoreHostlessEgress,
    );
}
