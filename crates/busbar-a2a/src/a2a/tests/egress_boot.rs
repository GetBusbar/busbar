// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TEST-SCAFFOLDING: the core-backed hostless-egress driver the App build hands this plane on its
//! build context. The plane's own test binary (which links `busbar_kernel` only under `test-support`,
//! the one place it is nameable) builds transports with no App behind them, so a transport built bare
//! reads this. It reaches core's `CoreHostlessEgress` — the driver's only production implementation —
//! as the plane's OWN test dependency, so the name lives HERE, in this `tests/`-path file the
//! neutral-purity lint excludes (the twin of `envelope_boot.rs`), and out of every shipped source file.

/// Core's `CoreHostlessEgress`, as the neutral driver a plane holds.
pub(crate) fn driver() -> &'static dyn busbar_kernel::egress::seam::HostlessEgress {
    &busbar_kernel::egress::seam::CoreHostlessEgress
}
