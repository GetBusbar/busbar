// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S HALF OF A PLANE-SIDE HOST DOUBLE. A plane tests itself against an in-memory host
//! (voice's `FixtureHost`), and that host implements only the PLANE-FACING seam — it names no cost or
//! price type (BUSBAR-1.6.0 #43: a plane is pricing-blind). What such a double still needs from the
//! money side — a session meter that leases, prices and hard-closes — is the kernel's, so it lives
//! here and the double asks for it by posture, never by rate.

use super::session_meter::HostMeteringPort;
use super::MeteringHost;
use crate::billing::Usage;
use std::sync::Arc;

/// A STOCK CARD for a host double: ONE unit per reported count, or nothing at all (the no-card
/// posture: every model prices at zero). Leases are the kernel registry's, as on a real host.
struct StockCard {
    one_unit_per_count: bool,
}

impl MeteringHost for StockCard {
    fn price_usage(&self, _model: &str, usage: &Usage) -> Option<u128> {
        let counted = usage.usage_units.values().copied().map(u128::from).sum();
        Some(if self.one_unit_per_count { counted } else { 0 })
    }
}

/// The session meter a host double hands its plane: the kernel's own [`HostMeteringPort`] over the
/// kernel lease registry, priced at one unit per count (`true`) or at nothing (`false`).
#[must_use]
pub fn stock_session_meter(one_unit_per_count: bool) -> HostMeteringPort {
    HostMeteringPort::new(Arc::new(StockCard { one_unit_per_count }))
}
