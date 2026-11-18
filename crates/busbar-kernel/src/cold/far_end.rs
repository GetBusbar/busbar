// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! The `plane_driver::far_end` section: refusal text the egress far end spells only when it refuses.

/// The audit resource of an upstream dial no `insecure_transport` acceptance covers
/// (`dest:<host>:<instance>`, as the connector writes for a Need), spelled only on that refusal.
#[cold]
pub(crate) fn insecure_dial_resource(destination: &str, pool: &str) -> String {
    format!("dest:{destination}:{pool}")
}
