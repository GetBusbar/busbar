// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EGRESS-TRUST CAPABILITY THE COMPOSITION ROOT INSTALLS (`busbar_kernel::secure::EgressTrustHost`):
//! the deployment's one destination guard and this crate's TLS wrap, both the connector's. The kernel
//! reaches them only through the capability; this decides nothing itself.

use std::net::IpAddr;
use std::sync::Arc;

use busbar_kernel::config::Destinations;
use busbar_kernel::host_services::{DestJudge, DestRefusal};
use busbar_kernel::secure::{EgressTrustHost, SecureLayer};

/// The capability the composition root installs: every answer judged by the deployment's one
/// destination guard, and every outbound connection secured by the one TLS wrap.
pub struct GuardedEgressTrust(pub Arc<dyn DestJudge>, pub Arc<dyn SecureLayer>);

impl EgressTrustHost for GuardedEgressTrust {
    fn secure_layer(&self) -> Option<Arc<dyn SecureLayer>> {
        Some(Arc::clone(&self.1))
    }
    fn judge_answer(&self, host: &str, addrs: &[IpAddr], class: u32) -> Result<(), DestRefusal> {
        self.0.judge_answer(host, addrs, class)
    }
    fn destinations_applied(&self, d: &Destinations) {
        self.0.destinations_applied(d);
    }
}

#[cfg(test)]
#[path = "trust_tests.rs"]
mod tests;
