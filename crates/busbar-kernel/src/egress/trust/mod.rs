// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COMPOSITION-ROOT-OWNED DESTINATIONS SEAM (OWNER ruling DESTINATION GUARD; ARCHITECT ruling
//! (C), DEST-GUARD).
//!
//! The deployment's one destination guard is the connector's (BUSBAR-1.6.0.md THE DESIGN §5: every
//! outbound connection is checked in ONE place, the connector). The kernel holds no TLS, no client
//! identity, no trust anchor, no resolver and no dial of its own (THE DESIGN §8: the connector is
//! "the only holder of TLS keys, certificates, trust roots and mTLS identity"; status row 130). What
//! is left here is the one fact the kernel owns and the guard needs: a config commit changed the
//! deployment's destinations. [`EgressTrustHost`] is the capability the composition root installs
//! once at boot ([`install_egress_trust_host`]) with the guard behind it, and
//! [`destinations_applied`] raises every commit to it.

use std::sync::Arc;

use crate::config::Destinations;
use crate::host_services::DestJudge;

/// THE CAPABILITY THE COMPOSITION ROOT INSTALLS: what the kernel tells the deployment's destination
/// guard. `Send + Sync` so the installed capability is a process-wide `&'static dyn`.
pub trait EgressTrustHost: Send + Sync {
    /// A config commit: the deployment's destinations are now `d`, raised to the guard behind the
    /// capability ([`DestJudge::destinations_applied`]); the pass-through has none and keeps nothing.
    fn destinations_applied(&self, _: &Destinations) {}
}

/// The capability with no guard behind it: a commit is heard by nobody.
pub struct PassThroughEgressTrust;

impl EgressTrustHost for PassThroughEgressTrust {}

/// The capability the composition root installs: every commit raised to the deployment's one
/// destination guard (the connector's; this decides nothing).
pub struct GuardedEgressTrust(pub Arc<dyn DestJudge>);

impl EgressTrustHost for GuardedEgressTrust {
    fn destinations_applied(&self, d: &Destinations) {
        self.0.destinations_applied(d);
    }
}

/// THE PROCESS-WIDE capability, installed once by the composition root
/// ([`install_egress_trust_host`]); `None` in a build that installed none.
static EGRESS_TRUST: std::sync::OnceLock<Arc<dyn EgressTrustHost>> = std::sync::OnceLock::new();

/// Install the process capability — the composition root's one write, at boot, before the boot
/// build commits. Idempotent by `OnceLock`: a second install is a no-op (the first wins).
pub fn install_egress_trust_host(host: Arc<dyn EgressTrustHost>) {
    let _ = EGRESS_TRUST.set(host);
}

/// Raise a config commit to the installed capability, so the deployment's one destination guard
/// re-reads its metadata lists. Called at the commit (`InstalledLimits::keep`), so a rejected apply
/// leaves the lists in force; with no capability installed there is no guard to hear it.
pub(crate) fn destinations_applied(d: &Destinations) {
    if let Some(host) = egress_trust_host() {
        host.destinations_applied(d);
    }
}

/// The installed capability, or `None` when none was installed.
#[must_use]
pub fn egress_trust_host() -> Option<&'static dyn EgressTrustHost> {
    EGRESS_TRUST.get().map(AsRef::as_ref)
}

#[cfg(test)]
#[path = "tests/egress_trust_tests.rs"]
mod egress_trust_tests;
