// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The probe service's target over `PlanePort::probe` (IF §8.6 FB_PROBES; PLANE-DRIVER.md slice 5 leftover).
//! [`PortProbes`] is the [`ProbeTarget`] the probe schedule drives: for one member it asks the plane for a minimal
//! request in that member's dialect ([`probe_member`]), sends it through the far end, feeds the reply back and
//! reports what the plane found. A member the plane declines to probe reports nothing; a probe that could not be
//! run (the plane faulted, or no far end can reach the member) reports unhealthy only when the plane was asked.
//! [`ProbeFar`] is the seam the egress walk's breaker and the carrier implement.

use std::sync::Arc;
use std::time::Duration;

use super::port_session::{Calls, Effects};
use super::port_upstream::{probe_member, Candidate, ProbeOutcome, UpSend};
use crate::probe::ProbeTarget;

/// What a probe needs of the member walk and the far end.
pub trait ProbeFar: Send + Sync + 'static {
    /// The breaker holds this member off (§12.3): it is not probed.
    fn suppressing(&self, member: usize) -> bool;
    /// The member as the plane's `Target` states it; `None` = no such member.
    fn candidate(&self, member: usize) -> Option<Candidate>;
    /// The carrier for one probe exchange to this member; `None` = it cannot be reached at all.
    fn sender(&self, member: usize, timeout: Duration) -> Option<Box<dyn UpSend + Send>>;
    /// What the probe found: a breaker input.
    fn reported(&self, member: usize, outcome: ProbeOutcome);
}

/// The probe target of one plane instance.
pub struct PortProbes<K: Calls + ?Sized + Send + Sync + 'static, F: ProbeFar> {
    calls: Arc<K>,
    far: Arc<F>,
    dialect: String,
    model: String,
    effects: Arc<dyn Effects + Send + Sync>,
}

impl<K: Calls + ?Sized + Send + Sync + 'static, F: ProbeFar> PortProbes<K, F> {
    /// `dialect` and `model` are what the plane's `probe` is asked in.
    #[must_use]
    pub fn new(
        calls: Arc<K>,
        far: Arc<F>,
        dialect: String,
        model: String,
        effects: Arc<dyn Effects + Send + Sync>,
    ) -> Self {
        Self {
            calls,
            far,
            dialect,
            model,
            effects,
        }
    }
}

impl<K: Calls + ?Sized + Send + Sync + 'static, F: ProbeFar> ProbeTarget for PortProbes<K, F> {
    fn suppressing(&self, member: usize) -> bool {
        self.far.suppressing(member)
    }

    async fn probe(&self, member: usize, timeout: Duration) {
        let Some(candidate) = self.far.candidate(member) else {
            return;
        };
        let Some(mut send) = self.far.sender(member, timeout) else {
            return;
        };
        let calls = Arc::clone(&self.calls);
        let effects = Arc::clone(&self.effects);
        let (dialect, model) = (self.dialect.clone(), self.model.clone());
        // The plane's calls are synchronous: the probe runs off the executor.
        let ran = tokio::task::spawn_blocking(move || {
            probe_member(&*calls, &candidate, &dialect, &model, &mut *send, &*effects)
        })
        .await;
        match ran {
            Ok(Ok(ProbeOutcome::Declined)) => {}
            Ok(Ok(outcome)) => self.far.reported(member, outcome),
            Ok(Err(error)) => {
                tracing::warn!(?error, member, "a plane probe could not run");
                self.far.reported(member, ProbeOutcome::Unhealthy);
            }
            Err(_) => tracing::warn!(member, "a plane probe was cancelled"),
        }
    }
}

#[cfg(test)]
#[path = "tests/port_probes_tests.rs"]
mod tests;
