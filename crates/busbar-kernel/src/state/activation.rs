// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Observations belong to a configuration generation, never to shared live runtime state.
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshFailure {
    BootstrapHeld,
    RefreshFailed,
    InvalidProjection,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PlaneRefresh {
    pub plane: String,
    pub section: String,
    pub generation: u64,
    pub outcome: &'static str,
    pub failure: Option<RefreshFailure>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RefreshSnapshot {
    pub scope: &'static str,
    pub coverage: &'static str,
    pub phase: &'static str,
    pub planes: Vec<PlaneRefresh>,
}

impl Default for RefreshSnapshot {
    fn default() -> Self {
        Self {
            scope: "synchronous_plane_refresh",
            coverage: "ordinary_door_callbacks_only",
            phase: "unobserved",
            planes: Vec::new(),
        }
    }
}

impl RefreshSnapshot {
    /// Only the typed cold-grant refusal establishes that a restart is required.
    pub fn restart_sections(&self) -> impl Iterator<Item = &str> {
        self.planes
            .iter()
            .filter(|p| p.failure == Some(RefreshFailure::BootstrapHeld))
            .map(|p| p.section.as_str())
    }
}

#[derive(Debug, Default)]
pub struct PlaneRefreshReport(Mutex<RefreshSnapshot>);

impl Clone for PlaneRefreshReport {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl PlaneRefreshReport {
    pub fn snapshot(&self) -> RefreshSnapshot {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn begin(&self) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = RefreshSnapshot {
            phase: "observing",
            ..RefreshSnapshot::default()
        };
    }

    /// Observed means callback completion only, never successful activation.
    /// An empty set of rows supplies no evidence of resource activation.
    pub(crate) fn finish(&self) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .phase = "observed";
    }

    pub fn record(
        &self,
        plane: &str,
        section: &str,
        generation: u64,
        failure: Option<RefreshFailure>,
    ) {
        let mut report = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if report.phase != "observing" {
            return;
        }
        report.planes.push(PlaneRefresh {
            plane: plane.into(),
            section: section.into(),
            generation,
            outcome: if failure.is_some() {
                "retained"
            } else {
                "installed"
            },
            failure,
        });
    }
}

#[cfg(test)]
#[path = "../tests/activation_report_tests.rs"]
mod tests;
