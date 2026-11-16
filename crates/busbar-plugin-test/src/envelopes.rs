// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A recording envelope sink (STH-ROWS D-5): what an image reported in its answers' envelopes,
//! owned copies of what production's sink sees. Bind it with `Host::sink`.

use std::sync::{Arc, Mutex, MutexGuard};

use busbar_plugin_loader::dispatch::{Diagnostic, Dropped, EnvelopeSink, Metric};

/// One recorded metric.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricRecord {
    /// The family's index in the Statement.
    pub family: u32,
    /// `METRIC_ADD` | `METRIC_SET` | `METRIC_OBSERVE`.
    pub kind: u8,
    /// The value.
    pub value: f64,
    /// One value per label key.
    pub labels: Vec<Vec<u8>>,
}

/// One recorded diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagRecord {
    /// The id's index in the Statement, or `DIAG_LOG`.
    pub id: u32,
    /// The declared id's name.
    pub name: Vec<u8>,
    /// The severity.
    pub severity: u8,
    /// The text.
    pub text: Vec<u8>,
}

#[derive(Default)]
struct Seen {
    metrics: Vec<MetricRecord>,
    diags: Vec<DiagRecord>,
    dropped: Vec<Dropped>,
}

/// The recording sink. Clone the `Arc` from [`Envelopes::new`] into `Host::sink` and read it back.
#[derive(Default)]
pub struct Envelopes(Mutex<Seen>);

impl Envelopes {
    /// A fresh, empty recorder.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn seen(&self) -> MutexGuard<'_, Seen> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Every metric recorded so far, in order.
    #[must_use]
    pub fn metrics(&self) -> Vec<MetricRecord> {
        self.seen().metrics.clone()
    }

    /// Every diagnostic recorded so far, in order.
    #[must_use]
    pub fn diags(&self) -> Vec<DiagRecord> {
        self.seen().diags.clone()
    }

    /// Every entry the host dropped, in order.
    #[must_use]
    pub fn dropped(&self) -> Vec<Dropped> {
        self.seen().dropped.clone()
    }
}

impl EnvelopeSink for Envelopes {
    fn metric(&self, m: Metric<'_>) {
        self.seen().metrics.push(MetricRecord {
            family: m.family,
            kind: m.kind,
            value: m.value,
            labels: m.labels.iter().map(|l| l.to_vec()).collect(),
        });
    }

    fn diag(&self, d: Diagnostic<'_>) {
        self.seen().diags.push(DiagRecord {
            id: d.id,
            name: d.name.to_vec(),
            severity: d.severity,
            text: d.text.to_vec(),
        });
    }

    fn dropped(&self, why: Dropped) {
        self.seen().dropped.push(why);
    }
}
