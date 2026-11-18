// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The walk ports' tables, built once per configured walk or published generation.

use std::collections::BTreeSet;
use std::sync::Arc;

use busbar_kernel_egress::ports::DestinationId;
use foldhash::HashMap;
use tokio::sync::Semaphore;

use crate::root::egress_ports::{LabelBound, MemberPermits, Wait, WalkTelemetry};

impl MemberPermits {
    /// The members' permits, built once per configured walk.
    #[must_use]
    pub(crate) fn new(limits: impl IntoIterator<Item = (DestinationId, usize)>) -> Self {
        let limits = limits
            .into_iter()
            .map(|(d, n)| (d, Arc::new(Semaphore::new(n))))
            .collect();
        MemberPermits { limits }
    }
}

impl LabelBound {
    /// A plane's lane vocabulary, gathered once per generation.
    #[must_use]
    pub(crate) fn new(vocabulary: impl IntoIterator<Item = String>) -> Self {
        let vocabulary = vocabulary.into_iter().collect();
        LabelBound {
            reach: HashMap::default(),
            vocabulary,
        }
    }

    /// A walk's reachable words, gathered and keyed once per generation.
    #[must_use]
    pub(crate) fn reaching(
        mut self,
        walked: &str,
        pool_words: impl IntoIterator<Item = String>,
        entries: impl IntoIterator<Item = String>,
    ) -> Self {
        let entries: BTreeSet<String> = entries.into_iter().collect();
        let pools = pool_words
            .into_iter()
            .chain(entries.iter().cloned())
            .collect();
        self.reach.insert(walked.to_string(), (pools, entries));
        self
    }
}

impl WalkTelemetry {
    /// The members' lane names, gathered once per configured walk.
    #[must_use]
    pub(crate) fn new(names: impl IntoIterator<Item = (DestinationId, String)>) -> Self {
        let names = names.into_iter().collect();
        WalkTelemetry {
            names,
            bound: LabelBound::default(),
        }
    }
}

impl MemberPermits {
    /// A wait-for-any's pending acquisitions: one per limited destination, in the given order,
    /// built when the walk has to queue (every named member is at capacity).
    pub(crate) fn waits(&self, destinations: &[DestinationId]) -> Vec<(DestinationId, Wait)> {
        let mut waits = Vec::with_capacity(destinations.len());
        for d in destinations {
            if let Some(slots) = self.limits.get(d) {
                waits.push((*d, Box::pin(Arc::clone(slots).acquire_owned()) as Wait));
            }
        }
        waits
    }
}
