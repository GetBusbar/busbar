// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The accept workers' balancers, built once when the listener starts.

use std::sync::Arc;

use crate::root::listener::{ConnBalancer, PaddedCount, HANDOFF_CHANNEL_DEPTH};

impl ConnBalancer {
    /// One balancer per accept worker: a shared count cell and hand-off sender per worker, and
    /// each worker's own receiver.
    pub(crate) fn build(n: usize) -> Vec<ConnBalancer> {
        let counts: Arc<[PaddedCount]> = (0..n)
            .map(|_| PaddedCount(std::sync::atomic::AtomicU32::new(0)))
            .collect();
        let mut txs = Vec::with_capacity(n);
        let mut rxs = Vec::with_capacity(n);
        for _ in 0..n {
            let (tx, rx) = tokio::sync::mpsc::channel(HANDOFF_CHANNEL_DEPTH);
            txs.push(tx);
            rxs.push(rx);
        }
        let txs: Arc<[_]> = txs.into();
        rxs.into_iter()
            .enumerate()
            .map(|(me, rx)| ConnBalancer {
                counts: counts.clone(),
                txs: txs.clone(),
                me,
                rx,
            })
            .collect()
    }
}
