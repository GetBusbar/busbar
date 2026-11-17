// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The accept workers' balancers and the data listener's framer, built once when the listener
//! starts.

use std::sync::Arc;

use busbar_contract::abi::transport::ROLE_FRAMER;

use crate::root::listener::framed::{DataFramer, FramerFor};
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

/// The data listener's framer, configured once when the listener is built.
pub fn listener_framer(
    framer_for: FramerFor,
    scheme: &str,
    policy: crate::root::inbound::ListenerPolicy,
) -> Option<DataFramer> {
    configured_framer(framer_for, scheme, Some(policy))
}

pub(crate) fn configured_framer(
    framer_for: FramerFor,
    scheme: &str,
    policy: Option<crate::root::inbound::ListenerPolicy>,
) -> Option<DataFramer> {
    let door = framer_for(scheme)?;
    let facts = door.facts();
    if facts.role != ROLE_FRAMER || facts.datagram || !door.accepts() {
        return None;
    }
    let owner = door.instance().filter(|o| *o != 0)?;
    static LISTENERS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let listener = LISTENERS
        .try_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |n| n.checked_add(1),
        )
        .ok()?;
    let scheme = scheme.to_owned();
    Some(DataFramer {
        door,
        owner,
        scheme,
        listener: match policy {
            Some(policy) => crate::root::inbound::ListenerRegistration::with_policy(
                owner,
                listener,
                Some(policy),
            ),
            None => crate::root::inbound::ListenerRegistration::new(owner, listener),
        },
        dispatch: None,
        inbound_limit: None,
        process: None,
        upgrade: framer_for,
    })
}
