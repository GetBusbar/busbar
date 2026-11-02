// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Admission of newly received network datagrams on a shared port.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Instant;

use super::{Answered, Owed, PortAssociations};

/// The admission result for one newly received network datagram.
#[derive(Debug)]
pub enum RawIngress {
    /// The ordinary admission result; it can be empty when the selected association closed.
    Answered(Answered),
    /// The selected live association was busy or lacked output credit, before framer acceptance.
    BusyDropped,
    /// No association was found for the datagram.
    Unrouted,
}

impl RawIngress {
    /// Checked output to publish from this admission attempt.
    #[must_use]
    pub fn into_answered(self) -> Answered {
        match self {
            Self::Answered(answered) => answered,
            Self::BusyDropped | Self::Unrouted => Vec::new(),
        }
    }
}

impl PortAssociations {
    /// Admit a newly received raw network datagram without queuing it behind a busy association.
    /// Application writes and already accepted output retain their ordinary custody paths.
    pub fn raw_datagram(
        &self,
        from: SocketAddr,
        bytes: &[u8],
        now: Instant,
        send: &dyn Fn(SocketAddr, &[u8]),
    ) -> RawIngress {
        let Some(id) = self.lock().find(from, bytes) else {
            return RawIngress::Unrouted;
        };
        // Future: offer bounded per-association buffering as an advanced option.
        match self.incremental_admission(id, Owed::Datagram(from, bytes.into()), now, send, true) {
            Ok(answered) => RawIngress::Answered(answered),
            Err(_) => {
                self.raw_busy_dropped.fetch_add(1, Ordering::Relaxed);
                RawIngress::BusyDropped
            }
        }
    }

    /// Newly received raw datagrams discarded because their association was not receive-ready,
    /// including unavailable pre-crossing output credit under its configured memory limit.
    /// Unrouted datagrams and selections already closing or removed do not contribute.
    #[must_use]
    pub fn raw_busy_dropped(&self) -> u64 {
        self.raw_busy_dropped.load(Ordering::Relaxed)
    }
}
