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

        match self.incremental_admission(id, Owed::Datagram(from, bytes.into()), now, send, true) {
            Ok(answered) => RawIngress::Answered(answered),
            Err(_) => {
                self.raw_busy_dropped.fetch_add(1, Ordering::Relaxed);
                RawIngress::BusyDropped
            }
        }
    }

    /// Admit raw input after helping at most four ready producer batches. The datagram
    /// remains borrowed throughout: busy producers and exhausted output credit never queue it.
    /// `publish` must publish each checked batch and release its publication barrier before
    /// returning; an unreleased barrier simply prevents further progress in this turn.
    pub fn raw_datagram_with_publication(
        &self,
        from: SocketAddr,
        bytes: &[u8],
        now: Instant,
        send: &dyn Fn(SocketAddr, &[u8]),
        mut publish: impl FnMut(Answered),
    ) -> RawIngress {
        use super::LineStep;
        use std::task::Poll;

        let Some(id) = self.lock().find(from, bytes) else {
            return RawIngress::Unrouted;
        };
        // Bound work on the shared UDP port even when a framer keeps recalling.
        for _ in 0..4 {
            match self.poll_line_inner(id, None, None, false, now, send) {
                Poll::Ready(Ok(LineStep::Batch { yielded, .. })) => {
                    publish(vec![(id, Ok(yielded))]);
                }
                Poll::Ready(Err(error)) => {
                    return RawIngress::Answered(vec![(id, Err(error))]);
                }
                Poll::Ready(Ok(LineStep::Complete | LineStep::Credit)) | Poll::Pending => break,
            }
        }
        self.raw_datagram(from, bytes, now, send)
    }

    /// Newly received raw datagrams discarded because their association was not receive-ready,
    #[must_use]
    pub fn raw_busy_dropped(&self) -> u64 {
        self.raw_busy_dropped.load(Ordering::Relaxed)
    }
}
