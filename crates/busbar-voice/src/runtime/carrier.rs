// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CARRIER — the live session's downlink write side and its HARD-CLOSE latch.
//!
//! A voice session is an open-ended full-duplex carrier. `busbar_substrate::ingress::byte_duplex`
//! pumps the UPSTREAM socket (server→client events in, client→server events out through the handler's
//! `out`), but the DOWNLINK toward the actual client (the browser / telephony leg) is a separate sink
//! the runtime holds here. The [`Carrier`] also owns the one thing post-hoc metering structurally
//! cannot do: a HARD CLOSE the metering lease trips the instant the budget is dry — after which no
//! further downlink audio reaches the client and the session's supervisor tears the socket down.

use futures::channel::mpsc::UnboundedSender;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;

/// THE DOWNLINK + HARD-CLOSE handle shared across a session's per-frame handlers. Cheap to clone (an
/// `Arc` of the latch + the client sender), so every concurrent handler holds one.
#[derive(Debug, Clone)]
pub struct Carrier {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// Set once when the carrier hard-closes; every later downlink is dropped and the latch stays set.
    closed: AtomicBool,
    /// Woken on hard-close so a supervisor awaiting [`Carrier::closed`] can abort the serve task.
    gate: Notify,
    /// The DOWNLINK sink toward the client — one wire-framed message per send. `None` for a sideband
    /// carrier (topology A) that relays no media (the browser's media path is peer-to-peer).
    downlink: Option<UnboundedSender<Vec<u8>>>,
}

impl Carrier {
    /// A carrier with a downlink sink toward the client (the telephony proxy leg / a browser that
    /// takes media over the same socket).
    #[must_use]
    pub fn with_downlink(downlink: UnboundedSender<Vec<u8>>) -> Self {
        Carrier {
            inner: Arc::new(Inner {
                closed: AtomicBool::new(false),
                gate: Notify::new(),
                downlink: Some(downlink),
            }),
        }
    }

    /// A SIDEBAND carrier that relays no media (topology A): the browser establishes the media path
    /// peer-to-peer, so busbar's downlink is control-only and drops audio frames.
    #[must_use]
    pub fn sideband() -> Self {
        Carrier {
            inner: Arc::new(Inner {
                closed: AtomicBool::new(false),
                gate: Notify::new(),
                downlink: None,
            }),
        }
    }

    /// HARD-CLOSE the carrier: latch closed, wake any supervisor, and stop relaying downlink. Idempotent
    /// — a second close is a no-op. Returns `true` the first time (the transition), `false` after.
    pub fn hard_close(&self) -> bool {
        let first = !self.inner.closed.swap(true, Ordering::SeqCst);
        if first {
            self.inner.gate.notify_waiters();
        }
        first
    }

    /// Whether the carrier has hard-closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    /// Relay ONE wire-framed downlink message toward the client. A no-op that returns `false` once the
    /// carrier is closed (the hard-close guarantee — nothing reaches the client after exhaustion) or on
    /// a sideband carrier with no media path.
    pub fn send_downlink(&self, frame: Vec<u8>) -> bool {
        if self.is_closed() {
            return false;
        }
        match &self.inner.downlink {
            Some(tx) => tx.unbounded_send(frame).is_ok(),
            None => false,
        }
    }

    /// Resolve when the carrier hard-closes — the await a session supervisor parks on to abort the
    /// serve loop and drop the upstream socket. Returns immediately if already closed.
    pub async fn closed(&self) {
        if self.is_closed() {
            return;
        }
        self.inner.gate.notified().await;
    }
}
