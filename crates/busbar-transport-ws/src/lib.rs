// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The WebSocket transport: duplex message frames over an HTTP upgrade.
//!
//! This crate carries exactly the byte-level behaviour the architecture's ws row names: the
//! session opens at the upgrade (`Unit0Trigger::Upgrade`), frames after the upgrade carry no
//! status leg (`STATUS_CLASS = None`), and text/binary WS messages are the frame unit. It carries
//! no protocol meaning — no verbs, no ids, no JSON. That belongs to whichever plane rides this
//! transport.
//!
//! ## The lower layer
//!
//! The architecture composes `ws` OVER `http` (itself over `tcp`/`tls`), and states the top
//! transport in a stack owns claims while lower layers only yield frames. That is literally what
//! happens here: this crate opens no socket, binds no address and resolves no name. It is built
//! [`WsTransport::over`] a lower transport, and every byte reaches it as a stream that layer gives
//! up — an inbound upgrade arrives on `http`, an outbound one is dialled through `tcp` or `tls`.
//! Which of those two carries an outbound dial is not a preference: this crate encrypts nothing,
//! so a `wss://` target is only honest when the layer below is `tls`, and a secure target dialled
//! over a cleartext layer is refused rather than downgraded onto the wire.
//!
//! Two things follow from that, and both are the point. The composed chain an arrival reports is
//! the one it actually stands on, because it is the layer below's chain plus this one. And the
//! resolve-then-pin network guard sits in front of the dial, in the trust unit, once for the whole
//! stack — not inside each transport, where a new carrier would have to remember to grow one.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod claims;
mod conn;
mod meta;
mod transport;

pub use conn::StaticConfig;
pub use transport::{WsTransport, MESSAGE_MAX_BYTES_KEY};

/// THE TRANSPORT AXIS ENTRY (#3, #30): what the composition root folds for this wire — its key, the
/// layers it declares, and how it is built. The root names none of them.
pub mod linked {
    use std::sync::Arc;

    use busbar_contract::transport::{Transport, TransportMeta, TransportSettings};

    use crate::WsTransport;

    /// The row's registry key.
    pub const KEY: &str = <WsTransport as TransportMeta>::KEY;
    /// The layers this wire declares it can be built over.
    pub const COMPOSES_OVER: &[&str] = <WsTransport as TransportMeta>::COMPOSES_OVER;
    /// Whether this wire carries sessions.
    pub const SESSION: bool = <WsTransport as TransportMeta>::SESSION;

    /// Built over `lower` — never over nothing, which yields a transport that refuses every
    /// connection — with the deployment's body cap as its message ceiling: a message is assembled
    /// from frames before anything above the transport sees it, so the ceiling is stated at the
    /// handshake or not at all. With no lower layer the boot check has already refused the stack.
    #[must_use]
    pub fn build(
        lower: Option<Arc<dyn Transport>>,
        settings: &TransportSettings,
    ) -> Arc<dyn Transport> {
        Arc::new(match lower {
            Some(lower) => {
                WsTransport::over_with_max_message_bytes(lower, settings.request_body_max_bytes)
            }
            None => WsTransport::new(),
        })
    }
}

#[cfg(test)]
#[path = "tests/battery.rs"]
mod battery;
