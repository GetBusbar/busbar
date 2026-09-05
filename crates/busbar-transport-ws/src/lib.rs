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
//!
//! Two things follow from that, and both are the point. The composed chain an arrival reports is
//! the one it actually stands on, because it is the layer below's chain plus this one. And the
//! resolve-then-pin network guard sits in front of the dial, in the trust unit, once for the whole
//! stack — not inside each transport, where a new carrier would have to remember to grow one.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod conn;
mod transport;

pub use conn::StaticConfig;
pub use transport::WsTransport;

#[cfg(test)]
#[path = "tests/battery.rs"]
mod battery;
