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
//! ## Serving a declared surface on it
//!
//! [`mount`] is the generic half: hand it a plane's declared surface and a session driver, and it
//! addresses the upgrade against a declared binding, publishes the arrival facts, hands every
//! inbound frame across the driver seam and writes back every frame the driver answers, in order.
//! Which plane it is serving it does not know, and `tests/no_plane_names.rs` holds it to that over
//! this crate's own source and manifest.
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

mod conn;
pub mod mount;
// The two ends of a real socket, as the generic mount's session loop wants them. Crate-private
// because the value it is built from — this crate's own upgraded socket type — is: nothing outside
// could hand it one, so a `pub` here would be a name no caller can reach. Behind `serve-sessions`
// because it is the half of the serving path that touches a socket; off, this crate is the
// byte-for-byte transport it was.
#[cfg(feature = "serve-sessions")]
pub(crate) mod session_io;
mod transport;

pub use conn::StaticConfig;
pub use transport::{WsTransport, MESSAGE_MAX_BYTES_KEY};

/// One session that is open and has not been pumped — the value an acceptor's drain reads.
///
/// Exported only where the serving path is compiled, because it is the serving path's own vocabulary
/// and a build without it has no acceptor to hold one.
#[cfg(feature = "serve-sessions")]
pub use transport::OpenSession;

#[cfg(test)]
#[path = "tests/battery.rs"]
mod battery;

#[cfg(all(test, feature = "serve-sessions"))]
#[path = "tests/session_io.rs"]
mod session_battery;
