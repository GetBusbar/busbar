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
//! ## The lower-layer boundary (a placeholder — see the crate's own report)
//!
//! The architecture composes `ws` OVER `http` (itself over `tcp`/`tls`), and states the top
//! transport in a stack owns claims while lower layers only yield frames. The `tcp`/`tls`/`http`
//! transport crates are owned by a different agent and are out of reach here (`you may not depend
//! on them yet`). So this crate defines its own lower-layer boundary as `rw::Rw` (any duplex,
//! `Unpin + Send` byte stream) and, until the shared transports exist, satisfies it itself: `dial`
//! resolves the host and opens a raw TCP (optionally TLS) socket directly, and `accept` binds and
//! accepts raw TCP directly, running `tokio-tungstenite`'s HTTP-upgrade handshake over whichever
//! socket it produced. Composing over the real `http`/`tls` transport crates, once they exist,
//! should mean handing this crate their already-established connection instead — the seam is
//! `rw::Rw` / [`WsTransport::handshake_over`], not a rewrite of the framing below it.
//!
//! Also placeholder: `dial` does its own DNS resolution rather than the resolve-then-pin discipline
//! the SSRF guard applies elsewhere in the codebase (`busbar_substrate::net_guard`), because that
//! guard lives in a crate this one may not depend on. A real deployment needs that guard placed in
//! front of this crate's `dial`, not inside it.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod conn;
mod rw;
mod transport;

pub use conn::StaticConfig;
pub use transport::WsTransport;

#[cfg(test)]
#[path = "tests/battery.rs"]
mod battery;
