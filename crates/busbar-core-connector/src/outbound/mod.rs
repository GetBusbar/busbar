// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OUTBOUND PARTS: what the engine itself decides about a connection it wrote to, each as a
//! part that owns no socket and calls no plugin, so each is proven alone against a reference
//! transport before the real one exists.
//!
//! * [`records`]: the transport 2.0 records these parts read, in the contract's own layouts.
//! * [`delivery`]: the delivery record (`whole` / `part` / `none`, the reason, the body bytes), the
//!   per-stream entry that produces it for an answer and for a provider attempt, the rules L2 to L7
//!   the engine checks on every answer, and the hold on an answer's last piece.
//! * [`seal`]: sealed credentials. The transport is told a slot and a length; the engine writes the
//!   bytes at the socket.
//! * [`credit`]: what a multiplexed session may make the engine hold, and the credit that reopens a
//!   stream's window as its reader reads.
//! * [`lend`]: which connection an open rides (a stream on one in use, a kept idle one, a dial).
//! * [`redial`]: what was sent decides: send again, charge the provider, and what is recorded.
//! * [`tunnel`]: the operator's proxy on the dial: the CONNECT, its answer, and the proxy reached
//!   over TLS.
//! * [`ws`]: a WebSocket upstream on the dial.
//!
//! Order of use on one dialled connection (the dial's wiring follows this, nothing else):
//!
//! 1. `lend::choose` picks the connection. A dial plans its route with `tunnel::route`.
//! 2. `tunnel::Phase` drives connect, the proxy's own TLS, the CONNECT, the target's TLS.
//! 3. `begin` answers `records::Session`: `credit::Credit::new` and `lend::InUse::state`.
//! 4. A head: `seal::Slots::take_from` (the opener's head loses its sealed values and its sealing
//!    metadata), `seal::Slots::admit` (the plaintext rule, before any byte), the head records with
//!    `seal::Slots::declared`, then `emit(0, HEAD)`.
//! 5. Every answer, in order, each item one [`records::Out`]: `delivery::Ledger` first (a breach
//!    ends the session), then `seal::Slots::cover` for a sealed part, `credit` for inbound body.
//! 6. The socket took bytes: `delivery::Ledger::accepted`.
//! 7. The attempt ended: `delivery::Ledger::state_of` then `redial::decide`.

pub(crate) mod credit;
pub(crate) mod delivery;
pub(crate) mod lend;
pub(crate) mod records;
pub(crate) mod redial;
pub(crate) mod seal;
pub(crate) mod tunnel;
pub(crate) mod ws;
