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
//! * [`connect`]: several addresses for one name: each its share of the time, the other family
//!   started after a short delay.
//! * [`ws`]: a WebSocket upstream on the dial.
//! * [`retry_after`]: `Retry-After` as seconds or as a date, both read.
//! * [`wire`]: the driver. One connection's ledger, slots, credit and lending state, applied to
//!   each answer of the transport in the one order that is right. The dial calls the driver and
//!   the three planners (`lend::choose`, `tunnel::Dialling`, `connect::Race`), nothing else.
//!
//! Order of use on one dialled connection (the dial's wiring follows this, nothing else):
//!
//! 1. `lend::choose` picks the connection: a stream on one in use, a kept idle one, or a dial.
//! 2. A dial: `tunnel::hop_for` and `tunnel::Target::of` plan the route, `connect::Race` orders
//!    the addresses, `tunnel::Dialling` drives the steps below the session (connect, the proxy's
//!    own TLS, the CONNECT, the target's TLS).
//! 3. `begin`'s answer goes to `wire::Wire::answer` like every answer: its `SESSION` record makes
//!    the connection's credit and lending state.
//! 4. A head: `seal::Slots::take_from` (the opener's head loses its sealed values and its sealing
//!    metadata), `seal::Slots::admit` (the plaintext rule, before any byte), the head records
//!    written from `seal::Slots::declared`, `wire::Wire::offer`, then `emit(0, HEAD)`.
//! 5. Every answer: `wire::Wire::answer`. Every `emit` of a body, an end, a refusal or a reset:
//!    the matching `wire::Wire::emitting_*` / `stopping` first.
//! 6. The socket took bytes: `wire::Wire::accepted`. A reader took body bytes: `wire::Wire::taken`.
//! 7. The attempt ended: `wire::Wire::state_of` and `wire::Wire::ended_how`, then
//!    `redial::decide`; `wire::Wire::over` releases the stream (and hands back the sealed values
//!    when the request is sent again).

pub(crate) mod connect;
pub(crate) mod credit;
pub(crate) mod delivery;
pub(crate) mod lend;
pub(crate) mod records;
pub(crate) mod redial;
pub(crate) mod retry_after;
pub(crate) mod seal;
pub(crate) mod tunnel;
pub(crate) mod wire;
pub(crate) mod ws;
