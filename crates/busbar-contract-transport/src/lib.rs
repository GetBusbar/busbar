// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The transport-facing contract: what a transport author reads, and nobody else has to.
//!
//! The contract crate has one job — be the thing a plugin author reads — and one ceiling that
//! measures whether it is doing it. Transports are in-tree and never dynamically loaded, so a
//! transport author is not a plugin author: they are inside the trusted computing base, reviewed
//! with the kernel. Everything the two axes shared was nevertheless in one crate, and it was the
//! transport half that made the plane half hard to read.
//!
//! So the transport half is here: the listener and the connection, the detached stream an in-band
//! upgrade hands over, the closed failure and close codes, the arrival record the bottom layer
//! writes, the upstream address the dialling family spells, the fact keys the kernel reserves, the
//! kind's ABI generation, and the boot check that a composed stack is the stack every layer
//! declared. The frame a plane reads, the cursor it reads through and the envelope it decorates
//! stayed in the contract, because those borrow the arena the contract owns.
//!
//! This crate sits BELOW the contract and names nothing of busbar's, so the contract can re-export
//! what a plane still touches and no plane import changes. A transport, and the three units that
//! deal in transports — egress, trust and the transport-key unit — name this crate directly.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]

pub mod dest;
pub mod registry;
pub mod wire;

/// A plugin kind's native interface generation.
///
/// Spelled here because the transport kind's own generation is spelled here, and a generation that
/// two crates each declared their own newtype for would compare equal to nothing. It carries no
/// meaning of its own: a kind pins a number, and the loader or the surface scan compares against it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct AbiVersion(pub u16);

pub use dest::UpstreamAddress;
pub use registry::{check_composition, facts, CompositionError, Registered, TRANSPORT_ABI};
pub use wire::{
    ArrivalRecord, CertFacts, CloseReason, Conn, ConnHandle, Decode, Direction, DiscardCode,
    Encode, FrameMeta, Framing, Handoff, HandshakeTrigger, Listener, ListenerHandle, RawIo,
    RawStream, StatusAt, StatusClass, TransportError, Unit0Trigger,
};
