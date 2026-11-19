// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The transport kind: how bytes move.

pub mod codes;
pub mod dest;
pub mod fields;
pub mod registry;

pub mod trust;
pub mod wire;

/// A plugin kind's native interface generation: the one ABI version type
/// ([`crate::abi::versions::AbiVersion`]), equal or not equal and nothing else (LINT-RULES R21).
pub use crate::abi::versions::AbiVersion;

/// The fact keys the kernel reserves for a transport, and the transport settings.
pub use registry::{
    facts, TransportSettings, DEFAULT_REQUEST_BODY_MAX_BYTES, DEFAULT_REQUEST_TIMEOUT_SECS,
};

/// Where a dial lands, as the transport family that dials it spells it — named at the transport
pub use dest::UpstreamAddress;

/// The host-owned trust seam currency: the client identity and the egress trust a
pub use trust::{ClientIdentity, EgressTrust};

/// The transport wire vocabulary a plane still touches, re-exported at the transport module root so
pub use wire::{
    ArrivalRecord, CertFacts, CloseReason, Conn, ConnFacts, ConnHandle, ConnectionIo, Decode,
    Direction, DiscardCode, Encode, FrameMeta, Framing, Handoff, RawIo, RawStream, Side, StatusAt,
    TransportError, Unit0Trigger, WireFault, WireStatus, WireStatusClass,
};
