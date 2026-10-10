// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `webrtc` TRANSPORT: a datagram framer holding ICE, SRTP and SCTP (`BUSBAR-1.6.0.md` THE
//! DESIGN §5, "Datagram media", l.756-765).
//!
//! WebRTC mirrors HTTPS layering. The datagram port is the host's (the connector's, no carrier
//! plugin); DTLS runs in the host's secure layer with the host certificate, demultiplexing the port
//! and gating each association on ICE. This framer holds what is left: the ICE agent (it answers and
//! nominates; the host binds only a path it has proven), SRTP (AEAD-AES-GCM only, on ring, with the
//! keying material the host's secure layer exported) and SCTP data channels. It holds no DTLS state
//! ([`shim`]). Opus passes through; no codec runs.
//!
//! ## One entry: the door
//!
//! [`door::door`] is the memory-ABI door, the same table compiled in (the `linked` row) and dropped
//! in (this crate's cdylib, built with the `dropped-in` feature).
//!
//! This crate is `deny`, not `forbid`: the export macro's `#[unsafe(no_mangle)]` is the one
//! reviewed exemption, compiled only into the dropped-in image. No other `unsafe` exists here.

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod crypto;
pub mod door;
pub mod framing;
pub mod shim;
pub mod stun;

/// THE TRANSPORT AXIS ENTRY: the row's key and its door.
pub mod linked {
    pub use crate::door::{door, KEY};
}

/// THE DROPPED-IN DOOR: the macro's `#[no_mangle]` symbol is the one exemption.
#[cfg(feature = "dropped-in")]
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(crate::door::door);
}
