// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's I/O table's off-path text (`crate::hostio`): a peer's address spelled once, as a
//! connection is accepted or a handle's ends are asked for, never per byte moved.

/// A peer's address as the host hands it to the entry.
pub(crate) fn peer_text(peer: &std::net::SocketAddr) -> String {
    peer.to_string()
}
