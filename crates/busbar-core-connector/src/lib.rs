// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `busbar-core-connector` — THE CONNECTOR (THE DESIGN: connections). The chain is kernel →
//! connector → transport plugins: every plugin that needs an external connection declares a need,
//! and the kernel instantiates the transport through this crate. The kernel knows nothing about
//! transport; this crate is where everything below the framer lives.
//!
//! * [`Connector`] is the host side of the one connection table every kind reaches the network
//!   through ([`busbar_contract::conn::Conns`]): a plugin opens a connection for a need it declared,
//!   then writes, reads, waits and closes it. Ownership is the shared book
//!   ([`busbar_contract::conn::ConnSlab`]): a connection another instance owns, a closed one and a
//!   need nobody declared are refused.
//! * [`endpoint`] is the pure check an open's target passes before any dial: a cloud metadata host,
//!   in any spelling, is refused by name.
//! * [`tls`] is connection security — core-only, never a plugin, never crossing the ABI.
//! * [`udp`] is the host's datagram socket: one bound port, a peer per datagram.
//!
//! THE SHELL. This landing holds the table and its ownership book; composing a need's transports
//! (carrier → [TLS] → framer) is the next step, so until then an open for a declared need is refused
//! with [`NO_TRANSPORT_YET`] — never a silent success.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod endpoint;
pub mod tls;
pub mod udp;

use busbar_contract::conn::{
    ConnError, ConnId, ConnSlab, Conns, InstanceId, NeedId, OpenDesc, Piece, Ticket,
};
use busbar_contract::transport::ConnFacts;

/// What an open for a DECLARED need answers while no transport is composed for it: refused, never
/// a silent success.
pub const NO_TRANSPORT_YET: ConnError = ConnError::Refused;

/// One connection the connector holds for its owner.
#[derive(Debug)]
struct Held;

/// THE CONNECTOR: the host side of the connection table.
#[derive(Debug, Default)]
pub struct Connector {
    slab: ConnSlab<Held>,
}

impl Connector {
    /// A connector holding no connection and no declared need.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `owner` declared `need` — the only needs it may open.
    pub fn declare(&self, owner: InstanceId, need: NeedId) {
        self.slab.declare(owner, need);
    }
}

impl Conns for Connector {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.slab.check_need(caller, need)?;
        endpoint::check(desc.target).map_err(|_| ConnError::Refused)?;
        Err(NO_TRANSPORT_YET)
    }

    fn write(
        &self,
        caller: InstanceId,
        conn: ConnId,
        _bytes: &[u8],
        _end: bool,
    ) -> Result<usize, ConnError> {
        self.slab.get(caller, conn)?;
        Err(ConnError::Closed)
    }

    fn read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        _ticket: Ticket,
        _buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        self.slab.get(caller, conn)?;
        Err(ConnError::Closed)
    }

    fn wait(
        &self,
        caller: InstanceId,
        set: &[ConnId],
        _ticket: Ticket,
    ) -> Result<usize, ConnError> {
        for conn in set {
            self.slab.get(caller, *conn)?;
        }
        Err(ConnError::Pending)
    }

    fn facts(&self, caller: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        self.slab.get(caller, conn)?;
        Err(ConnError::Closed)
    }

    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        self.slab.remove(caller, conn).map(|_| ())
    }
}

#[cfg(test)]
#[path = "tests/connector_tests.rs"]
mod tests;
