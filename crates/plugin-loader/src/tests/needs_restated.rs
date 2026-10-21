// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One outbound `tcp` need a test's door declares in its Statement (a door the macro builds, so the
//! loader enters no restated door), and a connection table that opens none. The bind tests read what
//! the loader does with a door that declares a need.

use busbar_contract::abi::host::conn::connector::{Need, DIRECTION_OUTBOUND, KEEP_NAMED};
use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::sdk::door::abi_str;

use crate::dispatch::NO_BLOB;

const NONE: AbiStr = AbiStr::ABSENT;

/// One outbound need over `transport`, its target the plugin's own.
#[must_use]
pub(crate) const fn need(transport: AbiStr) -> Need {
    let mut need = Need::EMPTY;
    need.direction = DIRECTION_OUTBOUND;
    need.transport = transport;
    need.auth = NONE;
    need.target_from = NONE;
    need.trust_from = NONE;
    need.details = NO_BLOB;
    need.keep_mode = KEEP_NAMED;
    need
}

/// One `tcp` need.
pub(crate) const TCP: [Need; 1] = [need(abi_str("tcp"))];

/// A connection table that DECLARES every need over any scheme and OPENS none: what a test that
/// serves a networked door it never lets dial binds over (the bind needs a table; nothing reaches it).
#[derive(Debug, Default)]
pub(crate) struct Inert;

impl busbar_contract::conn::Conns for Inert {
    fn open(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::NeedId,
        _: &busbar_contract::conn::OpenDesc<'_>,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Refused)
    }
    fn write(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
        _: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn read(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
        _: u64,
        _: &mut [u8],
    ) -> Result<busbar_contract::conn::Piece, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn wait(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: &[busbar_contract::conn::ConnId],
        _: u64,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn facts(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
    ) -> Result<busbar_contract::transport::ConnFacts, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn close(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        Ok(())
    }
}

impl busbar_contract::conn::DeclaredConns for Inert {
    fn declare(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::NeedId,
        _: &busbar_contract::abi::mechanism::rendering::ReadNeed,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        Ok(())
    }
    fn declared(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::NeedId,
    ) -> Option<Result<(), busbar_contract::conn::ConnError>> {
        Some(Ok(()))
    }
    fn serves_scheme(&self, _: &str) -> bool {
        true
    }
}
