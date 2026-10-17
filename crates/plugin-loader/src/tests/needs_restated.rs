// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A real door RESTATED with one outbound `tcp` need, the way the conformance suite's RED arms
//! restate a door (`red_ready`): no plugin of its own, the door's own table and Statement with only
//! its needs moved. The bind tests below read what the loader does with a door that declares a need.

use std::sync::atomic::{AtomicPtr, Ordering};

use busbar_contract::abi::host::conn::connector::{Need, DIRECTION_OUTBOUND, KEEP_NAMED};
use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::{Door, DoorFn, Statement};
use busbar_contract::abi::sdk::door::abi_str;

use crate::dispatch::NO_BLOB;

const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// One outbound need over `transport`, its target the plugin's own.
#[must_use]
pub(crate) const fn need(transport: AbiStr) -> Need {
    Need {
        direction: DIRECTION_OUTBOUND,
        egress_class: 0,
        transport,
        auth: NONE,
        target_from: NONE,
        trust_from: NONE,
        details: NO_BLOB,
        keep_response_headers: std::ptr::null(),
        keep_response_headers_len: 0,
        timeout_ms: 0,
        keep_mode: KEEP_NAMED,
        _reserved: 0,
        deny_response_headers: std::ptr::null(),
        deny_response_headers_len: 0,
    }
}

/// One `tcp` need.
pub(crate) const TCP: [Need; 1] = [need(abi_str("tcp"))];

/// `real`'s door with its Statement declaring `needs`, stored in `slot` (once) and answered.
pub(crate) fn restate(slot: &AtomicPtr<Door>, real: DoorFn, needs: &'static [Need]) -> *const Door {
    let have = slot.load(Ordering::SeqCst);
    if !have.is_null() {
        return have;
    }
    // SAFETY: a door function answers a `'static` door with a `'static` Statement.
    let door: Door = unsafe { real().read_unaligned() };
    let st: Statement = unsafe { door.statement.read_unaligned() };
    let st: &'static Statement = Box::leak(Box::new(Statement {
        needs: needs.as_ptr(),
        needs_len: needs.len(),
        ..st
    }));
    let door = Box::into_raw(Box::new(Door {
        statement: st,
        ..door
    }));
    match slot.compare_exchange(
        std::ptr::null_mut(),
        door,
        Ordering::SeqCst,
        Ordering::SeqCst,
    ) {
        Ok(_) => door,
        Err(won) => won,
    }
}

/// `$name`: a door function answering `$real` restated with one `tcp` need.
macro_rules! tcp_restated {
    ($name:ident, $real:path) => {
        extern "C" fn $name() -> *const ::busbar_contract::abi::mechanism::door::Door {
            static SLOT: ::std::sync::atomic::AtomicPtr<
                ::busbar_contract::abi::mechanism::door::Door,
            > = ::std::sync::atomic::AtomicPtr::new(::std::ptr::null_mut());
            $crate::needs_restated::restate(&SLOT, $real, &$crate::needs_restated::TCP)
        }
    };
}
pub(crate) use tcp_restated;

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
