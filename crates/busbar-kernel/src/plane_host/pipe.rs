// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The PIPE tier of the egress family: the two vtable slots a byte-DUPLEX channel is driven
//! through ([`pipe_read`] / [`pipe_write`], keyed by a [`PipeId`]).
//!
//! NO TIER OPENS A PIPE. The raw-connection tier answers `Unsupported` and the subprocess tier
//! answers `Refused` at the seam ([`super::egress`]): no operator configuration wires a subprocess
//! program allowlist over the FFI seam, so the host authorizes no plane-driven program (FFI-F3). The
//! spawning machinery this module held — the command decode, the host-side environment resolution
//! (a secret reference resolved at the spawn, on the request it served) and the child's lifecycle
//! — ran in no served path and is struck (F11; row 166). A member program a plane needs is spawned
//! by the connector over its declared program need, its environment held since config time
//! (`busbar_core_connector::spawn_env`).
//!
//! So both slots answer as they did for every pipe a plane could name: `Gone` (no such pipe), after
//! the host-context and out-pointer checks, and FAIL CLOSED on a caught panic.

use super::recover;
use busbar_contract::abi::hot::host::HostCtx;
use busbar_contract::abi::hot::{PipeId, StatusClass};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Read raw bytes from a governed pipe into the caller's buffer: no pipe is ever open, so every
/// named pipe is `Gone`.
pub(crate) extern "C-unwind" fn pipe_read(
    host: HostCtx,
    _pipe: PipeId,
    _buf: *mut u8,
    _buf_cap: usize,
    out_written: *mut usize,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let Some(_state) = (unsafe { recover(host) }) else {
            return StatusClass::Refused;
        };
        if out_written.is_null() {
            return StatusClass::Refused;
        }
        StatusClass::Gone
    }))
    .unwrap_or(StatusClass::Fault)
}

/// Write raw bytes to a governed pipe: no pipe is ever open, so every named pipe is `Gone`.
pub(crate) extern "C-unwind" fn pipe_write(
    host: HostCtx,
    _pipe: PipeId,
    _buf: *const u8,
    _len: usize,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let Some(_state) = (unsafe { recover(host) }) else {
            return StatusClass::Refused;
        };
        StatusClass::Gone
    }))
    .unwrap_or(StatusClass::Fault)
}

#[cfg(test)]
#[path = "pipe_tests.rs"]
mod tests;
