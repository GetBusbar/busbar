// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `io.*` — READINESS ON THE PER-WORKER REACTOR (`BUSBAR-1.6.0.md` THE DESIGN, §5 and §11.2).

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
pub use unix::*;
#[cfg(windows)]
pub use windows::*;

/// What [`register`] answers off a worker: the descriptor was not registered.
pub const NOT_ON_A_WORKER: &str = "io.register: not on a worker's reactor";

/// A direction of a registered descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Bytes can be read (or a connection accepted).
    Read,
    /// Bytes can be written (or a connect completed).
    Write,
}

/// The process's one runtime, as the root installed it at boot.
static PROCESS_REACTOR: std::sync::OnceLock<tokio::runtime::Handle> = std::sync::OnceLock::new();

/// Install the process's one runtime: a socket registered off a runtime thread goes on its
pub fn install_process_reactor(handle: tokio::runtime::Handle) {
    let _ = PROCESS_REACTOR.set(handle);
}

/// Off a runtime's task, the process's one runtime entered for the guard's life — its reactor for a
pub(crate) fn enter_process_runtime() -> Option<tokio::runtime::EnterGuard<'static>> {
    if tokio::runtime::Handle::try_current().is_ok() && tokio::task::try_id().is_some() {
        return None;
    }
    PROCESS_REACTOR.get().map(tokio::runtime::Handle::enter)
}

#[cfg(test)]
#[path = "tests/io_tests.rs"]
mod tests;
