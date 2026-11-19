// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core's side of the interface (IF §10, feature `host`), reached as `busbar_plugin_abi::host::*`.

pub mod answer;
pub mod caller;
pub mod driver;
pub mod entry;
pub mod host_vt;
pub mod needs;
pub mod pool;
pub mod proxy;
pub mod scrub;
pub mod watch;

/// The boundary crate's kind markers and live session, for core's host-side crates (busbar-ports):
/// only this crate, the loader and plugin-test may depend on busbar-ffi (unsafe.yaml `dependents`, E12),
/// so the others name these through here.
pub mod boundary {
    pub use busbar_ffi::host::Session;
    pub use busbar_ffi::{Kind, kind};
}

pub use answer::*;
pub use caller::*;
pub use driver::*;
pub use host_vt::*;
pub use needs::*;
pub use pool::*;
pub use scrub::*;
pub use watch::*;
