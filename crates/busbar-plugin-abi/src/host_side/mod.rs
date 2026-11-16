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

pub use answer::*;
pub use caller::*;
pub use driver::*;
pub use host_vt::*;
pub use needs::*;
pub use pool::*;
pub use scrub::*;
pub use watch::*;
