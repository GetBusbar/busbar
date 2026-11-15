// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MIN-3 plugin interface (ABI-MIN3-INTERFACE, round 34): the records codec, Host services, Need steps,
//! the plugin header, `Open`/`Describe`, the stamp, the fingerprint and the seven kind traits; feature `host`
//! adds core's side (§10), feature `memio` the in-memory IO adapter (§9).
//!
//! Wave 0 (W0-ABI) lands every frozen signature as a compiling stub with `todo!()` bodies; each wave-1 task
//! replaces the stubs in the files it owns. The stubs carry no `unsafe`: the raw entry tables and the other
//! `unsafe` items arrive with their owners (W1-A1, W1-A2, W1-A4, W1-H0) under an escapes admission.

#![deny(unsafe_code)]

pub mod bridge;
pub mod fail;
pub mod fp;
pub mod host;
#[cfg(feature = "host")]
pub mod host_side;
pub mod kind;
pub mod kinds;
#[cfg(feature = "memio")]
pub mod memio;
pub mod need;
pub mod plugin;
pub mod records;
pub mod slots;
pub mod stamp;
pub mod types;
pub mod versions;

pub use kinds::auth::{Auth, auth};
pub use kinds::export::{Export, export};
pub use kinds::hook::{Hook, hook};
pub use kinds::plane::{Plane, plane};
pub use kinds::secret::{Secret, secret};
pub use kinds::store::{Store, store};
pub use kinds::transport::{Transport, transport};
