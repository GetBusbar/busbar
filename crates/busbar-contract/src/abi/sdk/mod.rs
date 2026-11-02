// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN SDK: the typed Rust wrappers over the memory ABI (`BUSBAR-1.6.0.md` THE DESIGN, one

#![allow(unsafe_op_in_unsafe_fn)]

pub mod aead;
pub mod boundary;
pub mod completion_retirement;
/// Rust-only codec and typed facts for negotiated main-call host inspection.
pub mod inspection_wire;

pub use crate::net;

pub mod transport;

pub mod door;
pub mod hook;

pub mod export;

pub mod mask;

pub mod url;
pub use crate::{export_door, plugin_door};

pub mod capture;

#[macro_use]
pub mod lent;
pub mod safe;
pub use lent::{open_failed, HostBuf, Lent, LentList, SignalScalar};

pub mod generation;
pub use generation::Gen;

pub mod out;
pub use out::{Out, Scalar};

pub mod conn;
pub mod io;

/// A plane's reads of a body by declared pointer, one copy for every plane.
pub mod body;
pub mod exchange;
pub use safe::{Instance, Safe, SafeSlot};

pub mod services;
pub use services::{
    CredentialSecret, Judged, Minted, Names, Pend, Records, ServiceError, Services, Signature,
    Signed, StaticServices, StaticWake, TrustItem, TrustItems, Wake,
};

pub mod digest;

pub mod hmac;

pub mod cred;

mod secret_bytes;

pub mod chip;

pub mod auth_door;

pub mod auth_outbound;

pub mod auth_kit;

pub mod store;

pub mod secret;

pub mod publish;
pub use publish::{Generations, Keyed};

pub mod plane;

pub mod trust;

pub mod life;

pub mod migrate;

pub mod plane_life;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

/// The "decision observability" signal catalog: a plugin author references
pub use crate::signal::{Signal, SignalBag, SignalValue};

/// Re-export the export kind's stream and field vocabulary, and the scraped snapshot's family and
pub use crate::abi::export::{CheckPhase, ExportField, ExportStream, MetricFamily, MetricSample};

/// Re-export the observability envelope (#85) so a plugin author names
pub use crate::abi::mechanism::observe::{
    DiagLevel, Envelope, Observations, PluginDiagnostic, PluginMetric,
};

/// Re-export the endpoint wire types (plugin route registration + dispatch) so an export/hook
pub use crate::abi::mechanism::endpoint::{EndpointRequest, EndpointResponse};
pub use crate::abi::mechanism::route::{Route, RouteAuth, RouteMethod};
