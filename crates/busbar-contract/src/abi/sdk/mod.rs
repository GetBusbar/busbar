// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN SDK: the typed Rust wrappers over the memory ABI (`BUSBAR-1.6.0.md` THE DESIGN, one
//! place for every ABI shape, `abi/sdk/`). A plugin of any kind writes its slots against [`door`]
//! (`plugin_door!`) and exports its ONE door symbol through `export_door!`; compiled in or dropped
//! in, the host calls the same table.
//!
//! No plugin of any kind has a JSON-lane or a HOT-lane export: both lanes are gone (row 84), and the
//! door is the ONE symbol a plugin image exports. [`boundary`] is the one reviewed catch the
//! connection table and the safe layer cross.

// The SDK's `unsafe fn` bodies were written under the crate default (edition 2021: an `unsafe fn`
// body is itself an unsafe context). The shared ABI root denies `unsafe_op_in_unsafe_fn` for the two
// lanes; the SDK keeps the discipline it was written and reviewed under, unchanged by the merge.
#![allow(unsafe_op_in_unsafe_fn)]

pub mod boundary;
// THE URL AND HOST READER a plugin judges a destination with, the same one the host's guard reads
// through (`crate::net`, a pure helper outside `abi/`).
pub use crate::net;
// THE TRANSPORT DOOR'S HELPER: its selector forms as Statement codes (`form_codes`). The HOT transport
// lowering that lived here is deleted (row 84).
pub mod transport;
// THE DOOR MACRO (THE DESIGN, the plugin ABI; abi-v2, the SDK): the plugin side of the shared mechanism — one door,
// every slot a catch_unwind trampoline (`plugin_door!` / `export_door!`).
pub mod door;
pub mod hook;
// THE EXPORT KIND'S SHARED SINK PIECES: its tail, the push sink's refused `scrape`/`serve`, a quiet
// `status` and the `one_instance` check.
pub mod export;
// A URL AS A LOG LINE MAY NAME IT: userinfo and secret-looking query values masked.
pub mod mask;
pub use crate::{export_door, plugin_door};
// THE CALL CAPTURE: what a plugin logs during a call rides its reply as diagnostics (#85).
pub mod capture;
// THE SAFE SURFACE (THE DESIGN, plugins and the plugin ABI): a slot body with no `unsafe` — host-lent memory read and
// host buffers filled through `Lent`/`HostBuf`, the instance typed through `Instance`.
// `#[macro_use]`: the lists `lent.rs` states its accessors from are the test support's too (its
// pointer and length pairs, status row 194): one list, read in both places.
#[macro_use]
pub mod lent;
pub mod safe;
pub use lent::{open_failed, HostBuf, Lent, LentList, SignalScalar};
// THE GENERATION BORROW: what an op's `out` may name at runtime, held by the borrow checker to
// memory that lives until the instance's next refresh generation (status row 194).
pub mod generation;
pub use generation::Gen;
// A SLOT'S `out`, WRITTEN BY THE SDK: scalars set, every pointer through an SDK writer.
pub mod out;
pub use out::{Out, Scalar};
// A PLUGIN'S CONNECTIONS: the host connector for one op on one ticket, Ready|Pending, and exchange().
pub mod conn;
pub mod io;
// ONE REQUEST, ONE REPLY over the connector: exchange().
/// A plane's reads of a body by declared pointer, one copy for every plane.
pub mod body;
pub mod exchange;
pub use safe::{Instance, Safe, SafeSlot};
// THE HOST SERVICES, PLUGIN SIDE: the one home of every safe host-service wrapper.
pub mod services;
pub use services::{
    CredentialSecret, Judged, Names, Pend, Records, ServiceError, Services, Signature, Signed,
    StaticServices, StaticWake, TrustItem, TrustItems, Wake,
};
// THE ONE DIGEST A PLUGIN TAKES without linking a crypto crate of its own.
pub mod digest;
// THE ONE WIPED HMAC-SHA256 an auth plugin keys over secret material.
pub mod hmac;
// A PLUGIN'S CREDENTIALS: sealed at settings parse, no getter, no Debug (the chip design, its section on plugin credentials).
pub mod cred;
// THE CHIP'S RECIPES: every auth step performed by the credential (the chip design, its section on recipe classes).
pub mod chip;
// THE AUTH KIND'S VERIFY DOOR over the safe layer (`auth_verify_door!`). An auth plugin keeps its
// inbound verdict cache inside itself (THE DESIGN, section 11.11).
pub mod auth_door;
// THE AUTH KIND'S OUTBOUND DOOR over the safe layer (`auth_outbound_door!`, and
// `auth_door!(verify_and_outbound: ..)` for a plugin that does both).
pub mod auth_outbound;
// THE AUTH KIND'S SHARED PLUGIN PIECES: the withheld decode error and a completed login's identity.
pub mod auth_kit;
// THE STORE KIND'S TYPED SDK: the trait a store implements to be served through the store v3 table.
pub mod store;
// THE SECRET KIND'S SHARED SOURCE PIECES: the error-kind code, a reference's settings, the
// takes-no-settings refusal and the failed resolve.
pub mod secret;
// PUBLISHED GENERATION DATA: the SDK owns what a plugin publishes (`abi::sdk::publish`).
pub mod publish;
pub use publish::{Generations, Keyed};
// TRUST ON SIGHT, PLANE SIDE: the state word a trust view answers and the last contact it is
// derived from, one shape for every plane that sights an upstream on the kernel's trust book.
pub mod trust;
// THE LIFECYCLE, ONCE FOR EVERY KIND: the nine lifecycle slots over a kind's `Life` (`abi::sdk::life`).
pub mod life;
// THE PLANE LIFECYCLE, ONCE FOR EVERY PLANE: the nine slots over a plane's `PlaneLife`.
pub mod plane_life;
// THE PLUGIN TEST SUPPORT: the all-zero value of a reviewed ABI struct and a door's Statement read
// as Rust values, so a plugin's own tests drive its door with no `unsafe` (BUSBAR-1.6.0.md
// l.272-274). Compiled for this crate's tests and behind the dev-only `test-seal` feature, as the
// test kit is (`tests/feature_invariance.rs`); no shipped image carries it.
#[cfg(any(test, feature = "test-seal"))]
pub mod test_support;

/// The "decision observability" signal catalog: a plugin author references
/// `busbar_contract::abi::sdk::Signal::CandidateBreakerState` (etc.) at compile time to declare which
/// catalog entries their hook wants computed + projected — see `crate::signal::Signal`'s doc comment
/// for the full catalog and the append-only/non_exhaustive contract.
pub use crate::signal::{Signal, SignalBag, SignalValue};

// ── THE EXPORT KIND'S WIRE TYPES, re-exported for plugin authors ──────────────────────────────────

/// Re-export the export kind's stream and field vocabulary, and the scraped snapshot's family and
/// sample, so a plugin author names `busbar_contract::abi::sdk::ExportStream` (etc.) at this
/// module's path.
pub use crate::abi::export::{CheckPhase, ExportField, ExportStream, MetricFamily, MetricSample};

/// Re-export the observability envelope (#85) so a plugin author names
/// `busbar_contract::abi::sdk::PluginMetric` (etc.) without a direct `busbar-plugin` dependency, mirroring
/// every other wire type this SDK re-exports.
///
/// These are what a plugin uses to REPORT. Nothing here makes anything happen: the host validates
/// what arrives, bounds it, and decides. A plugin that wants a counter incremented says so and the
/// host increments it — which is also why a dropped-in build and a compiled-in build of the same
/// crate produce the same exposition (#11) instead of one of them reaching a recorder the other
/// cannot see.
pub use crate::abi::mechanism::observe::{
    DiagLevel, Envelope, Observations, PluginDiagnostic, PluginMetric,
};

/// Re-export the endpoint wire types (plugin route registration + dispatch) so an export/hook
/// author names `busbar_contract::abi::sdk::Route` / `EndpointRequest` (etc.) without a direct
/// `busbar-plugin` dependency.
pub use crate::abi::mechanism::endpoint::{EndpointRequest, EndpointResponse};
pub use crate::abi::mechanism::route::{Route, RouteAuth, RouteMethod};
