// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN TEST FACADE (SDK-SAFE-TEST-HOST §2): load and drive any plugin from test code with
//! no `unsafe`. The host is the loader's `test_host`; the reviewed boundary is the SDK's
//! `test_support`; R131's scan is `abi_scan`. A plugin repository's one test dev-dependency.
//! W1-T1 adds the MIN-3 conformance harness (ABI-MIN3-INTERFACE §14): [`FakeNeeds`] and [`ConnScript`], the
//! kind [`suites`], the C-ERRORS check ([`errors`]), and `tests/<case>.rs`, one file per live §14 case.
#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]

/// The Q24 wipe proof. It lives in the contract (`busbar_contract::canary_scan`), whose own wipe
/// tests use the same scan; a plugin repository reaches it here.
pub use busbar_contract::canary_scan;
pub mod envelopes;
pub mod errors;
pub mod fake_needs;
pub mod services;
/// The IF §14 kind suites and `migrate` (W1-T1).
pub mod suites;
/// Host targets (SDK-SAFE-TEST-HOST §10): a plugin repository's conformance subject, behind the
/// facade features `target` (shared code, `std::net`) and `target-http` (the hyper carrier). Its
/// files live in `src/host_target/`: a directory named `target` is skipped as build output by the
/// repository's `.gitignore`, R131's source walk and BP14's name corpus.
#[cfg(feature = "target")]
#[path = "host_target/mod.rs"]
pub mod target;

/// The harness runtime (R40: built under `host_target/`, the facade's exempt directory).
#[path = "host_target/test_rt.rs"]
pub(crate) mod test_rt;

/// The Q24 wipe proof: plant a canary, drop it, scan `/proc/self/mem`, assert it is absent.
pub use busbar_contract::abi::sdk::test_support::canary;
pub use busbar_contract::abi::sdk::test_support::cpu;
pub use busbar_contract::abi::sdk::test_support::loans::{
    Buf, List, Loans, SecretBlobs, SignalArg,
};
pub use busbar_contract::abi::sdk::test_support::mutant::Mutant;
pub use busbar_contract::abi::sdk::test_support::watch::{Block, Freed, Watch};
pub use busbar_contract::abi::sdk::test_support::zeroed;
pub use busbar_contract::abi_scan;
/// The completed growth and drop wipe counts on this thread (`(growth, drop)`), so a plugin test can
/// prove an owner wiped without naming `busbar_secure` (DES-store-zeroizing-residual §5.0).
pub use busbar_contract::secure::wipe_counts;
pub use busbar_contract::services::{Caller, Later, Ran, Reading, Stored, UNSERVED};
/// The kinds an [`Image`] loads as.
pub use busbar_plugin_loader::dispatch::kinds::{
    auth::Auth, export::Export, hook::Hook, plane::Plane, transport::Transport,
};
pub use busbar_plugin_loader::dispatch::{
    rendering_of, ConnTable, Diagnostic, DispatchConfig, Dropped, EnvelopeSink, LoadError, Metric,
};
pub use busbar_plugin_loader::test_host::{
    both, rendering, Answer, Called, Done, Host, Image, Life, Loaded, Opened, Opening, Pending,
    Refused, Submitted, TimedOut,
};
/// The existing login vocabulary used with [`suites::harness::Harness::open_auth`].
pub use busbar_ports::auth::{LoginAnswer, LoginIn};
/// The existing upstream target and output vocabulary used with [`suites::harness::Harness::open_plane`].
pub use busbar_ports::plane::{PlaneOut, TargetIn};
pub use busbar_ports::{CallCx, PortError};
pub use envelopes::{DiagRecord, Envelopes, MetricRecord};
pub use fake_needs::{ConnScript, FakeNeeds};
pub use services::Services;

/// Plain re-exports with no policy (STH-ROWS D-7, D-9): the boot selector, a reference-field read
/// and a rendered Statement's parse.
pub use busbar_contract::abi::mechanism::extensions::reference_fields;
pub use busbar_contract::rendering::{
    read as read_rendering, Read as RenderedStatement, Unreadable,
};
pub use busbar_plugin_loader::boot::{select, Candidate, Selected, Uses};

#[cfg(feature = "test-seal")]
pub use busbar_contract::abi::sdk::test_support::chip;
/// The caller seal's test path (STH-ROWS D-7), behind `test-seal`; it goes with the seal's test
/// path at W3-D.
#[cfg(feature = "test-seal")]
pub use busbar_contract::{
    caps::KernelSeal, conn::admissions::AdmissionAuthority, services::test_caller_binding,
};

/// A [`Host`] bound to the seal's test caller binding (STH-ROWS D-7).
#[cfg(feature = "test-seal")]
#[must_use]
pub fn host() -> Host {
    Host::new(test_caller_binding())
}

#[cfg(all(test, feature = "target-sockets"))]
#[path = "host_target/socket_tests.rs"]
mod socket_tests;

/// Explicit loopback sockets for MIN-3 SDK store tests.
#[cfg(feature = "target-sockets")]
#[path = "host_target/sockets.rs"]
pub mod sockets;

/// Typed live store test requests and harness; never exports a production KernelSeal.
#[cfg(feature = "test-seal")]
pub mod store;

/// Native message transport conformance; never a production listener.
#[cfg(feature = "target-native-stream")]
#[path = "host_target/native_stream.rs"]
pub mod native_stream;
