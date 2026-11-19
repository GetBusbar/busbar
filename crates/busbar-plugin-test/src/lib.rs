// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN TEST FACADE (SDK-SAFE-TEST-HOST §2): load and drive any plugin from test code with
//! no `unsafe`. R131's scan is `abi_scan`. A plugin repository's one test dev-dependency.
//! The MIN-3 conformance harness (ABI-MIN3-INTERFACE §14): [`FakeNeeds`] and [`ConnScript`], the
//! kind [`suites`], the C-ERRORS check ([`errors`]), and `tests/<case>.rs`, one file per live §14 case.
#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]

/// The Q24 wipe proof. It lives in the contract (`busbar_contract::canary_scan`), whose own wipe
/// tests use the same scan; a plugin repository reaches it here.
pub use busbar_contract::canary_scan;
pub mod errors;
pub mod fake_needs;
/// The IF §14 kind suites and `migrate` (W1-T1).
pub mod suites;

/// The harness runtime (R40: built under `host_target/`, the facade's exempt directory).
#[path = "host_target/test_rt.rs"]
pub(crate) mod test_rt;

pub use busbar_contract::abi_scan;
/// The completed growth and drop wipe counts on this thread (`(growth, drop)`), so a plugin test can
/// prove an owner wiped without naming `busbar_secure` (DES-store-zeroizing-residual §5.0).
pub use busbar_contract::secure::wipe_counts;
/// The allocation watch (SDK-SAFE-TEST-HOST §3.4), a plugin test's `#[global_allocator]`.
pub use busbar_ffi::test_watch::{Block, Freed, Watch};
/// The existing login vocabulary used with [`suites::harness::Harness::open_auth`].
pub use busbar_ports::auth::{LoginAnswer, LoginIn};
/// The existing upstream target and output vocabulary used with [`suites::harness::Harness::open_plane`].
pub use busbar_ports::plane::{PlaneOut, TargetIn};
pub use busbar_ports::{CallCx, PortError};
pub use fake_needs::{ConnScript, FakeNeeds};

/// The caller seal's test path (STH-ROWS D-7), behind `test-seal`; it goes with the seal's test
/// path at W3-D.
#[cfg(feature = "test-seal")]
pub use busbar_contract::{caps::KernelSeal, conn::admissions::AdmissionAuthority};

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
