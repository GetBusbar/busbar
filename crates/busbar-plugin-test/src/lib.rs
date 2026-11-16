// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN TEST FACADE (SDK-SAFE-TEST-HOST §2): load and drive any plugin from test code with
//! no `unsafe`. The host is the loader's `test_host`; the reviewed boundary is the SDK's
//! `test_support`; R131's scan is `abi_scan`. A plugin repository's one test dev-dependency.
//! W1-T1 adds the MIN-3 conformance harness (ABI-MIN3-INTERFACE §14): [`FakeNeeds`] and [`ConnScript`], the
//! kind [`suites`], the C-ERRORS check ([`errors`]), and `tests/<case>.rs`, one file per live §14 case.
#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]

pub mod canary_scan;
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

/// The Q24 wipe proof: plant a canary, drop it, scan `/proc/self/mem`, assert it is absent.
pub use busbar_contract::abi::sdk::test_support::canary;
pub use busbar_contract::abi::sdk::test_support::cpu;
pub use busbar_contract::abi::sdk::test_support::loans::{Buf, List, Loans};
pub use busbar_contract::abi::sdk::test_support::mutant::Mutant;
pub use busbar_contract::abi::sdk::test_support::watch::{Block, Freed, Watch};
pub use busbar_contract::abi::sdk::test_support::zeroed;
pub use busbar_contract::abi_scan;
pub use busbar_contract::services::{Caller, Later, Ran, Reading, Stored, UNSERVED};
/// The kinds an [`Image`] loads as.
pub use busbar_plugin_loader::dispatch::kinds::{
    auth::Auth, export::Export, hook::Hook, plane::Plane, secret::Secret, store_v4::StoreV4,
    transport::Transport,
};
pub use busbar_plugin_loader::dispatch::{rendering_of, ConnTable, LoadError};
pub use busbar_plugin_loader::test_host::{
    both, Answer, Called, Host, Image, Opened, Pending, Refused,
};
pub use fake_needs::{ConnScript, FakeNeeds};
pub use services::Services;
