// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN TEST FACADE (SDK-SAFE-TEST-HOST §2): load and drive any plugin from test code with
//! no `unsafe`. The host is the loader's `test_host`; the reviewed boundary is the SDK's
//! `test_support`; R131's scan is `abi_scan`. A plugin repository's one test dev-dependency.
#![forbid(unsafe_code)]

pub mod services;

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
pub use services::Services;
