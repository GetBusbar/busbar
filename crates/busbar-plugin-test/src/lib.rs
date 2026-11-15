// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN TEST FACADE (SDK-SAFE-TEST-HOST §2): load and drive any plugin from test code with
//! no `unsafe`. The host is the loader's `test_host`; the reviewed boundary is the SDK's
//! `test_support`; R131's scan is `abi_scan`. A plugin repository's one test dev-dependency.
#![forbid(unsafe_code)]

pub use busbar_contract::abi::sdk::test_support::loans::{Buf, List, Loans};
pub use busbar_contract::abi::sdk::test_support::mutant::Mutant;
pub use busbar_contract::abi::sdk::test_support::watch::{Freed, Watch};
pub use busbar_contract::abi::sdk::test_support::zeroed;
pub use busbar_contract::abi_scan;
pub use busbar_plugin_loader::test_host::{
    both, Answer, Called, Host, Image, Opened, Pending, Refused,
};
