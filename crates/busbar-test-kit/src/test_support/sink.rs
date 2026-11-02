// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The actual SDK sink, safely lent the caller's exclusive typed buffers.

// This is a public test-kit export; contract's own tests also mount this source privately.
#[allow(unused_imports)]
pub use busbar_contract::abi::sdk::test_support::sink::fill;
