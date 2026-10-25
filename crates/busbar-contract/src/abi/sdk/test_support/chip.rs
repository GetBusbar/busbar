// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CHIP IN A PLUGIN'S OWN TESTS (dev-only, `test-seal`): a test that stands in for the host's
//! wire (a fake server over a raw socket) writes a sealed message's bytes itself. No shipped image
//! carries this module (`tests/test_seal_is_dev_only.rs`).

use crate::abi::sdk::cred::Seal;

/// The bytes a [`Seal`] puts on the wire, for a test's own stand-in for the host's wire.
#[must_use]
pub fn sealed_bytes(seal: &Seal) -> Vec<u8> {
    seal.wire().to_vec()
}
