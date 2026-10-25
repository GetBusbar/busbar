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

/// A credential holding `text`, as a test configures one.
#[must_use]
pub fn cred(text: &str) -> crate::abi::sdk::cred::Cred {
    crate::abi::sdk::cred::Cred::captured(zeroize::Zeroizing::new(text.as_bytes().to_vec()))
}

/// Drive `w` over a test's own stand-in for the host's wire: `write` takes bytes and says how many
/// it took.
///
/// # Errors
/// What `write` answered.
pub fn drive_sealed<E>(
    w: &mut crate::abi::sdk::cred::SealedWrite,
    mut write: impl FnMut(&[u8]) -> std::task::Poll<Result<usize, E>>,
) -> std::task::Poll<Result<(), E>> {
    w.drive(&mut write)
}
