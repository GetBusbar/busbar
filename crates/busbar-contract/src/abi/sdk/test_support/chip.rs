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
    while w.done < w.buf.len() {
        match write(&w.buf[w.done..]) {
            std::task::Poll::Pending | std::task::Poll::Ready(Ok(0)) => {
                return std::task::Poll::Pending
            }
            std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
            std::task::Poll::Ready(Ok(n)) => w.done += n,
        }
    }
    std::task::Poll::Ready(Ok(()))
}

/// The bytes a [`Cred`](crate::abi::sdk::cred::Cred) holds, for a test's fake far end that checks
/// what it was authenticated with.
#[must_use]
pub fn cred_bytes(cred: &crate::abi::sdk::cred::Cred) -> Vec<u8> {
    cred.wire().to_vec()
}

/// The bytes [`Parts`](crate::abi::sdk::cred::Parts) put on the wire, in order.
#[must_use]
pub fn parts_bytes(parts: &crate::abi::sdk::cred::Parts) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.len());
    for p in &parts.parts {
        match p {
            crate::abi::sdk::cred::write::Part::Public(b) => out.extend_from_slice(b),
            crate::abi::sdk::cred::write::Part::Sealed(s) => out.extend_from_slice(s.wire()),
        }
    }
    out
}

/// The bytes a [`FormBody`](crate::abi::sdk::cred::FormBody) encodes to.
///
/// # Panics
/// A signature in it could not be made.
#[must_use]
pub fn form_bytes(body: &crate::abi::sdk::cred::FormBody) -> Vec<u8> {
    body.encoded().expect("the form encodes").buf.to_vec()
}

/// The whole head an [`Exchange`](crate::abi::sdk::exchange::Exchange) frames (its method, target
/// and field block, one after another), sealed values included: a test comparing a sealed request
/// with the unsealed one it replaces (raw bytes, for an exchange that sends them).
#[must_use]
pub fn framed_head(exchange: &crate::abi::sdk::exchange::Exchange) -> Vec<u8> {
    exchange.head_bytes()
}
