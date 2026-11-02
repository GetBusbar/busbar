// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CHIP IN A PLUGIN'S OWN TESTS (dev-only, `test-seal`): a test that stands in for the host's

/// A credential holding `text`, as a test configures one.
#[must_use]
pub fn cred(text: &str) -> crate::abi::sdk::cred::Cred {
    crate::abi::sdk::cred::Cred::captured(zeroize::Zeroizing::new(text.as_bytes().to_vec()))
}

/// Drive `w` over a test's own stand-in for the host's wire: `write` takes bytes and says how many

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

/// The whole head an [`Exchange`](crate::abi::sdk::exchange::Exchange) frames (its method, target

#[must_use]
pub fn framed_head(exchange: &crate::abi::sdk::exchange::Exchange) -> Vec<u8> {
    exchange.head_bytes()
}
