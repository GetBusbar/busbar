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

/// Observe the initialized payload of a credential in a test's allocator witness.
pub fn observe_credential(credential: &crate::abi::sdk::cred::Cred, observe: impl FnOnce(&[u8])) {
    observe(credential.wire());
}

/// Observe protected JSON buffers during an action. Available only to chip tests; production
/// builds have neither a callback nor a way to read protected response material.
pub fn with_json_observer<T>(observe: fn(&'static str, &[u8]), action: impl FnOnce() -> T) -> T {
    crate::abi::sdk::cred::protected_json::observing(observe, action)
}

/// Drive the real resolved-value writer against a test-owned host buffer, including short output.
pub fn resolve_into(
    value: crate::abi::sdk::cred::Held<Vec<u8>>,
    buffer: &mut [u8],
) -> (
    crate::abi::mechanism::call::Outcome,
    crate::abi::secret::ResolveOut,
) {
    use crate::abi::sdk::{Lent, Out};
    let input = crate::abi::secret::ResolveIn {
        secret_buf: buffer.as_mut_ptr(),
        secret_cap: buffer.len(),
        ..super::zeroed()
    };
    let mut output = super::zeroed();
    let holders = crate::abi::sdk::out::Holders::default();
    // SAFETY: input and its exclusively borrowed buffer live until the writer returns.
    let outcome = crate::abi::sdk::cred::resolved(
        unsafe { Lent::new(&input) },
        &mut Out::lent(&mut output, None, &holders),
        value,
    );
    (outcome, output)
}
