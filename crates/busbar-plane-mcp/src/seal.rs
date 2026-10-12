// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEALED `requestState`: busbar's own ask state, minted and opened by the door over the host's
//! `sign` (ARCHITECT Q-L3B-ASK). The payload is the [`AskState`] as JSON; the seal is the host's
//! signature of it under the door's declared signing domain, a subkey derived from the deployment's
//! fleet-shared signing key, so a state minted on one node opens on every node of the deployment.
//!
//! The signature is deterministic (Ed25519), so opening re-signs the payload and compares the two in
//! constant time: the plugin never holds key material and the host needs no second verb.
//!
//! The form is `base64url(payload) "." base64url(signature)`, unpadded and strict: a decoder that
//! tolerated trailing bytes would accept a tampered value whose prefix still verifies.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::ask::{AskState, Rejected};

/// The signature length the host's `sign` answers.
pub const SIGNATURE_LEN: usize = 64;

/// The sealed form of `state`, signed by `sign`; `None` when it cannot be signed.
pub fn seal_state(
    state: &AskState,
    sign: &mut dyn FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Option<String> {
    let payload = serde_json::to_vec(state).ok()?;
    let signature = sign(&payload)?;
    Some(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&payload),
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

/// The state `blob` seals, its signature re-made by `sign` and compared in constant time.
///
/// # Errors
///
/// [`Rejected::Malformed`] when it is not this form or its payload is not a state;
/// [`Rejected::BadSignature`] when the seal does not verify (or cannot be re-made).
pub fn unseal_state(
    blob: &str,
    sign: &mut dyn FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Result<AskState, Rejected> {
    let (payload, signature) = blob.split_once('.').ok_or(Rejected::Malformed)?;
    let payload = strict(payload).ok_or(Rejected::Malformed)?;
    let presented = strict(signature).ok_or(Rejected::Malformed)?;
    let made = sign(&payload).ok_or(Rejected::BadSignature)?;
    if presented.len() != SIGNATURE_LEN || !same(&presented, &made) {
        return Err(Rejected::BadSignature);
    }
    serde_json::from_slice(&payload).map_err(|_| Rejected::Malformed)
}

/// `text` decoded as unpadded base64url, and only when it is that value's one spelling.
fn strict(text: &str) -> Option<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    (URL_SAFE_NO_PAD.encode(&bytes) == text).then_some(bytes)
}

/// Whether `a` and `b` are equal, in time that depends only on their lengths.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
#[path = "tests/seal_tests.rs"]
mod tests;
