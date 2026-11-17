// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core's two PKCE/state/nonce minting functions, defined once (IF §12.12 round 22, §16.10; C-LOGIN-PKCE): the
//! hosted login (`busbar-core-oauth2`, re-exported there as `busbar_core_oauth2::pkce`) and the caller-connection
//! BEGIN ([`super::StoreConnections`]) both call these, so no auth plugin mints its own verifier, challenge or
//! nonce. Both run on the crypto facade (`busbar_crypto::fill` and `sha256`).
//!
//! W1-K10: the IF names the module `busbar-core-oauth2::pkce`, but `busbar-core-oauth2` depends on this crate, so
//! the one definition lives here and `busbar-core-oauth2` re-exports it under the IF's path.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

/// The verifier's random length in bytes (RFC 7636 §4.1: 32 octets, 43 base64url characters).
pub const VERIFIER_BYTES: usize = 32;
/// The state key's and the nonce's random length in bytes.
pub const STATE_BYTES: usize = 24;

/// `n_bytes` from the OS randomness source, base64url without padding. `None` when the source fails (the caller
/// refuses the login; nothing is ever minted from a zero-filled buffer).
#[must_use]
pub fn random_b64url(n_bytes: usize) -> Option<String> {
    let mut buf = vec![0u8; n_bytes];
    busbar_contract::crypto::fill(&mut buf).ok()?;
    Some(URL_SAFE_NO_PAD.encode(buf))
}

/// The S256 `code_challenge` of `code_verifier` (RFC 7636 §4.2): base64url(SHA-256(ASCII(verifier))), no padding.
#[must_use]
pub fn code_challenge_s256(code_verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(busbar_contract::crypto::sha256(code_verifier.as_bytes()))
}
