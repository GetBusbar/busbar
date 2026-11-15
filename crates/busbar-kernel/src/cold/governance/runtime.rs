// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `governance::runtime` cold code (see `crate::cold::governance`).

use busbar_contract::crypto;

/// `at_rest`: a credential seal refused (the CSPRNG or the cipher failed).
#[cold]
pub(crate) fn at_rest_seal_refusal(e: crypto::Error) -> String {
    match e {
        crypto::Error::Rng(e) => format!("CSPRNG unavailable: {e}"),
        _ => "the credential could not be sealed".to_owned(),
    }
}

/// `at_rest`: the sealed envelope, the stored row written once at mint or re-wrap.
#[cold]
pub(crate) fn at_rest_envelope(prefix: &str, kid: &str, nonce: &[u8], sealed: &[u8]) -> String {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!("{prefix}{kid}:{}:{}", b64.encode(nonce), b64.encode(sealed))
}

/// `at_rest`: a configured at-rest key that is not 32 bytes, refused at boot or reload.
#[cold]
pub(crate) fn at_rest_key_refusal(path: &str) -> String {
    format!(
        "{path} must resolve to a 32-byte key (32 raw bytes, or 64 hex characters: `openssl rand \
         -hex 32`)"
    )
}

/// `at_rest`: the raw 32-byte at-rest key, copied once per boot or reload.
#[cold]
pub(crate) fn at_rest_raw_key(bytes: &[u8]) -> busbar_contract::secure::SecureVec {
    busbar_contract::secure::SecureVec::from(bytes.to_vec())
}

/// `at_rest`: a refused kid, remembered once (at most the cap) and audited once.
#[cold]
pub(crate) fn at_rest_refused_kid(seen: &mut std::collections::BTreeSet<String>, kid: &str) {
    seen.insert(kid.to_owned());
}

/// `at_rest`: the audit resource naming a refused kid, at most the cap times per process.
#[cold]
pub(crate) fn at_rest_kid_resource(kid: &str) -> String {
    format!("kid:{kid}")
}
