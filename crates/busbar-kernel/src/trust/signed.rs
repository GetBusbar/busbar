// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A DOCUMENT'S DETACHED SIGNATURES, judged against a counterparty's declared root key: the
//! verifier behind `trust.verify` (`BUSBAR-1.6.0.md` host services, the trust row: the kernel
//! judges; ARCHITECT ruling on card crypto, option (b)). A plugin never links a crypto crate; it
//! hands the payload and the signatures as written, and the kernel answers the verdict.
//!
//! * **The key decides the algorithm, never the header.** A header is written by the party being
//!   authenticated, so `alg` is only CHECKED against the key's (`EdDSA`, the one this verifier
//!   reads) and a disagreement is a refusal by name, never a fallback: that is how `none` and
//!   algorithm confusion are refused.
//! * **The payload is detached** and the protected header is used exactly as received: the signing
//!   input is `protected || "." || BASE64URL(payload)` (RFC 7515 section 5.2, the JSON
//!   serialization's `signatures` list).
//! * **Every refusal is final.** A malformed signature anywhere refuses the document rather than
//!   being skipped; a signature by another key is no evidence; any `crit` member is refused, as
//!   this verifier implements none (RFC 7515 section 4.1.11).

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use busbar_contract::abi::host::service as svc;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::{Map, Value};

/// The DER head of an Ed25519 SubjectPublicKeyInfo (RFC 8410 section 4): a root key that does not
/// carry it byte for byte is not one this verifier reads.
const KEY_INFO_HEAD: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The most signatures one document carries; each costs a verification.
pub const MAX_SIGNATURES: usize = 8;

/// The one algorithm the root key implies.
const ALGORITHM: &str = "EdDSA";

/// Why a document was not accepted as signed by the root key: its `SIGNED_*` verdict, and the
/// algorithm or critical member it names (empty otherwise). No verdict means "unchecked".
pub type Refused = (u64, String);

fn refused(verdict: u64) -> Refused {
    (verdict, String::new())
}

/// The root key, read from the operator's out-of-band form: base64 Ed25519 SPKI.
///
/// # Errors
///
/// `SIGNED_MALFORMED_ROOT`.
pub fn root_key(key_info: &str) -> Result<VerifyingKey, Refused> {
    let der = STANDARD
        .decode(key_info.trim())
        .map_err(|_| refused(svc::SIGNED_MALFORMED_ROOT))?;
    let raw: [u8; 32] = der
        .strip_prefix(&KEY_INFO_HEAD[..])
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| refused(svc::SIGNED_MALFORMED_ROOT))?;
    VerifyingKey::from_bytes(&raw).map_err(|_| refused(svc::SIGNED_MALFORMED_ROOT))
}

/// Verify `signatures` (the document's list as written) over `payload` against `root`: at least
/// one signature is the root key's, and every signature is well-formed.
///
/// # Errors
///
/// The first refusal in the list's order.
pub fn verify(payload: &[u8], signatures: &Value, root: &VerifyingKey) -> Result<(), Refused> {
    let list = signatures
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or_else(|| refused(svc::SIGNED_NONE))?;
    if list.len() > MAX_SIGNATURES {
        return Err(refused(svc::SIGNED_TOO_MANY));
    }
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let mut verified = false;
    for sig in list {
        let protected = sig
            .get("protected")
            .and_then(Value::as_str)
            .ok_or_else(|| refused(svc::SIGNED_MALFORMED_HEADER))?;
        let header = header(protected)?;
        match header.get("alg").and_then(Value::as_str) {
            Some(ALGORITHM) => {}
            other => return Err((svc::SIGNED_ALGORITHM, other.unwrap_or_default().into())),
        }
        if let Some(crit) = header.get("crit") {
            return Err(match crit.as_array().and_then(|c| c.first()) {
                Some(Value::String(name)) => (svc::SIGNED_CRITICAL, name.clone()),
                _ => refused(svc::SIGNED_MALFORMED_HEADER),
            });
        }
        let raw = sig
            .get("signature")
            .and_then(Value::as_str)
            .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
            .and_then(|b| <[u8; 64]>::try_from(b).ok())
            .ok_or_else(|| refused(svc::SIGNED_MALFORMED_SIGNATURE))?;
        let input = format!("{protected}.{payload}");
        verified |= root
            .verify(input.as_bytes(), &Signature::from_bytes(&raw))
            .is_ok();
    }
    verified
        .then_some(())
        .ok_or_else(|| refused(svc::SIGNED_NOT_BY_ROOT))
}

/// A protected header: base64url of a JSON object.
fn header(protected: &str) -> Result<Map<String, Value>, Refused> {
    let raw = URL_SAFE_NO_PAD
        .decode(protected)
        .map_err(|_| refused(svc::SIGNED_MALFORMED_HEADER))?;
    match serde_json::from_slice(&raw) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(refused(svc::SIGNED_MALFORMED_HEADER)),
    }
}
