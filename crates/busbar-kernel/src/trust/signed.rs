// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use busbar_contract::abi::host::service as svc;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde_json::{Map, Value};

const KEY_INFO_HEAD: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

pub const MAX_SIGNATURES: usize = 8;

const ALGORITHM: &str = "EdDSA";

pub type Refused = (u64, String);

fn refused(verdict: u64) -> Refused {
    (verdict, String::new())
}

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

fn header(protected: &str) -> Result<Map<String, Value>, Refused> {
    let raw = URL_SAFE_NO_PAD
        .decode(protected)
        .map_err(|_| refused(svc::SIGNED_MALFORMED_HEADER))?;
    match serde_json::from_slice(&raw) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(refused(svc::SIGNED_MALFORMED_HEADER)),
    }
}
