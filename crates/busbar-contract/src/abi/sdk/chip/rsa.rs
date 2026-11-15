// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RSA-OAEP (SHA-1, MGF1-SHA-1; RFC 8017 7.1) to a server's PEM public key, over the crypto facade
//! (decision 224). Only the PEM and DER framing is here; the key check and the encryption are the
//! backend's.

use base64::Engine as _;

use super::Refused;
use crate::crypto;

const BAD_KEY: Refused = Refused("the server's RSA public key does not parse");

/// One DER item: tag, contents, rest.
fn der_item(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = b.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0_usize, |a, &x| (a << 8) | usize::from(x));
        (len, &rest[n..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// Whether `der` is framed as a `SubjectPublicKeyInfo` or a PKCS#1 `RSAPublicKey`.
fn framed(der: &[u8]) -> bool {
    let Some((0x30, body, [])) = der_item(der) else {
        return false;
    };
    match der_item(body) {
        Some((0x30, _, rest)) => matches!(der_item(rest), Some((0x03, [0, ..], _))),
        Some((0x02, _, rest)) => matches!(der_item(rest), Some((0x02, _, _))),
        _ => false,
    }
}

fn pem_body(pem: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(pem).ok()?;
    // The trimmed body lines, joined in place in one block sized to the PEM (never grown).
    let mut b64 = vec![0_u8; text.len()];
    let mut n = 0;
    for line in text.lines().filter(|l| !l.starts_with("-----")) {
        let line = line.trim().as_bytes();
        b64[n..n + line.len()].copy_from_slice(line);
        n += line.len();
    }
    base64::engine::general_purpose::STANDARD
        .decode(&b64[..n])
        .ok()
}

fn der(pem: &[u8]) -> Result<Vec<u8>, Refused> {
    let der = pem_body(pem).ok_or(BAD_KEY)?;
    if framed(&der) {
        Ok(der)
    } else {
        Err(BAD_KEY)
    }
}

/// The backend's refusal as this exchange words it.
fn refused(e: crypto::Error) -> Refused {
    match e {
        crypto::Error::Unsupported(u) => Refused(u.reason),
        crypto::Error::Invalid(w) if w.contains("too long") => {
            Refused("the password is too long for the server's RSA key")
        }
        _ => BAD_KEY,
    }
}

/// The SHA-256 of the PEM key's DER body, for a key the backend accepts as the RSA key
/// [`oaep_sha1`] encrypts to. A pin names a real RSA public key: DER that only has SPKI framing (a
/// key wrapped in a second SPKI) is refused, exactly as encrypting to it is.
pub(crate) fn key_sha256(pem: &[u8]) -> Result<[u8; 32], Refused> {
    let der = der(pem)?;
    crypto::legacy::rsa_oaep_public_key_check(&der).map_err(refused)?;
    Ok(crypto::sha256(&der))
}

/// `message` encrypted to the PEM public key `pem` with OAEP over SHA-1 and a fresh seed.
pub(crate) fn oaep_sha1(message: &[u8], pem: &[u8]) -> Result<Vec<u8>, Refused> {
    crypto::legacy::rsa_oaep_sha1_encrypt(&der(pem)?, message).map_err(refused)
}
