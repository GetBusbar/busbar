// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RSA-OAEP (SHA-1, MGF1-SHA-1; RFC 8017 7.1.1) to a server's public key: MySQL's
//! `caching_sha2_password` full authentication on a link with no TLS. The
//! encoded block is wiped; `num-bigint`'s own limbs for it are not (it offers no wipe), a residual
//! that ends when chip row 4 runs this in the secret plugin.

use base64::Engine as _;
use num_bigint::BigUint;
use zeroize::Zeroizing;

use super::digests::sha1;
use super::Refused;

const BAD_KEY: Refused = Refused("the server's RSA public key does not parse");

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

fn rsa_public_key(der: &[u8]) -> Option<(BigUint, BigUint)> {
    let (tag, body, _) = der_item(der)?;
    if tag != 0x30 {
        return None;
    }
    let (t1, first, rest) = der_item(body)?;
    if t1 == 0x30 {
        // SubjectPublicKeyInfo: the algorithm, then a BIT STRING holding an RSAPublicKey.
        let (t2, bits, _) = der_item(rest)?;
        if t2 != 0x03 || bits.first() != Some(&0) {
            return None;
        }
        return rsa_public_key(&bits[1..]);
    }
    // RSAPublicKey (PKCS #1): modulus, public exponent.
    let (t2, e, _) = der_item(rest)?;
    (t1 == 0x02 && t2 == 0x02).then(|| (BigUint::from_bytes_be(first), BigUint::from_bytes_be(e)))
}

fn pem_body(pem: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(pem).ok()?;
    let b64: String = text
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.trim().chars())
        .collect();
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

fn mgf1_sha1(seed: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(len + 20));
    let mut counter = 0_u32;
    while out.len() < len {
        out.extend_from_slice(&sha1(&[seed, &counter.to_be_bytes()])[..]);
        counter += 1;
    }
    out.truncate(len);
    out
}

/// The SHA-256 of the PEM key's DER body: what `server_public_key_sha256` pins.
pub(crate) fn key_sha256(pem: &[u8]) -> Result<[u8; 32], Refused> {
    let der = pem_body(pem).ok_or(BAD_KEY)?;
    rsa_public_key(&der).ok_or(BAD_KEY)?;
    Ok(*super::digests::sha256(&[&der]))
}

/// `message` encrypted to the PEM public key `pem` with OAEP over SHA-1 and the 20-byte `seed`.
pub(crate) fn oaep_sha1(message: &[u8], pem: &[u8], seed: &[u8; 20]) -> Result<Vec<u8>, Refused> {
    let der = pem_body(pem).ok_or(BAD_KEY)?;
    let (n, e) = rsa_public_key(&der).ok_or(BAD_KEY)?;
    let k = usize::try_from(n.bits().div_ceil(8)).map_err(|_| BAD_KEY)?;
    if k < 2 * 20 + 2 || message.len() > k - 2 * 20 - 2 {
        return Err(Refused("the password is too long for the server's RSA key"));
    }
    let mut db = Zeroizing::new(Vec::with_capacity(k - 21));
    db.extend_from_slice(&sha1(&[b""])[..]);
    db.resize(k - 21 - message.len() - 1, 0);
    db.push(1);
    db.extend_from_slice(message);
    for (d, m) in db.iter_mut().zip(mgf1_sha1(seed, k - 21).iter()) {
        *d ^= m;
    }
    let mut masked_seed = Zeroizing::new(*seed);
    for (s, m) in masked_seed.iter_mut().zip(mgf1_sha1(&db, 20).iter()) {
        *s ^= m;
    }
    let mut em = Zeroizing::new(Vec::with_capacity(k));
    em.push(0);
    em.extend_from_slice(&masked_seed[..]);
    em.extend_from_slice(&db);
    let c = BigUint::from_bytes_be(&em).modpow(&e, &n);
    let mut out = c.to_bytes_be();
    if out.len() < k {
        let mut padded = vec![0; k - out.len()];
        padded.append(&mut out);
        out = padded;
    }
    Ok(out)
}
