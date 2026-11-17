// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The backend contract (CRYPTO-SEAM §2.2). Any `busbar-crypto-backend` that misses an item, changes
//! a signature or carries a stale `API` fails to compile here, in the build that swapped it in.

use busbar_crypto_backend as b;

use crate::Error;

type R<T> = Result<T, b::Error>;

// The longer pinned signatures, named (a bare `fn(..)` this long trips clippy::type_complexity).
type Verify = fn(&[u8], &[u8], &[u8]) -> R<()>;
type Hkdf = fn(&[u8], &[u8], &[u8], &mut [u8]) -> R<()>;
type Pbkdf2 = fn(&[u8], &[u8], u32, &mut [u8]) -> R<()>;
type Seal<K> = fn(&K, &[u8; 12], &[u8], &mut [u8]) -> R<[u8; 16]>;
type Open<K> = fn(&K, &[u8; 12], &[u8], &mut [u8], &[u8; 16]) -> R<()>;
type SealRandomNonce<K> = fn(&K, &[u8], &mut [u8]) -> R<([u8; 12], [u8; 16])>;
type RsaVerify = fn(b::rsa::Scheme, &[u8], &[u8], &[u8]) -> R<()>;
type RsaVerifyComponents = fn(b::rsa::Scheme, &[u8], &[u8], &[u8], &[u8]) -> R<()>;
type AesCtr = fn(&[u8], &[u8; 16], &[u8], &mut [u8]) -> R<()>;

const fn const_str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

const fn name_ok(n: &str) -> bool {
    let n = n.as_bytes();
    if n.is_empty() || n.len() > 8 {
        return false;
    }
    let mut i = 0;
    while i < n.len() {
        let c = n[i];
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') {
            return false;
        }
        i += 1;
    }
    true
}

const _: () = {
    assert!(b::API == 3, "busbar-crypto-backend API mismatch");
    // Required, no default (IF §5.2 round 13): a backend that never states it does not build.
    let _: bool = b::EXTERNAL_PLUGINS;
    assert!(
        name_ok(b::NAME),
        "busbar-crypto-backend NAME must be 1..=8 of [a-z0-9-]"
    );
    assert!(
        !const_str_eq(b::NAME, "external"),
        "busbar-crypto-backend NAME `external` is reserved"
    );
    let _: fn() -> &'static str = b::module_version;
    let _: fn(&str) -> bool = b::supports;
    let _: fn() -> R<()> = b::self_test;
    let _: fn(bool, bool) -> R<()> = b::approve_signer;
    let _: fn(&[u8]) -> [u8; 32] = b::sha256;
    let _: fn(&[u8]) -> R<[u8; 32]> = b::sha256_checked;
    let _: fn(&[u8; 65]) -> R<()> = b::ecdsa_p256::validate_public_key;
    let _: fn(&[u8]) -> [u8; 48] = b::sha384;
    let _: fn(&[u8]) -> [u8; 64] = b::sha512;
    let _: fn() -> b::Sha256State = b::Sha256State::new;
    let _: fn(&mut b::Sha256State, &[u8]) = b::Sha256State::update;
    let _: fn(b::Sha256State) -> [u8; 32] = b::Sha256State::finish;
    let _: &str = b::link::RECIPE;
    let _: fn() -> b::link::Hasher = b::link::Hasher::new;
    let _: fn(&str) -> Option<b::link::Hasher> = b::link::Hasher::verifier;
    let _: fn(&mut b::link::Hasher, &[u8]) = b::link::Hasher::update;
    let _: fn(b::link::Hasher) -> [u8; 32] = b::link::Hasher::finish;
    let _: fn(&[u8], &[u8]) -> R<[u8; 32]> = b::hmac_sha256;
    let _: fn(&[u8], &[u8]) -> R<[u8; 48]> = b::hmac_sha384;
    let _: fn(&[u8], &[u8]) -> R<[u8; 64]> = b::hmac_sha512;
    let _: Verify = b::hmac_sha256_verify;
    let _: fn(&[u8]) -> R<b::HmacSha256Key> = b::HmacSha256Key::new;
    let _: fn(&b::HmacSha256Key, &[u8]) -> [u8; 32] = b::HmacSha256Key::sign;
    let _: fn(&b::HmacSha256Key, &[&[u8]]) -> [u8; 32] = b::HmacSha256Key::sign_parts;
    let _: fn(&b::HmacSha256Key, &[u8], &[u8]) -> R<()> = b::HmacSha256Key::verify;
    let _: fn(&[u8], &[u8]) -> bool = b::ct_eq;
    let _: fn(&mut [u8]) -> R<()> = b::fill;
    let _: fn() -> R<u64> = b::u64;
    let _: Hkdf = b::hkdf_sha256;
    let _: Pbkdf2 = b::pbkdf2_hmac_sha256;
    let _: fn(&[u8; 32]) -> R<b::Aes256Gcm> = b::Aes256Gcm::new;
    let _: Seal<b::Aes256Gcm> = b::Aes256Gcm::seal_in_place;
    let _: Open<b::Aes256Gcm> = b::Aes256Gcm::open_in_place;
    let _: SealRandomNonce<b::Aes256Gcm> = b::Aes256Gcm::seal_random_nonce;
    let _: fn(&[u8; 16]) -> R<b::Aes128Gcm> = b::Aes128Gcm::new;
    let _: Seal<b::Aes128Gcm> = b::Aes128Gcm::seal_in_place;
    let _: Open<b::Aes128Gcm> = b::Aes128Gcm::open_in_place;
    let _: SealRandomNonce<b::Aes128Gcm> = b::Aes128Gcm::seal_random_nonce;
    let _: fn(&[u8; 16], &[u8; 16]) -> R<[u8; 16]> = b::aes_block_encrypt;
    let _: AesCtr = b::aes_ctr::apply;
    let _: fn() -> R<b::ed25519::SigningKey> = b::ed25519::SigningKey::generate;
    let _: fn(&[u8; 32]) -> R<b::ed25519::SigningKey> = b::ed25519::SigningKey::from_seed;
    let _: fn(&[u8]) -> R<b::ed25519::SigningKey> = b::ed25519::SigningKey::from_pkcs8;
    let _: fn(&b::ed25519::SigningKey) -> &[u8; 32] = b::ed25519::SigningKey::seed;
    let _: fn(&b::ed25519::SigningKey, &[u8]) -> [u8; 64] = b::ed25519::SigningKey::sign;
    let _: fn(&b::ed25519::SigningKey) -> b::ed25519::VerifyingKey =
        b::ed25519::SigningKey::verifying_key;
    let _: fn(&[u8; 32]) -> R<()> = b::ed25519::validate_public_key;
    let _: fn(&[u8; 32]) -> R<b::ed25519::VerifyingKey> = b::ed25519::VerifyingKey::from_bytes;
    let _: fn(&[u8]) -> R<b::ed25519::VerifyingKey> = b::ed25519::VerifyingKey::from_spki;
    let _: fn(&b::ed25519::VerifyingKey) -> [u8; 32] = b::ed25519::VerifyingKey::to_bytes;
    let _: fn(&b::ed25519::VerifyingKey) -> bool = b::ed25519::VerifyingKey::is_weak;
    let _: fn(&b::ed25519::VerifyingKey, &[u8], &[u8; 64]) -> R<()> =
        b::ed25519::VerifyingKey::verify_strict;
    let _: fn() -> R<Vec<u8>> = b::ecdsa_p256::generate_pkcs8;
    let _: fn(&[u8]) -> R<b::ecdsa_p256::KeyPair> = b::ecdsa_p256::from_pkcs8;
    let _: fn(&b::ecdsa_p256::KeyPair, &[u8]) -> R<[u8; 64]> = b::ecdsa_p256::KeyPair::sign_fixed;
    let _: fn(&b::ecdsa_p256::KeyPair, &[u8]) -> R<Vec<u8>> = b::ecdsa_p256::KeyPair::sign_asn1;
    let _: fn(&b::ecdsa_p256::KeyPair) -> [u8; 65] = b::ecdsa_p256::KeyPair::public_key;
    let _: Verify = b::ecdsa_p256::verify_fixed;
    let _: Verify = b::ecdsa_p256::verify_asn1;
    let _: Verify = b::ecdsa_p256::verify_fixed_spki;
    let _: Verify = b::ecdsa_p384::verify_fixed;
    let _: Verify = b::ecdsa_p384::verify_fixed_spki;
    let _: RsaVerify = b::rsa::verify;
    let _: RsaVerify = b::rsa::verify_spki;
    let _: RsaVerifyComponents = b::rsa::verify_components;
    let _: Verify = b::rsa::verify_pkcs1_sha256;
    let _: Verify = b::rsa::verify_pss_sha256;
    let _: fn(&[u8], &[u8]) -> R<Vec<u8>> = b::rsa::sign_pkcs1_sha256;
    let _: fn(&[u8]) -> R<b::rsa::SigningKey> = b::rsa::SigningKey::from_pkcs8;
    let _: fn(&b::rsa::SigningKey) -> usize = b::rsa::SigningKey::modulus_len;
    let _: fn(&b::rsa::SigningKey) -> Vec<u8> = b::rsa::SigningKey::public_key;
    let _: fn(&b::rsa::SigningKey, &[u8]) -> R<Vec<u8>> = b::rsa::SigningKey::sign_pkcs1_sha256;
    let _: fn(&b::rsa::SigningKey, &[u8]) -> R<Vec<u8>> = b::rsa::SigningKey::sign_pss_sha256;
    let _: fn() -> R<b::ecdh_p256::EphemeralKey> = b::ecdh_p256::EphemeralKey::generate;
    let _: fn(&b::ecdh_p256::EphemeralKey) -> &[u8] = b::ecdh_p256::EphemeralKey::public_key;
    let _: fn(b::ecdh_p256::EphemeralKey, &[u8]) -> R<[u8; 32]> = b::ecdh_p256::agree;
    let _: fn(&[u8]) -> R<[u8; 16]> = b::legacy::md5;
    let _: fn(&[u8]) -> R<[u8; 20]> = b::legacy::sha1;
    let _: fn(&[u8], &[u8]) -> R<[u8; 20]> = b::legacy::hmac_sha1;
    let _: fn(&[u8], &[u8]) -> R<Vec<u8>> = b::legacy::rsa_oaep_sha1_encrypt;
    let _: fn(&[u8]) -> R<()> = b::legacy::rsa_oaep_public_key_check;
};

#[cfg(feature = "tls")]
const _: () = {
    let _: &[&rustls::SupportedProtocolVersion] = b::TLS_VERSIONS;
    let _: fn() -> rustls::crypto::CryptoProvider = b::tls_provider;
    let _: fn() -> R<std::sync::Arc<dyn rustls::server::ProducesTickets>> = b::ticketer;
    let _: fn() -> &'static [&'static dyn rustls_pki_types::SignatureVerificationAlgorithm] =
        b::webpki_algs;
    let _: fn(&rustls::ClientConfig) -> R<()> = b::approve_client_config;
    let _: fn(&rustls::ServerConfig) -> R<()> = b::approve_server_config;
    let _: fn(&rustls::Error) -> bool = b::ca_used_as_end_entity;
    let _: fn() -> R<dimpl::crypto::CryptoProvider> = b::dtls_provider;
    let _: fn() -> R<b::DtlsCert> = b::dtls_self_signed;
    let _: fn(&b::DtlsCert) -> &[u8] = b::DtlsCert::der;
    let _: fn(&b::DtlsCert) -> &[u8] = b::DtlsCert::handle;
};

/// The facade's start-up known answers, through this API (after the backend's own checks).
pub(crate) fn known_answers() -> Result<(), Error> {
    // FIPS 180-4: SHA-256("abc").
    if crate::sha256(b"abc")
        != hex::<32>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    {
        return Err(Error::SelfTest("SHA-256 known answer"));
    }
    // RFC 4231 test case 2 (a 4-byte key: a backend that refuses short keys skips this vector).
    match crate::hmac_sha256(b"Jefe", b"what do ya want for nothing?") {
        Ok(t)
            if t == hex::<32>(
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ) => {}
        Ok(_) => return Err(Error::SelfTest("HMAC-SHA256 known answer")),
        Err(Error::Unsupported(_)) => {
            // RFC 4231 test case 1: a 20-byte key every backend accepts.
            let t = crate::hmac_sha256(&[0x0b; 20], b"Hi There")?;
            if t != hex::<32>("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7") {
                return Err(Error::SelfTest("HMAC-SHA256 known answer"));
            }
        }
        Err(e) => return Err(e),
    }
    // AES-256-GCM: NIST GCM test case 14 (zero key, zero IV, one zero block).
    let key = crate::Aes256Gcm::new(&[0; 32])?;
    let mut block = [0_u8; 16];
    let tag = match key.seal_in_place(&[0; 12], &[], &mut block) {
        Ok(tag) => Some(tag),
        // A backend that refuses caller nonces: round-trip under its own nonce instead.
        Err(Error::Unsupported(_)) => None,
        Err(e) => return Err(e),
    };
    match tag {
        Some(tag) => {
            if block != hex::<16>("cea7403d4d606b6e074ec5d3baf39d18")
                || tag != hex::<16>("d0d1c8a799996bf0265b98b5d48ab919")
            {
                return Err(Error::SelfTest("AES-256-GCM known answer"));
            }
        }
        None => {
            let mut buf = *b"busbar self test";
            let (nonce, tag) = key.seal_random_nonce(b"aad", &mut buf)?;
            key.open_in_place(&nonce, b"aad", &mut buf, &tag)
                .map_err(|_| Error::SelfTest("AES-256-GCM round trip"))?;
            if &buf != b"busbar self test" {
                return Err(Error::SelfTest("AES-256-GCM round trip"));
            }
        }
    }
    // Ed25519: RFC 8032 test 1.
    let sk = crate::ed25519::SigningKey::from_seed(&hex::<32>(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ))?;
    let sig = sk.sign(b"");
    let want = hex::<64>(concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ));
    if sig != want
        || sk.verifying_key().to_bytes()
            != hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    {
        return Err(Error::SelfTest("Ed25519 known answer"));
    }
    sk.verifying_key()
        .verify_strict(b"", &sig)
        .map_err(|_| Error::SelfTest("Ed25519 verify"))?;
    Ok(())
}

/// Hex to bytes, for known answers (`s` is a fixed literal of exactly `2 * N` hex digits).
pub(crate) fn hex<const N: usize>(s: &str) -> [u8; N] {
    let s = s.as_bytes();
    let nib = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => 0,
    };
    let mut out = [0_u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nib(s[2 * i]) << 4) | nib(s[2 * i + 1]);
    }
    out
}
