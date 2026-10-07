// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FRAMER'S CRYPTO PROVIDER: every primitive the media stack asks for, on ring, with one
//! exception (THE DESIGN l.759-761):
//!
//! * SRTP is AEAD-AES-GCM only (RFC 7714), 128- and 256-bit, on `ring::aead`. The AES_CM profile's
//!   factory hands out a cipher that refuses every packet: `AES_CM` is refused here as it is at the
//!   host's handshake and at the keying-material item ([`crate::framing`]).
//! * The SRTP key derivation needs a raw AES block (RFC 3711 §4.3 runs AES in counter mode over
//!   the master key), which ring does not expose. That is the `aes` crate's one use, in
//!   [`Ring::srtp_aes_128_ecb_round`]/[`Ring::srtp_aes_256_ecb_round`]; `tests/dependency_closure.rs`
//!   holds the crate to this file.
//! * STUN's MESSAGE-INTEGRITY is HMAC-SHA1 and the certificate fingerprint SHA-256, both ring.
//! * DTLS is not here: the provider's DTLS factory is the host shim ([`crate::shim`]), which runs
//!   no handshake and holds no DTLS key.

use std::fmt;

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM};
use str0m::crypto::dtls::{DtlsCert, DtlsInstance, DtlsProvider, DtlsVersion};
use str0m::crypto::{
    AeadAes128GcmCipher, AeadAes256GcmCipher, Aes128CmSha1_80Cipher, CryptoError, CryptoProvider,
    Sha1HmacProvider, Sha256Provider, SrtpProvider, SupportedAeadAes128Gcm, SupportedAeadAes256Gcm,
    SupportedAes128CmSha1_80,
};
use zeroize::{Zeroize as _, Zeroizing};

/// The provider: one static instance of each component.
#[derive(Debug)]
pub struct Ring;

static RING: Ring = Ring;

/// The crypto provider every framing's media stack runs on.
#[must_use]
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        srtp_provider: &RING,
        sha1_hmac_provider: &RING,
        sha256_provider: &RING,
        dtls_provider: &crate::shim::HOST,
    }
}

fn refused(why: &str) -> CryptoError {
    CryptoError::Other(why.into())
}

/// The refusal an `AES_CM` packet meets.
pub const AES_CM_REFUSED: &str = "SRTP AES_CM is refused: AEAD-AES-GCM only";

// ── SRTP ─────────────────────────────────────────────────────────────────────────────────────────

impl SrtpProvider for Ring {
    fn aes_128_cm_sha1_80(&self) -> &'static dyn SupportedAes128CmSha1_80 {
        &RING
    }

    fn aead_aes_128_gcm(&self) -> &'static dyn SupportedAeadAes128Gcm {
        &RING
    }

    fn aead_aes_256_gcm(&self) -> &'static dyn SupportedAeadAes256Gcm {
        &RING
    }

    fn srtp_aes_128_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        ecb_round::<aes::Aes128>(key, input, output);
    }

    fn srtp_aes_256_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        ecb_round::<aes::Aes256>(key, input, output);
    }
}

/// One AES block of the SRTP key derivation: `output[..16] = AES_key(input[..16])`. A key of the
/// wrong length, or a block shorter than 16 bytes, leaves `output` zeroed (the derived key is then
/// useless and every packet fails authentication; nothing panics across the door).
fn ecb_round<C: KeyInit + BlockEncrypt>(key: &[u8], input: &[u8], output: &mut [u8]) {
    output.iter_mut().for_each(|b| *b = 0);
    let (Ok(cipher), Some(block), true) =
        (C::new_from_slice(key), input.get(..16), output.len() >= 16)
    else {
        return;
    };
    let mut b = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut b);
    output[..16].copy_from_slice(&b);
    b.as_mut_slice().zeroize();
}

impl SupportedAes128CmSha1_80 for Ring {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn Aes128CmSha1_80Cipher> {
        let _ = Zeroizing::new(key);
        Box::new(AesCmRefused)
    }
}

/// The `AES_CM` cipher: it refuses every packet.
#[derive(Debug)]
pub struct AesCmRefused;

impl Aes128CmSha1_80Cipher for AesCmRefused {
    fn encrypt(&mut self, _: &[u8; 16], _: &[u8], _: &mut [u8]) -> Result<(), CryptoError> {
        Err(refused(AES_CM_REFUSED))
    }

    fn decrypt(&mut self, _: &[u8; 16], _: &[u8], _: &mut [u8]) -> Result<(), CryptoError> {
        Err(refused(AES_CM_REFUSED))
    }
}

/// An AEAD-AES-GCM cipher on ring: one key, sealing or opening in place.
pub struct Gcm {
    key: LessSafeKey,
}

impl fmt::Debug for Gcm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gcm").finish_non_exhaustive()
    }
}

impl Gcm {
    fn new(alg: &'static ring::aead::Algorithm, key: &[u8]) -> Option<Self> {
        UnboundKey::new(alg, key).ok().map(|k| Gcm {
            key: LessSafeKey::new(k),
        })
    }

    /// `output = ciphertext(input) || tag`, `output.len() >= input.len() + 16`.
    fn seal(
        &self,
        iv: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        let tag_len = self.key.algorithm().tag_len();
        if output.len() < input.len() + tag_len {
            return Err(refused("SRTP seal: output too short"));
        }
        output[..input.len()].copy_from_slice(input);
        let tag = self
            .key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(*iv),
                Aad::from(aad),
                &mut output[..input.len()],
            )
            .map_err(|_| refused("SRTP seal failed"))?;
        output[input.len()..input.len() + tag_len].copy_from_slice(tag.as_ref());
        Ok(())
    }

    /// `input = ciphertext || tag`; the plaintext into `output`, its length answered.
    fn open(
        &self,
        iv: &[u8; 12],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let tag_len = self.key.algorithm().tag_len();
        if input.len() < tag_len {
            return Err(refused("SRTP open: shorter than its tag"));
        }
        let aad: Vec<u8> = aads.concat();
        let mut buf = Zeroizing::new(input.to_vec());
        let plain = self
            .key
            .open_in_place(Nonce::assume_unique_for_key(*iv), Aad::from(&aad), &mut buf)
            .map_err(|_| refused("SRTP authentication failed"))?;
        let n = plain.len();
        if output.len() < n {
            return Err(refused("SRTP open: output too short"));
        }
        output[..n].copy_from_slice(plain);
        Ok(n)
    }
}

impl AeadAes128GcmCipher for Gcm {
    fn encrypt(
        &mut self,
        iv: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.seal(iv, aad, input, output)
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 12],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.open(iv, aads, input, output)
    }
}

impl AeadAes256GcmCipher for Gcm {
    fn encrypt(
        &mut self,
        iv: &[u8; 12],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), CryptoError> {
        self.seal(iv, aad, input, output)
    }

    fn decrypt(
        &mut self,
        iv: &[u8; 12],
        aads: &[&[u8]],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.open(iv, aads, input, output)
    }
}

/// A key ring refused (it cannot happen for a key of the profile's length): every packet fails.
#[derive(Debug)]
struct Unkeyed;

impl AeadAes128GcmCipher for Unkeyed {
    fn encrypt(
        &mut self,
        _: &[u8; 12],
        _: &[u8],
        _: &[u8],
        _: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(refused("SRTP key refused"))
    }

    fn decrypt(
        &mut self,
        _: &[u8; 12],
        _: &[&[u8]],
        _: &[u8],
        _: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Err(refused("SRTP key refused"))
    }
}

impl AeadAes256GcmCipher for Unkeyed {
    fn encrypt(
        &mut self,
        _: &[u8; 12],
        _: &[u8],
        _: &[u8],
        _: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(refused("SRTP key refused"))
    }

    fn decrypt(
        &mut self,
        _: &[u8; 12],
        _: &[&[u8]],
        _: &[u8],
        _: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Err(refused("SRTP key refused"))
    }
}

impl SupportedAeadAes128Gcm for Ring {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn AeadAes128GcmCipher> {
        let key = Zeroizing::new(key);
        match Gcm::new(&AES_128_GCM, key.as_slice()) {
            Some(c) => Box::new(c),
            None => Box::new(Unkeyed),
        }
    }
}

impl SupportedAeadAes256Gcm for Ring {
    fn create_cipher(&self, key: [u8; 32], _encrypt: bool) -> Box<dyn AeadAes256GcmCipher> {
        let key = Zeroizing::new(key);
        match Gcm::new(&AES_256_GCM, key.as_slice()) {
            Some(c) => Box::new(c),
            None => Box::new(Unkeyed),
        }
    }
}

// ── STUN integrity, fingerprints ─────────────────────────────────────────────────────────────────

impl Sha1HmacProvider for Ring {
    fn sha1_hmac(&self, key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
        let mut ctx = ring::hmac::Context::with_key(&key);
        for p in payloads {
            ctx.update(p);
        }
        let mut out = [0_u8; 20];
        out.copy_from_slice(ctx.sign().as_ref());
        out
    }
}

impl Sha256Provider for Ring {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut out = [0_u8; 32];
        out.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, data).as_ref());
        out
    }
}

/// Random bytes from the OS, through ring.
#[must_use]
pub fn random<const N: usize>() -> Option<[u8; N]> {
    use ring::rand::SecureRandom as _;
    let mut out = [0_u8; N];
    ring::rand::SystemRandom::new().fill(&mut out).ok()?;
    Some(out)
}

// The DTLS factory is the shim's; these satisfy the provider's shape for it.
impl DtlsProvider for crate::shim::Host {
    fn generate_certificate(&self) -> Option<DtlsCert> {
        None
    }

    fn new_dtls(
        &self,
        _cert: &DtlsCert,
        _now: std::time::Instant,
        _version: DtlsVersion,
        _mtu: Option<usize>,
    ) -> Result<Box<dyn DtlsInstance>, CryptoError> {
        crate::shim::take_pending()
            .map(|s| Box::new(s) as Box<dyn DtlsInstance>)
            .ok_or_else(|| refused("no host shim is pending for this association"))
    }
}
