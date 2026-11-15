// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host services: the raw `Host` vtable, the crypto request shapes and consts, and the safe API plugins call (IF §5, §5.1, §5.2).
//!
//! The `Host` table, `HostFns`, `CryptoReq`, `CryptoRet`, `DeploymentId` and the entry brand `Ctx` are busbar-ffi's
//! (UNSAFE-MIN r3.1) and re-exported here; their `mechanism!` blocks are busbar-ffi's. This module keeps the
//! algorithm, key-form, status and level numbers, the safe value types and `HostExt`, the §5.1 safe methods
//! (W1-A2 fills the crypto ones).

use busbar_ffi::{Status, Str};

use crate::fail::{Fail, refused};

pub use busbar_ffi::{CryptoReq, CryptoRet, Ctx, DeploymentId, Host, HostFns, RawLent};

/// The most bytes one `random` call returns (IF §5).
const RANDOM_MAX: usize = 65_536;

/// A host `crypto_status` as the error a plugin sees (IF §5.2).
fn crypto_err(status: u32) -> CryptoErr {
    match status {
        crypto_status::BAD => CryptoErr::Bad,
        crypto_status::INVALID => CryptoErr::Invalid,
        crypto_status::UNAVAILABLE => CryptoErr::Unavailable,
        crypto_status::LIMIT => CryptoErr::Limit,
        _ => CryptoErr::Rng,
    }
}

mechanism! {

/// Algorithm numbers. Each is exactly one `busbar-crypto` function (§5.2 table). Whether the linked backend
/// offers it is the backend's answer alone (`Error::Unsupported` => UNAVAILABLE); the ABI keeps no FIPS column.
pub mod alg {
    // Digests: data = message. Out = digest.
    pub const SHA256: u32 = 1;
    pub const SHA384: u32 = 2;
    pub const SHA512: u32 = 3;
    /// Protocol use only (WebSocket accept, mysql_native_password, SRTP): facade `legacy::sha1`.
    pub const SHA1: u32 = 4;
    /// Protocol use only (Postgres AuthenticationMD5Password): facade `legacy::md5`.
    pub const MD5: u32 = 5;
    // MACs: key = MAC key, data = message. Out = tag.
    pub const HMAC_SHA256: u32 = 16;
    pub const HMAC_SHA384: u32 = 17;
    pub const HMAC_SHA512: u32 = 18;
    /// Protocol use only (webhook signatures, SRTP auth): facade `legacy::hmac_sha1`.
    pub const HMAC_SHA1: u32 = 19;
    /// key = password, data = salt, param = iterations (1..=10_000_000). Out = 32 bytes.
    pub const PBKDF2_HMAC_SHA256: u32 = 32;
    // Verify: key in key_form (allowed forms per alg in §5.2), data = message, aux = signature. status OK or BAD.
    pub const VERIFY_RS256: u32 = 48;
    pub const VERIFY_RS384: u32 = 49;
    pub const VERIFY_RS512: u32 = 50;
    pub const VERIFY_PS256: u32 = 51;
    pub const VERIFY_PS384: u32 = 52;
    pub const VERIFY_PS512: u32 = 53;
    /// aux = 64-byte r||s (JWS encoding).
    pub const VERIFY_ES256: u32 = 54;
    /// aux = 96-byte r||s (JWS encoding).
    pub const VERIFY_ES384: u32 = 55;
    pub const VERIFY_ED25519: u32 = 56;
    // Sign: key = PKCS#8 DER private key (KEY_PKCS8), data = message. Out = signature (JWS encoding for ES*).
    pub const SIGN_RS256: u32 = 80;
    pub const SIGN_ES256: u32 = 81;
    pub const SIGN_ED25519: u32 = 82;
    // AEAD AES-GCM. key = 16 or 32 bytes (AES-128 / AES-256), aad = AAD.
    /// The module generates the nonce (CRYPTO-SEAM F1): data = plaintext, aux empty.
    /// Out = nonce(12) || ciphertext || tag(16).
    pub const AEAD_SEAL: u32 = 96;
    /// aux = 12-byte nonce, data = ciphertext || tag. Out = plaintext.
    pub const AEAD_OPEN: u32 = 97;
    /// Protocol-derived nonce (SRTP-GCM): aux = 12-byte nonce, data = plaintext. Out = ciphertext || tag.
    /// A FIPS backend refuses it (module-generated IV only, F1).
    pub const AEAD_SEAL_EXPLICIT: u32 = 98;
    /// AES-CTR keystream XOR (SRTP AES-CM): key = 16 or 32 bytes, aux = 16-byte initial counter block,
    /// data = in. Out = same length.
    pub const AES_CTR: u32 = 99;
    /// RSA-OAEP with SHA-1 and MGF1-SHA1, encrypt only (MySQL caching_sha2_password full auth over plaintext
    /// TCP): key = SPKI_DER public key, data = plaintext. Out = ciphertext. Facade `legacy::rsa_oaep_sha1_encrypt`.
    pub const RSA_OAEP_SHA1_ENCRYPT: u32 = 112;
}
pub mod key_form {
    pub const RAW: u32 = 0; // MAC key, AEAD key, AES-CTR key, Ed25519 32-byte public key
    pub const SPKI_DER: u32 = 1; // SubjectPublicKeyInfo DER
    pub const RSA_COMPONENTS: u32 = 2; // u32 LE n_len, n (big-endian), e (big-endian): a JWK without DER
    pub const EC_POINT: u32 = 3; // SEC1 uncompressed point; curve from alg
    pub const PKCS8: u32 = 4; // private key for SIGN_*
    pub const RSA_PKCS1_DER: u32 = 5; // PKCS#1 RSAPublicKey DER
}
pub mod crypto_status {
    pub const OK: u32 = 0;
    pub const BAD: u32 = 1; // facade Error::Mismatch: signature invalid / AEAD authentication failed
    pub const INVALID: u32 = 2; // facade Error::Invalid, a key_form not allowed for the alg, or a bad length/param
    pub const UNAVAILABLE: u32 = 3; // facade Error::Unsupported only: the backend refuses this alg/param (a verdict)
    pub const LIMIT: u32 = 4; // scratch arena cap (1 MiB + 64 per outermost entry, r4 H3) exceeded
    /// The crypto module failed (a backend failure, never a verdict): facade Error::Rng (the DRBG failed:
    /// random, AEAD_SEAL, SIGN_*) or, round 23, Error::SelfTest from any call (§5.2; round 20 had put it in
    /// UNAVAILABLE, which the safe layer turned into REFUSED R_UNSUPPORTED). Safe layer: Err(Rng) → FAILED.
    pub const RNG: u32 = 5;
}
pub mod level {
    pub const ERROR: u32 = 1;
    pub const WARN: u32 = 2;
    pub const INFO: u32 = 3;
    pub const DEBUG: u32 = 4;
    pub const TRACE: u32 = 5;
}
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Hash {
    Sha256,
    Sha384,
    Sha512,
    Sha1,
    Md5, /* digest only; hmac(Md5) is Invalid */
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sig {
    Rs256,
    Rs384,
    Rs512,
    Ps256,
    Ps384,
    Ps512,
    Es256,
    Es384,
    Ed25519,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SignAlg {
    Rs256,
    Es256,
    Ed25519,
}
#[derive(Clone, Copy)]
pub enum Key<'a> {
    Raw(&'a [u8]),
    SpkiDer(&'a [u8]),
    RsaPkcs1Der(&'a [u8]),
    Rsa { n: &'a [u8], e: &'a [u8] },
    EcPoint(&'a [u8]),
}
/// Unavailable: the backend refuses this alg/param (status UNAVAILABLE, a verdict: `?` gives REFUSED
/// R_UNSUPPORTED). Rng: the crypto module failed, the DRBG or (round 23) a self-test (status RNG, a backend
/// failure: `?` gives FAILED F_UNAVAILABLE). Never silently replaced by zero bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CryptoErr {
    Bad,
    Invalid,
    Unavailable,
    Limit,
    Rng,
}

/// A digest or MAC, owned, no allocation. Zeroized on drop.
#[derive(Clone)]
pub struct Digest {
    len: u8,
    bytes: [u8; 64],
}
impl Digest {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
    pub fn ct_eq(&self, other: &[u8]) -> bool {
        let _ = other;
        todo!()
    }
}
// W0-ABI: `impl Drop for Digest` (zeroize) lands with W1-A2; a todo!() drop would panic.

/// The safe host methods of IF §5.1, as an extension trait over busbar-ffi's `Host` (coordinator ruling on
/// W1-U0: busbar-ffi owns the `Host` table and cannot name this crate's `CryptoErr`, `Digest`, `Fail` or `Key`,
/// and an inherent method cannot be added to a foreign type). Call syntax is unchanged with the trait in scope:
/// `use busbar_plugin_abi::host::HostExt;`. Every answer is read from `HostFns`' safe fn pointers under
/// `Host::scoped`, so nothing lent by the host outlives the call. A null (None) entry reads as its panic
/// fallback (round 20, I10): crypto and random Err(Rng), grow false, now/mono/log_level 0, deployment all
/// zero, a dropped log line, `migrate_admit` REFUSED.
///
/// The crypto methods (digest through rsa_oaep) are held for W1-A2, which marshals them onto `Host::crypto`.
pub trait HostExt {
    fn now_ns(&self) -> u64;
    fn now_s(&self) -> u64;
    fn mono_ns(&self) -> u64;
    /// N outside 1..=65_536 is a compile error (`const { assert!(N >= 1 && N <= 65_536) }` in the body).
    /// A DRBG failure is Err(Rng): there is no path that returns a zero-filled array.
    fn random<const N: usize>(&self) -> Result<[u8; N], CryptoErr>;
    /// len 0 or > 65,536: Err(Invalid). DRBG failure: Err(Rng). Round 23, every fallible method here: the
    /// backend's self-test failed is Err(Rng) (§5.2; round 20's Err(Unavailable) became a REFUSED verdict
    /// through `?`); the backend refuses the alg is Err(Unavailable); the entry's arena is full is Err(Limit) (r4 H3).
    fn random_vec(&self, len: usize) -> Result<Vec<u8>, CryptoErr>;
    /// Fills `buf` (1..=65,536 bytes) in place, no allocation. On Err, `buf` is zeroed and must not be used.
    fn random_into(&self, buf: &mut [u8]) -> Result<(), CryptoErr>;
    fn digest(&self, h: Hash, data: &[u8]) -> Result<Digest, CryptoErr>;
    fn hmac(&self, h: Hash, key: &[u8], data: &[u8]) -> Result<Digest, CryptoErr>;
    fn pbkdf2_sha256(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> Result<Digest, CryptoErr>;
    /// Ok(true) valid, Ok(false) invalid signature.
    fn verify(
        &self,
        sig: Sig,
        key: Key<'_>,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoErr>;
    fn sign(&self, alg: SignAlg, pkcs8: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoErr>;
    /// Host-generated nonce (F1). Returns nonce(12) || ciphertext || tag(16). key.len() is 16 or 32, else Invalid.
    fn aead_seal(&self, key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoErr>;
    /// Appends ciphertext || tag to `out` (no allocation once `out` has capacity). Unavailable on a backend that
    /// allows only module-generated IVs.
    fn aead_seal_explicit_into(
        &self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoErr>;
    /// Like aead_open, appending to `out` (the per-packet path for SRTP).
    fn aead_open_into(
        &self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        sealed: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoErr>;
    /// Appends the AES-CTR transform of `data` to `out`. key.len() is 16 or 32, else Invalid.
    fn aes_ctr_into(
        &self,
        key: &[u8],
        iv: &[u8; 16],
        data: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoErr>;
    /// `public` must be `Key::SpkiDer`, else Invalid.
    fn rsa_oaep_sha1_encrypt(
        &self,
        public: Key<'_>,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoErr>;
    /// Round 34: passes `error` = 0, so no existing call site changes.
    fn log(&self, level: u32, msg: &str);
    /// Round 34 (PLUGIN-ERROR-CODES): the same entry with one declared error number (D_ERRORS; 0 = none).
    fn log_error(&self, level: u32, error: u16, msg: &str);
    fn log_enabled(&self, level: u32) -> bool;
    /// Round 28: the raw `deployment` read. `None` while it is all zero (boot steps 2a/2b only, and `busbar
    /// --check-config`, which opens no store), else the whole id (round 29: never a partial one). A `None` seen in
    /// `check` during 2a/2b is always followed by a second `check` that sees `Some` before the instance serves
    /// anything outside boot (§5 `deployment`, §11.2); a binding check skips only on `None` and decides on `Some`.
    fn deployment_id(&self) -> Option<DeploymentId>;
    /// Round 31: the raw `migrate_admit`. Ok(()) on OK. REFUSED → Err(`Fail::refused(R_CONFIG)`), which the store
    /// returns unchanged from `open` before its first data, DDL or marker write; core substitutes its own text.
    fn migrate_admit(&self, recoverable: u64) -> Result<(), Fail>;
}

impl HostExt for Host {
    fn now_ns(&self) -> u64 {
        match self.fns().now {
            Some(now) => self.scoped(|ctx| now(ctx)),
            None => 0,
        }
    }
    fn now_s(&self) -> u64 {
        self.now_ns() / 1_000_000_000
    }
    fn mono_ns(&self) -> u64 {
        match self.fns().mono {
            Some(mono) => self.scoped(|ctx| mono(ctx)),
            None => 0,
        }
    }
    fn random<const N: usize>(&self) -> Result<[u8; N], CryptoErr> {
        const { assert!(N != 0 && N <= RANDOM_MAX) };
        let mut out = [0u8; N];
        self.random_into(&mut out)?;
        Ok(out)
    }
    fn random_vec(&self, len: usize) -> Result<Vec<u8>, CryptoErr> {
        let mut out = vec![0u8; len.min(RANDOM_MAX + 1)];
        self.random_into(&mut out)?;
        Ok(out)
    }
    fn random_into(&self, buf: &mut [u8]) -> Result<(), CryptoErr> {
        buf.fill(0);
        if buf.is_empty() || buf.len() > RANDOM_MAX {
            return Err(CryptoErr::Invalid);
        }
        let Some(random) = self.fns().random else {
            return Err(CryptoErr::Rng);
        };
        let len = buf.len();
        self.scoped(|ctx| {
            let ret = random(ctx, len);
            if ret.status != crypto_status::OK {
                return Err(crypto_err(ret.status));
            }
            // The host lends exactly `len` bytes on OK; any other length is a host bug, never random bytes.
            let lent = ret.out.get();
            if lent.len() != len {
                return Err(CryptoErr::Rng);
            }
            buf.copy_from_slice(lent);
            Ok(())
        })
    }
    fn digest(&self, h: Hash, data: &[u8]) -> Result<Digest, CryptoErr> {
        let _ = (h, data);
        todo!()
    }
    fn hmac(&self, h: Hash, key: &[u8], data: &[u8]) -> Result<Digest, CryptoErr> {
        let _ = (h, key, data);
        todo!()
    }
    fn pbkdf2_sha256(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> Result<Digest, CryptoErr> {
        let _ = (password, salt, iterations);
        todo!()
    }
    fn verify(
        &self,
        sig: Sig,
        key: Key<'_>,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoErr> {
        let _ = (sig, key, msg, signature);
        todo!()
    }
    fn sign(&self, alg: SignAlg, pkcs8: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoErr> {
        let _ = (alg, pkcs8, msg);
        todo!()
    }
    fn aead_seal(&self, key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoErr> {
        let _ = (key, aad, plaintext);
        todo!()
    }
    // W0-ABI: `aead_open` is omitted at wave 0: its frozen return type is
    // `Result<zeroize::Zeroizing<Vec<u8>>, CryptoErr>` and the stubs may not use zeroize. W1-A2 adds it:
    //   /// `sealed` = ciphertext || tag; the nonce is passed separately (split it off `aead_seal`'s output).
    //   pub fn aead_open(&self, key: &[u8], nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoErr>;
    fn aead_seal_explicit_into(
        &self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoErr> {
        let _ = (key, nonce, aad, plaintext, out);
        todo!()
    }
    fn aead_open_into(
        &self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        sealed: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoErr> {
        let _ = (key, nonce, aad, sealed, out);
        todo!()
    }
    fn aes_ctr_into(
        &self,
        key: &[u8],
        iv: &[u8; 16],
        data: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoErr> {
        let _ = (key, iv, data, out);
        todo!()
    }
    fn rsa_oaep_sha1_encrypt(
        &self,
        public: Key<'_>,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoErr> {
        let _ = (public, plaintext);
        todo!()
    }
    fn log(&self, level: u32, msg: &str) {
        self.log_error(level, 0, msg);
    }
    fn log_error(&self, level: u32, error: u16, msg: &str) {
        let Some(log) = self.fns().log else {
            return;
        };
        self.scoped(|ctx| log(ctx, level, u32::from(error), Str::new(msg)));
    }
    fn log_enabled(&self, level: u32) -> bool {
        let Some(log_level) = self.fns().log_level else {
            return false;
        };
        level != 0 && level <= self.scoped(|ctx| log_level(ctx))
    }
    fn deployment_id(&self) -> Option<DeploymentId> {
        let deployment = self.fns().deployment?;
        let id = self.scoped(|ctx| deployment(ctx));
        (id.0 != [0; 16]).then_some(id)
    }
    fn migrate_admit(&self, recoverable: u64) -> Result<(), Fail> {
        let admitted = match self.fns().migrate_admit {
            Some(admit) => self.scoped(|ctx| admit(ctx, recoverable)) == Status::OK,
            None => false,
        };
        if admitted {
            Ok(())
        } else {
            Err(Fail::refused(refused::R_CONFIG))
        }
    }
}
/// Constant-time compare, pure code (not a crypto primitive), for token and signature checks.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let _ = (a, b);
    todo!()
}

#[cfg(feature = "host")]
pub use crate::host_side::*;
