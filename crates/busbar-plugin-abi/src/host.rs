// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host services: the raw `Host` vtable, the crypto request shapes and consts, and the safe API plugins call (IF §5, §5.1, §5.2).
//!
//! The `Host` table, `HostFns`, `CryptoReq`, `CryptoRet`, `DeploymentId` and the entry brand `Ctx` are busbar-ffi's
//! (UNSAFE-MIN r3.1) and re-exported here; their `mechanism!` blocks are busbar-ffi's. This module keeps the
//! algorithm, key-form, status and level numbers, the safe value types and `HostExt`, the §5.1 safe methods
//! (W1-A2: the crypto ones marshal each call into one `CryptoReq` and copy every answer out before return).

use core::fmt;
use core::ops::Deref;

use busbar_ffi::{Bytes, Status, Str};
use zeroize::Zeroize as _;

use crate::fail::{Fail, refused};

pub use busbar_ffi::raw::{HOST_CTX_AT, HOST_FNS_AT};
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

/// AES-GCM's nonce and tag lengths (§5 `alg::AEAD_*`).
const NONCE: usize = 12;
const TAG: usize = 16;

/// One `CryptoReq` with no param, aux or aad (callers set those with struct update).
const fn req<'a>(alg: u32, key_form: u32, key: &'a [u8], data: &'a [u8]) -> CryptoReq<'a> {
    CryptoReq {
        alg,
        key_form,
        param: 0,
        key: Bytes::new(key),
        data: Bytes::new(data),
        aux: Bytes::EMPTY,
        aad: Bytes::EMPTY,
    }
}

/// One `crypto` call. The lent output is read inside `Host::scoped` and `take` copies it out, so nothing lent
/// outlives the call (r4 H3). A null entry is its panic fallback, Err(Rng); every non-OK status is its error.
fn call<R>(
    host: &Host,
    req: &CryptoReq<'_>,
    take: impl FnOnce(&[u8]) -> Result<R, CryptoErr>,
) -> Result<R, CryptoErr> {
    let Some(crypto) = host.fns().crypto else {
        return Err(CryptoErr::Rng);
    };
    host.scoped(|ctx| {
        let ret = crypto(ctx, req);
        if ret.status != crypto_status::OK {
            return Err(crypto_err(ret.status));
        }
        take(ret.out.get())
    })
}

/// The output when it is exactly `len` bytes; any other length is a host bug, never a short value (Err(Rng)).
fn sized(out: &[u8], len: usize) -> Result<&[u8], CryptoErr> {
    if out.len() == len {
        Ok(out)
    } else {
        Err(CryptoErr::Rng)
    }
}

/// An AES key is 16 or 32 bytes (§5.1), checked before any call.
fn aes_key(key: &[u8]) -> Result<(), CryptoErr> {
    if matches!(key.len(), 16 | 32) {
        Ok(())
    } else {
        Err(CryptoErr::Invalid)
    }
}

/// Appends `bytes` to `out` as I11 requires (§5.1): in place when `out` has room, else into a fresh block, the old
/// one wiped before it is freed; never `reserve` on `out`. No room for the new block is Err(Limit).
fn append(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CryptoErr> {
    if out.capacity() - out.len() < bytes.len() {
        let need = out.len().checked_add(bytes.len()).ok_or(CryptoErr::Limit)?;
        let mut grown = Vec::new();
        grown
            .try_reserve_exact(need.max(out.len().saturating_mul(2)))
            .map_err(|_| CryptoErr::Limit)?;
        grown.extend_from_slice(out);
        core::mem::swap(out, &mut grown);
        grown.zeroize();
    }
    out.extend_from_slice(bytes);
    Ok(())
}

/// The answer block of `core_service::HMAC_PARTS` as the MAC of `len` bytes: a `crypto_status`, then, only
/// when it is OK, exactly the tag. A block shorter than a status, and an OK status followed by a tag of
/// any other length, are a host bug, never a short value (Err(Rng)); a non-OK status is its error whatever
/// follows it.
fn hmac_parts_answer(block: &[u8], len: usize) -> Result<Digest, CryptoErr> {
    let Some((status, tag)) = block.split_first_chunk::<4>() else {
        return Err(CryptoErr::Rng);
    };
    match u32::from_le_bytes(*status) {
        crypto_status::OK => Digest::copied(tag, len),
        status => Err(crypto_err(status)),
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
/// Core host services (core 3.0): the ids `Host::service` serves for every kind. A core id has no kind
/// code in its high 32 bits (a kind's own service has its kind code there, `service_id`), so the two
/// spaces never meet. Each service's call follows the one call shape: numbers in `head` (little-endian,
/// natural alignment), then `texts` and `blobs` by position. An id the host does not serve is FAULT.
pub mod core_service {
    /// HMAC over parts (interface revision E.1). The message is the concatenation of the parts in order;
    /// the host MACs each part where the plugin lent it, copies none and allocates nothing.
    ///
    /// head: `alg: u32`, an `alg::HMAC_*`. texts: none.
    /// blobs: `[0]` = the MAC key (RAW), `[1..]` = the parts, 0 to `HMAC_PARTS_MAX` of them.
    /// Answer block: `crypto_status: u32` (little-endian), then, only when it is OK, the tag (the alg's
    /// length). INVALID: an alg that is no HMAC, or more than `HMAC_PARTS_MAX` parts. UNAVAILABLE: the
    /// backend refuses the alg or the key, or does not MAC parts with that hash. LIMIT: the block has no
    /// room for the tag. RNG: the crypto module failed, or the call was made outside an entry.
    /// Entry status FAULT, nothing written: a head shorter than `alg`, no key blob, or a block with no
    /// room for the status.
    pub const HMAC_PARTS: u64 = 1;
    /// The most parts one HMAC_PARTS call carries. Eight covers every signed-message shape a shipped
    /// plugin builds (Standard Webhooks: 5; the SigV4 string to sign: 7); a message of more pieces is
    /// joined by its plugin.
    pub const HMAC_PARTS_MAX: usize = 8;
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
        ct_eq(self.as_slice(), other)
    }
    /// A host output of exactly `len` (≤ 64) bytes, copied out; any other length is Err(Rng).
    fn copied(out: &[u8], len: usize) -> Result<Digest, CryptoErr> {
        let src = sized(out, len)?;
        let mut digest = Digest {
            len: u8::try_from(len).map_err(|_| CryptoErr::Rng)?,
            bytes: [0; 64],
        };
        match digest.bytes.get_mut(..len) {
            Some(dst) => dst.copy_from_slice(src),
            None => return Err(CryptoErr::Rng),
        }
        Ok(digest)
    }
}
impl Drop for Digest {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl Hash {
    /// The digest alg, its output length, and the HMAC alg (none for MD5: digest only).
    const fn algs(self) -> (u32, usize, Option<u32>) {
        match self {
            Hash::Sha256 => (alg::SHA256, 32, Some(alg::HMAC_SHA256)),
            Hash::Sha384 => (alg::SHA384, 48, Some(alg::HMAC_SHA384)),
            Hash::Sha512 => (alg::SHA512, 64, Some(alg::HMAC_SHA512)),
            Hash::Sha1 => (alg::SHA1, 20, Some(alg::HMAC_SHA1)),
            Hash::Md5 => (alg::MD5, 16, None),
        }
    }
}

/// Fixed-size custody for secret bytes a plugin must retain beyond the current call.
/// It never grows or exposes ownership of its allocation. Debug reports length only; dropping wipes it.
pub struct SecretBytes(Box<[u8]>);

impl SecretBytes {
    /// Copies borrowed secret bytes into one allocation of exactly the required length.
    #[must_use]
    pub fn copy_from_slice(bytes: &[u8]) -> Self {
        Self(Box::from(bytes))
    }
}

impl Deref for SecretBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes({} bytes)", self.0.len())
    }
}

/// Owned plaintext returned by `aead_open`, copied before the host scratch can be reused.
/// The shared secure byte owner wipes its allocation; this public wrapper remains read-only
/// and Debug prints only the length.
pub struct Plaintext(crate::secure::SecureVec);

impl Plaintext {
    fn copied(bytes: &[u8]) -> Plaintext {
        Plaintext(crate::secure::SecureVec::from(bytes))
    }
}

impl Deref for Plaintext {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Plaintext({} bytes)", self.0.len())
    }
}

/// The safe host methods of IF §5.1, as an extension trait over busbar-ffi's `Host` (coordinator ruling on
/// W1-U0: busbar-ffi owns the `Host` table and cannot name this crate's `CryptoErr`, `Digest`, `Fail` or `Key`,
/// and an inherent method cannot be added to a foreign type). Call syntax is unchanged with the trait in scope:
/// `use busbar_plugin_abi::host::HostExt;`. Every answer is read from `HostFns`' safe fn pointers under
/// `Host::scoped`, so nothing lent by the host outlives the call. A null (None) entry reads as its panic
/// fallback (round 20, I10): crypto and random Err(Rng), grow false, now/mono/log_level 0, deployment all
/// zero, a dropped log line, `migrate_admit` REFUSED.
///
/// The crypto methods (digest through rsa_oaep) are one `crypto` call each: a key form or AES key length the IF
/// rules out, a tag-less `sealed`, and `hmac(Md5)` are Err(Invalid) before any call; an answer whose length is not
/// the one the alg defines is Err(Rng), never a short value; every `*_into` appends as I11 requires.
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
    /// `hmac` of `parts[0] || parts[1] || ...` under `key` (core 3.0, `core_service::HMAC_PARTS`): the host
    /// MACs every part where it lies, so a signed body is never copied into one buffer and nothing is
    /// allocated on either side. `hmac_parts(Md5)` and more than `core_service::HMAC_PARTS_MAX` parts are
    /// Err(Invalid) before any call. A hash the host does not MAC parts with is Err(Unavailable): join the
    /// message and use `hmac`. A host without the service is Err(Rng), like a null `crypto`.
    fn hmac_parts(&self, h: Hash, key: &[u8], parts: &[&[u8]]) -> Result<Digest, CryptoErr>;
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
    /// `sealed` = ciphertext || tag; the nonce is passed separately (split it off `aead_seal`'s output). The IF's
    /// `zeroize::Zeroizing<Vec<u8>>` is a [`Plaintext`] (core bans `Zeroizing`, LR-094).
    fn aead_open(
        &self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Plaintext, CryptoErr>;
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
    /// Core 3.0: one of a kind's own host services, by id (`service_id(kind, n)`, allotted by that kind's
    /// contract). `call` carries the service's numbers, texts and blobs like any method call; the answer is
    /// records written into `answer` (caller storage, at least `RawOut::MIN` bytes for a fixed answer).
    /// Returns the status and the bytes written. A host without the entry, or an unknown id, is FAULT.
    fn service(&self, id: u64, call: &crate::types::Call<'_>, answer: &mut [u8])
    -> (Status, usize);
}

/// The id of host service `n` of kind `kind` (interface revision C.5): the kind code in the high half, so
/// a kind gains a service without touching the host table or another kind's numbers.
pub const fn service_id(kind: crate::types::KindCode, n: u32) -> u64 {
    ((kind as u64) << 32) | n as u64
}
/// Store service 1: the store-open recoverable gate (was the host table's `migrate_admit`). Head: the
/// recoverable count, `u64`. Answer: no records; OK admits, REFUSED does not.
/// E.1: moves to the store contract crate with `HostExt::migrate_admit` when the crates are split.
pub const SERVICE_STORE_MIGRATE_ADMIT: u64 = service_id(crate::types::KindCode::Store, 1);

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
        // Core 3.0: the host hands its one clock reading for the operation in with the call; inside an
        // entry that is the answer, with no call back. Outside one (or from a host that gave none) ask.
        let handed = busbar_ffi::shim::mono_ns();
        if handed != 0 {
            return handed;
        }
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
        let (alg, len, _) = h.algs();
        call(self, &req(alg, key_form::RAW, &[], data), |out| {
            Digest::copied(out, len)
        })
    }
    fn hmac(&self, h: Hash, key: &[u8], data: &[u8]) -> Result<Digest, CryptoErr> {
        let (_, len, Some(alg)) = h.algs() else {
            return Err(CryptoErr::Invalid);
        };
        call(self, &req(alg, key_form::RAW, key, data), |out| {
            Digest::copied(out, len)
        })
    }
    fn hmac_parts(&self, h: Hash, key: &[u8], parts: &[&[u8]]) -> Result<Digest, CryptoErr> {
        let (_, len, Some(alg)) = h.algs() else {
            return Err(CryptoErr::Invalid);
        };
        if parts.len() > core_service::HMAC_PARTS_MAX {
            return Err(CryptoErr::Invalid);
        }
        // The key, then each part, as borrowed views on this frame: the array holds addresses and
        // lengths only, no byte of the message.
        let mut lent = [Bytes::EMPTY; 1 + core_service::HMAC_PARTS_MAX];
        let message = core::iter::once(key).chain(parts.iter().copied());
        for (slot, bytes) in lent.iter_mut().zip(message) {
            *slot = Bytes::new(bytes);
        }
        let Some(blobs) = lent.get(..=parts.len()) else {
            return Err(CryptoErr::Invalid);
        };
        let head = alg.to_le_bytes();
        let call = crate::types::Call::new(0, &head, &[], blobs);
        let mut answer = [0u8; busbar_ffi::RawOut::MIN];
        let (status, written) = self.service(core_service::HMAC_PARTS, &call, &mut answer);
        let mac = if status == Status::OK {
            hmac_parts_answer(answer.get(..written).unwrap_or(&[]), len)
        } else {
            Err(CryptoErr::Rng)
        };
        answer.zeroize();
        mac
    }
    fn pbkdf2_sha256(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> Result<Digest, CryptoErr> {
        let r = CryptoReq {
            param: u64::from(iterations),
            ..req(alg::PBKDF2_HMAC_SHA256, key_form::RAW, password, salt)
        };
        call(self, &r, |out| Digest::copied(out, 32))
    }
    fn verify(
        &self,
        sig: Sig,
        key: Key<'_>,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoErr> {
        let alg = match sig {
            Sig::Rs256 => alg::VERIFY_RS256,
            Sig::Rs384 => alg::VERIFY_RS384,
            Sig::Rs512 => alg::VERIFY_RS512,
            Sig::Ps256 => alg::VERIFY_PS256,
            Sig::Ps384 => alg::VERIFY_PS384,
            Sig::Ps512 => alg::VERIFY_PS512,
            Sig::Es256 => alg::VERIFY_ES256,
            Sig::Es384 => alg::VERIFY_ES384,
            Sig::Ed25519 => alg::VERIFY_ED25519,
        };
        // RSA_COMPONENTS: u32 LE n_len, n, e (§5 `key_form`); public bytes, no wipe.
        let components;
        let (form, key): (u32, &[u8]) = match key {
            Key::Raw(k) => (key_form::RAW, k),
            Key::SpkiDer(k) => (key_form::SPKI_DER, k),
            Key::RsaPkcs1Der(k) => (key_form::RSA_PKCS1_DER, k),
            Key::EcPoint(k) => (key_form::EC_POINT, k),
            Key::Rsa { n, e } => {
                let n_len = u32::try_from(n.len()).map_err(|_| CryptoErr::Invalid)?;
                components = [&n_len.to_le_bytes()[..], n, e].concat();
                (key_form::RSA_COMPONENTS, components.as_slice())
            }
        };
        let r = CryptoReq {
            aux: Bytes::new(signature),
            ..req(alg, form, key, msg)
        };
        match call(self, &r, |_| Ok(())) {
            Ok(()) => Ok(true),
            Err(CryptoErr::Bad) => Ok(false),
            Err(e) => Err(e),
        }
    }
    fn sign(&self, alg: SignAlg, pkcs8: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoErr> {
        let code = match alg {
            SignAlg::Rs256 => alg::SIGN_RS256,
            SignAlg::Es256 => alg::SIGN_ES256,
            SignAlg::Ed25519 => alg::SIGN_ED25519,
        };
        call(self, &req(code, key_form::PKCS8, pkcs8, msg), |out| {
            Ok(out.to_vec())
        })
    }
    fn aead_seal(&self, key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoErr> {
        aes_key(key)?;
        let len = plaintext
            .len()
            .checked_add(NONCE + TAG)
            .ok_or(CryptoErr::Invalid)?;
        let r = CryptoReq {
            aad: Bytes::new(aad),
            ..req(alg::AEAD_SEAL, key_form::RAW, key, plaintext)
        };
        call(self, &r, |out| sized(out, len).map(<[u8]>::to_vec))
    }
    fn aead_open(
        &self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        sealed: &[u8],
    ) -> Result<Plaintext, CryptoErr> {
        aes_key(key)?;
        let len = sealed.len().checked_sub(TAG).ok_or(CryptoErr::Invalid)?;
        let r = CryptoReq {
            aux: Bytes::new(nonce),
            aad: Bytes::new(aad),
            ..req(alg::AEAD_OPEN, key_form::RAW, key, sealed)
        };
        call(self, &r, |out| sized(out, len).map(Plaintext::copied))
    }
    fn aead_seal_explicit_into(
        &self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoErr> {
        aes_key(key)?;
        let len = plaintext.len().checked_add(TAG).ok_or(CryptoErr::Invalid)?;
        let r = CryptoReq {
            aux: Bytes::new(nonce),
            aad: Bytes::new(aad),
            ..req(alg::AEAD_SEAL_EXPLICIT, key_form::RAW, key, plaintext)
        };
        call(self, &r, |lent| append(out, sized(lent, len)?))
    }
    fn aead_open_into(
        &self,
        key: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
        sealed: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoErr> {
        aes_key(key)?;
        let len = sealed.len().checked_sub(TAG).ok_or(CryptoErr::Invalid)?;
        let r = CryptoReq {
            aux: Bytes::new(nonce),
            aad: Bytes::new(aad),
            ..req(alg::AEAD_OPEN, key_form::RAW, key, sealed)
        };
        call(self, &r, |lent| append(out, sized(lent, len)?))
    }
    fn aes_ctr_into(
        &self,
        key: &[u8],
        iv: &[u8; 16],
        data: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoErr> {
        aes_key(key)?;
        let r = CryptoReq {
            aux: Bytes::new(iv),
            ..req(alg::AES_CTR, key_form::RAW, key, data)
        };
        call(self, &r, |lent| append(out, sized(lent, data.len())?))
    }
    fn rsa_oaep_sha1_encrypt(
        &self,
        public: Key<'_>,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoErr> {
        let Key::SpkiDer(spki) = public else {
            return Err(CryptoErr::Invalid);
        };
        let r = req(
            alg::RSA_OAEP_SHA1_ENCRYPT,
            key_form::SPKI_DER,
            spki,
            plaintext,
        );
        call(self, &r, |out| Ok(out.to_vec()))
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
        let head = recoverable.to_le_bytes();
        let call = crate::types::Call::new(0, &head, &[], &[]);
        let mut answer = [0u8; busbar_ffi::RawOut::MIN];
        if self
            .service(SERVICE_STORE_MIGRATE_ADMIT, &call, &mut answer)
            .0
            == Status::OK
        {
            Ok(())
        } else {
            Err(Fail::refused(refused::R_CONFIG))
        }
    }
    fn service(
        &self,
        id: u64,
        call: &crate::types::Call<'_>,
        answer: &mut [u8],
    ) -> (Status, usize) {
        let Some(service) = self.fns().service else {
            return (Status::FAULT, 0);
        };
        let mut out = busbar_ffi::RawOut::over(answer);
        let status = self.scoped(|ctx| service(ctx, id, call, &mut out));
        (status, out.len())
    }
}
/// Constant-time compare, pure code (not a crypto primitive), for token and signature checks.
/// Unequal lengths answer false at once (a length is not the secret); equal lengths always read every byte, and the
/// folded difference passes `black_box` so the comparison is not cut short.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    core::hint::black_box(diff) == 0
}

#[cfg(feature = "host")]
pub use crate::host_side::*;

/// The safe crypto API over a test vtable (W1-A2): each test sets this thread's canned answer, calls one method and
/// checks the request it marshalled and the value it returned. The entry lends its output from a busbar-ffi
/// `Arena`, as `host_vt` does, and [`tests::seen`] overwrites the arena before the value is read, so a value that
/// still reads right was copied out before return (r4 H3).
#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use busbar_ffi::host::Arena;

    use super::*;

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct Seen {
        alg: u32,
        key_form: u32,
        param: u64,
        key: Vec<u8>,
        data: Vec<u8>,
        aux: Vec<u8>,
        aad: Vec<u8>,
    }

    std::thread_local! {
        static ARENA: RefCell<Arena> = RefCell::new(Arena::new(1 << 16));
        static REPLY: RefCell<(u32, Vec<u8>)> = const { RefCell::new((0, Vec::new())) };
        static SEEN: RefCell<Vec<Seen>> = const { RefCell::new(Vec::new()) };
    }

    extern "C" fn answer<'e>(ctx: Ctx<'e>, req: &CryptoReq<'_>) -> CryptoRet<'e> {
        SEEN.with(|seen| {
            seen.borrow_mut().push(Seen {
                alg: req.alg,
                key_form: req.key_form,
                param: req.param,
                key: req.key.get().to_vec(),
                data: req.data.get().to_vec(),
                aux: req.aux.get().to_vec(),
                aad: req.aad.get().to_vec(),
            });
        });
        let (status, out) = REPLY.with(|reply| reply.borrow().clone());
        if status != crypto_status::OK {
            return CryptoRet::empty(ctx, status);
        }
        match ARENA.with(|arena| arena.borrow_mut().lend(ctx, &out)) {
            Some(out) => CryptoRet { status, _r: 0, out },
            None => CryptoRet::empty(ctx, crypto_status::LIMIT),
        }
    }

    const NONE: HostFns = HostFns {
        now: None,
        mono: None,
        random: None,
        crypto: None,
        log: None,
        log_level: None,
        grow: None,
        deployment: None,
        service: None,
    };
    static HOST: Host = Host::new(
        0,
        HostFns {
            crypto: Some(answer),
            ..NONE
        },
    );
    static NO_CRYPTO: Host = Host::new(0, NONE);

    /// The entry's next answer.
    fn reply(status: u32, out: &[u8]) {
        REPLY.with(|reply| *reply.borrow_mut() = (status, out.to_vec()));
    }

    /// The requests made since the last look; the arena is overwritten first (the outermost entry's exit).
    fn seen() -> Vec<Seen> {
        ARENA.with(|arena| arena.borrow_mut().drain().fill(0xEE));
        SEEN.with(|seen| core::mem::take(&mut *seen.borrow_mut()))
    }

    fn one() -> Seen {
        let mut seen = seen();
        assert_eq!(seen.len(), 1, "exactly one host call");
        seen.remove(0)
    }

    #[test]
    fn digest_and_hmac_copy_the_lent_output_out() {
        for (h, digest_alg, hmac_alg, len) in [
            (Hash::Sha256, alg::SHA256, alg::HMAC_SHA256, 32u8),
            (Hash::Sha384, alg::SHA384, alg::HMAC_SHA384, 48),
            (Hash::Sha512, alg::SHA512, alg::HMAC_SHA512, 64),
            (Hash::Sha1, alg::SHA1, alg::HMAC_SHA1, 20),
            (Hash::Md5, alg::MD5, 0, 16),
        ] {
            let lent: Vec<u8> = (1..=len).collect();
            reply(crypto_status::OK, &lent);
            let digest = HOST.digest(h, b"message");
            let req = one();
            assert_eq!(
                digest.map(|d| d.as_slice().to_vec()),
                Ok(lent.clone()),
                "{h:?}: intact after the arena is overwritten"
            );
            assert_eq!(
                (req.alg, req.key, req.data),
                (digest_alg, vec![], b"message".to_vec())
            );
            if h == Hash::Md5 {
                assert_eq!(HOST.hmac(h, b"key", b"m").err(), Some(CryptoErr::Invalid));
                assert!(seen().is_empty(), "hmac(Md5) never reaches the host");
                continue;
            }
            reply(crypto_status::OK, &lent);
            let mac = HOST.hmac(h, b"key", b"message");
            let req = one();
            assert_eq!(mac.map(|d| d.as_slice().to_vec()), Ok(lent));
            assert_eq!(
                (req.alg, req.key_form, req.key, req.data),
                (
                    hmac_alg,
                    key_form::RAW,
                    b"key".to_vec(),
                    b"message".to_vec()
                )
            );
        }
    }

    #[test]
    fn an_answer_of_the_wrong_length_is_rng_never_a_short_value() {
        reply(crypto_status::OK, &[7; 31]);
        assert_eq!(HOST.digest(Hash::Sha256, b"m").err(), Some(CryptoErr::Rng));
        reply(crypto_status::OK, &[7; 33]);
        assert_eq!(
            HOST.pbkdf2_sha256(b"pw", b"salt", 1).err(),
            Some(CryptoErr::Rng)
        );
        reply(crypto_status::OK, &[7; 4]);
        assert_eq!(HOST.aead_seal(&[1; 16], b"", b"plain"), Err(CryptoErr::Rng));
        reply(crypto_status::OK, &[7; 4]);
        assert_eq!(
            HOST.aead_open(&[1; 16], &[0; 12], b"", &[2; 21]).err(),
            Some(CryptoErr::Rng)
        );
        let mut out = vec![1, 2];
        reply(crypto_status::OK, &[7; 4]);
        assert_eq!(
            HOST.aes_ctr_into(&[1; 16], &[0; 16], b"abc", &mut out),
            Err(CryptoErr::Rng)
        );
        assert_eq!(out, [1, 2], "nothing is appended on Err");
        assert_eq!(seen().len(), 5);
    }

    #[test]
    fn every_status_is_one_error_and_verify_reads_bad_as_false() {
        for (status, want) in [
            (crypto_status::BAD, CryptoErr::Bad),
            (crypto_status::INVALID, CryptoErr::Invalid),
            (crypto_status::UNAVAILABLE, CryptoErr::Unavailable),
            (crypto_status::LIMIT, CryptoErr::Limit),
            (crypto_status::RNG, CryptoErr::Rng),
            (99, CryptoErr::Rng),
        ] {
            reply(status, &[]);
            assert_eq!(
                HOST.digest(Hash::Sha256, b"m").err(),
                Some(want),
                "{status}"
            );
            reply(status, &[]);
            let verdict = HOST.verify(Sig::Ed25519, Key::Raw(&[1; 32]), b"m", &[2; 64]);
            let want = if want == CryptoErr::Bad {
                Ok(false)
            } else {
                Err(want)
            };
            assert_eq!(verdict, want, "{status}");
        }
        reply(crypto_status::OK, &[]);
        assert_eq!(
            HOST.verify(Sig::Ed25519, Key::Raw(&[1; 32]), b"m", &[2; 64]),
            Ok(true)
        );
        assert_eq!(seen().len(), 13);
    }

    #[test]
    fn verify_marshals_the_alg_the_key_form_and_the_signature() {
        for (sig, want) in [
            (Sig::Rs256, alg::VERIFY_RS256),
            (Sig::Rs384, alg::VERIFY_RS384),
            (Sig::Rs512, alg::VERIFY_RS512),
            (Sig::Ps256, alg::VERIFY_PS256),
            (Sig::Ps384, alg::VERIFY_PS384),
            (Sig::Ps512, alg::VERIFY_PS512),
            (Sig::Es256, alg::VERIFY_ES256),
            (Sig::Es384, alg::VERIFY_ES384),
            (Sig::Ed25519, alg::VERIFY_ED25519),
        ] {
            reply(crypto_status::OK, &[]);
            assert_eq!(
                HOST.verify(sig, Key::SpkiDer(b"spki"), b"msg", b"sig"),
                Ok(true)
            );
            let req = one();
            assert_eq!(
                (req.alg, req.key_form, req.key, req.data, req.aux),
                (
                    want,
                    key_form::SPKI_DER,
                    b"spki".to_vec(),
                    b"msg".to_vec(),
                    b"sig".to_vec()
                )
            );
        }
        for (key, form, bytes) in [
            (Key::Raw(b"raw"), key_form::RAW, b"raw".to_vec()),
            (
                Key::RsaPkcs1Der(b"der"),
                key_form::RSA_PKCS1_DER,
                b"der".to_vec(),
            ),
            (
                Key::EcPoint(b"\x04xy"),
                key_form::EC_POINT,
                b"\x04xy".to_vec(),
            ),
            (
                Key::Rsa {
                    n: b"nn",
                    e: b"\x01\x00\x01",
                },
                key_form::RSA_COMPONENTS,
                vec![2, 0, 0, 0, b'n', b'n', 1, 0, 1],
            ),
        ] {
            reply(crypto_status::OK, &[]);
            assert_eq!(HOST.verify(Sig::Rs256, key, b"m", b"s"), Ok(true));
            let req = one();
            assert_eq!((req.key_form, req.key), (form, bytes));
        }
    }

    #[test]
    fn sign_pbkdf2_and_rsa_oaep_marshal_their_arguments() {
        for (sign, want) in [
            (SignAlg::Rs256, alg::SIGN_RS256),
            (SignAlg::Es256, alg::SIGN_ES256),
            (SignAlg::Ed25519, alg::SIGN_ED25519),
        ] {
            reply(crypto_status::OK, b"signature");
            let signed = HOST.sign(sign, b"pkcs8", b"msg");
            let req = one();
            assert_eq!(signed, Ok(b"signature".to_vec()));
            assert_eq!(
                (req.alg, req.key_form, req.key, req.data),
                (want, key_form::PKCS8, b"pkcs8".to_vec(), b"msg".to_vec())
            );
        }
        reply(crypto_status::OK, &[3; 32]);
        let derived = HOST.pbkdf2_sha256(b"pw", b"salt", 4096);
        let req = one();
        assert_eq!(derived.map(|d| d.as_slice().to_vec()), Ok(vec![3; 32]));
        assert_eq!(
            (req.alg, req.key_form, req.param, req.key, req.data),
            (
                alg::PBKDF2_HMAC_SHA256,
                key_form::RAW,
                4096,
                b"pw".to_vec(),
                b"salt".to_vec()
            )
        );
        reply(crypto_status::OK, b"ciphertext");
        let sealed = HOST.rsa_oaep_sha1_encrypt(Key::SpkiDer(b"spki"), b"secret");
        let req = one();
        assert_eq!(sealed, Ok(b"ciphertext".to_vec()));
        assert_eq!(
            (req.alg, req.key_form, req.key, req.data),
            (
                alg::RSA_OAEP_SHA1_ENCRYPT,
                key_form::SPKI_DER,
                b"spki".to_vec(),
                b"secret".to_vec()
            )
        );
        let raw = HOST.rsa_oaep_sha1_encrypt(Key::Raw(b"raw"), b"secret");
        assert_eq!(raw, Err(CryptoErr::Invalid));
        assert!(
            seen().is_empty(),
            "a key that is not SPKI never reaches the host"
        );
    }

    #[test]
    fn aead_seal_and_open_keep_the_nonce_framing() {
        let sealed: Vec<u8> = (0..33).collect();
        reply(crypto_status::OK, &sealed);
        let out = HOST.aead_seal(&[1; 16], b"aad", b"plain");
        let req = one();
        assert_eq!(out, Ok(sealed));
        assert_eq!(
            (req.alg, req.key_form, req.key, req.data, req.aux, req.aad),
            (
                alg::AEAD_SEAL,
                key_form::RAW,
                vec![1; 16],
                b"plain".to_vec(),
                vec![],
                b"aad".to_vec()
            )
        );
        reply(crypto_status::OK, b"plain");
        let opened = HOST.aead_open(&[2; 32], &[9; 12], b"aad", &[5; 21]);
        let req = one();
        assert_eq!(
            opened.as_ref().map(|p| format!("{p:?}")).ok().as_deref(),
            Some("Plaintext(5 bytes)")
        );
        assert_eq!(opened.map(|p| p.to_vec()), Ok(b"plain".to_vec()));
        assert_eq!(
            (req.alg, req.key, req.data, req.aux, req.aad),
            (
                alg::AEAD_OPEN,
                vec![2; 32],
                vec![5; 21],
                vec![9; 12],
                b"aad".to_vec()
            )
        );
        for key in [&[0u8; 24][..], &[][..]] {
            assert_eq!(HOST.aead_seal(key, b"", b"p"), Err(CryptoErr::Invalid));
            assert_eq!(
                HOST.aead_open(key, &[0; 12], b"", &[0; 16]).err(),
                Some(CryptoErr::Invalid)
            );
        }
        let short = HOST.aead_open(&[0; 16], &[0; 12], b"", &[0; 15]);
        assert_eq!(
            short.err(),
            Some(CryptoErr::Invalid),
            "shorter than the tag"
        );
        assert!(
            seen().is_empty(),
            "a refused key or length never reaches the host"
        );
    }

    #[test]
    fn the_into_methods_append_in_place_and_move_only_when_they_outgrow() {
        let mut roomy = Vec::with_capacity(64);
        roomy.extend_from_slice(b"head");
        let at = roomy.as_ptr();
        reply(crypto_status::OK, &[7; 21]);
        let sealed = HOST.aead_seal_explicit_into(&[1; 16], &[3; 12], b"aad", b"plain", &mut roomy);
        let req = one();
        assert_eq!(sealed, Ok(()));
        assert_eq!(
            (req.alg, req.aux, req.data, req.aad),
            (
                alg::AEAD_SEAL_EXPLICIT,
                vec![3; 12],
                b"plain".to_vec(),
                b"aad".to_vec()
            )
        );
        assert_eq!(roomy.as_ptr(), at, "room enough: the same block");
        assert_eq!((&roomy[..4], &roomy[4..]), (&b"head"[..], &[7; 21][..]));
        let mut tight = b"ab".to_vec();
        tight.shrink_to_fit();
        reply(crypto_status::OK, b"plain");
        let opened = HOST.aead_open_into(&[1; 32], &[4; 12], b"", &[5; 21], &mut tight);
        let req = one();
        assert_eq!(opened, Ok(()));
        assert_eq!(
            (req.alg, req.aux, req.data),
            (alg::AEAD_OPEN, vec![4; 12], vec![5; 21])
        );
        assert_eq!(tight, b"abplain");
        let mut ctr = Vec::new();
        reply(crypto_status::OK, b"xyz");
        assert_eq!(
            HOST.aes_ctr_into(&[1; 16], &[6; 16], b"abc", &mut ctr),
            Ok(())
        );
        let req = one();
        assert_eq!(
            (req.alg, req.key_form, req.aux, req.data),
            (alg::AES_CTR, key_form::RAW, vec![6; 16], b"abc".to_vec())
        );
        assert_eq!(ctr, b"xyz");
        let mut kept = b"kept".to_vec();
        let key = [0u8; 24];
        let seal = HOST.aead_seal_explicit_into(&key, &[0; 12], b"", b"p", &mut kept);
        let open = HOST.aead_open_into(&key, &[0; 12], b"", &[0; 17], &mut kept);
        let ctr = HOST.aes_ctr_into(&key, &[0; 16], b"p", &mut kept);
        assert_eq!([seal, open, ctr], [Err(CryptoErr::Invalid); 3]);
        assert_eq!(kept, b"kept");
        assert!(seen().is_empty());
    }

    #[test]
    fn a_null_crypto_entry_is_rng_on_every_method() {
        let h = &NO_CRYPTO;
        let mut out = Vec::new();
        assert_eq!(h.digest(Hash::Sha256, b"m").err(), Some(CryptoErr::Rng));
        assert_eq!(h.hmac(Hash::Sha256, b"k", b"m").err(), Some(CryptoErr::Rng));
        assert_eq!(h.pbkdf2_sha256(b"p", b"s", 1).err(), Some(CryptoErr::Rng));
        assert_eq!(
            h.verify(Sig::Es256, Key::EcPoint(b"p"), b"m", b"s"),
            Err(CryptoErr::Rng)
        );
        assert_eq!(h.sign(SignAlg::Es256, b"k", b"m"), Err(CryptoErr::Rng));
        assert_eq!(h.aead_seal(&[0; 16], b"", b"p"), Err(CryptoErr::Rng));
        assert_eq!(
            h.aead_open(&[0; 16], &[0; 12], b"", &[0; 17]).err(),
            Some(CryptoErr::Rng)
        );
        let seal = h.aead_seal_explicit_into(&[0; 16], &[0; 12], b"", b"p", &mut out);
        let open = h.aead_open_into(&[0; 16], &[0; 12], b"", &[0; 17], &mut out);
        let ctr = h.aes_ctr_into(&[0; 16], &[0; 16], b"p", &mut out);
        assert_eq!([seal, open, ctr], [Err(CryptoErr::Rng); 3]);
        let oaep = h.rsa_oaep_sha1_encrypt(Key::SpkiDer(b"k"), b"p");
        assert_eq!(oaep, Err(CryptoErr::Rng));
        assert!(out.is_empty());
    }

    /// One `service` call as the test entry saw it: the id, the head, how many texts, and each blob's
    /// address and length (so a test can tell a lent part from a copy of it).
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct Served {
        id: u64,
        head: Vec<u8>,
        texts: usize,
        blobs: Vec<(usize, usize)>,
    }

    std::thread_local! {
        static SERVICE_REPLY: RefCell<(Status, Vec<u8>)> = const { RefCell::new((Status::OK, Vec::new())) };
        static SERVED: RefCell<Vec<Served>> = const { RefCell::new(Vec::new()) };
    }

    /// A `service` entry that records the call and writes this thread's canned answer into the block.
    extern "C" fn serve(
        _: Ctx<'_>,
        id: u64,
        call: &crate::types::Call<'_>,
        out: &mut busbar_ffi::RawOut,
    ) -> Status {
        SERVED.with(|served| {
            served.borrow_mut().push(Served {
                id,
                head: call.head().to_vec(),
                texts: call.texts().len(),
                blobs: call
                    .blobs()
                    .iter()
                    .map(|blob| (blob.get().as_ptr().addr(), blob.get().len()))
                    .collect(),
            });
        });
        let (status, bytes) = SERVICE_REPLY.with(|reply| reply.borrow().clone());
        if busbar_ffi::host::answer(out, &bytes) {
            status
        } else {
            Status::FAULT
        }
    }

    static SERVICE_HOST: Host = Host::new(
        0,
        HostFns {
            service: Some(serve),
            ..NONE
        },
    );

    /// The service entry's next answer: its status, then the answer block (a `crypto_status`, then `tag`).
    fn service_reply(status: Status, crypto: u32, tag: &[u8]) {
        let mut bytes = crypto.to_le_bytes().to_vec();
        bytes.extend_from_slice(tag);
        SERVICE_REPLY.with(|reply| *reply.borrow_mut() = (status, bytes));
    }

    fn served() -> Vec<Served> {
        SERVED.with(|served| core::mem::take(&mut *served.borrow_mut()))
    }

    fn tag_bytes(mac: Result<Digest, CryptoErr>) -> Result<Vec<u8>, CryptoErr> {
        mac.map(|digest| digest.as_slice().to_vec())
    }

    /// E.1: the key and every part cross as the call's blobs, each lent where it lies (same address, same
    /// length, in order), the alg crosses in the head, and the tag is copied out of the answer block.
    #[test]
    fn hmac_parts_lends_the_key_and_every_part_where_it_lies() {
        let key = b"webhook-key".to_vec();
        let body = vec![7u8; 4096];
        let parts: [&[u8]; 5] = [b"msg_1", b".", b"1700000000", b".", &body];
        for (h, hmac_alg, len) in [
            (Hash::Sha256, alg::HMAC_SHA256, 32u8),
            (Hash::Sha384, alg::HMAC_SHA384, 48),
            (Hash::Sha512, alg::HMAC_SHA512, 64),
            (Hash::Sha1, alg::HMAC_SHA1, 20),
        ] {
            let tag: Vec<u8> = (1..=len).collect();
            service_reply(Status::OK, crypto_status::OK, &tag);
            let mac = SERVICE_HOST.hmac_parts(h, &key, &parts);
            let calls = served();
            assert_eq!(calls.len(), 1, "{h:?}: exactly one host call");
            assert_eq!(tag_bytes(mac), Ok(tag), "{h:?}");
            let lent: Vec<(usize, usize)> = core::iter::once(key.as_slice())
                .chain(parts)
                .map(|part| (part.as_ptr().addr(), part.len()))
                .collect();
            assert_eq!(
                calls.first(),
                Some(&Served {
                    id: core_service::HMAC_PARTS,
                    head: hmac_alg.to_le_bytes().to_vec(),
                    texts: 0,
                    blobs: lent,
                }),
                "{h:?}: the key, then each part, each where it lies"
            );
        }
    }

    #[test]
    fn hmac_parts_takes_none_to_the_most_parts_and_refuses_more_and_md5_before_any_call() {
        service_reply(Status::OK, crypto_status::OK, &[9; 32]);
        let none = SERVICE_HOST.hmac_parts(Hash::Sha256, b"k", &[]);
        assert_eq!(tag_bytes(none), Ok(vec![9; 32]));
        assert_eq!(
            served().first().map(|call| call.blobs.len()),
            Some(1),
            "no parts: the key alone crosses"
        );
        let most = [&b"p"[..]; core_service::HMAC_PARTS_MAX];
        service_reply(Status::OK, crypto_status::OK, &[9; 32]);
        assert_eq!(
            tag_bytes(SERVICE_HOST.hmac_parts(Hash::Sha256, b"k", &most)),
            Ok(vec![9; 32])
        );
        assert_eq!(
            served().first().map(|call| call.blobs.len()),
            Some(1 + core_service::HMAC_PARTS_MAX)
        );
        let over = [&b"p"[..]; core_service::HMAC_PARTS_MAX + 1];
        assert_eq!(
            SERVICE_HOST.hmac_parts(Hash::Sha256, b"k", &over).err(),
            Some(CryptoErr::Invalid)
        );
        assert_eq!(
            SERVICE_HOST.hmac_parts(Hash::Md5, b"k", &[b"m"]).err(),
            Some(CryptoErr::Invalid)
        );
        assert!(
            served().is_empty(),
            "a refused request never reaches the host"
        );
    }

    /// Only an OK entry status with an OK `crypto_status` and a tag of exactly the alg's length is a MAC.
    /// Every other answer is its error: a host that answers OK and writes nothing, or writes a short or a
    /// long tag, is never read as a tag.
    #[test]
    fn hmac_parts_reads_every_other_answer_as_an_error_never_a_short_tag() {
        let mac = || SERVICE_HOST.hmac_parts(Hash::Sha256, b"key", &[b"id", b"body"]);
        for (crypto, want) in [
            (crypto_status::BAD, CryptoErr::Bad),
            (crypto_status::INVALID, CryptoErr::Invalid),
            (crypto_status::UNAVAILABLE, CryptoErr::Unavailable),
            (crypto_status::LIMIT, CryptoErr::Limit),
            (crypto_status::RNG, CryptoErr::Rng),
            (99, CryptoErr::Rng),
        ] {
            service_reply(Status::OK, crypto, &[]);
            assert_eq!(mac().err(), Some(want), "{crypto}");
            // A non-OK crypto status carries no tag, whatever follows it in the block.
            service_reply(Status::OK, crypto, &[7; 32]);
            assert_eq!(mac().err(), Some(want), "{crypto} with trailing bytes");
        }
        for len in [0, 1, 31, 33, 64] {
            service_reply(Status::OK, crypto_status::OK, &vec![7; len]);
            assert_eq!(mac().err(), Some(CryptoErr::Rng), "a tag of {len} bytes");
        }
        let short: [&[u8]; 2] = [&[], &[0, 0]];
        for block in short {
            SERVICE_REPLY.with(|reply| *reply.borrow_mut() = (Status::OK, block.to_vec()));
            assert_eq!(mac().err(), Some(CryptoErr::Rng), "an answer of {block:?}");
        }
        for status in [Status::REFUSED, Status::FAILED, Status::NEED, Status::FAULT] {
            service_reply(status, crypto_status::OK, &[7; 32]);
            assert_eq!(mac().err(), Some(CryptoErr::Rng), "{status:?}");
        }
        served();
        // A host without the service entry: the entry's fallback, like a null `crypto`.
        let absent = NO_CRYPTO.hmac_parts(Hash::Sha256, b"key", &[b"id", b"body"]);
        assert_eq!(absent.err(), Some(CryptoErr::Rng));
    }

    /// The core services are part of the core contract: the id, the most parts and the stated layout live
    /// in the block `fp::CORE_FP` folds, so moving any of them moves the fingerprint and the pin. A core id
    /// has no kind code, so it can never be a kind's own service; and the largest answer (a status and a
    /// 64-byte tag) fits the smallest block a plugin may hand.
    #[test]
    fn the_core_service_numbers_are_fixed_and_fingerprinted() {
        assert_eq!(core_service::HMAC_PARTS, 1);
        assert_eq!(core_service::HMAC_PARTS_MAX, 8);
        assert_eq!(core_service::HMAC_PARTS >> 32, 0);
        assert_ne!(core_service::HMAC_PARTS, SERVICE_STORE_MIGRATE_ADMIT);
        for kind in crate::types::KindCode::ALL {
            assert_ne!(service_id(kind, 1), core_service::HMAC_PARTS, "{kind:?}");
        }
        for token in ["core_service", "HMAC_PARTS", "HMAC_PARTS_MAX"] {
            assert!(MECHANISM_BLOCK.contains(token), "{token}");
        }
        assert!(4 + 64 <= busbar_ffi::RawOut::MIN);
    }

    #[test]
    fn ct_eq_is_true_only_for_equal_whole_slices() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"token", b"token"));
        assert!(!ct_eq(b"token", b"tokeN"));
        assert!(!ct_eq(b"Token", b"token"));
        assert!(!ct_eq(b"token", b"toke"));
        reply(crypto_status::OK, &[8; 32]);
        let digest = HOST.digest(Hash::Sha256, b"m");
        seen();
        assert_eq!(digest.as_ref().map(|d| d.ct_eq(&[8; 32])), Ok(true));
        assert_eq!(digest.as_ref().map(|d| d.ct_eq(&[8; 31])), Ok(false));
        assert_eq!(digest.map(|d| d.ct_eq(&[9; 32])), Ok(false));
    }

    #[test]
    fn retained_secret_bytes_own_their_copy_and_redact_debug() {
        let mut source = b"callback-secret".to_vec();
        let secret = SecretBytes::copy_from_slice(&source);
        source.fill(0);
        assert_eq!(&*secret, b"callback-secret");
        assert_eq!(format!("{secret:?}"), "SecretBytes(15 bytes)");
        assert!(!format!("{secret:?}").contains("callback"));
    }
}
