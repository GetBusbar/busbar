// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host services: the raw `Host` vtable, the crypto request shapes and consts, and the safe API plugins call (IF §5, §5.1, §5.2). W0-ABI stub: frozen signatures, `todo!()` bodies; A2 fills it.

use core::ffi::c_void;

use crate::fail::Fail;
use crate::types::{Bytes, RawOut, Status, Str};

mechanism! {
/// The host vtable. One process-wide static; plugins get `&'static Host`. The raw fields are private to abi.
/// Round 20: every fn field is panic-contained host-side (I10, §10.7 `contain`): a host bug answers crypto
/// and random RNG (out EMPTY; round 24: FAILED, never REFUSED), grow false, now/mono/log_level 0, deployment all
/// zero (round 28), or drops the log line; never an unwind.
#[repr(C)]
pub struct Host {
    pub(crate) ctx: *const c_void,
    /// UTC nanoseconds since the Unix epoch, from the host clock.
    pub(crate) now: unsafe extern "C" fn(ctx: *const c_void) -> u64,
    /// Monotonic nanoseconds, same clock as WAKE_AT.
    pub(crate) mono: unsafe extern "C" fn(ctx: *const c_void) -> u64,
    /// `len` (1..=65_536) random bytes from `busbar_crypto::fill_checked` (round 21; the backend's DRBG, its error
    /// through the facade's `map`, §5.2), in this thread's scratch
    /// arena (r4 H3, owned by host_vt.rs §10.7: allocated once at its cap, never grown, **append-only for the
    /// whole outermost entry**: every `random`/`crypto` output in one entry gets fresh space after the previous
    /// ones and never clobbers them; zeroed over what was written when the outermost entry-guard exits and on
    /// thread exit, I11). `out` stays valid and unchanged until the outermost entry on this thread returns, and
    /// no longer. status OK, or INVALID (len 0 or > 65,536), or LIMIT (the entry's outputs would pass the arena
    /// cap), or RNG (the crypto module failed: the DRBG failed, or, round 23, the backend's self-test failed,
    /// §5.2, reachable here through `fill_checked`); on every
    /// non-OK status `out` is EMPTY, never zero bytes. This is
    /// the only randomness a plugin has (§15.4 bans getrandom/rand and every other RNG crate outright).
    pub(crate) random: unsafe extern "C" fn(ctx: *const c_void, len: usize) -> CryptoRet,
    /// One crypto operation: exactly one `busbar-crypto` call (§5.2). Output in the thread's scratch arena
    /// (fixed 1 MiB + 64 for the whole outermost entry, never grown; an output that does not fit after the
    /// entry's earlier outputs is LIMIT, written nowhere, and the earlier outputs stay intact). r4 H3: append-only,
    /// so two calls in one entry return distinct, non-overlapping buffers and the first is still intact after
    /// the second; `out` is valid until the outermost entry on this thread returns. AEAD_OPEN plaintext, PBKDF2
    /// and HMAC outputs land here and are zeroed by the arena rule (I11).
    pub(crate) crypto: unsafe extern "C" fn(ctx: *const c_void, req: *const CryptoReq<'static>) -> CryptoRet,
    /// Emit a log line, attributed by the host to the owner of the entry running on this thread (round 24: the
    /// entry guard's host-side `OWNER` cell, §10.7, set by every FFI entry whether or not the thread holds a
    /// watchdog word), so attribution holds in polls, describe, cancel and close too, and on an unwatched thread. The host scrubs the
    /// line against that instance's scrub set before it is written (I14, §12.16); plugins never mask.
    /// Round 34 (PLUGIN-ERROR-CODES): `error` is one of this image's declared numbers (D_ERRORS), 0 = none. The
    /// host checks it as the `u32` it arrives as (above 9999 = not declared, before any narrowing) and renders a
    /// declared one as `BUSBAR-<identity>-NNNN` in its own `plugin_diag` field (§10.7, §11.2). Widened in place:
    /// no slot is appended, and an image built against the round-33 `log` has the old CORE_FP (stamp refusal).
    pub(crate) log: unsafe extern "C" fn(ctx: *const c_void, level: u32, error: u32, msg: Str<'static>),
    /// The most verbose level currently enabled (0 = off). Check before formatting.
    pub(crate) log_level: unsafe extern "C" fn(ctx: *const c_void) -> u32,
    /// Grow this thread's ACTIVE OutBuf (set by the entry guard for every entry that has an `out`, I10) to hold
    /// `need` more bytes, up to max_out. Rewrites out.ptr/out.cap from host state. False if no ACTIVE buffer,
    /// if `out` is not the ACTIVE buffer's RawOut, if `len + need` overflows, or over max_out (round 13: the host
    /// computes `len + need` with `checked_add` and clamps its high-water mark to its own capacity, §10.1). Growth moves to a larger pooled block and
    /// zeroes the old one before release (I11, §10.1); the plugin must reload ptr/cap after every grow.
    pub(crate) grow: unsafe extern "C" fn(ctx: *const c_void, out: *mut RawOut, need: usize) -> bool,
    /// Round 28 (the generic deployment-id read). The stable 16-byte install identity: the
    /// keep-once Store row `busbar.deployment.v1`/`id` of ADMIN-API-1.6 (`dep_` + 32 hex there; these are the 16
    /// bytes the hex spells). Not the `deployment` keyset seed (boot_identity.rs:18), which never leaves core. Opaque
    /// to the plugin: stable across restarts, nodes and replicas of one deployment, never a secret, never a verdict.
    /// All zero until core has read or written the row at boot (§11.2 `BootPlan`: only during the open/migrate of
    /// the secret and store instances the store needs, steps 2a/2b); non-zero and unchanging for the rest of the
    /// process. Round 29: lock-free, one Acquire load of a `OnceLock<DeploymentId>` published once with all 16
    /// bytes (§10.7 `set_deployment`), so a reader sees either all zero or the whole id, never half; no allocation.
    /// Panic fallback (I10): all zero. Plugins use it to bind their own state to this install and for object keys;
    /// core never reads what they do with it. Round 29, the boot ordering rule: an instance opened in
    /// steps 2a/2b reads all zero there; core re-runs that instance's `check` (OPEN_DRY_RUN, `Open::check`) once
    /// after `set_deployment` and before step 2c starts, and a REFUSED there refuses the boot exactly as a step-2c
    /// `open` refusal does (§11.2 `BootPlan`). A plugin that binds to the deployment does the binding in `check`.
    pub(crate) deployment: unsafe extern "C" fn(ctx: *const c_void) -> DeploymentId,
    /// Round 31 (owner ruling; MIGRATE-ON-BOOT r42 §4): the recoverable gate. Valid only inside an entry of a
    /// **store** instance's non-DRY_RUN `open` (its first poll or any resume of its chain), on every load path.
    /// `recoverable` = how many older rows this store is about to hand core that hold a recoverable secret (its
    /// own count of its own column). OK: core can seal them (n == 0, or an at-rest key resolves). REFUSED: it
    /// cannot; core records its own text (how to add the key) against the instance and reports that text when
    /// the open refuses. Any other entry or kind: FAULT (`NeedNotAllowed`), and the entry is faulted. Panic
    /// fallback (I10): REFUSED.
    pub(crate) migrate_admit: unsafe extern "C" fn(ctx: *const c_void, recoverable: u64) -> Status,
}

/// Round 28. A deployment id by value (16 bytes, align 1; `bb_deployment_id` in C, §7.8).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DeploymentId(pub [u8; 16]);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CryptoReq<'a> {
    pub alg: u32,
    pub key_form: u32,
    pub param: u64,
    pub key: Bytes<'a>,
    pub data: Bytes<'a>,
    pub aux: Bytes<'a>,
    pub aad: Bytes<'a>,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CryptoRet {
    pub status: u32,
    pub _r: u32,
    pub out: Bytes<'static>,
}

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

// SAFETY: the host builds one process-wide `Host` (§10.7) and never mutates it; `ctx` is the host's own
// context, read only by the host's fns, each of which is thread-safe and panic-contained (I10).
#[allow(unsafe_code)]
unsafe impl Sync for Host {}

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

impl Host {
    pub fn now_ns(&self) -> u64 {
        todo!()
    }
    pub fn now_s(&self) -> u64 {
        todo!()
    }
    pub fn mono_ns(&self) -> u64 {
        todo!()
    }
    /// N outside 1..=65_536 is a compile error (`const { assert!(N >= 1 && N <= 65_536) }` in the body).
    /// A DRBG failure is Err(Rng): there is no path that returns a zero-filled array.
    pub fn random<const N: usize>(&self) -> Result<[u8; N], CryptoErr> {
        todo!()
    }
    /// len 0 or > 65,536: Err(Invalid). DRBG failure: Err(Rng). Round 23, every fallible method here: the
    /// backend's self-test failed is Err(Rng) (§5.2; round 20's Err(Unavailable) became a REFUSED verdict
    /// through `?`); the backend refuses the alg is Err(Unavailable); the entry's arena is full is Err(Limit) (r4 H3).
    pub fn random_vec(&self, len: usize) -> Result<Vec<u8>, CryptoErr> {
        let _ = len;
        todo!()
    }
    /// Fills `buf` (1..=65,536 bytes) in place, no allocation. On Err, `buf` is zeroed and must not be used.
    pub fn random_into(&self, buf: &mut [u8]) -> Result<(), CryptoErr> {
        let _ = buf;
        todo!()
    }
    pub fn digest(&self, h: Hash, data: &[u8]) -> Result<Digest, CryptoErr> {
        let _ = (h, data);
        todo!()
    }
    pub fn hmac(&self, h: Hash, key: &[u8], data: &[u8]) -> Result<Digest, CryptoErr> {
        let _ = (h, key, data);
        todo!()
    }
    pub fn pbkdf2_sha256(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> Result<Digest, CryptoErr> {
        let _ = (password, salt, iterations);
        todo!()
    }
    /// Ok(true) valid, Ok(false) invalid signature.
    pub fn verify(
        &self,
        sig: Sig,
        key: Key<'_>,
        msg: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoErr> {
        let _ = (sig, key, msg, signature);
        todo!()
    }
    pub fn sign(&self, alg: SignAlg, pkcs8: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoErr> {
        let _ = (alg, pkcs8, msg);
        todo!()
    }
    /// Host-generated nonce (F1). Returns nonce(12) || ciphertext || tag(16). key.len() is 16 or 32, else Invalid.
    pub fn aead_seal(
        &self,
        key: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoErr> {
        let _ = (key, aad, plaintext);
        todo!()
    }
    // W0-ABI: `aead_open` is omitted at wave 0: its frozen return type is
    // `Result<zeroize::Zeroizing<Vec<u8>>, CryptoErr>` and the stubs may not use zeroize. W1-A2 adds it:
    //   /// `sealed` = ciphertext || tag; the nonce is passed separately (split it off `aead_seal`'s output).
    //   pub fn aead_open(&self, key: &[u8], nonce: &[u8; 12], aad: &[u8], sealed: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoErr>;
    /// Appends ciphertext || tag to `out` (no allocation once `out` has capacity). Unavailable on a backend that
    /// allows only module-generated IVs.
    pub fn aead_seal_explicit_into(
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
    /// Like aead_open, appending to `out` (the per-packet path for SRTP).
    pub fn aead_open_into(
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
    /// Appends the AES-CTR transform of `data` to `out`. key.len() is 16 or 32, else Invalid.
    pub fn aes_ctr_into(
        &self,
        key: &[u8],
        iv: &[u8; 16],
        data: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoErr> {
        let _ = (key, iv, data, out);
        todo!()
    }
    /// `public` must be `Key::SpkiDer`, else Invalid.
    pub fn rsa_oaep_sha1_encrypt(
        &self,
        public: Key<'_>,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoErr> {
        let _ = (public, plaintext);
        todo!()
    }
    /// Round 34: passes `error` = 0, so no existing call site changes.
    pub fn log(&self, level: u32, msg: &str) {
        let _ = (level, msg);
        todo!()
    }
    /// Round 34 (PLUGIN-ERROR-CODES): the same entry with one declared error number (D_ERRORS; 0 = none).
    pub fn log_error(&self, level: u32, error: u16, msg: &str) {
        let _ = (level, error, msg);
        todo!()
    }
    pub fn log_enabled(&self, level: u32) -> bool {
        let _ = level;
        todo!()
    }
    /// Round 28: the raw `deployment` read. `None` while it is all zero (boot steps 2a/2b only, and `busbar
    /// --check-config`, which opens no store), else the whole id (round 29: never a partial one). A `None` seen in
    /// `check` during 2a/2b is always followed by a second `check` that sees `Some` before the instance serves
    /// anything outside boot (§5 `deployment`, §11.2); a binding check skips only on `None` and decides on `Some`.
    pub fn deployment_id(&self) -> Option<DeploymentId> {
        todo!()
    }
    /// Round 31: the raw `migrate_admit`. Ok(()) on OK. REFUSED → Err(`Fail::refused(R_CONFIG)`), which the store
    /// returns unchanged from `open` before its first data, DDL or marker write; core substitutes its own text.
    pub fn migrate_admit(&self, recoverable: u64) -> Result<(), Fail> {
        let _ = recoverable;
        todo!()
    }
}
/// Constant-time compare, pure code (not a crypto primitive), for token and signature checks.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let _ = (a, b);
    todo!()
}

#[cfg(feature = "host")]
pub use crate::host_side::*;
