// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The bodies of the process-wide `Host` vtable (IF §5, §5.2, §10.7; W1-H0): the per-thread scratch arena,
//! `contain`, the one-call-per-request marshalling onto `busbar-crypto`, the fault counters, the deployment id
//! and the log sink.
//!
//! Safe Rust only (owner, 2026-11-15: no `unsafe`). The IF's raw side is left out until the UNSAFE-MIN design
//! settles the boundary, as W0-ABI left it:
//!   pub static HOST: Host;  // IF §10.7: `Host { ctx, now, mono, random, crypto, log, log_level, grow,
//!                           // deployment, migrate_admit }`, each field an `unsafe extern "C" fn` whose body is
//!                           // `contain(FALLBACK, || ..)` over the matching `vt` fn here
//! together with those `extern "C"` entries: reading a `*const CryptoReq` and handing a `random`/`crypto` output
//! back as a `Bytes<'static>` view of this thread's arena both need `unsafe`. `Host`'s raw fields are also
//! W1-A2's, which the WBS orders after this task. `grow` (it rewrites the entry's ACTIVE pool buffer, W1-H1),
//! `log_level` (no source in the IF) and `migrate_admit` (K9's seam, valid only in a store's open chain, which
//! the entry guard knows) land with those pieces.

use core::cell::RefCell;
use core::panic::AssertUnwindSafe;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering::Relaxed;
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use busbar_crypto::{self as crypto, Error};
use zeroize::Zeroize as _;

use crate::host::{CryptoReq, DeploymentId, alg, crypto_status as status, key_form};

/// Round 20: host-side fault counters, `[SELF_TEST, HOST_PANIC, LOG_UNATTRIBUTED]` (indices 0, 1 and, round 24, 2:
/// a log line the sink got with no slot, §10.7 `set_log_sink`), written only on the failure paths (one Relaxed
/// `fetch_add`), read by the registry's watchdog thread every tick (§5.2, I10).
pub static HOST_FAULTS: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
const SELF_TEST: usize = 0;
const HOST_PANIC: usize = 1;

/// The scratch arena's fixed size: 1 MiB + 64 for the whole outermost entry (r4 H3).
const ARENA_CAP: usize = (1 << 20) + 64;
/// The most bytes one `random` call answers.
const RANDOM_MAX: usize = 65_536;
/// PBKDF2's iteration bound (§5 `alg::PBKDF2_HMAC_SHA256`).
const PBKDF2_ITERATIONS: core::ops::RangeInclusive<u32> = 1..=10_000_000;

/// Round 20 (I10): runs `body`, and answers `fallback` if it panics. A caught panic bumps
/// `HOST_FAULTS[HOST_PANIC]` and nothing else: no log call, no allocation here (the payload is dropped).
fn contain<R>(fallback: R, body: impl FnOnce() -> R) -> R {
    #[cfg(feature = "conformance")]
    if conformance::uncontained() {
        return body();
    }
    let run = AssertUnwindSafe(|| {
        #[cfg(any(test, feature = "conformance"))]
        conformance::fire();
        body()
    });
    match std::panic::catch_unwind(run) {
        Ok(answer) => answer,
        Err(_) => {
            HOST_FAULTS[HOST_PANIC].fetch_add(1, Relaxed);
            fallback
        }
    }
}

/// The `conformance` feature (dev-only, like the kernel's; C-PANIC-HOST): the one injection point at the top of
/// `contain`, and the negative control's switch that runs bodies bare.
#[cfg(any(test, feature = "conformance"))]
pub mod conformance {
    use core::cell::Cell;

    std::thread_local! {
        static ARMED: Cell<bool> = const { Cell::new(false) };
    }

    /// The next `contain` on this thread panics once, inside its guarded body.
    pub fn arm_panic() {
        ARMED.with(|armed| armed.set(true));
    }

    pub(super) fn fire() {
        if ARMED.with(|armed| armed.replace(false)) {
            std::panic::resume_unwind(Box::new("C-PANIC-HOST injection"));
        }
    }

    #[cfg(feature = "conformance")]
    static UNCONTAINED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

    /// C-PANIC-HOST's negative control: with `on`, `contain` runs its body bare, so an injected panic unwinds
    /// across `extern "C"` and aborts the process the case runs in.
    #[cfg(feature = "conformance")]
    pub fn set_uncontained(on: bool) {
        UNCONTAINED.store(on, core::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(feature = "conformance")]
    pub(super) fn uncontained() -> bool {
        UNCONTAINED.load(core::sync::atomic::Ordering::Relaxed)
    }
}

/// Per-thread scratch arena for `random` and `crypto` outputs (r4 H3): append-only for the whole outermost entry.
/// Its block is allocated once, lazily on the thread's first output, at the full cap (`vec![0; ..]` is
/// `alloc_zeroed`, so pages never written are never committed) and never grown, so no realloc can free a block
/// holding an earlier output. `used` is the bytes written since the last reset; the outermost entry guard's exit
/// zeroes `[0, used)` (W1-H1's guard wiring), and the thread's exit zeroes it before the free (I11).
struct Arena {
    buf: Vec<u8>,
    used: usize,
}

impl Arena {
    /// `len` fresh bytes after the entry's earlier outputs, or None (LIMIT: written nowhere, earlier outputs
    /// untouched). `used` advances before the output is written, so a write followed by an error or a caught
    /// panic leaves nothing past `used` that the reset would miss; a non-OK answer's span stays reserved.
    fn take(&mut self, len: usize) -> Option<usize> {
        let end = self.used.checked_add(len).filter(|&end| end <= ARENA_CAP)?;
        if self.buf.is_empty() {
            self.buf = vec![0; ARENA_CAP];
        }
        let at = self.used;
        self.used = end;
        Some(at)
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        if let Some(written) = self.buf.get_mut(..self.used) {
            written.zeroize();
        }
    }
}

std::thread_local! {
    static ARENA: RefCell<Arena> = const { RefCell::new(Arena { buf: Vec::new(), used: 0 }) };
}

/// A `random`/`crypto` answer: a `crypto_status` and the span of the calling thread's arena that holds the
/// output (empty on every non-OK status). The raw entry turns it into `CryptoRet`'s `out`; safe code reads it
/// with [`CryptoOut::read`] on the same thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoOut {
    status: u32,
    at: usize,
    len: usize,
}

impl CryptoOut {
    const fn status(status: u32) -> CryptoOut {
        CryptoOut {
            status,
            at: 0,
            len: 0,
        }
    }

    /// The `crypto_status`.
    pub fn crypto_status(self) -> u32 {
        self.status
    }

    pub fn len(self) -> usize {
        self.len
    }

    pub fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Runs `f` over the output bytes in this thread's arena (empty if this thread holds no such span).
    pub fn read<R>(self, f: impl FnOnce(&[u8]) -> R) -> R {
        ARENA.with(|cell| {
            let arena = cell.borrow();
            f(arena
                .buf
                .get(self.at..self.at + self.len)
                .unwrap_or_default())
        })
    }
}

/// The one map from the facade's `Error` to `crypto_status` (§5.2). Round 23: a self-test failure is RNG (a
/// backend failure, never a verdict) and the only arm that moves `HOST_FAULTS[SELF_TEST]`; the backend's text
/// is dropped here.
fn status_of(error: Error) -> u32 {
    match error {
        Error::Mismatch => status::BAD,
        Error::Invalid(_) => status::INVALID,
        Error::Unsupported(_) => status::UNAVAILABLE,
        Error::Rng(_) => status::RNG,
        Error::SelfTest(_) => {
            HOST_FAULTS[SELF_TEST].fetch_add(1, Relaxed);
            status::RNG
        }
    }
}

/// One output of `len` bytes, written by `write` straight into fresh arena space.
fn written(len: usize, write: impl FnOnce(&mut [u8]) -> Result<(), Error>) -> CryptoOut {
    ARENA.with(|cell| {
        let mut arena = cell.borrow_mut();
        let Some(at) = arena.take(len) else {
            return CryptoOut::status(status::LIMIT);
        };
        match write(&mut arena.buf[at..at + len]) {
            Ok(()) => CryptoOut {
                status: status::OK,
                at,
                len,
            },
            Err(error) => CryptoOut::status(status_of(error)),
        }
    })
}

/// A fixed-size output (digest, MAC, signature).
fn fixed<const N: usize>(call: impl FnOnce() -> Result<[u8; N], Error>) -> CryptoOut {
    written(N, |out| {
        out.copy_from_slice(&call()?);
        Ok(())
    })
}

/// An output the facade returns as its own `Vec` (an RSA signature or ciphertext: public bytes).
fn copied(result: Result<Vec<u8>, Error>) -> CryptoOut {
    match result {
        Ok(bytes) => written(bytes.len(), |out| {
            out.copy_from_slice(&bytes);
            Ok(())
        }),
        Err(error) => CryptoOut::status(status_of(error)),
    }
}

/// A verification: OK or BAD, no output.
fn verified(result: Result<(), Error>) -> CryptoOut {
    CryptoOut::status(result.map_or_else(status_of, |()| status::OK))
}

/// A `CryptoReq` with its views read.
struct Req<'a> {
    alg: u32,
    key_form: u32,
    param: u64,
    key: &'a [u8],
    data: &'a [u8],
    aux: &'a [u8],
    aad: &'a [u8],
}

/// One crypto operation: exactly one `busbar-crypto` call per request (§5.2 table). A `key_form` not listed for
/// the alg, or an alg number §5 does not define, is INVALID before any call. No DER, PEM or JWK parsing and no
/// block-mode or MAC construction here: an RSA_COMPONENTS key is split at its length prefix, nothing more.
fn crypto_body(r: &Req<'_>) -> CryptoOut {
    use crypto::rsa::Scheme;
    use key_form::{EC_POINT, PKCS8, RAW, RSA_COMPONENTS, RSA_PKCS1_DER, SPKI_DER};
    let forms: &[u32] = match r.alg {
        alg::SHA256 | alg::SHA384 | alg::SHA512 | alg::SHA1 | alg::MD5 => &[],
        alg::HMAC_SHA256 | alg::HMAC_SHA384 | alg::HMAC_SHA512 | alg::HMAC_SHA1 => &[RAW],
        alg::PBKDF2_HMAC_SHA256 | alg::AES_CTR => &[RAW],
        alg::AEAD_SEAL | alg::AEAD_OPEN | alg::AEAD_SEAL_EXPLICIT => &[RAW],
        alg::VERIFY_RS256
        | alg::VERIFY_RS384
        | alg::VERIFY_RS512
        | alg::VERIFY_PS256
        | alg::VERIFY_PS384
        | alg::VERIFY_PS512 => &[RSA_COMPONENTS, RSA_PKCS1_DER, SPKI_DER],
        alg::VERIFY_ES256 | alg::VERIFY_ES384 => &[EC_POINT, SPKI_DER],
        alg::VERIFY_ED25519 => &[RAW, SPKI_DER],
        alg::SIGN_RS256 | alg::SIGN_ES256 | alg::SIGN_ED25519 => &[PKCS8],
        alg::RSA_OAEP_SHA1_ENCRYPT => &[SPKI_DER],
        _ => return CryptoOut::status(status::INVALID),
    };
    if !forms.is_empty() && !forms.contains(&r.key_form) {
        return CryptoOut::status(status::INVALID);
    }
    match r.alg {
        alg::SHA256 => fixed(|| Ok(crypto::sha256(r.data))),
        alg::SHA384 => fixed(|| Ok(crypto::sha384(r.data))),
        alg::SHA512 => fixed(|| Ok(crypto::sha512(r.data))),
        alg::SHA1 => fixed(|| crypto::legacy::sha1(r.data)),
        alg::MD5 => fixed(|| crypto::legacy::md5(r.data)),
        alg::HMAC_SHA256 => fixed(|| crypto::hmac_sha256(r.key, r.data)),
        alg::HMAC_SHA384 => fixed(|| crypto::hmac_sha384(r.key, r.data)),
        alg::HMAC_SHA512 => fixed(|| crypto::hmac_sha512(r.key, r.data)),
        alg::HMAC_SHA1 => fixed(|| crypto::legacy::hmac_sha1(r.key, r.data)),
        alg::PBKDF2_HMAC_SHA256 => match u32::try_from(r.param) {
            Ok(iterations) if PBKDF2_ITERATIONS.contains(&iterations) => written(32, |out| {
                crypto::pbkdf2_hmac_sha256(r.key, r.data, iterations, out)
            }),
            _ => CryptoOut::status(status::INVALID),
        },
        alg::VERIFY_RS256 => rsa_verify(Scheme::Pkcs1Sha256, r),
        alg::VERIFY_RS384 => rsa_verify(Scheme::Pkcs1Sha384, r),
        alg::VERIFY_RS512 => rsa_verify(Scheme::Pkcs1Sha512, r),
        alg::VERIFY_PS256 => rsa_verify(Scheme::PssSha256, r),
        alg::VERIFY_PS384 => rsa_verify(Scheme::PssSha384, r),
        alg::VERIFY_PS512 => rsa_verify(Scheme::PssSha512, r),
        alg::VERIFY_ES256 => verified(if r.key_form == EC_POINT {
            crypto::ecdsa_p256::verify_fixed(r.key, r.data, r.aux)
        } else {
            crypto::ecdsa_p256::verify_fixed_spki(r.key, r.data, r.aux)
        }),
        alg::VERIFY_ES384 => verified(if r.key_form == EC_POINT {
            crypto::ecdsa_p384::verify_fixed(r.key, r.data, r.aux)
        } else {
            crypto::ecdsa_p384::verify_fixed_spki(r.key, r.data, r.aux)
        }),
        alg::VERIFY_ED25519 => verified(ed25519_verify(r)),
        alg::SIGN_RS256 => copied(crypto::rsa::sign_pkcs1_sha256(r.key, r.data)),
        alg::SIGN_ES256 => fixed(|| crypto::ecdsa_p256::from_pkcs8(r.key)?.sign_fixed(r.data)),
        alg::SIGN_ED25519 => {
            fixed(|| Ok(crypto::ed25519::SigningKey::from_pkcs8(r.key)?.sign(r.data)))
        }
        alg::AEAD_SEAL => aead_seal(r),
        alg::AEAD_OPEN => aead_open(r),
        alg::AEAD_SEAL_EXPLICIT => aead_seal_explicit(r),
        alg::AES_CTR => match <&[u8; 16]>::try_from(r.aux) {
            Ok(iv) => written(r.data.len(), |out| {
                crypto::aes_ctr::apply(r.key, iv, r.data, out)
            }),
            Err(_) => CryptoOut::status(status::INVALID),
        },
        alg::RSA_OAEP_SHA1_ENCRYPT => copied(crypto::legacy::rsa_oaep_sha1_encrypt(r.key, r.data)),
        _ => CryptoOut::status(status::INVALID),
    }
}

fn rsa_verify(scheme: crypto::rsa::Scheme, r: &Req<'_>) -> CryptoOut {
    verified(match r.key_form {
        key_form::RSA_COMPONENTS => match rsa_components(r.key) {
            Some((n, e)) => crypto::rsa::verify_components(scheme, n, e, r.data, r.aux),
            None => return CryptoOut::status(status::INVALID),
        },
        key_form::RSA_PKCS1_DER => crypto::rsa::verify(scheme, r.key, r.data, r.aux),
        _ => crypto::rsa::verify_spki(scheme, r.key, r.data, r.aux),
    })
}

/// `u32 LE n_len, n, e` (§5 `key_form::RSA_COMPONENTS`), both non-empty.
fn rsa_components(key: &[u8]) -> Option<(&[u8], &[u8])> {
    let (n_len, rest) = key.split_first_chunk::<4>()?;
    let (n, e) = rest.split_at_checked(usize::try_from(u32::from_le_bytes(*n_len)).ok()?)?;
    (!n.is_empty() && !e.is_empty()).then_some((n, e))
}

fn ed25519_verify(r: &Req<'_>) -> Result<(), Error> {
    let signature =
        <&[u8; 64]>::try_from(r.aux).map_err(|_| Error::Invalid("Ed25519 signature length"))?;
    let key = if r.key_form == key_form::RAW {
        let raw = <&[u8; 32]>::try_from(r.key).map_err(|_| Error::Invalid("Ed25519 key length"))?;
        crypto::ed25519::VerifyingKey::from_bytes(raw)?
    } else {
        crypto::ed25519::VerifyingKey::from_spki(r.key)?
    };
    key.verify_strict(r.data, signature)
}

/// AES-GCM under a 16- or 32-byte key.
enum Gcm {
    A128(crypto::Aes128Gcm),
    A256(crypto::Aes256Gcm),
}

impl Gcm {
    fn new(key: &[u8]) -> Result<Gcm, Error> {
        if let Ok(key) = <&[u8; 16]>::try_from(key) {
            return crypto::Aes128Gcm::new(key).map(Gcm::A128);
        }
        let key = <&[u8; 32]>::try_from(key).map_err(|_| Error::Invalid("AES-GCM key length"))?;
        crypto::Aes256Gcm::new(key).map(Gcm::A256)
    }
}

/// AEAD_SEAL: the module's nonce. Out = nonce(12) || ciphertext || tag(16).
fn aead_seal(r: &Req<'_>) -> CryptoOut {
    if !r.aux.is_empty() {
        return CryptoOut::status(status::INVALID);
    }
    let gcm = match Gcm::new(r.key) {
        Ok(gcm) => gcm,
        Err(error) => return CryptoOut::status(status_of(error)),
    };
    let Some(len) = r.data.len().checked_add(12 + 16) else {
        return CryptoOut::status(status::LIMIT);
    };
    written(len, |out| {
        let (nonce_out, rest) = out.split_at_mut(12);
        let (body, tag_out) = rest.split_at_mut(r.data.len());
        body.copy_from_slice(r.data);
        let (nonce, tag) = match &gcm {
            Gcm::A128(gcm) => gcm.seal_random_nonce(r.aad, body)?,
            Gcm::A256(gcm) => gcm.seal_random_nonce(r.aad, body)?,
        };
        nonce_out.copy_from_slice(&nonce);
        tag_out.copy_from_slice(&tag);
        Ok(())
    })
}

/// AEAD_OPEN: aux = 12-byte nonce, data = ciphertext || tag. Out = plaintext (zeroed by the arena rule, I11).
fn aead_open(r: &Req<'_>) -> CryptoOut {
    let Ok(nonce) = <&[u8; 12]>::try_from(r.aux) else {
        return CryptoOut::status(status::INVALID);
    };
    let Some((sealed, tag)) = r.data.split_last_chunk::<16>() else {
        return CryptoOut::status(status::INVALID);
    };
    let gcm = match Gcm::new(r.key) {
        Ok(gcm) => gcm,
        Err(error) => return CryptoOut::status(status_of(error)),
    };
    written(sealed.len(), |out| {
        out.copy_from_slice(sealed);
        match &gcm {
            Gcm::A128(gcm) => gcm.open_in_place(nonce, r.aad, out, tag),
            Gcm::A256(gcm) => gcm.open_in_place(nonce, r.aad, out, tag),
        }
    })
}

/// AEAD_SEAL_EXPLICIT: aux = 12-byte nonce, data = plaintext. Out = ciphertext || tag.
fn aead_seal_explicit(r: &Req<'_>) -> CryptoOut {
    let Ok(nonce) = <&[u8; 12]>::try_from(r.aux) else {
        return CryptoOut::status(status::INVALID);
    };
    let gcm = match Gcm::new(r.key) {
        Ok(gcm) => gcm,
        Err(error) => return CryptoOut::status(status_of(error)),
    };
    let Some(len) = r.data.len().checked_add(16) else {
        return CryptoOut::status(status::LIMIT);
    };
    written(len, |out| {
        let (body, tag_out) = out.split_at_mut(r.data.len());
        body.copy_from_slice(r.data);
        let tag = match &gcm {
            Gcm::A128(gcm) => gcm.seal_in_place(nonce, r.aad, body)?,
            Gcm::A256(gcm) => gcm.seal_in_place(nonce, r.aad, body)?,
        };
        tag_out.copy_from_slice(&tag);
        Ok(())
    })
}

/// `len` (1..=65,536) random bytes through `fill_checked` (round 21: the backend's error through the facade's
/// `map`, so a failed self-test is counted and audited like every other crypto call).
fn random_body(len: usize) -> CryptoOut {
    if len == 0 || len > RANDOM_MAX {
        return CryptoOut::status(status::INVALID);
    }
    written(len, crypto::fill_checked)
}

/// UTC nanoseconds since the Unix epoch, from the host clock.
fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_nanos()).unwrap_or(u64::MAX)
        })
}

/// Monotonic nanoseconds since the process's first reading: the one clock WAKE_AT is stated in.
pub(crate) fn mono_ns() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    u64::try_from(EPOCH.get_or_init(Instant::now).elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// Round 29: the deployment id, published once with all 16 bytes.
static DEPLOYMENT: OnceLock<DeploymentId> = OnceLock::new();

/// Round 28: the deployment id `Host::deployment` answers. **Round 29: held as one
/// `static DEPLOYMENT: OnceLock<DeploymentId>`** (round 28's two `AtomicU64` with two Relaxed loads could be read
/// torn by a step-2a/2b instance on another thread: one word set, the other still 0, which `deployment_id()` would
/// have returned as `Some` of a half-written id). `set_deployment` is `DEPLOYMENT.set(DeploymentId(id))` (release
/// publication of all 16 bytes at once); `deployment`'s body is `*DEPLOYMENT.get().unwrap_or(&DeploymentId([0; 16]))`
/// under `contain` (one Acquire load, no lock on the read path, no allocation). An all-zero `id` is refused by a
/// debug assert and not stored. Called once by L2's `BootPlan` right after step 2b, with the id the kernel's boot
/// identity read or wrote (boot_identity.rs keep-once pattern, `busbar.deployment.v1`/`id`; K-side, ADMIN-API-1.6
/// AR-01), before the step-2a/2b re-check and before any step-2c instance is migrated or opened (§11.2); a second
/// call with a different id panics in debug and is ignored in release (the row is keep-once).
pub fn set_deployment(id: [u8; 16]) {
    debug_assert!(
        id != [0; 16],
        "set_deployment: an all-zero id is not a deployment id"
    );
    if id == [0; 16] {
        return;
    }
    let kept = DEPLOYMENT.get_or_init(|| DeploymentId(id));
    debug_assert!(
        kept.0 == id,
        "set_deployment: a second, different id (the row is keep-once)"
    );
}

fn deployment_body() -> DeploymentId {
    DEPLOYMENT.get().copied().unwrap_or(DeploymentId([0; 16]))
}

/// The installed log sink (`set_log_sink`, once).
type LogSink = fn(slot: Option<u32>, level: u32, error: u32, msg: &str);
static SINK: OnceLock<LogSink> = OnceLock::new();

/// Where `Host::log` lines go. The registry installs it once (`Registry::new`; a later call is ignored): it maps the slot from
/// `watch::current_slot()` to the **slot record** (round 8: never to an `Instance`; the record holds kind,
/// configured name and `Arc<Scrub>` and lives from slot allocation until its lease is released after close or
/// after the last cancel of an Image-owned chain), runs `record.scrub.text(msg)` (§12.16; round 17: 2 RMWs on the
/// thread's own arc-swap debt slot per line, I5's fourth stated exception, and never a free) and emits the scrubbed
/// line attributed to (`kind`, `instance` = configured name) — operator vocabulary only, never the stamp name
/// except inside a core-written code (round 34, I2's exception: `plugin_diag` and the joined text that starts
/// with it), so the line can go to STREAM_LOGS exporters unchanged (I2, round 6). **Round 34
/// (PLUGIN-ERROR-CODES):** the sink gets `log`'s `error` as the raw `u32` and resolves it through the slot
/// record's `ErrorBook` (§11.2 `ErrorBook::resolve`): 0 = no code; above 9999 (checked as a `u32`, before any
/// narrowing, so 65,607 never becomes 71) or not in the book = not declared (no code, one WARN per slot via the
/// record's latch); a refused book = no code, no WARN; else the code. The emitted line carries `kind`,
/// `instance`, `plugin_diag` (only when there is a code) and `text`: a plain `&str` field, never `message` and never
/// `%`/`?`, holding the scrubbed line, or with a code the joined `"{code}: {text}"` written into a fixed stack buffer
/// (≤ 76 + 2 + 512 bytes, no allocation); §12.16 states the quoting rule. A describe-time line renders no code and
/// no WARN (the book does not exist yet). No rate cap: GetBusbar/busbar #241. An Image-owned entry (describe, migrate, open)
/// attributes to the instance-to-be's configured name (describe: `kind` only). Before installation, or outside an
/// entry, lines are dropped. **Round 24, normative:** the sink gets `None` only outside an entry (every guard sets
/// `OWNER`, watched or not); a `None` line, or a slot whose record is already gone, is dropped and counted
/// (`HOST_FAULTS[LOG_UNATTRIBUTED]`, metric `plugin_host_fault_total{fault="log_unattributed"}`), **never emitted
/// unscrubbed** (I14). Round 20: the sink runs inside `log`'s `contain`; a panicking sink drops that line
/// and counts one `HOST_PANIC`, never an abort.
pub fn set_log_sink(sink: fn(slot: Option<u32>, level: u32, error: u32, msg: &str)) {
    let _ = SINK.set(sink);
}

/// `log`'s body: the line, its level and its raw `error` (round 34: unchanged, never narrowed) go to the sink
/// with the slot of the entry running on this thread.
fn log_body(level: u32, error: u32, msg: &str) {
    if let Some(sink) = SINK.get() {
        sink(super::entry::owner(), level, error, msg);
    }
}

/// The bodies of `Host`'s fields, in safe Rust, each inside `contain` (I10): `crypto` and `random` answer RNG with
/// an empty output (round 24: the safe layer's `Err(Rng)`, FAILED, never REFUSED), `now`/`mono` 0, `deployment`
/// all zero, and `log` drops the line. The raw `extern "C"` entries `HOST` points at wrap these one to one; they
/// and `HOST` wait for UNSAFE-MIN (module doc).
pub mod vt {
    use super::*;

    const RNG: CryptoOut = CryptoOut::status(status::RNG);

    pub fn now() -> u64 {
        contain(0, now_ns)
    }

    pub fn mono() -> u64 {
        contain(0, mono_ns)
    }

    pub fn random(len: usize) -> CryptoOut {
        contain(RNG, || random_body(len))
    }

    pub fn crypto(req: &CryptoReq<'_>) -> CryptoOut {
        contain(RNG, || {
            crypto_body(&Req {
                alg: req.alg,
                key_form: req.key_form,
                param: req.param,
                key: req.key.get(),
                data: req.data.get(),
                aux: req.aux.get(),
                aad: req.aad.get(),
            })
        })
    }

    /// Round 34: `error` reaches the sink as the raw `u32` it arrived as.
    pub fn log(level: u32, error: u32, msg: &str) {
        contain((), || log_body(level, error, msg));
    }

    pub fn deployment() -> DeploymentId {
        contain(DeploymentId([0; 16]), deployment_body)
    }
}

#[cfg(test)]
mod tests {
    //! The H0 arms of C-CRYPTO-SELFTEST, C-RANDOM, C-PANIC-HOST, C-DEPLOYMENT-ID (e) and the C-HEADER arena
    //! arm (IF §5, §5.2, §10.7, §14), over the bodies `HOST` points at.

    use super::*;
    use core::cell::Cell;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    fn req<'a>(alg: u32, key_form: u32, key: &'a [u8], data: &'a [u8], aux: &'a [u8]) -> Req<'a> {
        Req {
            alg,
            key_form,
            param: 0,
            key,
            data,
            aux,
            aad: b"",
        }
    }

    /// The bytes of an answer, read back from this thread's arena.
    fn bytes(out: CryptoOut) -> Vec<u8> {
        assert_eq!(out.status, status::OK, "{out:?}");
        ARENA.with(|cell| cell.borrow().buf[out.at..out.at + out.len].to_vec())
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn faults(index: usize) -> u64 {
        HOST_FAULTS[index].load(Relaxed)
    }

    /// Runs `f` on a fresh thread, so it starts with an empty arena.
    fn fresh<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> R {
        std::thread::spawn(f).join().expect("test thread")
    }

    #[test]
    fn c_crypto_selftest_answers_rng_and_counts_only_the_self_test() {
        let before = faults(SELF_TEST);
        assert_eq!(status_of(Error::SelfTest("pct")), status::RNG);
        assert_eq!(faults(SELF_TEST), before + 1);
        assert_eq!(status_of(Error::Rng(crypto::RngError)), status::RNG);
        assert_eq!(status_of(Error::Mismatch), status::BAD);
        assert_eq!(status_of(Error::Invalid("x")), status::INVALID);
        let refused = crypto::Unsupported {
            alg: "HMAC-SHA384",
            backend: crypto::BACKEND,
            reason: "test",
        };
        assert_eq!(status_of(Error::Unsupported(refused)), status::UNAVAILABLE);
        assert_eq!(
            faults(SELF_TEST),
            before + 1,
            "only SelfTest moves the counter"
        );

        // The mapping has no panic path, and `random` reaches the backend through `fill_checked` alone.
        let source = include_str!("host_vt.rs");
        let production = &source[..source.find("#[cfg(test)]\nmod tests").expect("test module")];
        for banned in ["unreachable!(", "panic!(", ".expect(", "crypto::fill("] {
            assert!(!production.contains(banned), "host_vt.rs holds {banned}");
        }
        assert!(production.contains("crypto::fill_checked"));
    }

    #[test]
    fn c_header_arena_outputs_are_append_only_and_intact() {
        fresh(|| {
            let kat = unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
            let first = crypto_body(&req(
                alg::HMAC_SHA256,
                key_form::RAW,
                b"Jefe",
                b"what do ya want for nothing?",
                b"",
            ));
            let second = crypto_body(&req(
                alg::HMAC_SHA256,
                key_form::RAW,
                b"Jefe",
                b"provided",
                b"",
            ));
            assert!(first.at + first.len <= second.at, "{first:?} {second:?}");
            assert_eq!(bytes(first), kat);
            assert_ne!(bytes(second), kat);
            let random = random_body(64);
            assert!(second.at + second.len <= random.at);
            assert_eq!(
                bytes(first),
                kat,
                "the first output is intact after two more"
            );

            // Filling to the cap: the output that does not fit is LIMIT, written nowhere; earlier outputs stay.
            let mut last = random;
            while let Some(next) = Some(random_body(RANDOM_MAX)).filter(|o| o.status == status::OK)
            {
                last = next;
            }
            assert_eq!(random_body(RANDOM_MAX), CryptoOut::status(status::LIMIT));
            let room = ARENA_CAP - (last.at + last.len);
            assert_eq!(random_body(room + 1), CryptoOut::status(status::LIMIT));
            if room > 0 {
                assert_eq!(random_body(room).status, status::OK);
            }
            assert_eq!(random_body(1), CryptoOut::status(status::LIMIT));
            assert_eq!(bytes(first), kat);
            let limit = vt::random(1);
            assert_eq!((limit.crypto_status(), limit.len()), (status::LIMIT, 0));
        });
    }

    #[test]
    fn c_random_bounds_and_distinct_outputs() {
        fresh(|| {
            assert_eq!(random_body(0), CryptoOut::status(status::INVALID));
            assert_eq!(
                random_body(RANDOM_MAX + 1),
                CryptoOut::status(status::INVALID)
            );
            let (a, b) = (random_body(32), random_body(32));
            assert_ne!(bytes(a), bytes(b));
            assert_ne!(bytes(a), [0; 32]);
            let raw = vt::random(16);
            assert_eq!((raw.crypto_status(), raw.len()), (status::OK, 16));
            assert_eq!(raw.read(<[u8]>::len), 16);
            let refused = vt::random(0);
            assert_eq!(
                (refused.crypto_status(), refused.len()),
                (status::INVALID, 0)
            );
        });
    }

    #[test]
    fn crypto_key_forms_and_parameters_are_checked_before_any_call() {
        let invalid = CryptoOut::status(status::INVALID);
        let k16 = [7_u8; 16];
        for (alg, form, key, aux) in [
            (alg::HMAC_SHA256, key_form::SPKI_DER, &k16[..], &[][..]),
            (alg::SIGN_ES256, key_form::RAW, &k16[..], &[][..]),
            (alg::VERIFY_ES256, key_form::RAW, &k16[..], &[0; 64][..]),
            (
                alg::RSA_OAEP_SHA1_ENCRYPT,
                key_form::RSA_PKCS1_DER,
                &k16[..],
                &[][..],
            ),
            (7, key_form::RAW, &k16[..], &[][..]),
            (alg::AEAD_SEAL, key_form::RAW, &[1_u8; 20][..], &[][..]),
            (alg::AEAD_SEAL, key_form::RAW, &k16[..], &[0; 12][..]),
            (alg::AEAD_OPEN, key_form::RAW, &k16[..], &[0; 12][..]),
            (alg::AEAD_OPEN, key_form::RAW, &k16[..], &[0; 11][..]),
            (alg::AES_CTR, key_form::RAW, &k16[..], &[0; 15][..]),
            (
                alg::VERIFY_ED25519,
                key_form::RAW,
                &[0; 32][..],
                &[0; 63][..],
            ),
            (
                alg::VERIFY_RS256,
                key_form::RSA_COMPONENTS,
                &[9, 0, 0, 0, 1][..],
                &[][..],
            ),
        ] {
            assert_eq!(
                crypto_body(&req(alg, form, key, b"short", aux)),
                invalid,
                "alg {alg}"
            );
        }
        for iterations in [0, 10_000_001, u64::MAX] {
            let mut r = req(
                alg::PBKDF2_HMAC_SHA256,
                key_form::RAW,
                b"password",
                b"salt",
                b"",
            );
            r.param = iterations;
            assert_eq!(crypto_body(&r), invalid);
        }
        assert_eq!(
            rsa_components(&[1, 0, 0, 0, 0xab, 1, 0, 1]),
            Some((&[0xab][..], &[1, 0, 1][..]))
        );
        assert_eq!(rsa_components(&[2, 0, 0, 0, 0xab, 0xcd]), None);
    }

    #[test]
    fn crypto_round_trips_through_the_facade() {
        fresh(|| {
            let sha = crypto_body(&req(alg::SHA256, key_form::RAW, b"", b"abc", b""));
            assert_eq!(
                bytes(sha),
                unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            );
            let mut r = req(
                alg::PBKDF2_HMAC_SHA256,
                key_form::RAW,
                b"password",
                b"salt",
                b"",
            );
            r.param = 1;
            assert_eq!(
                bytes(crypto_body(&r)),
                unhex("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
            );

            // AEAD: seal, open, tamper.
            let key = [3_u8; 32];
            let sealed = bytes(crypto_body(&req(
                alg::AEAD_SEAL,
                key_form::RAW,
                &key,
                b"plain text",
                b"",
            )));
            assert_eq!(sealed.len(), 12 + 10 + 16);
            let (nonce, body) = sealed.split_at(12);
            let opened = crypto_body(&req(alg::AEAD_OPEN, key_form::RAW, &key, body, nonce));
            assert_eq!(bytes(opened), b"plain text");
            let mut bad = body.to_vec();
            bad[0] ^= 1;
            let refused = crypto_body(&req(alg::AEAD_OPEN, key_form::RAW, &key, &bad, nonce));
            assert_eq!(refused, CryptoOut::status(status::BAD));
            let explicit = bytes(crypto_body(&req(
                alg::AEAD_SEAL_EXPLICIT,
                key_form::RAW,
                &[4; 16],
                b"srtp",
                &[9; 12],
            )));
            let back = crypto_body(&req(
                alg::AEAD_OPEN,
                key_form::RAW,
                &[4; 16],
                &explicit,
                &[9; 12],
            ));
            assert_eq!(bytes(back), b"srtp");

            // AES-CTR is its own inverse.
            let once = bytes(crypto_body(&req(
                alg::AES_CTR,
                key_form::RAW,
                &[5; 16],
                b"counter mode",
                &[0; 16],
            )));
            let twice = crypto_body(&req(alg::AES_CTR, key_form::RAW, &[5; 16], &once, &[0; 16]));
            assert_eq!(bytes(twice), b"counter mode");

            // Sign and verify: P-256 from PKCS#8, Ed25519 from a raw public key.
            let pkcs8 = crypto::ecdsa_p256::generate_pkcs8().expect("P-256 key");
            let point = crypto::ecdsa_p256::from_pkcs8(&pkcs8)
                .expect("P-256 key")
                .public_key();
            let sig = bytes(crypto_body(&req(
                alg::SIGN_ES256,
                key_form::PKCS8,
                &pkcs8,
                b"msg",
                b"",
            )));
            let ok = crypto_body(&req(
                alg::VERIFY_ES256,
                key_form::EC_POINT,
                &point,
                b"msg",
                &sig,
            ));
            assert_eq!(ok, CryptoOut::status(status::OK));
            let no = crypto_body(&req(
                alg::VERIFY_ES256,
                key_form::EC_POINT,
                &point,
                b"msh",
                &sig,
            ));
            assert_eq!(no, CryptoOut::status(status::BAD));
            let ed = crypto::ed25519::SigningKey::generate().expect("Ed25519 key");
            let public = ed.verifying_key().to_bytes();
            let signature = ed.sign(b"msg");
            let ok = crypto_body(&req(
                alg::VERIFY_ED25519,
                key_form::RAW,
                &public,
                b"msg",
                &signature,
            ));
            assert_eq!(ok, CryptoOut::status(status::OK));
            let no = crypto_body(&req(
                alg::VERIFY_ED25519,
                key_form::RAW,
                &public,
                b"msh",
                &signature,
            ));
            assert_eq!(no, CryptoOut::status(status::BAD));
        });
    }

    std::thread_local! {
        static SEEN: Cell<Option<(Option<u32>, u32, u32, usize)>> = const { Cell::new(None) };
        static SINK_PANICS: Cell<bool> = const { Cell::new(false) };
    }

    fn test_sink(slot: Option<u32>, level: u32, error: u32, msg: &str) {
        if SINK_PANICS.with(Cell::get) {
            panic!("sink failure");
        }
        SEEN.with(|seen| seen.set(Some((slot, level, error, msg.len()))));
    }

    #[test]
    fn c_panic_host_every_body_answers_its_fallback() {
        fresh(|| {
            let before = faults(HOST_PANIC);
            conformance::arm_panic();
            assert_eq!(vt::now(), 0);
            conformance::arm_panic();
            assert_eq!(vt::mono(), 0);
            conformance::arm_panic();
            let random = vt::random(16);
            assert_eq!((random.crypto_status(), random.len()), (status::RNG, 0));
            conformance::arm_panic();
            assert_eq!(vt::deployment(), DeploymentId([0; 16]));
            conformance::arm_panic();
            vt::log(3, 0, "dropped");
            assert_eq!(faults(HOST_PANIC), before + 5);
            assert!(vt::now() > 1_600_000_000_000_000_000);
            assert_eq!(
                faults(HOST_PANIC),
                before + 5,
                "an armed injection fires once"
            );

            // A sink that panics: the line is dropped and one HOST_PANIC counted, never an unwind.
            set_log_sink(test_sink);
            SINK_PANICS.with(|p| p.set(true));
            contain((), || log_body(1, 0, "line"));
            assert_eq!(faults(HOST_PANIC), before + 6);
            SINK_PANICS.with(|p| p.set(false));
        });
    }

    #[test]
    fn log_lines_reach_the_sink_with_the_raw_error_and_no_slot_outside_an_entry() {
        fresh(|| {
            set_log_sink(test_sink);
            log_body(2, 65_607, "four");
            assert_eq!(SEEN.with(Cell::get), Some((None, 2, 65_607, 4)));
        });
    }

    #[test]
    fn mono_never_goes_back() {
        let a = vt::mono();
        let b = vt::mono();
        assert!(b >= a);
    }

    #[test]
    fn c_deployment_id_is_read_all_zero_or_whole() {
        assert_eq!(vt::deployment(), DeploymentId([0; 16]));
        if cfg!(debug_assertions) {
            assert!(std::panic::catch_unwind(|| set_deployment([0; 16])).is_err());
        }
        assert_eq!(
            deployment_body(),
            DeploymentId([0; 16]),
            "an all-zero id is not stored"
        );

        let id = [0xa5_u8; 16];
        let stop = Arc::new(AtomicBool::new(false));
        let readers: Vec<_> = (0..8)
            .map(|_| {
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let mut torn = 0_usize;
                    let mut reads = 0_usize;
                    while reads < 125_000 || !stop.load(Relaxed) {
                        let seen = vt::deployment().0;
                        torn += usize::from(seen != [0; 16] && seen != id);
                        reads += 1;
                    }
                    torn
                })
            })
            .collect();
        set_deployment(id);
        stop.store(true, Relaxed);
        for reader in readers {
            assert_eq!(reader.join().expect("reader"), 0);
        }
        assert_eq!(vt::deployment(), DeploymentId(id));
        set_deployment(id);
        if cfg!(debug_assertions) {
            assert!(std::panic::catch_unwind(|| set_deployment([1; 16])).is_err());
        }
        assert_eq!(deployment_body(), DeploymentId(id), "keep-once");
    }
}
