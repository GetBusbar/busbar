// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host_vt probe of busbar#262: the real `HOST` (host_vt) of busbar-plugin-abi[host], built in a scratch
//! workspace whose busbar-crypto links the CRYPTO-SEAM stub backend (`crates/busbar-crypto/fixtures/fips_gate/
//! backend.rs`). Not a module of the `cases` binary: `c_unavailable::stub_host_vt` builds it as the `probe` bin
//! and runs it once per arm, with the stub's switches (`BUSBAR_STUB_FILL`, `BUSBAR_STUB_PCT_AFTER`) in its
//! environment. Every call runs inside one entry of `entry::guard` (host_vt answers RNG for everything outside
//! an entry); the probe prints one `key=value` line per answer and the arm compares the whole output.
//!
//! Modes: `random` (C-RANDOM), `self-test` (C-CRYPTO-SELFTEST (a)-(c)), `unavailable` (C-UNAVAILABLE).

use std::sync::atomic::Ordering::Relaxed;

use busbar_plugin_abi::host::{CryptoReq, Hash, HostExt, Key, SignAlg, alg, key_form};
use busbar_plugin_abi::host_side::entry;
use busbar_plugin_abi::host_side::host_vt::{HOST, HOST_FAULTS};
use busbar_plugin_abi::host_side::pool::Pool;
use busbar_plugin_abi::types::Bytes;

/// The slot and entry code the probe's one entry is attributed to (no watch table is installed here).
const SLOT: u32 = 7;
const ENTRY: u8 = 1;

/// `HOST_FAULTS[SELF_TEST]` and `HOST_FAULTS[HOST_PANIC]`.
fn faults() -> (u64, u64) {
    (HOST_FAULTS[0].load(Relaxed), HOST_FAULTS[1].load(Relaxed))
}

/// `status/len` of one raw `random` answer.
fn raw_random(len: usize) -> String {
    let Some(random) = HOST.fns().random else {
        return "none".to_owned();
    };
    HOST.scoped(|ctx| {
        let ret = random(ctx, len);
        format!("{}/{}", ret.status, ret.out.len())
    })
}

/// `status/len` of one raw `crypto` answer.
fn raw_crypto(alg: u32, form: u32, key: &[u8], data: &[u8]) -> String {
    let Some(crypto) = HOST.fns().crypto else {
        return "none".to_owned();
    };
    let req = CryptoReq {
        alg,
        key_form: form,
        param: 0,
        key: Bytes::new(key),
        data: Bytes::new(data),
        aux: Bytes::EMPTY,
        aad: Bytes::EMPTY,
    };
    HOST.scoped(|ctx| {
        let ret = crypto(ctx, &req);
        format!("{}/{}", ret.status, ret.out.len())
    })
}

/// The bytes the arena holds between two HMAC outputs lent around one `random(32)` in the same scope: 0 when
/// `random` lent nothing, 32 when it lent its output. None if either HMAC did not answer OK.
fn arena_gap() -> Option<usize> {
    let crypto = HOST.fns().crypto?;
    let random = HOST.fns().random?;
    let req = CryptoReq {
        alg: alg::HMAC_SHA256,
        key_form: key_form::RAW,
        param: 0,
        key: Bytes::new(b"key"),
        data: Bytes::new(b"message"),
        aux: Bytes::EMPTY,
        aad: Bytes::EMPTY,
    };
    HOST.scoped(|ctx| {
        let before = crypto(ctx, &req);
        let _ = random(ctx, 32);
        let after = crypto(ctx, &req);
        let (b, a) = (before.out.get(), after.out.get());
        if b.is_empty() || a.is_empty() {
            return None;
        }
        a.as_ptr()
            .addr()
            .checked_sub(b.as_ptr().addr().checked_add(b.len())?)
    })
}

/// C-RANDOM: `random` over the stub's `fill`.
fn random() {
    let (_, panics) = faults();
    println!("random={}", raw_random(32));
    println!(
        "random32={:?}",
        HOST.random::<32>().map(|out| out == [0x5a; 32])
    );
    println!(
        "random_vec={:?}",
        HOST.random_vec(32).map(|out| out == [0x5a; 32])
    );
    let mut buf = [0xa5_u8; 32];
    let into = HOST.random_into(&mut buf);
    let held = if buf == [0; 32] {
        "zero"
    } else if buf == [0x5a; 32] {
        "5a"
    } else {
        "other"
    };
    println!("random_into={into:?} buf={held}");
    println!("arena_gap={:?}", arena_gap());
    println!("host_panic={}", faults().1 - panics);
}

/// C-CRYPTO-SELFTEST (a)-(c): `random` first, then HMAC_SHA256 and SIGN_ES256 across the stub's schedule, with
/// the `HOST_FAULTS[SELF_TEST]` delta after each failing answer; then the facade's own `fill` on the same stub.
fn self_test() {
    let (tests, panics) = faults();
    let moved = || faults().0 - tests;
    println!("random={} self_test={}", raw_random(16), moved());
    println!(
        "random16={:?} self_test={}",
        HOST.random::<16>().map(|out| out == [0x5a; 16]),
        moved()
    );
    let hmac = || {
        HOST.hmac(Hash::Sha256, b"key", b"message")
            .map(|mac| mac.as_slice() == [0x5a; 32])
    };
    println!("hmac1={:?}", hmac());
    println!("hmac2={:?}", hmac());
    println!("hmac3={:?} self_test={}", hmac(), moved());
    println!(
        "hmac4={} self_test={}",
        raw_crypto(alg::HMAC_SHA256, key_form::RAW, b"key", b"message"),
        moved()
    );
    let sign = || {
        HOST.sign(SignAlg::Es256, b"pkcs8", b"message")
            .map(|sig| sig == [0x5a; 64])
    };
    println!("sign1={:?}", sign());
    println!("sign2={:?}", sign());
    println!("sign3={:?} self_test={}", sign(), moved());
    println!(
        "sign4={} self_test={}",
        raw_crypto(alg::SIGN_ES256, key_form::PKCS8, b"pkcs8", b"message"),
        moved()
    );
    let mut buf = [0_u8; 16];
    println!("fill_checked={:?}", busbar_crypto::fill_checked(&mut buf));
    println!("fill={:?}", busbar_crypto::fill(&mut buf));
    println!("host_panic={}", faults().1 - panics);
}

/// C-UNAVAILABLE: the deny list through the facade and through host_vt, with HMAC_SHA256 answering OK in the
/// same run (so UNAVAILABLE is the deny list's answer, not every alg's).
fn unavailable() {
    let (tests, panics) = faults();
    println!(
        "supports=md5:{} rsa_oaep_sha1:{} dtls_srtp:{} hmac_key_short:{}",
        busbar_crypto::supports(busbar_crypto::alg::MD5),
        busbar_crypto::supports(busbar_crypto::alg::RSA_OAEP_SHA1),
        busbar_crypto::supports(busbar_crypto::alg::DTLS_SRTP),
        busbar_crypto::supports(busbar_crypto::alg::HMAC_KEY_SHORT),
    );
    let refused = |result: Result<(), busbar_crypto::Error>| match result {
        Err(busbar_crypto::Error::Unsupported(u)) => {
            format!("Unsupported({}, {})", u.alg, u.backend)
        }
        other => format!("{other:?}"),
    };
    println!(
        "facade_md5={}",
        refused(busbar_crypto::legacy::md5(b"password").map(drop))
    );
    println!(
        "facade_oaep={}",
        refused(busbar_crypto::legacy::rsa_oaep_sha1_encrypt(b"spki", b"password").map(drop))
    );
    println!(
        "md5={}",
        raw_crypto(alg::MD5, key_form::RAW, b"", b"password")
    );
    println!(
        "md5_safe={:?}",
        HOST.digest(Hash::Md5, b"password")
            .map(|digest| digest.as_slice().len())
    );
    println!(
        "oaep={}",
        raw_crypto(
            alg::RSA_OAEP_SHA1_ENCRYPT,
            key_form::SPKI_DER,
            b"spki",
            b"password"
        )
    );
    println!(
        "oaep_safe={:?}",
        HOST.rsa_oaep_sha1_encrypt(Key::SpkiDer(b"spki"), b"password")
            .map(|out| out.len())
    );
    println!(
        "hmac={:?}",
        HOST.hmac(Hash::Sha256, b"key", b"message")
            .map(|mac| mac.as_slice() == [0x5a; 32])
    );
    println!(
        "self_test={} host_panic={}",
        faults().0 - tests,
        faults().1 - panics
    );
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    // Outside an entry host_vt answers RNG whatever the backend says.
    println!("outside={}", raw_random(16));
    let mut out = Pool::global().acquire(4096);
    let ran = entry::guard(SLOT, ENTRY, &mut out, |_lease| match mode.as_str() {
        "random" => random(),
        "self-test" => self_test(),
        "unavailable" => unavailable(),
        other => println!("mode={other}?"),
    });
    println!("entry={}", if ran.is_some() { "ran" } else { "refused" });
}
