// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CRYPTO-SELFTEST (ABI-MIN3-INTERFACE §14 rounds 20, 21, 23). The two source arms over `host_vt.rs` are
//! W1-H0's (merged). Everything run against the stub backend needs A2's `HOST` and safe layer, so it is not H0's
//! (W1-H0 handoff, design hole 1): arms (a)-(c) are W1-A2's; the audit row and metric are the registry
//! watchdog's (W1-L2); (e), the refusal path through the ports, `RefusalMap` and `RetryPolicy`, is the last of
//! its writers (W1-K8D); (f) goes through the auth adapter (W1-L5).
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use std::sync::Mutex;

use busbar_plugin_abi::fail::{failed, Fail};
use busbar_plugin_abi::host::{
    alg, crypto_status, CryptoErr, CryptoReq, CryptoRet, Ctx, Hash, Host, HostExt, HostFns, SignAlg,
};
use busbar_plugin_abi::types::Status;

fn host_vt() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../busbar-plugin-abi/src/host_side/host_vt.rs"
    );
    let source = std::fs::read_to_string(path).expect("host_vt.rs");
    // The production half: the file's own test module names the banned words it checks for.
    let end = source
        .find("#[cfg(test)]\nmod tests")
        .expect("the test module");
    source[..end].to_owned()
}

/// Round 21 (d): `random` goes through `fill_checked`, never the facade's bare `fill`.
#[test]
fn random_goes_through_fill_checked() {
    let source = host_vt();
    assert!(source.contains("fill_checked"));
    assert!(!source.contains("busbar_crypto::fill("));
    assert!(!source.contains("crypto::fill("));
}

/// The status map has no panic path.
#[test]
fn the_status_map_has_no_panic_path() {
    let source = host_vt();
    let start = source.find("fn status_of(").expect("the status map");
    let map = &source[start..];
    let map = &map[..map.find("\n}\n").expect("its end")];
    assert!(map.contains("SelfTest"));
    for bad in ["unreachable!", "panic!", ".expect("] {
        assert!(!map.contains(bad), "{bad} in the status map");
    }
}

static ASKED: Mutex<Vec<u32>> = Mutex::new(Vec::new());

/// What host_vt's `random` answers while the backend is in its self-test failure state (§5.2 round 23).
extern "C" fn failed_random(ctx: Ctx<'_>, _len: usize) -> CryptoRet<'_> {
    CryptoRet::empty(ctx, crypto_status::RNG)
}

/// What host_vt's `crypto` answers then for any alg: RNG with `out` EMPTY. The algs asked are recorded.
extern "C" fn failed_crypto<'e>(ctx: Ctx<'e>, req: &CryptoReq<'_>) -> CryptoRet<'e> {
    if let Ok(mut asked) = ASKED.lock() {
        asked.push(req.alg);
    }
    CryptoRet::empty(ctx, crypto_status::RNG)
}

static SELF_TEST: Host = Host::new(
    0,
    HostFns {
        now: None,
        mono: None,
        random: Some(failed_random),
        crypto: Some(failed_crypto),
        log: None,
        log_level: None,
        grow: None,
        deployment: None,
        migrate_admit: None,
    },
);

/// Arms (a)-(c), the plugin-facing half: `random` first, then `crypto(HMAC_SHA256)` and `crypto(SIGN_ES256)`, each
/// RNG with `out` EMPTY, reach the plugin as `Err(Rng)` with no panic and no zero-filled value, and the plugin's `?`
/// is FAILED F_UNAVAILABLE (retried or rerouted by core), never a REFUSED verdict and never a fault. host_vt's
/// half (SelfTest -> RNG, `HOST_FAULTS[SELF_TEST]`) is H0's `status_of`, checked by the source arms above.
#[test]
fn self_test_answers_rng_with_empty_out_and_no_fault() {
    assert_eq!(SELF_TEST.random::<16>(), Err(CryptoErr::Rng));
    let mac = SELF_TEST.hmac(Hash::Sha256, b"key", b"message");
    assert_eq!(mac.err(), Some(CryptoErr::Rng));
    let signed = SELF_TEST.sign(SignAlg::Es256, b"pkcs8", b"message");
    assert_eq!(signed, Err(CryptoErr::Rng));
    let asked = ASKED.lock().map(|asked| asked.clone()).unwrap_or_default();
    assert_eq!(asked, [alg::HMAC_SHA256, alg::SIGN_ES256]);
    let fail = Fail::from(CryptoErr::Rng);
    assert_eq!(
        (fail.status(), fail.code()),
        (Status::FAILED, failed::F_UNAVAILABLE)
    );
}

/// Arms (a)-(c) through host_vt itself over the CRYPTO-SEAM stub backend (busbar#262; the scratch build is
/// `c_unavailable::stub_host_vt`), inside one entry: (a) with the stub's `fill` failing its self-test
/// (`SelfTest("crngt")` through `fill_checked`), `random` runs first, before any other crypto call, and answers RNG
/// with `out` EMPTY and `HOST_FAULTS[SELF_TEST]` +1; `hmac_sha256` and ECDSA P-256 signing answer OK twice (the
/// stub's bytes) and then `SelfTest("pct")`: `crypto(HMAC_SHA256)` and `crypto(SIGN_ES256)` answer RNG with `out`
/// EMPTY (the safe layer's `Err(Rng)`), each moving the counter by one; (b) with `fill` answering `Rng`, `random`
/// answers RNG and the counter does not move; (c) the facade's own `fill` on the same stub still returns
/// `Err(RngError)` while `fill_checked` forwards the backend's error. No panic (`HOST_FAULTS[HOST_PANIC]` flat), no
/// abort (the probe exits cleanly) and no plugin fault (the entry completes); the plugin's `?` is FAILED
/// F_UNAVAILABLE. The audit row and metric are W1-L2's arm below.
#[test]
fn self_test_through_host_vt_on_the_stub_backend() {
    let rng = crypto_status::RNG;
    for (fill, random, checked) in [
        ("crngt", [1, 2], r#"Err(SelfTest("crngt"))"#),
        ("rng", [0, 0], "Err(Rng(RngError))"),
    ] {
        let [after_raw, after_safe] = random;
        let pct = after_safe;
        let got = crate::c_unavailable::stub_host_vt::probe("self-test", fill, "2");
        let want = format!(
            "outside={rng}/0\n\
             random={rng}/0 self_test={after_raw}\n\
             random16=Err(Rng) self_test={after_safe}\n\
             hmac1=Ok(true)\n\
             hmac2=Ok(true)\n\
             hmac3=Err(Rng) self_test={}\n\
             hmac4={rng}/0 self_test={}\n\
             sign1=Ok(true)\n\
             sign2=Ok(true)\n\
             sign3=Err(Rng) self_test={}\n\
             sign4={rng}/0 self_test={}\n\
             fill_checked={checked}\n\
             fill=Err(RngError)\n\
             host_panic=0\n\
             entry=ran\n",
            pct + 1,
            pct + 2,
            pct + 3,
            pct + 4,
        );
        assert_eq!(got, want, "BUSBAR_STUB_FILL={fill}");
    }
    let fail = Fail::from(CryptoErr::Rng);
    assert_eq!(
        (fail.status(), fail.code()),
        (Status::FAILED, failed::F_UNAVAILABLE)
    );
}

/// The stub backend this arm needs is in place (busbar#262: `self_test_through_host_vt_on_the_stub_backend` above
/// drives `HOST_FAULTS[SELF_TEST]` through host_vt, one per failing call); what is missing is the reader.
#[test]
#[ignore = "owner: W1-L2; blocked (re-checked 2026-11-16): nothing reads HOST_FAULTS outside host_vt: the registry watchdog (crates/plugin-loader/src/watchdog.rs) has no host-fault tick, and no crypto_self_test_failed audit row or plugin_host_fault_total metric exists in crates/; the stub backend half is done (busbar#262)"]
fn one_crypto_self_test_failed_row_and_metric_within_a_tick() {
    todo!("owner: W1-L2 (C-CRYPTO-SELFTEST)")
}

#[test]
#[ignore = "owner: W1-K8D; blocked (re-checked on dev 2026-11-16): the kernel admission path that reads error_codes_refused and the crypto self-test row is not on dev (OUTSTANDING row 5)"]
fn self_test_reaches_each_port_as_failed_unavailable() {
    todo!("owner: W1-K8D (C-CRYPTO-SELFTEST)")
}

/// (f), the auth adapter's side (W1-L5): a host crypto call the module does not offer (`Error::Unsupported`, the
/// facade's one UNAVAILABLE) reaches the plugin as `CryptoErr::Unavailable`, which `?` turns into REFUSED
/// R_UNSUPPORTED (§4.1 `From`); the auth adapter returns that from `verify` as `PortError::Refused { code:
/// R_UNSUPPORTED }`, never as a credential verdict, and the mapping moves no host fault counter. The fixture run
/// through the stub backend joins with A2's `HOST` and H1's guard.
#[test]
fn unsupported_is_refused_unsupported_and_moves_no_counter() {
    use std::sync::atomic::Ordering;

    use busbar_plugin_abi::fail::refused;
    use busbar_plugin_abi::host_side::host_vt::HOST_FAULTS;
    use busbar_plugin_abi::host_side::scrub::Scrub;
    use busbar_plugin_loader::adapters::auth::verify_refusal;
    use busbar_plugin_loader::ports::PortError;

    let before: Vec<u64> = HOST_FAULTS
        .iter()
        .map(|c| c.load(Ordering::Relaxed))
        .collect();
    assert!(matches!(
        verify_refusal(
            refused::R_UNSUPPORTED,
            "HMAC_SHA384 unsupported",
            &Scrub::new()
        ),
        Err(PortError::Refused {
            code: refused::R_UNSUPPORTED,
            ..
        })
    ));
    let after: Vec<u64> = HOST_FAULTS
        .iter()
        .map(|c| c.load(Ordering::Relaxed))
        .collect();
    assert_eq!(before[0], after[0], "HOST_FAULTS[SELF_TEST] does not move");
}
