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

/// Arms (a)-(c) through host_vt itself over the CRYPTO-SEAM stub backend (SelfTest from `fill_checked`, then from
/// `hmac_sha256` and `ecdsa_p256` signing after N good calls), with `HOST_FAULTS[SELF_TEST]` moving (busbar#262).
#[test]
#[ignore = "owner: busbar#262 (host_vt over the stub backend); blocked (re-checked on dev 2026-11-16): host_vt over the stub crypto backend is not constructible from the facade on dev"]
fn self_test_through_host_vt_on_the_stub_backend() {
    todo!("owner: busbar#262 (C-CRYPTO-SELFTEST)")
}
#[test]
#[ignore = "owner: W1-L2; blocked (re-checked on dev 2026-11-16): no test constructor for Registry<N> (Needs impl, ConfigBinder, Ceilings, a static Host) and no second-identity MIN-3 fixture image exist in busbar-plugin-test on dev"]
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
