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

fn host_vt() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../busbar-plugin-abi/src/host_side/host_vt.rs"
    );
    std::fs::read_to_string(path).expect("host_vt.rs")
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

#[test]
#[ignore = "owner: W1-A2"]
fn self_test_answers_rng_with_empty_out_and_no_fault() {
    todo!("owner: W1-A2 (C-CRYPTO-SELFTEST)")
}

#[test]
#[ignore = "owner: W1-L2"]
fn one_crypto_self_test_failed_row_and_metric_within_a_tick() {
    todo!("owner: W1-L2 (C-CRYPTO-SELFTEST)")
}

#[test]
#[ignore = "owner: W1-K8D"]
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
