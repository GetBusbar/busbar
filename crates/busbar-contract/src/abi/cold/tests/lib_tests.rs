// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the login residue of the JSON lane (`abi/cold/mod.rs`).

use super::*;

/// The five status codes are pairwise DISTINCT integers. The loader's discrimination (esp. the
/// revocation-denylist fallback) keys on these being different: an undecodable-variant signal
/// ([`STATUS_UNSUPPORTED`]) must never collide with a caught panic ([`STATUS_PANIC`]) or a backend
/// failure ([`STATUS_ERR`]) or a caller-protocol violation ([`STATUS_PROTOCOL`]).
#[test]
fn status_codes_are_pairwise_distinct() {
    let all = [
        STATUS_OK,
        STATUS_ERR,
        STATUS_PROTOCOL,
        STATUS_UNSUPPORTED,
        STATUS_PANIC,
    ];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b, "status codes must be pairwise distinct");
        }
    }
    // The two forward-compat codes are the specific values the loader/SDK agree on.
    assert_eq!(STATUS_UNSUPPORTED, 2);
    assert_eq!(STATUS_PANIC, 3);
}

/// The response cap is exactly 256 MiB, not some other magnitude a mutated `*`/`+`/`/` in its
/// definition could silently produce (e.g. `256 * 1024 + 1024` is ~262 KiB, `256 * 1024 / 1024`
/// is 256 bytes — both would pass a loose "it's some positive number" check but leave the loader
/// either OOM-vulnerable or unable to carry a real payload).
#[test]
fn max_plugin_response_len_is_exactly_256_mebibytes() {
    assert_eq!(MAX_PLUGIN_RESPONSE_LEN, 268_435_456);
    assert_eq!(MAX_PLUGIN_RESPONSE_LEN, 256 * 1024 * 1024);
}
