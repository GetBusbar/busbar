// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Need-time transport gate (TRANSPORT-SECURITY-POLICY 8 tests 3, 4, 6, 8, 14, 15).

use super::*;
use busbar_plugin_abi::need::need_flag::{TLS_INBAND, TLS_MUTUAL, TLS_REQUIRED};

const NONE: Accept = Accept(0);
const PLAIN: Accept = Accept(Accept::PLAINTEXT);
const UNVERIFIED: Accept = Accept(Accept::UNVERIFIED_TLS);

/// Tests 4 and 8: an undeclared TLS_NONE OPEN is refused whatever the destination is called, with
/// no loopback, `localhost` or unix exemption and no kind consulted (the gate has no such input).
#[test]
fn a_plaintext_open_is_denied_without_the_acceptance() {
    for dest in [
        "db.internal:5432",
        "127.0.0.1:5432",
        "[::1]:5432",
        "localhost:6379",
        "unix:/run/valkey.sock",
    ] {
        assert_eq!(
            admit_open(NONE, TLS_NONE, dest),
            Err(NeedErr::Denied),
            "{dest}"
        );
        assert_eq!(
            admit_open(UNVERIFIED, TLS_NONE, dest),
            Err(NeedErr::Denied),
            "{dest}"
        );
        assert_eq!(
            admit_open(PLAIN, TLS_NONE, dest),
            Ok(Admit::Plain),
            "{dest}"
        );
    }
}

/// Tests 3 and 15: a `unix:` dest is admitted only under `accept: plaintext`, the same for every
/// caller, since the gate has no kind parameter (unix rule 4 is gone).
#[test]
fn a_unix_dest_needs_the_plaintext_acceptance_for_every_kind() {
    assert_eq!(admit_open(NONE, TLS_NONE, "unix:/s"), Err(NeedErr::Denied));
    assert_eq!(admit_open(PLAIN, TLS_NONE, "unix:/s"), Ok(Admit::Plain));
}

/// Test 6: a TLS mode is verified unless the instance accepted `unverified_tls`; only a waived
/// admission sets the PoolKey `verify` bit; `plaintext` waives nothing.
#[test]
fn only_the_unverified_acceptance_waives_verification() {
    for tls in [TLS_REQUIRED, TLS_MUTUAL, TLS_INBAND] {
        for accept in [NONE, PLAIN] {
            let a = admit_open(accept, tls, "db:5432").unwrap();
            assert_eq!(a, Admit::Verified, "{tls}");
            assert!(!a.waived());
        }
        let a = admit_open(UNVERIFIED, tls, "db:5432").unwrap();
        assert_eq!(a, Admit::Waived, "{tls}");
        assert!(a.waived());
    }
}

/// A FETCH is judged by its URL's scheme: `https://` is verified, `http://` is plaintext, and a
/// userinfo-bearing or upper-case scheme changes nothing.
#[test]
fn a_fetch_url_scheme_is_its_mode() {
    assert_eq!(
        admit_fetch(NONE, "https://idp.example/jwks"),
        Ok(Admit::Verified)
    );
    assert_eq!(
        admit_fetch(NONE, "HTTPS://idp.example/jwks"),
        Ok(Admit::Verified)
    );
    assert_eq!(
        admit_fetch(UNVERIFIED, "https://idp.example"),
        Ok(Admit::Waived)
    );
    assert_eq!(
        admit_fetch(NONE, "http://127.0.0.1:9/x"),
        Err(NeedErr::Denied)
    );
    assert_eq!(
        admit_fetch(UNVERIFIED, "http://idp.example"),
        Err(NeedErr::Denied)
    );
    assert_eq!(admit_fetch(PLAIN, "http://127.0.0.1:9/x"), Ok(Admit::Plain));
}

/// An unknown TLS mode is refused, never read as a secure one.
#[test]
fn an_unknown_tls_mode_is_denied() {
    assert_eq!(admit_open(PLAIN, 9, "db:5432"), Err(NeedErr::Denied));
}

/// The ERROR line is written once per instance and endpoint, the endpoint without userinfo; a
/// forgotten instance starts over.
#[test]
fn the_refusal_log_is_once_per_instance_and_endpoint() {
    let r = Reported::default();
    assert!(r.first(1, "https://u:pw@db:5432/x"));
    assert!(
        !r.first(1, "https://other:pw@db:5432/y"),
        "same endpoint, userinfo and path aside"
    );
    assert!(r.first(1, "db:5433"), "another endpoint");
    assert!(r.first(2, "db:5432"), "another instance");
    r.forget(1);
    assert!(r.first(1, "db:5432"), "a forgotten instance reports again");
    assert!(!r.first(2, "db:5432"));
}
