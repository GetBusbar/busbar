// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth acceptance suite: black-box pins for 1.5.5 auth behaviour that the scattered
//! unit suites (`tests.rs`, `plugin_chain_tests.rs`, `self_keys_tests.rs`, `token_tests.rs`,
//! the identity crate's `operator_tests`, and each auth plugin's own suite) do not directly assert. This file does not re-port behaviour those
//! suites already pin byte-for-byte against v1.5.5 (fail-closed mapping, warn-once latch, chain
//! semantics, carrier precedence, dual-carrier operator fold, byte-for-byte header handling). It
//! targets the genuine gap an inventory of those suites found:
//!
//! 1. The nine auth fault/saturation diagnostic identities (`auth/mod.rs:14-18`) have NO test
//!    anywhere asserting their (code, slug) or that they actually fire on their documented trigger
//!    — a silent rename or a dropped `diag_*!` call at a refactor would go unnoticed.
//!
//! Every test here goes through a public (or `pub(crate)`, crate-internal-but-not-implementation-
//! private) entry point, never a store internal type. The inbound credential cache lives in the
//! plugins (THE DESIGN 11.11 R3); the kernel keeps none.

use super::*;
use crate::diagnostics::{
    Diagnostic, ADMIN_AUTH_CHAIN_EMPTY, ADMIN_CHAIN_STALLED, ADMIN_FORBIDDEN_SUPPRESSED,
    ADMIN_MODULE_UNRESOLVED, ADMIN_OFFLOAD_SATURATED, AUTH_CHAIN_OPEN_RELAY, AUTH_CHAIN_PANICKED,
    AUTH_OFFLOAD_SATURATED, KEYS_IN_CHAIN_PASSTHROUGH_CONFLICT,
};
use std::io::Write;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buf {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

fn capture<T>(f: impl FnOnce() -> T) -> (T, Buf) {
    let buf = Buf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_target(false)
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let out = tracing::subscriber::with_default(subscriber, || {
        tracing::callsite::rebuild_interest_cache();
        f()
    });
    (out, buf)
}

#[test]
fn auth_fault_path_diagnostic_identities_are_pinned() {
    let table: &[(&Diagnostic, u16, &str, &str)] = &[
        (
            &AUTH_CHAIN_OPEN_RELAY,
            4004,
            "auth-chain-open-relay",
            "v1.5.5 auth/mod.rs:338-340 (`chain.is_empty() && !keys_in_chain` warn)",
        ),
        (
            &AUTH_OFFLOAD_SATURATED,
            4005,
            "auth-offload-saturated",
            "v1.5.5 auth/mod.rs:526-535 (AUTH_OFFLOAD_WAIT permit-acquire timeout warn)",
        ),
        (
            &AUTH_CHAIN_PANICKED,
            4006,
            "auth-chain-panicked",
            "v1.5.5 auth/mod.rs:552 (`auth chain panicked; denying (fail-closed)`)",
        ),
        (
            &ADMIN_MODULE_UNRESOLVED,
            4007,
            "admin-module-unresolved",
            "v1.5.5 auth/mod.rs:919 (`admin_auth names a module with no resolved plugin`)",
        ),
        (
            &ADMIN_OFFLOAD_SATURATED,
            4008,
            "admin-offload-saturated",
            "v1.5.5 auth/mod.rs:985 area (admin's own spawn_blocking offload wait timeout)",
        ),
        (
            &ADMIN_CHAIN_STALLED,
            4009,
            "admin-chain-stalled",
            "v1.5.5 auth/mod.rs admin spawn_blocking join timeout (sibling of the data-plane wait)",
        ),
        (
            &ADMIN_FORBIDDEN_SUPPRESSED,
            4010,
            "admin-forbidden-suppressed",
            "v1.5.5 auth/mod.rs:1338 (`admin request forbidden (audit suppressed...)`)",
        ),
        (
            &KEYS_IN_CHAIN_PASSTHROUGH_CONFLICT,
            4011,
            "keys-in-chain-passthrough-conflict",
            "v1.5.5 auth/mod.rs:1417-1421 (`keys_in_chain && upstream_creds == Passthrough` warn)",
        ),
        (
            &ADMIN_AUTH_CHAIN_EMPTY,
            4026,
            "admin-auth-chain-empty",
            "predev-derived (NOT a v1.5.5 behaviour): `dry_run_admin_scope` fail-open-masking fix; \
             v1.5.5's own `run_admin_chain` empty-chain check returns `ChainVerdict::Open` with no \
             diagnostic at all (auth/mod.rs:847-849) — listed here only so the fault-path table stays \
             exhaustive, not as a parity claim.",
        ),
    ];
    for (diag, code, slug, cite) in table {
        assert_eq!(diag.code, *code, "code drifted for {slug} ({cite})");
        assert_eq!(diag.slug, *slug, "slug drifted for code {code} ({cite})");
    }
}

#[test]
fn admin_module_unresolved_diag_fires_and_falls_through_to_pass() {
    let mut app = crate::test_support::TestApp::new().build();
    let a = Arc::get_mut(&mut app).expect("freshly built App Arc is unshared");
    a.admin_chain = vec!["ghost-module".to_string()];
    let (verdict, buf) =
        capture(|| super::tests::run_admin_chain_on(&app, Some("anything"), None).0);
    assert_eq!(
        verdict,
        ChainVerdict::Denied,
        "an all-Pass admin chain (the only module deferred) denies, same fold as the data plane"
    );
    let text = buf.text();
    assert!(
        text.contains("diag=BUSBAR-4007"),
        "expected ADMIN_MODULE_UNRESOLVED (BUSBAR-4007) to fire; got: {text:?}"
    );
    assert!(
        text.contains("module=\"ghost-module\""),
        "the unresolved name must be logged; got: {text:?}"
    );
}

type Emitter = fn(&std::sync::atomic::AtomicBool);

fn captured_on_paused_clock<T>(f: impl std::future::Future<Output = T>) -> (T, Buf) {
    capture(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("runtime")
            .block_on(f)
    })
}

const AUTH_SATURATED_TEXT: &str =
    "auth chain offload could not be started within 5s (64 already in \
     flight); an auth plugin is not returning. Denying (fail-closed) rather than admitting \
     unverified.";

const AUTH_PANICKED_TEXT: &str = "auth chain panicked; denying (fail-closed)";

const ADMIN_SATURATED_TEXT: &str = "admin auth chain offload could not be started within 5s (16 \
     already in flight); an admin auth plugin is not returning. Denying (fail-closed) rather than \
     admitting unverified.";

const ADMIN_STALLED_TEXT: &str =
    "admin auth chain did not complete within 5s (or panicked); denying (fail-closed).";

#[test]
fn a_saturated_data_plane_verifier_says_4005_in_1_5_5_words_and_denies() {
    use busbar_contract::auth_calls::Verified;
    // Internal continuation: outcome DATA is interpreted by production functions; actual
    // auth-product I/O is exercised by the root's OIDC controls.
    let (judged, said) = captured_on_paused_clock(async {
        data_verdict_of("door", Verified::Overloaded.into(), false).map(|judged| {
            chain_position_verdict("door", judged.verdict).unwrap_or(ChainVerdict::Denied)
        })
    });
    assert_eq!(
        judged,
        Err(VerifierUnavailable::Overloaded),
        "handed back apart"
    );
    assert!(!said.text().contains("BUSBAR-4005"), "{:?}", said.text());
    let (verdict, said) = captured_on_paused_clock(async {
        let held = AUTH_ADMISSION_PERMITS
            .acquire_many(AUTH_ADMISSION_MAX_INFLIGHT as u32)
            .await
            .expect("the budget");
        let refused = match auth_admission_permit().await {
            Ok(_) => panic!("the held actual admission budget must time out"),
            Err(refused) => refused,
        };
        drop(held);
        chain_position_verdict("door", refused.verdict).expect("a refusal is terminal")
    });
    assert_eq!(
        verdict,
        ChainVerdict::Denied,
        "denied, never admitted unverified"
    );
    assert!(
        said.text().contains(AUTH_SATURATED_TEXT),
        "{:?}",
        said.text()
    );
    let (verdict, said) = captured_on_paused_clock(async {
        let judged =
            data_verdict_of("door", Verified::Reject.into(), false).expect("an actual refusal");
        chain_position_verdict("door", judged.verdict).expect("a refusal is terminal")
    });
    assert_eq!(verdict, ChainVerdict::Denied);
    assert!(!said.text().contains("BUSBAR-4005"), "{:?}", said.text());
}

#[test]
fn a_faulted_data_plane_verify_says_4006_in_1_5_5_words_and_denies() {
    use busbar_contract::auth_calls::Verified;
    // Internal fault/result continuation, preserving the exact production fail-closed fold.
    let (verdict, said) = captured_on_paused_clock(async {
        deny_unavailable_chain(data_verdict_of("door", Verified::Failed.into(), true).map(
            |judged| chain_position_verdict("door", judged.verdict).unwrap_or(ChainVerdict::Denied),
        ))
    });
    assert_eq!(verdict, ChainVerdict::Denied);
    let text = said.text();
    assert!(text.contains("diag=BUSBAR-4006"), "{text:?}");
    assert!(text.contains(AUTH_PANICKED_TEXT), "1.5.5's text: {text:?}");
    let (verdict, said) = captured_on_paused_clock(async {
        deny_unavailable_chain(data_verdict_of("door", Verified::Failed.into(), false).map(
            |judged| chain_position_verdict("door", judged.verdict).unwrap_or(ChainVerdict::Denied),
        ))
    });
    assert_eq!(verdict, ChainVerdict::Denied);
    assert!(!said.text().contains("BUSBAR-4006"), "{:?}", said.text());
}

#[test]
fn a_saturated_admin_verifier_says_4008_in_1_5_5_words_and_denies() {
    use busbar_contract::auth_calls::Verified;
    // Internal outcome and actual admission-budget continuations.
    let (verdict, said) = captured_on_paused_clock(async {
        let judged = admin_verdict_of(Verified::Overloaded.into(), false);
        chain_position_verdict("ext", judged.verdict).expect("overload is terminal")
    });
    assert_eq!(verdict, ChainVerdict::Denied);
    let text = said.text();
    assert!(text.contains("diag=BUSBAR-4008"), "{text:?}");
    assert!(
        text.contains(ADMIN_SATURATED_TEXT),
        "1.5.5's text: {text:?}"
    );
    let (verdict, said) = captured_on_paused_clock(async {
        let held = ADMIN_ADMISSION_PERMITS
            .acquire_many(ADMIN_ADMISSION_MAX_INFLIGHT as u32)
            .await
            .expect("the budget");
        let refused = match admin_admission_permit().await {
            Ok(_) => panic!("the held actual admission budget must time out"),
            Err(refused) => refused,
        };
        drop(held);
        chain_position_verdict("ext", refused.verdict).expect("a refusal is terminal")
    });
    assert_eq!(verdict, ChainVerdict::Denied);
    assert!(
        said.text().contains(ADMIN_SATURATED_TEXT),
        "{:?}",
        said.text()
    );
    let (verdict, said) = captured_on_paused_clock(async {
        let judged = admin_verdict_of(Verified::Reject.into(), false);
        chain_position_verdict("ext", judged.verdict).expect("a refusal is terminal")
    });
    assert_eq!(verdict, ChainVerdict::Denied);
    assert!(!said.text().contains("BUSBAR-4008"), "{:?}", said.text());
}

#[test]
fn a_stalled_or_faulted_admin_verify_says_4009_in_1_5_5_words_and_denies() {
    use busbar_contract::auth_calls::Verified;
    for timed_out in [true, false] {
        let (verdict, said) = captured_on_paused_clock(async {
            let judged = if timed_out {
                // The timeout error comes from the actual Tokio timer, not a pending auth door.
                let elapsed =
                    tokio::time::timeout(ADMIN_ADMISSION_WAIT, std::future::pending::<()>())
                        .await
                        .expect_err("the actual timer elapses");
                admin_verification_timed_out(elapsed)
            } else {
                admin_verdict_of(Verified::Failed.into(), true)
            };
            chain_position_verdict("ext", judged.verdict).expect("no verdict is terminal")
        });
        assert_eq!(verdict, ChainVerdict::Denied);
        let text = said.text();
        assert!(text.contains("diag=BUSBAR-4009"), "{text:?}");
        assert!(text.contains(ADMIN_STALLED_TEXT), "1.5.5's text: {text:?}");
    }
    let (verdict, said) = captured_on_paused_clock(async {
        let judged = admin_verdict_of(Verified::Failed.into(), false);
        chain_position_verdict("ext", judged.verdict).expect("a failed verification is terminal")
    });
    assert_eq!(verdict, ChainVerdict::Denied);
    assert!(!said.text().contains("BUSBAR-4009"), "{:?}", said.text());
}

#[test]
fn the_door_path_diagnostics_warn_once_then_debug_as_1_5_5() {
    let emitters: [(&str, Emitter); 4] = [
        ("BUSBAR-4005", auth_saturated_on),
        ("BUSBAR-4006", auth_faulted_on),
        ("BUSBAR-4008", admin_saturated_on),
        ("BUSBAR-4009", admin_stalled_on),
    ];
    for (code, emit) in emitters {
        let latch = std::sync::atomic::AtomicBool::new(false);
        let levels: Vec<String> = [false, false, true]
            .into_iter()
            .map(|clear_first| {
                if clear_first {
                    cleared(&latch);
                }
                let ((), said) = capture(|| emit(&latch));
                let text = said.text();
                assert!(text.contains(code), "{code}: {text:?}");
                if text.contains(" WARN ") {
                    "WARN".to_string()
                } else if text.contains("DEBUG") {
                    "DEBUG".to_string()
                } else {
                    text
                }
            })
            .collect();
        assert_eq!(levels, ["WARN", "DEBUG", "WARN"], "{code}");
    }
}

#[test]
fn the_admin_credential_never_reaches_a_log_line() {
    use busbar_contract::auth_calls::{Verified, VerifiedIdentity};
    const BEARER: &str = "secret-bearer-value-7f3a";
    const HEADER: &str = "secret-header-value-91cc";
    for verified in [
        Verified::Identity(VerifiedIdentity {
            subject: "admin".into(),
            ..VerifiedIdentity::default()
        }),
        Verified::Reject,
        Verified::Pass,
        Verified::Overloaded,
        Verified::Failed,
    ] {
        let app = super::tests::operator_app(verified);
        let (_, buf) =
            capture(|| super::tests::run_admin_chain_on(&app, Some(BEARER), Some(HEADER)));
        let text = buf.text();
        assert!(
            !text.contains(BEARER) && !text.contains(HEADER),
            "a credential reached a log line: {text}"
        );
    }
}
