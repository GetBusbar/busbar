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

// ───────────────────────── shared log-capture fixture (mirrors
// `diagnostics::tests::emit_tests::Buf`/`lines`, duplicated locally: that helper is private to its
// own test module and this suite lives in a different crate-internal module tree) ─────────────

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
    let out = tracing::subscriber::with_default(subscriber, f);
    (out, buf)
}

// ───────────────────────────────── 1. fault-path diagnostic identities ───────────────────────

/// Every auth fault/saturation diagnostic `auth/mod.rs` imports (`auth/mod.rs:14-18`), pinned by
/// (code, slug) so a refactor cannot silently rename or renumber one without this test moving. Each
/// one traces to a bare `tracing::warn!`/`tracing::error!` at the SAME trigger condition in 1.5.5
/// `crates/busbar/src/auth/mod.rs` (line cited per row) — the Diagnostic wrapper is new in 1.6.0
/// (K9c coded-diagnostics migration), the trigger and message are not.
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

/// **TRIGGERED** (not just identity-pinned): an empty data-plane chain with no `keys` verifier is
/// the open-relay posture and must warn `AUTH_CHAIN_OPEN_RELAY` — byte-identical condition and
/// message to v1.5.5 `crates/busbar/src/auth/mod.rs:338-340`.
#[test]
fn auth_chain_open_relay_diag_fires_on_empty_data_plane_chain() {
    let cfg = crate::config::AuthCfg::default_none();
    let (chain, buf) = capture(|| AuthMiddleware::new_builtin(&cfg));
    assert!(
        chain.is_open(),
        "an empty chain with no keys verifier is open"
    );
    let text = buf.text();
    assert!(
        text.contains("diag=BUSBAR-4004"),
        "expected AUTH_CHAIN_OPEN_RELAY (BUSBAR-4004) to fire; got: {text:?}"
    );
    assert!(
        text.contains("auth.chain is empty (open relay)"),
        "message text must match the v1.5.5 wording; got: {text:?}"
    );
}

/// **TRIGGERED**: an `admin_auth` chain naming a module with no resolved plugin skips it (falls
/// through to `Pass`) and warns loudly — `ADMIN_MODULE_UNRESOLVED`, the same condition and message
/// as v1.5.5 `crates/busbar/src/auth/mod.rs:919` ("boot resolves every non-builtin admin module,
/// fail-closed" — this path is reachable only via the test-fixture shortcut below, since a real boot
/// would already have failed closed before `run_admin_chain` ever runs).
#[test]
fn admin_module_unresolved_diag_fires_and_falls_through_to_pass() {
    let mut app = crate::test_support::TestApp::new().build();
    let a = Arc::get_mut(&mut app).expect("freshly built App Arc is unshared");
    a.admin_chain = vec!["ghost-module".to_string()]; // never resolved into a_.admin_modules
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

// ─────────────── 1b. the saturation / fault diagnostics on the door path (TRIGGERED) ───────────
//
// 1.5.5 emitted 4005/4006 on the data plane and 4008/4009 on the admin plane around its offloaded
// auth calls. The door path keeps each at the analogous trigger — a saturated admission budget or a
// door's own `max_inflight` full (4005/4008), a FAULTED verify (4006/4009), an admitted admin verify
// that does not answer within the wait (4009) — with 1.5.5's text byte for byte at the default
// budgets (64 data / 16 admin in flight, a 5s wait), and each one denies. RED arms: the same deny
// from a verifier that merely refused says nothing.

/// How a [`FakeDoor`] answers each `verify`.
#[derive(Clone)]
enum DoorAnswer {
    /// Answers this verdict.
    Verdict(Box<busbar_contract::auth_calls::Verified>),
    /// FAULTS (the plugin broke its contract), answered as a failed verify that says so.
    Fault,
    /// Never answers.
    Never,
}

impl DoorAnswer {
    /// Answers `verified`.
    fn verdict(verified: busbar_contract::auth_calls::Verified) -> Self {
        Self::Verdict(Box::new(verified))
    }
}

/// An emitter of one of the four, on a latch.
type Emitter = fn(&std::sync::atomic::AtomicBool);

/// A door stand-in that never answers on the spot, so every `verify` is submitted and awaited.
struct FakeDoor(DoorAnswer);

/// One submitted `verify` of a [`FakeDoor`].
struct FakeCall(DoorAnswer);

impl std::future::Future for FakeCall {
    type Output = busbar_contract::auth_calls::VerifyAnswer;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        use busbar_contract::auth_calls::Verified;
        match &self.0 {
            DoorAnswer::Verdict(v) => std::task::Poll::Ready((**v).clone().into()),
            DoorAnswer::Fault => std::task::Poll::Ready(Verified::Failed.into()),
            DoorAnswer::Never => std::task::Poll::Pending,
        }
    }
}

impl busbar_contract::auth_calls::Verifying for FakeCall {
    fn settled(&mut self) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        None
    }
    fn faulted(&self) -> bool {
        matches!(self.0, DoorAnswer::Fault)
    }
}

impl busbar_contract::auth_calls::AuthCalls for FakeDoor {
    fn name(&self) -> &str {
        "fake-door"
    }
    fn facts(&self) -> u32 {
        0
    }
    fn verify_now(
        &self,
        _: &busbar_contract::auth_calls::VerifyRequest,
    ) -> Option<busbar_contract::auth_calls::VerifyAnswer> {
        None
    }
    fn verify(
        &self,
        _: busbar_contract::auth_calls::VerifyRequest,
    ) -> Box<dyn busbar_contract::auth_calls::Verifying> {
        Box::new(FakeCall(self.0.clone()))
    }
    fn refresh(&self) -> Result<u64, String> {
        Ok(0)
    }
}

/// Run `f` on a current-thread runtime whose clock is paused (a wait elapses the moment the runtime
/// is idle), inside the log capture. A latch another test tripped turns a warning into a debug line,
/// so the capture must see DEBUG: the [`WarnCapture`] gate held across it keeps every callsite's
/// interest live (and serializes with the other capturing tests).
///
/// [`WarnCapture`]: crate::test_support::warn_capture::WarnCapture
fn captured_on_paused_clock<T>(f: impl std::future::Future<Output = T>) -> (T, Buf) {
    let _gate = crate::test_support::warn_capture::WarnCapture::capturing_debug();
    capture(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("runtime")
            .block_on(f)
    })
}

/// The data-plane chain `[door]` over `answer`, walked on the request path.
async fn data_door(answer: DoorAnswer) -> ChainVerdict {
    let auth = Arc::new(AuthMiddleware::from_doors_for_test(vec![(
        "door".to_string(),
        Arc::new(FakeDoor(answer)) as Arc<dyn AuthCalls>,
    )]));
    AuthMiddleware::run_chain_on_request_path(
        &auth,
        Some("cred".into()),
        ChainHead::default(),
        None,
        None,
    )
    .await
}

/// The admin chain `[ext]`, `ext` an external admin door over `answer`, walked awaited.
async fn admin_door_walk(answer: DoorAnswer) -> ChainVerdict {
    let app = crate::test_support::TestApp::new()
        .admin_chain(vec!["ext".to_string()])
        .admin_door("ext", Arc::new(FakeDoor(answer)))
        .build();
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer cred"));
    run_admin_chain(&app, "GET", "/", &headers, false, &mut Default::default())
        .await
        .0
}

/// 4005's text at the default budget: 1.5.5's, byte for byte.
const AUTH_SATURATED_TEXT: &str =
    "auth chain offload could not be started within 5s (64 already in \
     flight); an auth plugin is not returning. Denying (fail-closed) rather than admitting \
     unverified.";
/// 4006's text: 1.5.5's.
const AUTH_PANICKED_TEXT: &str = "auth chain panicked; denying (fail-closed)";
/// 4008's text at the default budget: 1.5.5's, byte for byte.
const ADMIN_SATURATED_TEXT: &str = "admin auth chain offload could not be started within 5s (16 \
     already in flight); an admin auth plugin is not returning. Denying (fail-closed) rather than \
     admitting unverified.";
/// 4009's text at the default wait: 1.5.5's, byte for byte.
const ADMIN_STALLED_TEXT: &str =
    "admin auth chain did not complete within 5s (or panicked); denying (fail-closed).";

/// 4005: a data-plane door whose own `max_inflight` is full, and a data-plane admission budget with
/// no slot free within the wait, each deny with 1.5.5's saturation text. RED: a door that refused
/// denies too, and says nothing of saturation.
#[test]
fn a_saturated_data_plane_verifier_says_4005_in_1_5_5_words_and_denies() {
    use busbar_contract::auth_calls::Verified;
    let (verdict, said) =
        captured_on_paused_clock(data_door(DoorAnswer::verdict(Verified::Overloaded)));
    assert_eq!(verdict, ChainVerdict::Denied);
    let text = said.text();
    assert!(text.contains("diag=BUSBAR-4005"), "{text:?}");
    assert!(text.contains(AUTH_SATURATED_TEXT), "1.5.5's text: {text:?}");

    // The budget itself: every slot held, the wait elapses, the request is denied unverified.
    let (verdict, said) = captured_on_paused_clock(async {
        let held = AUTH_ADMISSION_PERMITS
            .acquire_many(AUTH_ADMISSION_MAX_INFLIGHT as u32)
            .await
            .expect("the budget");
        let verdict = data_door(DoorAnswer::verdict(Verified::Pass)).await;
        drop(held);
        verdict
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

    // RED: a refusal is a deny with no saturation said.
    let (verdict, said) =
        captured_on_paused_clock(data_door(DoorAnswer::verdict(Verified::Reject)));
    assert_eq!(verdict, ChainVerdict::Denied);
    assert!(!said.text().contains("BUSBAR-4005"), "{:?}", said.text());
}

/// 4006: a data-plane door whose verify FAULTED denies with 1.5.5's panic text. RED: the same failed
/// verify that did not fault denies and says nothing of a panic.
#[test]
fn a_faulted_data_plane_verify_says_4006_in_1_5_5_words_and_denies() {
    use busbar_contract::auth_calls::Verified;
    let (verdict, said) = captured_on_paused_clock(data_door(DoorAnswer::Fault));
    assert_eq!(verdict, ChainVerdict::Denied);
    let text = said.text();
    assert!(text.contains("diag=BUSBAR-4006"), "{text:?}");
    assert!(text.contains(AUTH_PANICKED_TEXT), "1.5.5's text: {text:?}");

    let (verdict, said) =
        captured_on_paused_clock(data_door(DoorAnswer::verdict(Verified::Failed)));
    assert_eq!(verdict, ChainVerdict::Denied);
    assert!(!said.text().contains("BUSBAR-4006"), "{:?}", said.text());
}

/// 4008: an external admin door whose own `max_inflight` is full, and an admin admission budget
/// with no slot free within the wait, each deny with 1.5.5's admin saturation text. RED: a door that
/// refused denies and says nothing.
#[test]
fn a_saturated_admin_verifier_says_4008_in_1_5_5_words_and_denies() {
    use busbar_contract::auth_calls::Verified;
    let (verdict, said) =
        captured_on_paused_clock(admin_door_walk(DoorAnswer::verdict(Verified::Overloaded)));
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
        let verdict = admin_door_walk(DoorAnswer::verdict(Verified::Pass)).await;
        drop(held);
        verdict
    });
    assert_eq!(verdict, ChainVerdict::Denied);
    assert!(
        said.text().contains(ADMIN_SATURATED_TEXT),
        "{:?}",
        said.text()
    );

    let (verdict, said) =
        captured_on_paused_clock(admin_door_walk(DoorAnswer::verdict(Verified::Reject)));
    assert_eq!(verdict, ChainVerdict::Denied);
    assert!(!said.text().contains("BUSBAR-4008"), "{:?}", said.text());
}

/// 4009: an admitted admin verify that does not answer within the wait, and one that FAULTED, each
/// deny with 1.5.5's stalled text. RED: a failed verify that did not fault denies and says nothing.
#[test]
fn a_stalled_or_faulted_admin_verify_says_4009_in_1_5_5_words_and_denies() {
    use busbar_contract::auth_calls::Verified;
    for answer in [DoorAnswer::Never, DoorAnswer::Fault] {
        let (verdict, said) = captured_on_paused_clock(admin_door_walk(answer));
        assert_eq!(verdict, ChainVerdict::Denied);
        let text = said.text();
        assert!(text.contains("diag=BUSBAR-4009"), "{text:?}");
        assert!(text.contains(ADMIN_STALLED_TEXT), "1.5.5's text: {text:?}");
    }
    let (verdict, said) =
        captured_on_paused_clock(admin_door_walk(DoorAnswer::verdict(Verified::Failed)));
    assert_eq!(verdict, ChainVerdict::Denied);
    assert!(!said.text().contains("BUSBAR-4009"), "{:?}", said.text());
}

/// Each of the four keeps 1.5.5's WARN-ONCE latch: the transition into the state warns, a
/// recurrence logs at debug, and once the state clears the next transition warns again.
#[test]
fn the_door_path_diagnostics_warn_once_then_debug_as_1_5_5() {
    let _gate = crate::test_support::warn_capture::WarnCapture::capturing_debug();
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

// ───────────────────────── 2. pre-mint READY-with-zero-fields -> no auth header ───────────────

/// THE ADMIN CREDENTIAL NEVER REACHES A LOG LINE (ARCHITECT ruling 2026-09-30, AUTH-DOOR: admin
/// requests terminate locally and the verify answer's strips are not applied there, so nothing the
/// chain writes may carry the credential). Every answer the operator's door can give — an identity,
/// a bad credential, a pass, an overloaded verifier, an outage — is walked with both carriers
/// presented, under a DEBUG capture, and neither value appears.
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
