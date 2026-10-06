// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth acceptance suite: black-box pins for 1.5.5 auth behaviour that the scattered
//! unit suites (`tests.rs`, `plugin_chain_tests.rs`, `self_keys_tests.rs`, `token_tests.rs`,
//! the identity crate's `operator_tests` and `ingress_sigv4_tests`,
//! `egress_auth::tests::*`) do not directly assert. This file does not re-port behaviour those
//! suites already pin byte-for-byte against v1.5.5 (fail-closed mapping, warn-once latch, chain
//! semantics, carrier precedence, dual-carrier operator fold, SigV4 constant-time/body-hash-rebind,
//! byte-for-byte header handling). It targets the two genuine gaps an inventory of those suites
//! found:
//!
//! 1. The nine auth fault/saturation diagnostic identities (`auth/mod.rs:14-18`) have NO test
//!    anywhere asserting their (code, slug) or that they actually fire on their documented trigger
//!    — a silent rename or a dropped `diag_*!` call at a refactor would go unnoticed.
//! 2. The pre-mint "`READY` with zero fields" -> no auth header (which sends the caller into the
//!    upstream's ordinary 401, per 1.5.5 `egress_auth/mod.rs:150-200`) was exercised only inside the
//!    `NoCredential` unit itself, never proven reachable through the public `resolve()` entry point
//!    the boot path actually calls.
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

// ───────────────────────── 2. pre-mint READY-with-zero-fields -> no auth header ───────────────

/// **Public entry point, not the unit**: `egress_auth::resolve()` — the SAME function the boot path
/// calls to pick a lane's egress credential — for `jwt-bearer`/`oauth-client-credentials` returns a
/// credential that emits NO auth header at all rather than a self-minted token synchronously (those
/// mint asynchronously at boot via a separate special-cased path; reaching `resolve` with one of
/// these styles means that wiring was bypassed). Zero header bytes on the wire is exactly what turns
/// into the upstream's OWN ordinary 401 — no busbar-side header is emitted for the upstream to
/// reject on shape, and no raw secret material is sent as a bogus bearer either. Pins v1.5.5
/// `crates/busbar/src/egress_auth/mod.rs:150-200` via the
/// CURRENT public surface, not by reaching into `NoCredential` directly.
#[test]
fn ready_credential_with_no_fields_emits_no_auth_header_through_public_resolve() {
    use crate::config::ProviderAuth;
    use crate::egress_auth::resolve;
    use crate::proto::SigningContext;

    for style in [
        ProviderAuth::JwtBearer,
        ProviderAuth::OAuthClientCredentials,
    ] {
        let cred = resolve("anthropic", Some(style));
        // `NoCredential` IS lane-constant — it is constantly nothing, so freezing it at boot is
        // sound (unlike a real self-minting credential, which never reaches this arm: it is
        // special-cased at boot into its own async mint path before `resolve` is ever called).
        assert!(
            cred.is_lane_constant(),
            "the fail-closed no-header stand-in is context-independent by construction"
        );
        let ctx = SigningContext {
            host: "h.example.com",
            canonical_uri: "/v1/messages",
            body: b"",
            timestamp_epoch: 0,
            upstream_creds: busbar_contract::config::UpstreamCreds::Own,
        };
        let headers = cred.headers_for("should-be-ignored", &ctx);
        assert!(
            headers.is_empty(),
            "resolve() reaching a self-minting style outside its async boot path must emit ZERO \
             auth header bytes (upstream sees its own ordinary 401), never the raw key verbatim: \
             got {headers:?}"
        );
    }
}

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
