// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/observability.rs`.
//!
//! The SSRF/URL guard suite's tests are not here any more: they moved with the guard, to
//! `busbar-unit-egress/src/tests/sink_guard_tests.rs`, ported and not rewritten. What is left is
//! what is still this module's — the OTLP credential split and its base64, the tracer shutdown, and
//! the two-filter level policy of the subscriber install.

use super::*;

#[test]
fn test_base64_encode_rfc4648_vectors() {
    // Standard RFC 4648 test vectors, including the padding edge cases the OTLP Basic-auth token
    // exercises (input lengths not a multiple of 3).
    assert_eq!(base64_encode(b""), "");
    assert_eq!(base64_encode(b"f"), "Zg==");
    assert_eq!(base64_encode(b"fo"), "Zm8=");
    assert_eq!(base64_encode(b"foo"), "Zm9v");
    assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
    assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
    assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    // The exact token the credential path produces for `alice:s3cr3t`.
    assert_eq!(base64_encode(b"alice:s3cr3t"), "YWxpY2U6czNjcjN0");
}

#[test]
fn test_split_otlp_credentials_moves_secret_off_url() {
    // Regression: an endpoint with embedded userinfo must yield (a) a credential-FREE
    // endpoint for `with_endpoint` (so the URI the SDK may log never carries the secret) and (b)
    // an `Authorization: Basic base64(user:pass)` header carrying the credential out of band.
    let (clean, auth) =
        split_otlp_credentials("https://alice:s3cr3t@collector.example.com:4318/v1/traces");
    // The clean endpoint must NOT contain the username or password in any form...
    assert!(
        !clean.contains("alice") && !clean.contains("s3cr3t") && !clean.contains('@'),
        "endpoint passed to the SDK must be credential-free: {clean}"
    );
    // ...while still pointing at the same collector (host/port/path preserved).
    assert_eq!(clean, "https://collector.example.com:4318/v1/traces");
    // The credential rides in a Basic auth header, base64 of `alice:s3cr3t`.
    let auth = auth.expect("userinfo must produce an Authorization header");
    let auth = auth.to_str().expect("header value is ascii");
    assert_eq!(auth, "Basic YWxpY2U6czNjcjN0"); // golden wire-contract literal (kept bare on purpose)
                                                // Belt-and-braces: the raw secret must not appear verbatim in the header either.
    assert!(
        !auth.contains("s3cr3t") && !auth.contains("alice"),
        "credential must be base64-encoded, not plaintext: {auth}"
    );
}

#[test]
fn test_split_otlp_credentials_password_only_and_user_only() {
    // Password-only (`:pass@`) and username-only (`user@`) userinfo are both moved off the URL.
    let (clean, auth) = split_otlp_credentials("https://:topsecret@host:4318/v1/traces");
    assert!(
        !clean.contains("topsecret") && !clean.contains('@'),
        "password-only secret must leave the URL: {clean}"
    );
    let auth = auth.expect("password-only userinfo still authenticates");
    assert_eq!(
        auth.to_str().unwrap(),
        format!("Basic {}", base64_encode(b":topsecret")) // golden wire-contract literal (kept bare on purpose)
    );

    let (clean, auth) = split_otlp_credentials("https://tokenuser@host:4318/v1/traces");
    assert!(
        !clean.contains("tokenuser") && !clean.contains('@'),
        "username-only secret must leave the URL: {clean}"
    );
    let auth = auth.expect("username-only userinfo still authenticates");
    assert_eq!(
        auth.to_str().unwrap(),
        format!("Basic {}", base64_encode(b"tokenuser:")) // golden wire-contract literal (kept bare on purpose)
    );
}

#[test]
fn test_split_otlp_credentials_passthrough_without_userinfo() {
    // A credential-free endpoint must be returned unchanged with NO Authorization header, so
    // unauthenticated collectors keep working exactly as before.
    let (clean, auth) = split_otlp_credentials("https://collector.example.com:4318/v1/traces");
    assert_eq!(clean, "https://collector.example.com:4318/v1/traces");
    assert!(auth.is_none(), "no userinfo must mean no auth header");
    // Loopback http collector, also credential-free.
    let (clean, auth) = split_otlp_credentials("http://localhost:4318");
    assert!(auth.is_none());
    assert!(clean.starts_with("http://localhost:4318"));
}

#[test]
fn test_split_otlp_credentials_percent_decodes() {
    // Percent-encoded userinfo (e.g. a password containing `@` or `:`) must be decoded so the
    // wire credential matches what the operator configured. `%40` is `@`, `%3A` is `:`.
    let (clean, auth) = split_otlp_credentials("https://u:p%40ss%3Aword@host/v1/traces");
    assert!(!clean.contains('@'), "userinfo stripped: {clean}");
    let auth = auth.expect("auth header present");
    // Decoded credential is `u:p@ss:word`.
    assert_eq!(
        auth.to_str().unwrap(),
        format!("Basic {}", base64_encode(b"u:p@ss:word")) // golden wire-contract literal (kept bare on purpose)
    );
}

#[test]
fn test_shutdown_tracing_is_noop_when_unconfigured() {
    // OTLP never configured (TRACER_PROVIDER unset): shutdown must be a harmless, panic-free
    // no-op. Also exercises the function so it is not dead code outside `cfg(test)`.
    shutdown_tracing();
}

/// A span-name capture layer, standing in for the OTLP export layer: it records exactly the
/// spans a layer at its position would export.
#[derive(Clone, Default)]
struct SpanCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl<S> tracing_subscriber::Layer<S> for SpanCapture
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &tracing::span::Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if let Ok(mut v) = self.0.lock() {
            v.push(attrs.metadata().name().to_string());
        }
    }
}

/// OTLP must export the request-path spans, which are all `debug`, without the operator having
/// to set `RUST_LOG=debug` and flood stderr. So the OTLP filter floors at DEBUG and is never
/// less verbose than the stderr one.
#[test]
fn otlp_level_floors_at_debug_and_never_trails_stderr() {
    let (stderr, otlp) = log_levels();
    assert!(
        otlp >= tracing_subscriber::filter::LevelFilter::DEBUG,
        "OTLP must capture debug spans; got {otlp:?}"
    );
    assert!(
        otlp >= stderr,
        "OTLP must never be less verbose than stderr; got otlp={otlp:?} stderr={stderr:?}"
    );
}

/// The filters must be attached PER LAYER. A bare `LevelFilter` added to the registry itself is
/// a global filter that gates callsite enablement for every layer, so a more-verbose OTLP filter
/// underneath one records nothing. Both halves are asserted: the correct shape exports the debug
/// span, and the shape this replaced does not.
#[test]
fn a_registry_level_filter_gates_the_otlp_layer() {
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::Layer as _;

    let per_layer = SpanCapture::default();
    {
        let subscriber = tracing_subscriber::registry()
            .with(SpanCapture::default().with_filter(LevelFilter::INFO))
            .with(per_layer.clone().with_filter(LevelFilter::DEBUG));
        let _g = tracing::subscriber::set_default(subscriber);
        let _s = tracing::debug_span!("forward").entered();
    }
    assert_eq!(
        *per_layer.0.lock().unwrap(),
        vec!["forward".to_string()],
        "per-layer filters must let the OTLP layer see debug spans the stderr layer skips"
    );

    let under_global = SpanCapture::default();
    {
        let subscriber = tracing_subscriber::registry()
            .with(LevelFilter::INFO)
            .with(under_global.clone().with_filter(LevelFilter::DEBUG));
        let _g = tracing::subscriber::set_default(subscriber);
        let _s = tracing::debug_span!("forward").entered();
    }
    assert!(
        under_global.0.lock().unwrap().is_empty(),
        "a registry-level filter suppresses the callsite for every layer beneath it"
    );
}
