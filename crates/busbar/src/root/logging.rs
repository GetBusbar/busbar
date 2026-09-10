// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The process's logging: the subscriber install, the two level filters, the OTLP trace export and
//! the tracer shutdown.
//!
//! MOVED HERE, not written here. This is the retiring engine's `observability` module minus the
//! sink guard (which went to the egress unit) and minus `percent_decode` (whose reader is still on
//! the request path). It is here because it is BOOT, by definition and by measurement: three call
//! sites, all three in `main`, and a process installs its logging exactly once. A library crate
//! that installs a process-global subscriber is a library that cannot be linked twice.
//!
//! THE TWO FILTERS ARE NOT THE SAME FILTER, and that is the design rather than an oversight. stderr
//! takes `RUST_LOG`, default `info`. OTLP FLOORS at DEBUG, because every request-path span is
//! emitted at debug so it costs nothing on the stderr path at the default level; exporting at the
//! stderr level meant an operator who configured a collector received no request trace at all. Both
//! are attached PER LAYER — a bare `LevelFilter` on the registry is a GLOBAL filter that gates
//! callsite enablement for every layer, so an OTLP-specific filter underneath one is inert.
//!
//! THE ORDERING IS LOAD-BEARING. The exporter and provider are built BEFORE the subscriber is
//! installed, but the global side effect (`set_tracer_provider`) is deferred until `try_init()`
//! actually succeeds — a repeated call must not leave a new provider behind an old subscriber.

use std::sync::OnceLock;

use busbar_unit_egress::sink_guard::{mask_userinfo, percent_decode, validate_otlp_endpoint};

/// The HTTP Basic auth scheme prefix (RFC 7617). Includes the trailing space so callers can
/// write `format!("{OTLP_AUTH_SCHEME}{token}")` without hard-coding the space.
const OTLP_AUTH_SCHEME: &str = "Basic ";

/// Standard base64 (RFC 4648 §4, with `=` padding) of arbitrary bytes. Used only to build the
/// `Authorization: Basic <base64(user:pass)>` header value for OTLP export (see
/// `split_otlp_credentials`); we hand-roll it rather than pull a `base64` crate into the direct
/// dependency set (the encoder is a dozen lines and runs once, at startup, off the request path).
/// Pure, so it is unit-testable.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        // Pack up to three input bytes into a 24-bit big-endian buffer; absent bytes are 0.
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        // The 3rd/4th sextets become `=` padding when the input chunk was short.
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Split any embedded userinfo (`scheme://user:pass@host/...`) OUT of a validated OTLP endpoint,
/// returning `(clean_endpoint, authorization)`:
///   * `clean_endpoint` is the endpoint with the userinfo component removed entirely, so the URI the
///     OTLP SDK stores and may echo into its own error/debug messages NEVER carries the secret.
///   * `authorization`, when the endpoint carried a non-empty username or any password, is
///     `Some(Authorization: Basic base64(user:pass))` — the credential is moved off the URL and into
///     a request header (passed as the `HyperClient::new` 3rd argument), which the SDK does not log.
///
/// This splits the credential out of the URL so the endpoint handed to the SDK never carries the secret:
/// masking only sanitized busbar's OWN log lines, but the raw URL was still handed to
/// `with_endpoint()`, so SDK-internal diagnostics could expose the secret in the request URI.
///
/// A URL with no userinfo, or a string that does not parse as a URL, yields `(endpoint unchanged,
/// None)` — we must not mangle a credential-free endpoint, and validation already accepted it. Pure,
/// so it is unit-testable without process-wide state.
fn split_otlp_credentials(endpoint: &str) -> (String, Option<http::header::HeaderValue>) {
    let Ok(mut parsed) = url::Url::parse(endpoint) else {
        return (endpoint.to_string(), None);
    };
    let username = parsed.username().to_string();
    let password = parsed.password().map(str::to_string);
    if username.is_empty() && password.is_none() {
        return (endpoint.to_string(), None);
    }
    // Per RFC 7617 the Basic credential is `base64(user-id ":" password)`, with an empty password
    // when none was supplied. The userinfo arrives percent-encoded in the URL; decode it so the wire
    // credential matches what the operator configured.
    let user = percent_decode(&username);
    let pass = percent_decode(password.as_deref().unwrap_or(""));
    let token = base64_encode(format!("{user}:{pass}").as_bytes());
    // Strip the userinfo from the URL so the endpoint handed to the SDK is credential-free. Both
    // setters return `Err(())` only for a cannot-be-a-base URL, which a URL that parsed WITH userinfo
    // is not; on the unexpected error we still must not leak, so fall back to a host-only rebuild.
    let clean = if parsed.set_username("").is_err() || parsed.set_password(None).is_err() {
        let host = parsed.host_str().unwrap_or("");
        match parsed.port() {
            Some(p) => format!("{}://{host}:{p}", parsed.scheme()),
            None => format!("{}://{host}", parsed.scheme()),
        }
    } else {
        parsed.into()
    };
    // `HeaderValue::from_str` only fails on bytes a header value cannot carry; a base64 token is pure
    // ASCII from `[A-Za-z0-9+/=]`, so this never fails. If it somehow did, drop the credential rather
    // than panic on the startup path — the export simply goes out unauthenticated.
    let auth = http::header::HeaderValue::from_str(&format!("{OTLP_AUTH_SCHEME}{token}")).ok();
    (clean, auth)
}

/// Retained `SdkTracerProvider` handle so its batched span buffer can be flushed/shut down on
/// process exit (`shutdown_tracing`). Set at most once, only after the subscriber installs
/// successfully — see `init_logging`.
static TRACER_PROVIDER: OnceLock<opentelemetry_sdk::trace::SdkTracerProvider> = OnceLock::new();

/// Install the process-wide `tracing` subscriber once at startup: always a stderr `fmt` layer
/// (level from `RUST_LOG`, default `info`) so spans/warnings are visible out of the box, plus an
/// OpenTelemetry OTLP/HTTP export layer when `observability.otlp_endpoint` is set. Resilient: an
/// OTLP build failure logs and continues with stderr-only logging rather than crashing serving.
///
/// The global OTLP tracer provider is installed only AFTER `try_init()` succeeds: a repeated call
/// (e.g. a re-init path or a second test) must not mutate global tracing state when the new
/// subscriber is not actually installed, which would otherwise leave a new provider behind an old
/// subscriber.
/// The stderr and OTLP level filters, which are deliberately NOT the same.
///
/// stderr takes `RUST_LOG` (a bare level word, e.g. `debug`), default `info`. Full `EnvFilter`
/// directive syntax (`busbar=debug,hyper=warn`) would require the `env-filter` feature.
///
/// OTLP floors at DEBUG (== `busbar_substrate::observability::HOTPATH_LEVEL`, the one-spot hot-path
/// tracing seam), because every request-path span (`forward`,
/// `gemini_ingress`, `bedrock_converse`, `named`, `adhoc`) is emitted at debug so it costs nothing on the stderr path
/// at the default level. Exporting at the stderr level meant an operator who configured a collector
/// received no request trace at all — only the one span that happens to default to INFO, orphaned
/// from the parent that was never created. The two must be independent: turning traces on must not
/// require `RUST_LOG=debug`, which would flood stderr with every debug line in the process.
///
/// Both are attached PER LAYER. A bare `LevelFilter` added to the registry itself is a GLOBAL
/// filter that gates callsite enablement for every layer, so an OTLP-specific filter underneath one
/// is inert.
fn log_levels() -> (
    tracing_subscriber::filter::LevelFilter,
    tracing_subscriber::filter::LevelFilter,
) {
    let stderr = std::env::var("RUST_LOG")
        .ok()
        .and_then(|v| v.trim().parse::<tracing::Level>().ok())
        .unwrap_or(tracing::Level::INFO);
    // `Level`'s ordering is by verbosity, so this is "DEBUG, or more verbose if asked for".
    let otlp = stderr.max(tracing::Level::DEBUG);
    (
        tracing_subscriber::filter::LevelFilter::from_level(stderr),
        tracing_subscriber::filter::LevelFilter::from_level(otlp),
    )
}

/// `stdout_reserved`: the MCP STDIO SERVE MODE's one logging requirement. In `--mcp-stdio` the
/// process's stdout IS the protocol channel — `STDIO.STDOUT-ONLY-MCP` forbids anything on it that
/// is not a JSON-RPC message — so every log line moves to stderr, which is where the transport
/// spec sends a server's diagnostics anyway. The listener modes keep stdout, unchanged.
pub fn init_logging(otlp_endpoint: Option<&str>, stdout_reserved: bool) {
    use tracing_subscriber::fmt::writer::BoxMakeWriter;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    use tracing_subscriber::Layer as _;
    let (stderr_filter, otlp_filter) = log_levels();
    let make_writer = if stdout_reserved {
        BoxMakeWriter::new(std::io::stderr)
    } else {
        BoxMakeWriter::new(std::io::stdout)
    };
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(make_writer)
        .with_target(false)
        .with_filter(stderr_filter);

    // SSRF-validate the OTLP endpoint BEFORE building the exporter, so a config pointing at cloud
    // metadata / an internal service (e.g. `https://169.254.169.254/v1/traces`) is rejected and OTLP
    // left disabled — span data carries key_ids, pool names, and governance decisions, so the export
    // sink must be SSRF-safe (parity with the request-log webhook; loopback collectors are allowed).
    // THE RESOLUTION IS THIS SIDE'S; the verdict is the unit's. A unit does no I/O, so the guard
    // takes the lookup as an argument and decides what the answer means. `to_socket_addrs` is the
    // same call the guard used to make in-line, and the same failure-is-not-a-rejection reading
    // holds: a lookup that errors yields no addresses, which refuses nothing.
    let resolve = |host: &str, port: u16| -> Vec<std::net::IpAddr> {
        use std::net::ToSocketAddrs as _;
        (host, port)
            .to_socket_addrs()
            .map(|it| it.map(|sa| sa.ip()).collect())
            .unwrap_or_default()
    };
    let validated_otlp = match validate_otlp_endpoint(otlp_endpoint, &resolve) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("busbar: {msg}; disabling OTLP trace export");
            None
        }
    };
    let otlp_endpoint = validated_otlp.as_deref();

    // Build the OTLP exporter/provider BEFORE installing the subscriber, but defer the global
    // side effect (`set_tracer_provider`) until we know the subscriber actually installed.
    let otel = otlp_endpoint.and_then(build_otlp);
    // Decompose into the layer (used to build the subscriber) and the provider (installed on
    // success). `Option<Layer>` is itself a `Layer`, so it composes cleanly when absent.
    let (otel_layer, otel_provider) = match otel {
        Some((layer, provider)) => (Some(layer.with_filter(otlp_filter)), Some(provider)),
        None => (None, None),
    };

    let initialized = tracing_subscriber::registry()
        .with(fmt_layer)
        .with(otel_layer)
        .try_init()
        .is_ok();
    if !initialized {
        eprintln!("busbar: tracing subscriber already initialized");
        // Subscriber not installed — do NOT mutate global tracing state. The provider we built is
        // dropped here, which shuts down its (never-used) exporter cleanly.
        return;
    }
    if let Some(provider) = otel_provider {
        opentelemetry::global::set_tracer_provider(provider.clone());
        // Retain the handle for an explicit shutdown/flush on exit.
        let _ = TRACER_PROVIDER.set(provider);
    }
    if let Some(endpoint) = otlp_endpoint {
        // Mask any embedded userinfo (`https://user:pass@host`) BEFORE logging — the raw endpoint
        // can carry operator credentials that must not leak into structured logs.
        let endpoint = mask_userinfo(endpoint);
        tracing::info!(endpoint, "OTLP tracing enabled");
    }
}

/// Flush and shut down the OTLP tracer provider's batched span buffer. Idempotent and a no-op when
/// OTLP was never configured. Wired into the server's graceful-shutdown path (`main.rs`:
/// `tls::serve(...)` / `tls::serve_plain(...)` driven by `shutdown_signal()`, then `shutdown_tracing()`) so the
/// final spans (often the most diagnostic) are exported rather than dropped when the runtime tears
/// down. Covered by `test_shutdown_tracing_is_noop_when_unconfigured`.
pub fn shutdown_tracing() {
    if let Some(provider) = TRACER_PROVIDER.get() {
        if let Err(e) = provider.shutdown() {
            eprintln!("busbar: OTLP tracer shutdown failed ({e})");
        }
    }
}

/// Build the OpenTelemetry tracing layer + retained provider for OTLP/HTTP export to `endpoint`.
/// Returns `None` (and logs to stderr — the subscriber isn't up yet) if the exporter can't be
/// built. Does NOT install the global provider; the caller does so only after the subscriber is
/// successfully installed.
fn build_otlp<S>(
    endpoint: &str,
) -> Option<(
    impl tracing_subscriber::Layer<S>,
    opentelemetry_sdk::trace::SdkTracerProvider,
)>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig as _;
    use opentelemetry_otlp::WithHttpConfig as _;

    // Build a hyper-based HTTP client for trace export that does NOT follow redirects. hyper is a
    // low-level client (unlike reqwest it performs no automatic redirect handling), so a validated
    // OTLP endpoint cannot 3xx-redirect the exporter to an internal/metadata target at runtime —
    // closing the redirect-SSRF vector the bundled reqwest client left open. Using hyper-rustls also
    // keeps OTLP on busbar's single client stack (no duplicate reqwest major). `https_or_http` accepts
    // an `http://` collector (e.g. a localhost sidecar) as well as `https://`.
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    // Move any embedded userinfo (`https://user:pass@host`) OUT of the URL and into an
    // `Authorization: Basic ...` header: the endpoint string passed to `with_endpoint`
    // below — which the OTLP SDK may echo into its own error/debug messages as the request URI —
    // must never carry the operator's secret. The credential travels as the `HyperClient::new` 3rd
    // argument (`authorization`), which the SDK injects per-request and does not log.
    let (clean_endpoint, authorization) = split_otlp_credentials(endpoint);
    let http_client = opentelemetry_http::hyper::HyperClient::new(
        https,
        std::time::Duration::from_secs(10),
        authorization,
    );

    let exporter = match opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_http_client(http_client)
        .with_endpoint(&clean_endpoint)
        .build()
    {
        Ok(e) => e,
        Err(e) => {
            eprintln!("busbar: OTLP exporter init failed ({e}); continuing with stderr logging");
            return None;
        }
    };
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .build();
    let tracer = provider.tracer("busbar");
    let layer = tracing_opentelemetry::layer().with_tracer(tracer);
    Some((layer, provider))
}

#[cfg(test)]
#[path = "tests/logging.rs"]
mod tests;
