// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OTLP SPAN EXPORTER, at the composition root (K9e-1, a stepping stone to the
//! `busbar-export-otlp` plugin). An `export.<name>.module: otlp` instance's `settings.url` is
//! SSRF-validated here, the OpenTelemetry OTLP/HTTP exporter and tracer provider are built here, the
//! layer is handed to the kernel's [`busbar_kernel::observability::init_logging`], and the provider
//! is installed — and flushed on shutdown — here. The code is the kernel's, moved unchanged: the
//! same layer, the same exporter, the same guard and the same lines, so the bytes a collector
//! receives do not move.

use busbar_kernel::net_guard::{is_alternate_ipv4_encoding, METADATA_HOSTS};
use busbar_kernel::observability::{mask_userinfo, percent_decode, scheme_is, ExporterBase};
use opentelemetry_sdk::trace::SdkTracerProvider;
use std::sync::OnceLock;

/// The `https` scheme word, for the OTLP guard's scheme checks.
const SCHEME_HTTPS: &str = "https";

/// Install the process-wide `tracing` subscriber (the kernel's [`init_logging`]) with the OTLP
/// export layer when `observability.otlp_endpoint` is set. Resilient: an OTLP build failure logs
/// and continues with stderr-only logging rather than crashing serving.
///
/// The global OTLP tracer provider is installed only AFTER the subscriber installs: a repeated call
/// (e.g. a re-init path or a second test) must not mutate global tracing state when the new
/// subscriber is not actually installed, which would otherwise leave a new provider behind an old
/// subscriber.
///
/// [`init_logging`]: busbar_kernel::observability::init_logging
pub fn init_logging(otlp_endpoint: Option<&str>, stdout_reserved: bool) {
    // SSRF-validate the OTLP endpoint BEFORE building the exporter, so a config pointing at cloud
    // metadata / an internal service (e.g. `https://169.254.169.254/v1/traces`) is rejected and OTLP
    // left disabled — span data carries key_ids and other governance-relevant request details, so the export
    // sink must be SSRF-safe (parity with the request-log webhook; loopback collectors are allowed).
    let validated_otlp = match validate_otlp_endpoint(otlp_endpoint) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("busbar: {msg}; disabling OTLP trace export");
            None
        }
    };
    let otlp_endpoint = validated_otlp.as_deref();

    // Build the OTLP exporter/provider BEFORE installing the subscriber, but defer the global
    // side effect (`set_tracer_provider`) until we know the subscriber actually installed.
    let otel = otlp_endpoint.and_then(build_otlp::<ExporterBase>);
    // Decompose into the layer (used to build the subscriber) and the provider (installed on
    // success).
    let (otel_layer, otel_provider) = match otel {
        Some((layer, provider)) => (Some(layer), Some(provider)),
        None => (None, None),
    };
    // Subscriber not installed — do NOT mutate global tracing state. The provider we built is
    // dropped here, which shuts down its (never-used) exporter cleanly.
    if busbar_kernel::observability::init_logging(otel_layer, stdout_reserved) {
        install_otlp(otel_provider, otlp_endpoint);
    }
}

/// The HTTP Basic auth scheme prefix (RFC 7617). Includes the trailing space so callers can
/// write `format!("{OTLP_AUTH_SCHEME}{token}")` without hard-coding the space.
const OTLP_AUTH_SCHEME: &str = "Basic ";

/// The `http` scheme word used by `scheme_is` to permit plaintext on loopback OTLP endpoints.
const SCHEME_HTTP: &str = "http";

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
static TRACER_PROVIDER: OnceLock<SdkTracerProvider> = OnceLock::new();

/// Install a built OTLP provider and say so — the "enabled" line is gated on the PROVIDER, never on
/// the endpoint alone. An endpoint whose exporter failed to build (`build_otlp`'s `None` arm, which
/// has already said so on stderr) installs nothing and exports nothing, and a boot log that still
/// read "OTLP tracing enabled" is the line a rollout check greps for and believes (item 570).
fn install_otlp(provider: Option<SdkTracerProvider>, endpoint: Option<&str>) {
    let (Some(provider), Some(endpoint)) = (provider, endpoint) else {
        return;
    };
    opentelemetry::global::set_tracer_provider(provider.clone());
    // Retain the handle for an explicit shutdown/flush on exit.
    let _ = TRACER_PROVIDER.set(provider);
    // Mask any embedded userinfo (`https://user:pass@host`) BEFORE logging — the raw endpoint can
    // carry operator credentials that must not leak into structured logs.
    tracing::info!(endpoint = mask_userinfo(endpoint), "OTLP tracing enabled");
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

/// Validate an operator-configured OTLP endpoint as an SSRF-safe export target, mirroring the
/// webhook guard (`validate_webhook_url`) so the documented invariant "observability sinks are
/// SSRF-safe" holds for OTLP as well, not just the webhook. Two differences from the webhook guard,
/// both deliberate:
///   1. SCHEME: `http://` is permitted in addition to `https://`, but ONLY for a loopback/localhost
///      target, because the standard OTLP collector deployment is a co-located
///      `http://localhost:4318` (or a sidecar) — a plaintext loopback hop never leaves the host, so
///      it carries no exfiltration risk. Plaintext `http://` to a NON-loopback (remote) collector is
///      rejected: span data carries key_ids and other governance-relevant request details, so a remote sink
///      MUST use `https://` to avoid sending traces in cleartext over the network. Any other scheme
///      is rejected.
///   2. LOOPBACK: a loopback / `localhost` target is ALLOWED (it IS the standard collector pattern),
///      whereas the webhook blocks it. Everything else `host_is_internal` blocks is STILL blocked:
///      `169.254.169.254` cloud-metadata, the `METADATA_HOSTS` DNS names, RFC1918 private, RFC6598
///      CGNAT, link-local, and the alternate-IPv4 encodings the resolver expands to those targets.
///      So `http://169.254.169.254/v1/traces` or `https://10.0.0.1/collect` is rejected, but
///      `http://localhost:4318` is accepted.
///
/// `None` (OTLP disabled) is always valid. Pure, so it is unit-testable without process-wide state.
fn validate_otlp_endpoint(endpoint: Option<&str>) -> Result<Option<String>, String> {
    let Some(e) = endpoint else {
        return Ok(None);
    };
    // Case-INSENSITIVE scheme check (see `scheme_is`): `HTTP://localhost:4318` / `HTTPS://...` are
    // valid per RFC 3986 and would be wrongly rejected by a literal lowercase `starts_with`.
    if !(scheme_is(e, SCHEME_HTTPS) || scheme_is(e, SCHEME_HTTP)) {
        // Mask any embedded userinfo before it reaches the (logged) error message.
        return Err(format!(
            "observability.otlp_endpoint must be an http:// or https:// URL (got '{}')",
            mask_userinfo(e)
        ));
    }
    let parsed = url::Url::parse(e)
        .map_err(|err| format!("observability.otlp_endpoint is not a valid URL: {err}"))?;
    // Block the internal/metadata set, but carve out loopback (the localhost-collector exception).
    // `otlp_host_is_blocked` is `host_is_internal` minus the loopback/localhost arms.
    if otlp_host_is_blocked(&parsed) {
        return Err(format!(
            "observability.otlp_endpoint must not target a link-local/private/CGNAT/cloud-metadata \
             host (SSRF guard; loopback/localhost collectors are allowed); got '{}'",
            mask_userinfo(e)
        ));
    }
    // RESOLVE the host too, not just read its literal text. `otlp_host_is_blocked` above stops
    // `https://169.254.169.254/v1/traces` and every alternate spelling of it — the misconfiguration
    // and copy-paste case — but a NAME pointed at an internal address passes it, because a name is
    // not an address until something resolves it. Span data carries key_ids and other
    // governance-relevant request details, so the export sink has to be checked as an address, not as a string.
    //
    // Safe to do here: this runs from `init_logging` on the RUNTIME boot path only. `--validate`
    // documents that it performs no network I/O and reaches the OTLP endpoint through
    // `config_validate`'s own pure textual guard, which is deliberately left alone.
    if let Some(offender) = otlp_resolves_to_internal(&parsed) {
        return Err(format!(
            "observability.otlp_endpoint resolves to the internal address {offender} (SSRF guard; \
             loopback/localhost collectors are allowed); got '{}'",
            mask_userinfo(e)
        ));
    }
    // The `http://` carve-out is ONLY for the co-located loopback collector. A plaintext hop to a
    // REMOTE collector would put span data (key_ids and other governance-relevant request details) on the wire in
    // cleartext, so require `https://` for any non-loopback host. (`scheme_is` is case-insensitive,
    // matching the scheme check above; the host already passed `otlp_host_is_blocked`, so a
    // non-loopback host here is an allowed EXTERNAL collector — which must be reached over TLS.)
    if scheme_is(e, SCHEME_HTTP) && !otlp_host_is_loopback(&parsed) {
        return Err(format!(
            "observability.otlp_endpoint must use https:// for a non-loopback collector (plaintext \
             http:// is only permitted for a loopback/localhost collector; traces would otherwise be \
             sent in cleartext); got '{}'",
            mask_userinfo(e)
        ));
    }
    Ok(Some(e.to_string()))
}

/// The first resolved address of `url`'s host that is internal, if any — the resolve half of the
/// OTLP SSRF guard, paired with the literal-text half in [`otlp_host_is_blocked`].
///
/// ANY, not all: a name resolving to one external and one internal address is rejected. Connecting
/// would be a coin flip between them, and "sometimes exports spans to the metadata service" is not a
/// smaller problem than "always does".
///
/// A resolution FAILURE is not a rejection. A collector whose DNS is briefly down is an availability
/// event, not a security one: it cannot reach anything, internal or otherwise, and disabling trace
/// export over a transient blip would be the wrong trade.
///
/// The addresses are NOT pinned for the exporter's own connections, unlike the webrequest hook's
/// forwarder. That is a deliberate difference, not an oversight: the exporter requires `https://`
/// for every non-loopback collector and verifies the certificate against the hostname, so a host
/// that later re-resolves to an internal address cannot present a valid certificate for the
/// configured collector name and the connection fails. TLS closes the rebinding window on this path;
/// on the hook's path the pin is defence in depth on top of the same requirement.
fn otlp_resolves_to_internal(url: &url::Url) -> Option<std::net::IpAddr> {
    use std::net::{IpAddr, ToSocketAddrs};
    let host = url.host_str()?;
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    let host = host.strip_suffix('.').unwrap_or(host);
    // An IP literal was already ruled on textually; resolving it could only agree with itself.
    if host.parse::<IpAddr>().is_ok() || is_alternate_ipv4_encoding(host) {
        return None;
    }
    let port = url.port_or_known_default().unwrap_or(443);
    (host, port)
        .to_socket_addrs()
        .ok()?
        .map(|sa| sa.ip())
        .find(otlp_addr_is_internal)
}

/// The internal-address predicate for an ALREADY-RESOLVED address, carrying the same loopback
/// carve-out [`otlp_host_is_blocked`] applies to literals — so a name and a literal spelling of one
/// address can never get different verdicts, which is the inconsistency that makes a guard
/// bypassable.
fn otlp_addr_is_internal(ip: &std::net::IpAddr) -> bool {
    // ONE relaxation of the shared predicate, expressed as a relaxation rather than as a second
    // table. `http://localhost:4318` is the standard collector, so loopback — and only loopback — is
    // carved out; everything `net_guard::ip_is_internal` refuses is still refused here. Written this
    // way so a range added to the shared predicate reaches this guard automatically: the previous
    // spelling was a hand-copied v6 arm that had already lost `is_multicast()`.
    !ip_is_loopback(ip) && busbar_kernel::net_guard::ip_is_internal(ip)
}

/// LOOPBACK, in every spelling a connecting stack routes to the local host: the v4 `127.0.0.0/8`
/// block, IPv6 `::1`, and the embedded-v4 forms (`::ffff:127.0.0.1`, `::127.0.0.1`).
///
/// `to_ipv4()` rather than `to_ipv4_mapped()`, and `::1` tested FIRST, for the reason
/// [`busbar_kernel::net_guard::ipv6_is_internal`] documents: `::1` canonicalizes to `0.0.0.1` under
/// `to_ipv4()`, which is not a v4 loopback.
fn ip_is_loopback(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4().is_some_and(|v4| v4.is_loopback()),
    }
}

/// True iff the OTLP endpoint URL's host is the loopback/localhost collector target — the exact
/// carve-out `otlp_host_is_blocked` leaves un-blocked: the `localhost` / `*.localhost` DNS names
/// (RFC 6761), the loopback v4 block `127.0.0.0/8`, IPv6 `::1` (incl. its `::ffff:127.x` mapped
/// form), and the alternate-IPv4 spellings of `127.0.0.1` (`is_alternate_loopback_v4`). Used to gate
/// the plaintext-`http://` allowance to loopback only. Mirrors the loopback arms of
/// `otlp_host_is_blocked` so the two stay in lockstep: every host this returns `true` for is a host
/// that guard intentionally permits.
fn otlp_host_is_loopback(url: &url::Url) -> bool {
    use std::net::IpAddr;
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    let host = host.strip_suffix('.').unwrap_or(host);

    // Alternate (non-dotted-quad) IPv4 encodings: only the loopback spellings count (parity with the
    // `is_alternate_ipv4_encoding` arm of `otlp_host_is_blocked`).
    if is_alternate_ipv4_encoding(host) {
        return is_alternate_loopback_v4(host);
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(IpAddr::V6(v6)) => v6.is_loopback() || v6.to_ipv4().is_some_and(|v4| v4.is_loopback()),
        // DNS name: the loopback carve-out is `localhost` / `*.localhost` (RFC 6761). Any other DNS
        // name is an external collector (NOT loopback) and so must use https.
        Err(_) => {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .rsplit_once('.')
                    .is_some_and(|(_, tld)| tld.eq_ignore_ascii_case("localhost"))
        }
    }
}

/// SSRF block predicate for the OTLP endpoint: identical to `host_is_internal` EXCEPT loopback and
/// the `localhost` DNS name are NOT blocked (the standard `http://localhost:4318` collector). Every
/// other internal/metadata target `host_is_internal` rejects is rejected here too — same
/// link-local/IMDS, private, CGNAT, unspecified, alternate-IPv4-encoding, and `METADATA_HOSTS`
/// coverage — so the only relaxation versus the webhook guard is the intentional loopback carve-out.
fn otlp_host_is_blocked(url: &url::Url) -> bool {
    use std::net::IpAddr;
    match url.host_str() {
        // A URL with no host is unusable as an export target; reject it.
        None => true,
        Some(host) => {
            let host = host.strip_prefix('[').unwrap_or(host);
            let host = host.strip_suffix(']').unwrap_or(host);
            // Strip a single trailing FQDN-root dot BEFORE every check — otherwise a trailing-dot
            // metadata name (`metadata.google.internal.`) misses the exact METADATA_HOSTS compare and
            // a trailing-dot internal IP literal (`169.254.169.254.`) fails to parse and falls into
            // the allow-by-default DNS arm, bypassing the block. Mirrors host_is_internal /
            // config_validate::ssrf_blocked_host. (Loopback `127.0.0.1.` still canonicalizes to the
            // allowed collector carve-out below.)
            let host = host.strip_suffix('.').unwrap_or(host);

            if METADATA_HOSTS.iter().any(|m| host.eq_ignore_ascii_case(m)) {
                return true;
            }
            // Defense-in-depth parity mirror via the shared `net_guard::is_alternate_ipv4_encoding`, NOT the
            // primary guard. As in `host_is_internal`, for an http(s) URL `url::Url::parse` has
            // already canonicalized every alternate IPv4 encoding to a dotted-quad before `host_str()`
            // is read (http(s) is a WHATWG special scheme): `2130706433` / `0x7f000001` /
            // `017700000001` / `127.1` arrive here as `127.0.0.1`, so this branch does not meaningfully
            // fire on the http(s) export path — the canonical `parse::<IpAddr>()` arm below applies the
            // loopback-collector carve-out and the internal-v4 block. It is retained for structural
            // parity with `config_validate` and as belt-and-suspenders for any pre-normalization host.
            // Were it to fire, the loopback-vs-internal split below is preserved: a loopback alternate
            // encoding (e.g. `2130706433` == 127.0.0.1) is the localhost-collector exception (allowed);
            // every other alternate encoding is an internal target and is blocked. We can't run
            // getaddrinfo in a pure validator, so be conservative — allow ONLY the canonical
            // decimal/hex/octal/short-dotted spellings of 127.0.0.1, which are unambiguously loopback.
            if is_alternate_ipv4_encoding(host) {
                return !is_alternate_loopback_v4(host);
            }

            match host.parse::<IpAddr>() {
                // Loopback is the allowed collector pattern; every other internal address is
                // blocked, by the SAME predicate the resolved-address arm uses — so an endpoint
                // written as a literal and the same endpoint reached through a name cannot get
                // different verdicts, which is the inconsistency that makes a guard bypassable.
                Ok(ip) => otlp_addr_is_internal(&ip),
                // DNS name: block the cloud-metadata names (handled above) but ALLOW `localhost`
                // (and `*.localhost`) — the loopback carve-out — and any external collector hostname.
                Err(_) => false,
            }
        }
    }
}

/// True iff `host` is an alternate (non-dotted-quad) IPv4 encoding that unambiguously denotes the
/// loopback address `127.0.0.1`: the decimal integer `2130706433`, the hex `0x7f000001`, the octal
/// `017700000001`, or a short-dotted form like `127.1` / `127.0.1`. Used by `otlp_host_is_blocked`
/// to permit the localhost-collector exception while still blocking every other alternate-encoded
/// internal target. Conservative: anything it can't positively confirm as loopback is treated as
/// non-loopback by the caller (and therefore blocked).
fn is_alternate_loopback_v4(host: &str) -> bool {
    // Decimal integer form: must equal 127.0.0.1 == 2130706433.
    if !host.contains('.') {
        if let Some(hex) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
            return u32::from_str_radix(hex, 16).ok() == Some(0x7f00_0001);
        }
        if let Some(oct) = host.strip_prefix('0').filter(|_| host.len() > 1) {
            // Leading-zero octal (e.g. `017700000001`).
            if let Ok(v) = u32::from_str_radix(oct, 8) {
                return v == 0x7f00_0001;
            }
        }
        if let Ok(v) = host.parse::<u32>() {
            return v == 0x7f00_0001;
        }
        return false;
    }
    // Short-dotted form: first octet 127 and every present octet numeric, fewer than 4 parts.
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 4 || parts.is_empty() {
        return false;
    }
    let Some(first) = parts.first().and_then(|p| p.parse::<u32>().ok()) else {
        return false;
    };
    first == 127 && parts.iter().all(|p| p.parse::<u32>().is_ok())
}

/// Build the OpenTelemetry tracing layer + retained provider for OTLP/HTTP export to `endpoint`.
/// Returns `None` (and logs to stderr — the subscriber isn't up yet) if the exporter can't be
/// built. Does NOT install the global provider; the caller does so only after the subscriber is
/// successfully installed.
fn build_otlp<S>(endpoint: &str) -> Option<(impl tracing_subscriber::Layer<S>, SdkTracerProvider)>
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
    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .build();
    let tracer = provider.tracer("busbar");
    let layer = tracing_opentelemetry::layer().with_tracer(tracer);
    Some((layer, provider))
}

#[cfg(test)]
#[path = "tests/otlp.rs"]
mod tests;
