// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Observability beyond Prometheus `/metrics`: the process-wide `tracing` subscriber
//! ([`init_logging`]), the one-spot hot-path level policy, and the URL guard and userinfo masker the
//! request-log webhook and the host's egress carrier use.
//!
//! The OTLP span EXPORTER is not here: it is built, validated, installed and flushed by the
//! composition root (`busbar::root::otlp`, K9e), which hands [`init_logging`] its layer.

// SSRF obfuscation-defense primitives shared with the analogous operator-configured-upstream-URL
// guard in `config_validate`.
// Here they are a defense-in-depth parity mirror (the webhook/OTLP URL is already
// `url::Url::parse`-normalized, so the canonical `parse::<IpAddr>()` path does the real
// blocking); keeping the byte-identical atoms in one tested leaf stops the two guards drifting.
use crate::net_guard::{
    ipv4_is_internal as net_guard_ipv4_is_internal, ipv6_is_internal, is_alternate_ipv4_encoding,
};

// 1.5.3 LIFT-OUT: the request-log webhook DELIVERY (the `WEBHOOK_URL`/`CLIENT`/
// `AdmissionGate` machinery, `configure_webhook`, `fire_request_log`, `build_request_log`) moved OUT
// of this module into the `request-log-webhook` EXPORTER (now the `busbar-export-webhook` plugin). The
// SSRF VALIDATOR ([`validate_webhook_url`] / [`host_is_internal`]) + the userinfo masker
// ([`mask_userinfo`]) STAY here (they are shared, validated primitives — `mask_userinfo` also guards
// the OTLP endpoint log below) and are called BY the exporter. Only distribution moved; validation
// did not.

/// Return `url` with any URL userinfo (`scheme://user:pass@host/...`) masked, SAFE to put in a log
/// line. An operator can embed credentials in a webhook / OTLP endpoint URL (RFC 3986 §3.2.1 allows
/// `user:password@` in the authority), and logging the raw `&str` would leak that secret into the
/// structured logs / stderr. We reparse the string and, if it carries a non-empty username or any
/// password, replace the whole userinfo component with the fixed marker `***` (so it is visible that
/// something was redacted) before reserializing. A URL with no userinfo, or a string that does not
/// parse as a URL, is returned UNCHANGED (allocating a fresh owned `String` either way so callers
/// have one uniform type) — masking must never alter or drop a URL that carried no secret. Pure, so
/// it is unit-testable. Applied at EVERY URL-logging site in this module (the `endpoint` info log and
/// the validation-error messages, which interpolate the raw URL).
pub fn mask_userinfo(url: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(url) else {
        // Not a parseable URL (e.g. the empty string or `not-a-url`): no userinfo to leak, and we
        // must not mangle the operator's original spelling in the diagnostic. Return as-is.
        return url.to_string();
    };
    let has_userinfo = !parsed.username().is_empty() || parsed.password().is_some();
    if !has_userinfo {
        return url.to_string();
    }
    // `set_password(None)` then `set_username("***")` collapses the userinfo to the redaction
    // marker. Both setters return `Err(())` for a "cannot-be-a-base" URL, but a URL that parsed
    // WITH userinfo necessarily has an authority, so these succeed; on the unexpected error we fall
    // back to a host-only reserialization rather than risk logging the secret.
    if parsed.set_password(None).is_err() || parsed.set_username("***").is_err() {
        // Defensive: strip to scheme + host (+ port) so no userinfo can survive into the log.
        let host = parsed.host_str().unwrap_or("");
        return match parsed.port() {
            Some(p) => format!("{}://***@{host}:{p}", parsed.scheme()),
            None => format!("{}://***@{host}", parsed.scheme()),
        };
    }
    parsed.into()
}

/// The `https` scheme word used by `scheme_is` to enforce TLS on webhook/OTLP endpoints.
const SCHEME_HTTPS: &str = "https";
/// Percent-decode a URL component to its raw UTF-8 string, leaving any byte that is not a valid
/// `%XX` escape (or invalid UTF-8) untouched so a credential is never silently corrupted. Also used
/// by the protocol catch-all to decode path-model segments (axum's `Path` extractor decoded them
/// before the collapse; the raw-path dispatch must match).
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// True when `url`'s scheme equals `scheme` (an all-lowercase ASCII scheme word like `https`),
/// compared CASE-INSENSITIVELY per RFC 3986 §3.1. Matches `<scheme>://...`; the `://` is required so
/// `httpsx://` does not match `https`. Avoids the case-sensitivity bug in a raw
/// `starts_with("https://")`, which rejects the valid uppercase spelling `HTTPS://host/` that
/// reqwest's `Url::parse` would happily lowercase and accept.
pub fn scheme_is(url: &str, scheme: &str) -> bool {
    url.split_once("://")
        .is_some_and(|(s, _)| s.eq_ignore_ascii_case(scheme))
}

/// Validate the configured webhook URL. Two guarantees, both enforced (not just documented):
///   1. The scheme MUST be `https` (compared case-insensitively, so `HTTPS://` is accepted) — a
///      plaintext `http://` endpoint would expose per-request metadata on the wire.
///   2. The host MUST NOT be an internal target — loopback / link-local / private (RFC1918) / RFC6598
///      CGNAT / unspecified / broadcast, whether written as a canonical IP literal, an IPv4-mapped
///      IPv6 literal, or an alternate IPv4 encoding (decimal/hex/octal/short-dotted) the resolver
///      still expands; nor a loopback (`localhost`) or cloud-metadata (`metadata.google.internal`)
///      DNS name. The URL may not point at `169.254.169.254` cloud-metadata, `127.0.0.1`,
///      `10.x`/`192.168.x`/`172.16.x` internal services, etc.
///
/// This guard is a SIBLING of `config_validate::ssrf_blocked_host`, not an exact mirror of it — the
/// two cover the same threat (operator-supplied URL pointed at an internal target) but DIVERGE in
/// these respects, so do NOT assume bit-for-bit parity:
///   - HOST PARSING: this validator runs the already-`url::Url::parse`d URL and reads
///     `host_str()` (the URL crate has already percent-decoded and normalized the authority);
///     `ssrf_blocked_host` instead parses the raw config string by hand and percent-decodes the host
///     itself (`percent_decode_host`) to neutralize spellings like `169%2E254%2E169%2E254`.
///   - BROADCAST: this guard ALSO blocks `255.255.255.255` (`is_broadcast()`); `ssrf_blocked_host`
///     does not — so this validator is strictly more conservative on that one literal.
///   - LOCALHOST (a deliberate divergence, NOT just code shape): this webhook guard BLOCKS the
///     `localhost`/`*.localhost` family in the DNS arm of `host_is_internal` — no request-log
///     webhook should POST to a co-located loopback process. `ssrf_blocked_host`, by contrast,
///     ALLOWS `localhost`: it is a metadata-denylist guard for operator-configured upstream URLs, and
///     `localhost` is a legitimate loopback upstream for such a URL. So the two
///     guards do NOT block the same set on the localhost family — they intentionally differ.
///
/// `None` (webhook disabled) is always valid. Pure, so it is unit-testable without touching the
/// process-wide `OnceLock`s. `pub` because it is the URL policy the composition root's egress
/// carrier applies to every target a plugin sink asks the host to admit or carry (K9a S5, K9c) —
/// the `request-log-webhook` sink's among them.
pub fn validate_webhook_url(url: Option<String>) -> Result<Option<String>, String> {
    let Some(u) = url else {
        return Ok(None);
    };
    // Case-INSENSITIVE scheme check: per RFC 3986 the scheme is case-insensitive, and reqwest's
    // `Url::parse` lowercases it — so a valid `HTTPS://host/` (or mixed-case `Https://`) would be
    // wrongly rejected by a literal `starts_with("https://")` on the raw string. Compare the scheme
    // (everything up to and including `://`) without allocating by lowercasing only that prefix.
    if !scheme_is(&u, SCHEME_HTTPS) {
        // Mask any embedded userinfo before it reaches the (logged) error message — the raw URL can
        // carry `user:pass@` operator credentials.
        return Err(format!(
            "observability.request_log_webhook_url must be an https:// URL (got '{}')",
            mask_userinfo(&u)
        ));
    }
    let parsed = url::Url::parse(&u)
        .map_err(|e| format!("observability.request_log_webhook_url is not a valid URL: {e}"))?;
    if host_is_internal(&parsed) {
        return Err(format!(
            "observability.request_log_webhook_url must not target a loopback/link-local/private/\
             CGNAT/cloud-metadata host (SSRF guard); got '{}'",
            mask_userinfo(&u)
        ));
    }
    Ok(Some(u))
}

/// Well-known cloud-metadata / internal DNS names that must be blocked even though they are not IP
/// literals (they resolve, at connect time, to the IMDS family). The `localhost` / `*.localhost`
/// family is blocked separately in the `Err(_)` DNS arm of `host_is_internal`. NOTE the deliberate
/// divergence: `config_validate::ssrf_blocked_host` (the operator-configured-upstream-URL guard)
/// does NOT block `localhost` — it ALLOWS it as a legitimate loopback upstream — so the two guards
/// block DIFFERENT sets on the LOCALHOST family.
///
/// The METADATA family is NOT a place the two may differ, and this is no longer a second copy: it
/// is [`crate::net_guard::METADATA_HOSTS`] itself — which is now the egress unit's list, reached
/// through the re-export shim, so there is exactly ONE metadata list in the tree and this guard
/// reads it rather than a sibling of it. It used to be a private two-name list beside a six-name
/// one, which is a telemetry guard that had never heard of four names the config guard refused.
use crate::net_guard::METADATA_HOSTS;

/// True for an IPv4 literal busbar must not POST telemetry to. Shared by the V4 arm and the
/// IPv4-mapped-IPv6 arm so the two stay identical. Covers loopback, link-local (incl. the
/// `169.254.169.254` IMDS endpoint), RFC1918 private, RFC6598 CGNAT, unspecified, and broadcast.
fn is_internal_v4(v4: &std::net::Ipv4Addr) -> bool {
    // THE PREDICATE ITSELF LIVES IN `net_guard` and is called, not copied. It used to be spelled
    // out here, and another SSRF guard elsewhere in the codebase would have been the THIRD copy of the
    // same range list (Azure WireServer and OCI IMDS in particular sit on public addresses that every range
    // predicate misses, so a copy that forgets them looks correct). Hoisted rather than duplicated:
    // a contributor hardening one guard against a new range must not be able to miss the others.
    net_guard_ipv4_is_internal(v4)
}

/// True if the URL's host is an address busbar must not POST telemetry to: a literal loopback,
/// link-local (incl. `169.254.169.254` cloud-metadata), private (RFC1918 / unique-local), RFC6598
/// CGNAT, unspecified, or broadcast IP — whether written as a canonical IP literal, an IPv4-mapped
/// IPv6 literal, or one of the alternate IPv4 encodings the OS resolver still expands to an internal
/// address (decimal `2130706433`, hex `0x7f000001`, octal, short-dotted `127.1`). A hostname that
/// does not parse as an IP literal is allowed (operators may name an external collector) EXCEPT the
/// well-known loopback DNS name `localhost` (and its dotted subdomains) and the cloud-metadata DNS
/// names in `METADATA_HOSTS`, which are blocked case-insensitively so an `https://localhost:<port>/`
/// or `https://metadata.google.internal/` URL can't be used to POST request logs to a co-located /
/// metadata process.
///
/// This shares its threat model with `config_validate::ssrf_blocked_host` but is NOT a bit-for-bit
/// mirror — the divergences are (1) host parsing: this guard reads the host from an already
/// `url::Url::parse`d URL, while `ssrf_blocked_host` hand-parses and percent-decodes the raw
/// config string; (2) broadcast: this guard ALSO blocks `255.255.255.255`, which `ssrf_blocked_host`
/// does not; (3) LOCALHOST: this guard BLOCKS `localhost`/`*.localhost` (matched in the `Err(_)`
/// DNS arm below), whereas `ssrf_blocked_host` deliberately ALLOWS it as a legitimate loopback
/// upstream — so the blocked SETS differ on the localhost family (as well as on the broadcast literal). Full
/// DNS-rebinding is out of scope for a startup-validated,
/// operator-supplied URL. Returns `true` (reject) when the host is missing entirely.
fn host_is_internal(url: &url::Url) -> bool {
    use std::net::IpAddr;
    match url.host_str() {
        None => true,
        Some(host) => {
            // `Url::host_str` keeps IPv6 literals bracketed; strip for `IpAddr` parsing.
            let host = host.strip_prefix('[').unwrap_or(host);
            let host = host.strip_suffix(']').unwrap_or(host);
            // Strip a single trailing FQDN-root dot BEFORE every check. `Url` preserves it, and
            // getaddrinfo resolves `127.0.0.1.` / `metadata.google.internal.` / `localhost.` to the
            // SAME internal targets as the bare spelling — but without stripping here, the trailing
            // dot makes the IP-literal parse fail (slipping into the DNS arm) and the METADATA_HOSTS
            // exact-compare miss (lengths differ by one), so a trailing-dot host bypassed BOTH the
            // metadata and IP-literal guards. Mirrors `config_validate::ssrf_blocked_host`.
            let host = host.strip_suffix('.').unwrap_or(host);

            // Cloud-metadata DNS names (e.g. `metadata.google.internal`) resolve to internal/IMDS
            // targets but are not IP literals, so check them BEFORE the parse() fallthrough.
            if METADATA_HOSTS.iter().any(|m| host.eq_ignore_ascii_case(m)) {
                return true;
            }

            // Defense-in-depth parity mirror via the shared `net_guard::is_alternate_ipv4_encoding`, NOT the
            // primary guard. For an http(s) URL the PRIMARY protection is `url::Url::parse`: http(s)
            // is a WHATWG "special scheme", so its host parser already canonicalizes every alternate
            // IPv4 encoding to a dotted-quad BEFORE we ever read `host_str()` — `2130706433` /
            // `0x7f000001` / `017700000001` / `127.1` / `0177.0.0.1` all arrive here as `127.0.0.1`,
            // which the canonical `parse::<IpAddr>()` arm below then blocks. So `host_str()` is already
            // a dotted-quad and this branch does not meaningfully fire on the http(s) SSRF path. It is
            // retained for structural parity with `config_validate` (which hand-parses a raw config
            // string where Url::parse has NOT normalized the host, so the check IS load-bearing there)
            // and as belt-and-suspenders should the host ever reach this guard pre-normalization.
            if is_alternate_ipv4_encoding(host) {
                return true;
            }

            match host.parse::<IpAddr>() {
                Ok(IpAddr::V4(v4)) => is_internal_v4(&v4),
                // THE V6 ARM IS THE SHARED PREDICATE, not a local transcription of it. It used to be
                // spelled out here — `is_loopback()`, then `to_ipv4()`, then unspecified /
                // unique-local / link-local — and the transcription had DROPPED `is_multicast()`,
                // which `net_guard::ipv6_is_internal` has. `[ff02::1]` is the all-nodes group: it
                // reaches every host on the segment, and this guard admitted it while the predicate
                // it was written as a sibling of refused it. The order that arm depends on (loopback
                // first, embedded-v4 before the v6 masks) is documented once, on `ipv6_is_internal`.
                Ok(IpAddr::V6(v6)) => ipv6_is_internal(&v6),
                // Not an IP literal — a DNS name. Block the well-known loopback name `localhost`
                // (and any `*.localhost` subdomain, which RFC 6761 reserves to loopback) so it can't
                // be used as an SSRF target; allow any other external-collector hostname. The
                // trailing FQDN-root dot was already stripped above, so `localhost.` and
                // `sub.localhost.` are caught here too.
                Err(_) => {
                    host.eq_ignore_ascii_case("localhost")
                        || host
                            .rsplit_once('.')
                            .is_some_and(|(_, tld)| tld.eq_ignore_ascii_case("localhost"))
                }
            }
        }
    }
}

/// THE TRACING SEAM — the one-spot level policy for every per-request span/event.
///
/// Every per-request span or event MUST be bound to a level, and that level MUST be set in exactly
/// one place. This constant is that one place: every hot-path `#[tracing::instrument]`
/// and every per-request `tracing::debug!`/`trace!` call references `HOTPATH_LEVEL` (or the literal
/// it is set to) rather than picking its own level ad hoc, so raising or lowering the hot-path
/// verbosity for the WHOLE request path is a one-line change here, and `scripts/tracing-lint.sh`
/// fails CI on any `#[instrument]` that skips the reference and hand-picks a level instead (a
/// "rogue trace").
///
/// Deliberately `DEBUG`, not the `tracing::Level::TRACE` variant: `log_levels()` below is the other
/// half of the one-spot policy — it floors the OTLP export filter at DEBUG specifically so an
/// operator who points `observability.otlp_endpoint` at a collector gets every request-path span
/// (this crate's own `named`/`adhoc` ingress spans among them) WITHOUT also having to
/// set `RUST_LOG=debug` and flood stderr with every debug line in the process (see the doc comment
/// on `log_levels`). If `HOTPATH_LEVEL` were `TRACE` instead, that OTLP floor would need to move to
/// TRACE too — losing the "OTLP get the hot path, stderr stays at its own level" split the two-filter
/// design exists for. Both stay OFF at the default `RUST_LOG=info` filter either way: `DEBUG` is
/// less verbose than `TRACE`, so nothing about the "off by default" contract changes with this
/// choice.
// A′ (ABI-purity P4): the hot-path tracing floor relocated DOWN to busbar-substrate so a plane crate
// can name it via the ABI (`busbar_kernel::observability::HOTPATH_LEVEL`). A pure
// compile-time `const` (no registry, no dual-compile concern). Re-exported here so `crate::
// observability::HOTPATH_LEVEL` and every in-core reference stay unchanged and byte-identical.
pub const HOTPATH_LEVEL: tracing::Level = tracing::Level::DEBUG;

/// The stderr and OTLP level filters, which are deliberately NOT the same.
///
/// stderr takes `RUST_LOG` (a bare level word, e.g. `debug`), default `info`. Full `EnvFilter`
/// directive syntax (`busbar=debug,hyper=warn`) would require the `env-filter` feature.
///
/// OTLP floors at DEBUG (== `HOTPATH_LEVEL` above), because every request-path span (including this
/// crate's own `named`/`adhoc` ingress spans) is emitted at debug so it costs nothing on the stderr path
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

/// The subscriber a SPAN EXPORTER layer rides: the registry under the stderr `fmt` layer — the
/// stack [`init_logging`] builds, named so the composition root can build its exporter for it.
pub type ExporterBase = tracing_subscriber::layer::Layered<
    tracing_subscriber::filter::Filtered<
        tracing_subscriber::fmt::Layer<
            tracing_subscriber::Registry,
            tracing_subscriber::fmt::format::DefaultFields,
            tracing_subscriber::fmt::format::Format,
            tracing_subscriber::fmt::writer::BoxMakeWriter,
        >,
        tracing_subscriber::filter::LevelFilter,
        tracing_subscriber::Registry,
    >,
    tracing_subscriber::Registry,
>;

/// Install the process-wide `tracing` subscriber once at startup: always a stderr `fmt` layer
/// (level from `RUST_LOG`, default `info`) so spans/warnings are visible out of the box, plus the
/// composition root's span exporter when one is configured.
///
/// `stdout_reserved`: set by a caller whose transport uses this process's own stdout as its wire
/// channel — the framed protocol on stdout forbids any byte that is not one of its own messages —
/// so every log line moves to stderr instead, which is where such a transport's spec sends a
/// server's diagnostics anyway. The listener modes keep stdout, unchanged.
///
/// `span_exporter`: the composition root's span EXPORTER layer, when one is configured (the OTLP
/// layer, built and validated there), attached under the span exporter's own level filter (see
/// [`log_levels`]). Returns whether the subscriber installed: the caller installs anything global
/// its exporter needs only when it did, so a repeated call never leaves new global state behind an
/// old subscriber.
pub fn init_logging<L>(span_exporter: Option<L>, stdout_reserved: bool) -> bool
where
    L: tracing_subscriber::Layer<ExporterBase> + Send + Sync + 'static,
{
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
    let initialized = tracing_subscriber::registry()
        .with(fmt_layer)
        .with(span_exporter.map(|layer| layer.with_filter(otlp_filter)))
        .try_init()
        .is_ok();
    if !initialized {
        eprintln!("busbar: tracing subscriber already initialized");
    }
    initialized
}

#[cfg(test)]
#[path = "tests/observability_tests.rs"]
mod tests;
