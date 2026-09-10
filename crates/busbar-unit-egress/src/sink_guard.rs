// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The SINK GUARD: may this unit send there at all?
//!
//! MOVED HERE, not written here. This is the operator-supplied-URL guard suite that lived in the
//! retiring engine's `observability` module, where it guarded the two sinks that module owned — the
//! request-log webhook and the OTLP trace collector. It is here because the question it answers is
//! this unit's question and no other's: the egress unit is the one that decides whether a
//! destination may be dialled, and a sink URL an operator typed is a destination like any other.
//!
//! WHAT IS AND IS NOT DUPLICATED. The range predicates are NOT copied: `ipv4_is_internal`,
//! `ipv6_is_internal`, `ip_is_internal` and `is_alternate_ipv4_encoding` are called from
//! [`busbar_unit_trust::net`], exactly as they were called from the engine's own shim, so a
//! contributor hardening one guard against a new range cannot miss this one. What IS here is the
//! two POLICIES — what a request-log webhook may target, and what a trace collector may target —
//! and the URL-shaped atoms they are written over. The two policies deliberately DIVERGE on the
//! `localhost` family and on plaintext to loopback, and each documents its own divergence; that
//! divergence is the reason they are two functions and not one with a flag.
//!
//! THE ONE SIGNATURE CHANGE. [`validate_otlp_endpoint`] resolves the collector's NAME, not just its
//! text, because a name pointed at an internal address passes every textual check. A unit does no
//! I/O, so the resolution enters as an argument — the caller passes the resolver it already has,
//! and the DECISION about what a resolved address means stays here with the rest of the policy.
//! Everything else moved by identity: same names, same bodies, same refusal words, same tests.

use std::net::IpAddr;

use busbar_unit_trust::net::{
    ip_is_internal, ipv4_is_internal as net_guard_ipv4_is_internal, ipv6_is_internal,
    is_alternate_ipv4_encoding,
};

/// The `https` scheme word used by `scheme_is` to enforce TLS on webhook/OTLP endpoints.
const SCHEME_HTTPS: &str = "https";
/// The `http` scheme word used by `scheme_is` to permit plaintext on loopback OTLP endpoints.
const SCHEME_HTTP: &str = "http";

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

/// True when `url`'s scheme equals `scheme` (an all-lowercase ASCII scheme word like `https`),
/// compared CASE-INSENSITIVELY per RFC 3986 §3.1. Matches `<scheme>://...`; the `://` is required so
/// `httpsx://` does not match `https`. Avoids the case-sensitivity bug in a raw
/// `starts_with("https://")`, which rejects the valid uppercase spelling `HTTPS://host/` that
/// reqwest's `Url::parse` would happily lowercase and accept.
fn scheme_is(url: &str, scheme: &str) -> bool {
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
/// This guard is a SIBLING of `busbar_unit_trust::net::ssrf_blocked_host`, not an exact mirror of it — the
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
///     ALLOWS `localhost`: it is a metadata-denylist guard for provider base-URLs, and `localhost`
///     is a legitimate local-model upstream (e.g. Ollama on `http://localhost:11434`). So the two
///     guards do NOT block the same set on the localhost family — they intentionally differ.
///
/// `None` (webhook disabled) is always valid. Pure, so it is unit-testable without touching the
/// process-wide `OnceLock`s. Called by the built-in request-log-webhook /
/// generic-webhook exporters that own the delivery.
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
/// literals (they resolve, at connect time, to the IMDS family). This holds ONLY the two metadata
/// names; the `localhost` / `*.localhost` family is blocked separately in the `Err(_)` DNS arm of
/// `host_is_internal`. NOTE the deliberate divergence: `busbar_unit_trust::net::ssrf_blocked_host` (the
/// provider-base-URL guard) does NOT block `localhost` — it ALLOWS it as a legitimate local-model
/// upstream — so this const overlaps `ssrf_blocked_host`'s metadata denylist only on the shared
/// cloud-metadata names; the two guards block DIFFERENT sets on the localhost family.
const METADATA_HOSTS: &[&str] = &["metadata.google.internal", "metadata.internal"];

/// True for an IPv4 literal busbar must not POST telemetry to. Shared by the V4 arm and the
/// IPv4-mapped-IPv6 arm so the two stay identical. Covers loopback, link-local (incl. the
/// `169.254.169.254` IMDS endpoint), RFC1918 private, RFC6598 CGNAT, unspecified, and broadcast.
fn is_internal_v4(v4: &std::net::Ipv4Addr) -> bool {
    // THE PREDICATE ITSELF LIVES IN `busbar_unit_trust::net` and is called, not copied. It used to be spelled
    // out here, and the A2A card-fetch guard would have been the THIRD copy of the same range list
    // (Azure WireServer and OCI IMDS in particular sit on public addresses that every range
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
/// This shares its threat model with `busbar_unit_trust::net::ssrf_blocked_host` but is NOT a bit-for-bit
/// mirror — the divergences are (1) host parsing: this guard reads the host from an already
/// `url::Url::parse`d URL, while `ssrf_blocked_host` hand-parses and percent-decodes the raw
/// config string; (2) broadcast: this guard ALSO blocks `255.255.255.255`, which `ssrf_blocked_host`
/// does not; (3) LOCALHOST: this guard BLOCKS `localhost`/`*.localhost` (matched in the `Err(_)`
/// DNS arm below), whereas `ssrf_blocked_host` deliberately ALLOWS it as a local-model upstream — so
/// the blocked SETS differ on the localhost family (as well as on the broadcast literal). Full
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
            // metadata and IP-literal guards. Mirrors `busbar_unit_trust::net::ssrf_blocked_host`.
            let host = host.strip_suffix('.').unwrap_or(host);

            // Cloud-metadata DNS names (e.g. `metadata.google.internal`) resolve to internal/IMDS
            // targets but are not IP literals, so check them BEFORE the parse() fallthrough.
            if METADATA_HOSTS.iter().any(|m| host.eq_ignore_ascii_case(m)) {
                return true;
            }

            // Defense-in-depth parity mirror via the shared `busbar_unit_trust::net::is_alternate_ipv4_encoding`, NOT the
            // primary guard. For an http(s) URL the PRIMARY protection is `url::Url::parse`: http(s)
            // is a WHATWG "special scheme", so its host parser already canonicalizes every alternate
            // IPv4 encoding to a dotted-quad BEFORE we ever read `host_str()` — `2130706433` /
            // `0x7f000001` / `017700000001` / `127.1` / `0177.0.0.1` all arrive here as `127.0.0.1`,
            // which the canonical `parse::<IpAddr>()` arm below then blocks. So `host_str()` is already
            // a dotted-quad and this branch does not meaningfully fire on the http(s) SSRF path. It is
            // retained for structural parity with the provider-base-URL guard (which hand-parses a raw config
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
                // which `busbar_unit_trust::net::ipv6_is_internal` has. `[ff02::1]` is the all-nodes group: it
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

/// Validate an operator-configured OTLP endpoint as an SSRF-safe export target, mirroring the
/// webhook guard (`validate_webhook_url`) so the documented invariant "observability sinks are
/// SSRF-safe" holds for OTLP as well, not just the webhook. Two differences from the webhook guard,
/// both deliberate:
///   1. SCHEME: `http://` is permitted in addition to `https://`, but ONLY for a loopback/localhost
///      target, because the standard OTLP collector deployment is a co-located
///      `http://localhost:4318` (or a sidecar) — a plaintext loopback hop never leaves the host, so
///      it carries no exfiltration risk. Plaintext `http://` to a NON-loopback (remote) collector is
///      rejected: span data carries key_ids, pool names, and governance decisions, so a remote sink
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
pub fn validate_otlp_endpoint(
    endpoint: Option<&str>,
    resolve: &dyn Fn(&str, u16) -> Vec<IpAddr>,
) -> Result<Option<String>, String> {
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
    // not an address until something resolves it. Span data carries key_ids, pool names and
    // governance decisions, so the export sink has to be checked as an address, not as a string.
    //
    // Safe to do here: this runs from `init_logging` on the RUNTIME boot path only. `--validate`
    // documents that it performs no network I/O and reaches the OTLP endpoint through
    // the config validator's own pure textual guard, which is deliberately left alone.
    if let Some(offender) = otlp_resolves_to_internal(&parsed, resolve) {
        return Err(format!(
            "observability.otlp_endpoint resolves to the internal address {offender} (SSRF guard; \
             loopback/localhost collectors are allowed); got '{}'",
            mask_userinfo(e)
        ));
    }
    // The `http://` carve-out is ONLY for the co-located loopback collector. A plaintext hop to a
    // REMOTE collector would put span data (key_ids, pool names, governance decisions) on the wire in
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
fn otlp_resolves_to_internal(
    url: &url::Url,
    resolve: &dyn Fn(&str, u16) -> Vec<IpAddr>,
) -> Option<IpAddr> {
    let host = url.host_str()?;
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    let host = host.strip_suffix('.').unwrap_or(host);
    // An IP literal was already ruled on textually; resolving it could only agree with itself.
    if host.parse::<IpAddr>().is_ok() || is_alternate_ipv4_encoding(host) {
        return None;
    }
    let port = url.port_or_known_default().unwrap_or(443);
    // THE RESOLUTION IS THE CALLER'S — a unit does no I/O. What it means is still decided here: a
    // resolution FAILURE arrives as an empty answer, which finds nothing and therefore refuses
    // nothing, exactly as the `.ok()?` it replaces did. A collector whose DNS is briefly down is an
    // availability event, not a security one.
    resolve(host, port).into_iter().find(otlp_addr_is_internal)
}

/// The internal-address predicate for an ALREADY-RESOLVED address, carrying the same loopback
/// carve-out [`otlp_host_is_blocked`] applies to literals — so a name and a literal spelling of one
/// address can never get different verdicts, which is the inconsistency that makes a guard
/// bypassable.
fn otlp_addr_is_internal(ip: &IpAddr) -> bool {
    // ONE relaxation of the shared predicate, expressed as a relaxation rather than as a second
    // table. `http://localhost:4318` is the standard collector, so loopback — and only loopback — is
    // carved out; everything `busbar_unit_trust::net::ip_is_internal` refuses is still refused here. Written this
    // way so a range added to the shared predicate reaches this guard automatically: the previous
    // spelling was a hand-copied v6 arm that had already lost `is_multicast()`.
    !ip_is_loopback(ip) && ip_is_internal(ip)
}

/// LOOPBACK, in every spelling a connecting stack routes to the local host: the v4 `127.0.0.0/8`
/// block, IPv6 `::1`, and the embedded-v4 forms (`::ffff:127.0.0.1`, `::127.0.0.1`).
///
/// `to_ipv4()` rather than `to_ipv4_mapped()`, and `::1` tested FIRST, for the reason
/// [`busbar_unit_trust::net::ipv6_is_internal`] documents: `::1` canonicalizes to `0.0.0.1` under
/// `to_ipv4()`, which is not a v4 loopback.
fn ip_is_loopback(ip: &IpAddr) -> bool {
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
            // busbar_unit_trust::net::ssrf_blocked_host. (Loopback `127.0.0.1.` still canonicalizes to the
            // allowed collector carve-out below.)
            let host = host.strip_suffix('.').unwrap_or(host);

            if METADATA_HOSTS.iter().any(|m| host.eq_ignore_ascii_case(m)) {
                return true;
            }
            // Defense-in-depth parity mirror via the shared `busbar_unit_trust::net::is_alternate_ipv4_encoding`, NOT the
            // primary guard. As in `host_is_internal`, for an http(s) URL `url::Url::parse` has
            // already canonicalized every alternate IPv4 encoding to a dotted-quad before `host_str()`
            // is read (http(s) is a WHATWG special scheme): `2130706433` / `0x7f000001` /
            // `017700000001` / `127.1` arrive here as `127.0.0.1`, so this branch does not meaningfully
            // fire on the http(s) export path — the canonical `parse::<IpAddr>()` arm below applies the
            // loopback-collector carve-out and the internal-v4 block. It is retained for structural
            // parity with the provider-base-URL guard and as belt-and-suspenders for any pre-normalization host.
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

// ── THE URL-COMPONENT DECODER ────────────────────────────────────────────────────────────────────
//
// It arrives here with the rest of the URL-shaped atoms and for the same reason: it has TWO readers
// that live in different crates — the OTLP credential split at boot, and the protocol catch-all's
// raw-path dispatch on the request path — and a decoder that both call is either in one place both
// can name or it is two decoders. It was already the latter twice over: two further hand-copies of
// this exact function sat in the retiring engine, at `ingress/mod.rs` (test-support only, one
// reader) and `oauth_as/routes.rs` (the form-urlencoded variant: this decoder plus `+` → space).
// Both are DELETED against this one; the form reader folds `+` on the raw bytes and calls here.

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

#[cfg(test)]
#[path = "tests/sink_guard_tests.rs"]
mod sink_guard_tests;
