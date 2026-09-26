// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/observability.rs`.

use super::*;

#[test]
fn test_mask_userinfo_strips_credentials() {
    // Regression: a URL with embedded userinfo (`user:pass@host`) must have the secret
    // stripped before it is logged. The masked form must NOT contain the username or password,
    // must replace the userinfo with the `***` marker, and must preserve the host/port/path so
    // the diagnostic is still useful.
    let masked = mask_userinfo("https://alice:s3cr3t@collector.example.com:4318/v1/traces");
    assert!(
        !masked.contains("s3cr3t"),
        "password must not survive masking: {masked}"
    );
    assert!(
        !masked.contains("alice"),
        "username must not survive masking: {masked}"
    );
    assert!(
        masked.contains("***@"),
        "userinfo marker expected: {masked}"
    );
    assert!(
        masked.contains("collector.example.com"),
        "host must be preserved: {masked}"
    );
    assert!(masked.contains("4318"), "port must be preserved: {masked}");
    assert!(
        masked.contains("/v1/traces"),
        "path must be preserved: {masked}"
    );

    // Password-only userinfo (`:pass@`) and username-only userinfo (`user@`) are both masked.
    assert!(!mask_userinfo("https://:topsecret@host/path").contains("topsecret"));
    assert!(!mask_userinfo("https://tokenuser@host/path").contains("tokenuser"));
}

#[test]
fn test_mask_userinfo_passthrough_without_credentials() {
    // A URL with no userinfo must be returned unchanged (modulo the trailing-slash normalization
    // reqwest applies to a bare authority); masking must never drop or alter a credential-free URL.
    assert_eq!(
        mask_userinfo("https://collector.example.com:4318/v1/traces"),
        "https://collector.example.com:4318/v1/traces"
    );
    // Non-URL strings (no userinfo to leak) are passed through verbatim for the diagnostic.
    assert_eq!(mask_userinfo("not-a-url"), "not-a-url");
    assert_eq!(mask_userinfo(""), "");
}

#[test]
fn test_validate_webhook_url_error_masks_userinfo() {
    // Regression: the validation error message is logged (`configure_webhook` ->
    // tracing::error!), so a rejected webhook URL bearing userinfo must not leak its credentials
    // into that message. Use an internal host so it is rejected by the SSRF guard with the URL
    // interpolated.
    let err = validate_webhook_url(Some(
        "https://user:hunter2@169.254.169.254/latest/meta-data/".to_string(),
    ))
    .expect_err("internal host must be rejected");
    assert!(
        !err.contains("hunter2") && !err.contains("user:"),
        "webhook validation error must mask embedded userinfo; leaked: {err}"
    );
    // A plaintext (non-https) URL with userinfo is rejected by the scheme check, also masked.
    let err = validate_webhook_url(Some("http://u:p4ss@hook.example.com/log".to_string()))
        .expect_err("plaintext scheme must be rejected");
    assert!(
        !err.contains("p4ss"),
        "scheme-rejection error must mask embedded userinfo; leaked: {err}"
    );
}

#[test]
fn test_validate_webhook_url_accepts_https_and_none() {
    assert_eq!(validate_webhook_url(None), Ok(None));
    assert_eq!(
        validate_webhook_url(Some("https://hook.example.com/log".to_string())),
        Ok(Some("https://hook.example.com/log".to_string()))
    );
}

#[test]
fn test_validate_webhook_url_accepts_uppercase_https_scheme() {
    // Regression: the scheme is case-insensitive per RFC 3986, and reqwest's `Url::parse`
    // lowercases it — so an uppercase/mixed-case `HTTPS://` to a public host is a valid webhook
    // and must NOT be rejected. The old literal `starts_with("https://")` check failed these.
    for ok in [
        "HTTPS://hook.example.com/log",
        "Https://hook.example.com/log",
        "hTTpS://collector.example.org/v1/logs",
    ] {
        assert_eq!(
            validate_webhook_url(Some(ok.to_string())),
            Ok(Some(ok.to_string())),
            "uppercase/mixed-case https scheme '{ok}' must be accepted"
        );
    }
}

#[test]
fn test_validate_webhook_url_uppercase_scheme_still_guards_ssrf() {
    // The case-insensitive scheme acceptance must not bypass the host guard: an uppercase-scheme
    // URL pointed at an internal target is still rejected (by the SSRF host check, not the scheme
    // check). Also confirms `HTTP://` (any case) is still refused as plaintext.
    for bad in [
        "HTTPS://169.254.169.254/latest/meta-data/", // uppercase scheme, internal host
        "HTTPS://127.0.0.1/log",
        "HTTP://hook.example.com/log", // plaintext, uppercase scheme
        "Http://hook.example.com/log", // plaintext, mixed case
    ] {
        assert!(
            validate_webhook_url(Some(bad.to_string())).is_err(),
            "'{bad}' must be rejected (SSRF host guard or plaintext scheme)"
        );
    }
}

#[test]
fn test_scheme_is_case_insensitive() {
    assert!(scheme_is("HTTPS://host/", SCHEME_HTTPS));
    assert!(scheme_is("https://host/", SCHEME_HTTPS));
    assert!(scheme_is("HtTp://host/", "http"));
    assert!(!scheme_is("http://host/", SCHEME_HTTPS));
    assert!(!scheme_is("httpsx://host/", SCHEME_HTTPS)); // require the `://` boundary
    assert!(!scheme_is("not-a-url", SCHEME_HTTPS));
}

#[test]
fn test_validate_webhook_url_rejects_non_https() {
    for bad in [
        "http://hook.example.com/log",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/shadow",
        "ftp://example.com",
        "not-a-url",
        "",
    ] {
        let res = validate_webhook_url(Some(bad.to_string()));
        assert!(
            res.is_err(),
            "non-https webhook URL '{bad}' must be rejected; got {res:?}"
        );
        assert!(
            res.unwrap_err().contains("https://"),
            "rejection message should mention the https requirement for '{bad}'"
        );
    }
}

#[test]
fn test_validate_webhook_url_rejects_https_internal_hosts() {
    // Regression: the scheme check alone let an `https://` SSRF target through. These must all
    // be rejected by the host guard so enforcement matches the documented protection.
    for bad in [
        "https://169.254.169.254/latest/meta-data/", // cloud metadata (link-local)
        "https://127.0.0.1/log",                     // loopback
        "https://10.0.0.5/hook",                     // RFC1918
        "https://192.168.1.10/hook",                 // RFC1918
        "https://172.16.5.4/hook",                   // RFC1918
        "https://0.0.0.0/hook",                      // unspecified
        "https://[::1]/hook",                        // IPv6 loopback
        "https://[fe80::1]/hook",                    // IPv6 link-local
        "https://[fc00::1]/hook",                    // IPv6 unique-local
        // THE RANGES THIS GUARD'S HAND-WRITTEN V6 ARM MISSED while `net_guard::ipv6_is_internal`
        // — the predicate it was supposed to be a sibling of — had them. v6 multicast reaches every
        // node on the segment; the IPv4-COMPATIBLE spelling matches no v6 range at all.
        "https://[ff02::1]/hook",           // IPv6 multicast (all-nodes)
        "https://[::169.254.169.254]/hook", // IPv4-COMPATIBLE metadata
        // ...and the v4 ranges the shared predicate gained from `a2a::pushnotify`'s copy.
        "https://0.1.2.3/hook",    // 0.0.0.0/8 "this network"
        "https://192.0.0.8/hook",  // IETF protocol assignments 192.0.0.0/24
        "https://198.18.0.1/hook", // benchmarking 198.18.0.0/15
    ] {
        let res = validate_webhook_url(Some(bad.to_string()));
        assert!(
            res.is_err(),
            "https internal-host webhook URL '{bad}' must be rejected; got {res:?}"
        );
    }
}

#[test]
fn test_validate_webhook_url_rejects_localhost_dns_name() {
    // `localhost` is a DNS name, not an IP literal, but RFC 6761 reserves it
    // (and its subdomains) to loopback. An operator-set `https://localhost:<port>/path` would
    // POST request logs to a co-located process, so it must be blocked case-insensitively.
    for bad in [
        "https://localhost/log",
        "https://LOCALHOST/log",
        "https://localhost:8443/exfil",
        "https://api.localhost/log", // `*.localhost` subdomain -> loopback per RFC 6761
        "https://service.LocalHost/log",
        // Trailing-dot FQDN-root spellings: getaddrinfo resolves `localhost.` to loopback exactly
        // like `localhost`, so this webhook guard must block them too — these previously slipped
        // past `host_is_internal` (the bare-label compare missed the dot and the rsplit TLD was
        // the empty string), enabling `https://localhost./exfil`.
        "https://localhost./log",
        "https://localhost.:443/exfil",
        "https://api.localhost./log", // `*.localhost.` subdomain, trailing dot
    ] {
        let res = validate_webhook_url(Some(bad.to_string()));
        assert!(
            res.is_err(),
            "localhost-family webhook URL '{bad}' must be rejected by the SSRF guard; got {res:?}"
        );
    }
}

#[test]
fn test_validate_webhook_url_rejects_ipv4_mapped_ipv6_internal() {
    // An IPv4-mapped IPv6 literal (`::ffff:a.b.c.d`) parses as IpAddr::V6 and
    // matches none of the plain V6 predicates, so without canonicalization it would reach the
    // same internal targets (loopback / cloud-metadata / RFC1918) the V4 arm rejects.
    for bad in [
        "https://[::ffff:127.0.0.1]/log",        // mapped loopback
        "https://[::ffff:169.254.169.254]/meta", // mapped cloud metadata (link-local)
        "https://[::ffff:10.0.0.5]/hook",        // mapped RFC1918
        "https://[::ffff:192.168.1.10]/hook",    // mapped RFC1918
        "https://[::ffff:0.0.0.0]/hook",         // mapped unspecified
        // IPv4-COMPATIBLE form (`::a.b.c.d`): `to_ipv4_mapped()` returns None for these and the
        // leading `segments()[0] == 0` makes the ULA/link-local masks miss, so under the old
        // `to_ipv4_mapped()` canonicalization they fell through to `false` (allowed) — a real
        // SSRF gap and a broken documented parity with `config_validate::ssrf_blocked_host`.
        "https://[::127.0.0.1]/log",        // compatible loopback
        "https://[::169.254.169.254]/meta", // compatible cloud metadata (link-local IMDS)
        "https://[::10.0.0.5]/hook",        // compatible RFC1918
        "https://[::1]/log",                // bare loopback must still be caught
    ] {
        let res = validate_webhook_url(Some(bad.to_string()));
        assert!(
            res.is_err(),
            "IPv4-mapped-IPv6 internal webhook URL '{bad}' must be rejected; got {res:?}"
        );
    }
}

#[test]
fn test_validate_webhook_url_rejects_cgnat_v4() {
    // RFC 6598 CGNAT
    // 100.64.0.0/10 is NOT is_private(), yet routable inside cloud VPCs / k8s clusters where it
    // fronts internal services. The V4 arm previously checked only loopback/link-local/private/
    // unspecified/broadcast, so https://100.64.0.5/ slipped through.
    for bad in [
        "https://100.64.0.5/hook",      // bottom of the /10
        "https://100.64.0.0/hook",      // network address
        "https://100.96.0.1/hook",      // mid-range (second octet 0x60, top two bits 01)
        "https://100.127.255.254/hook", // top of the /10
    ] {
        let res = validate_webhook_url(Some(bad.to_string()));
        assert!(
            res.is_err(),
            "CGNAT (RFC6598) webhook URL '{bad}' must be rejected by the SSRF guard; got {res:?}"
        );
    }
}

#[test]
fn test_validate_webhook_url_accepts_non_cgnat_100_block() {
    // 100.0.0.0/8 outside the 100.64.0.0/10 CGNAT slice is ordinary public space and must NOT
    // be over-blocked (top two bits of the second octet are not `01`).
    for ok in [
        "https://100.0.0.1/hook",      // second octet 0
        "https://100.63.255.255/hook", // just below the /10
        "https://100.128.0.1/hook",    // second octet 0x80, top two bits 10
    ] {
        assert!(
            validate_webhook_url(Some(ok.to_string())).is_ok(),
            "public 100.x address '{ok}' must be accepted (no CGNAT over-block)"
        );
    }
}

#[test]
fn test_validate_webhook_url_rejects_alternate_ipv4_encodings() {
    // Non-canonical IPv4 encodings are rejected
    // by IpAddr::from_str but the OS resolver still maps them to internal addresses. Previously
    // they fell into the Err(_) DNS branch (which only blocked the localhost family) and passed.
    for bad in [
        "https://2130706433/log",   // decimal int = 127.0.0.1
        "https://0x7f000001/log",   // hex = 127.0.0.1
        "https://0X7F000001/log",   // hex, upper-case prefix
        "https://017700000001/log", // octal = 127.0.0.1
        "https://127.1/log",        // short-dotted = 127.0.0.1
        "https://10.0.1/log",       // short-dotted = 10.0.0.1 (RFC1918)
        "https://2852039166/meta",  // decimal = 169.254.169.254 (IMDS)
        "https://0x7f.0.0.1/log",   // per-octet hex in a 4-part form
        "https://0177.0.0.1/log",   // per-octet octal in a 4-part form
    ] {
        let res = validate_webhook_url(Some(bad.to_string()));
        assert!(
                res.is_err(),
                "alternate IPv4 encoding webhook URL '{bad}' must be rejected by the SSRF guard; got {res:?}"
            );
    }
}

#[test]
fn test_url_parse_canonicalizes_alternate_ipv4_encodings() {
    // Documentation lock: pins what the surrounding comments assert — for an http(s) URL
    // `url::Url::parse` (WHATWG special-scheme host parsing) is the PRIMARY guard,
    // canonicalizing every alternate IPv4 encoding to a dotted-quad BEFORE `host_str()` is
    // read, so `is_alternate_ipv4_encoding` is a defense-in-depth parity mirror rather than
    // the primary block. If a future url/reqwest bump stops normalizing these, this test fails
    // and both the comment and the reliance on the parity mirror must be revisited.
    for (raw, want) in [
        ("https://2130706433/log", "127.0.0.1"),        // decimal
        ("https://0x7f000001/log", "127.0.0.1"),        // hex
        ("https://0X7F000001/log", "127.0.0.1"),        // hex, upper prefix
        ("https://017700000001/log", "127.0.0.1"),      // octal
        ("https://127.1/log", "127.0.0.1"),             // short-dotted loopback
        ("https://10.0.1/log", "10.0.0.1"),             // short-dotted RFC1918
        ("https://2852039166/meta", "169.254.169.254"), // decimal IMDS
        ("https://0x7f.0.0.1/log", "127.0.0.1"),        // per-octet hex
        ("https://0177.0.0.1/log", "127.0.0.1"),        // per-octet octal
    ] {
        let parsed = url::Url::parse(raw).expect("special-scheme URL with numeric host must parse");
        assert_eq!(
            parsed.host_str(),
            Some(want),
            "Url::parse must canonicalize '{raw}' to the dotted-quad '{want}' before host_str()"
        );
        // is_alternate_ipv4_encoding therefore sees a canonical dotted-quad and does NOT fire;
        // the real block on the SSRF path is the canonical IpAddr parse below it.
        assert!(
            !is_alternate_ipv4_encoding(want),
            "canonical dotted-quad '{want}' must not be flagged as an alternate encoding"
        );
        // ...and the end-to-end guard still rejects/normalizes the target correctly.
        assert!(
            validate_webhook_url(Some(raw.to_string())).is_err(),
            "post-normalization internal target '{raw}' must still be blocked by the SSRF guard"
        );
    }
}

#[test]
fn test_validate_webhook_url_rejects_cloud_metadata_dns_names() {
    // The well-known cloud
    // metadata DNS names resolve to internal/IMDS targets. They are not IP literals, so the
    // Err(_) DNS branch (localhost-only) let them through previously.
    for bad in [
        "https://metadata.google.internal/computeMetadata/v1/",
        "https://METADATA.GOOGLE.INTERNAL/x", // case-insensitive
        "https://metadata.internal/x",
    ] {
        let res = validate_webhook_url(Some(bad.to_string()));
        assert!(
                res.is_err(),
                "cloud-metadata DNS name webhook URL '{bad}' must be rejected by the SSRF guard; got {res:?}"
            );
    }
}

#[test]
fn test_validate_webhook_url_rejects_trailing_dot_internal_hosts() {
    // A trailing FQDN-root dot made the IP-literal parse
    // fail (slipping into the allow-by-default DNS arm) and the METADATA_HOSTS exact-compare miss,
    // so a trailing-dot internal target bypassed BOTH guards. getaddrinfo resolves these to the
    // same internal targets as the bare spelling, so they MUST be rejected.
    for bad in [
        "https://127.0.0.1./exfil",
        "https://169.254.169.254./latest/meta-data/",
        "https://metadata.google.internal./computeMetadata/v1/",
        "https://metadata.internal./x",
        "https://localhost./exfil",
    ] {
        let res = validate_webhook_url(Some(bad.to_string()));
        assert!(
            res.is_err(),
            "trailing-dot internal host '{bad}' must be rejected by the SSRF guard; got {res:?}"
        );
    }
}

#[test]
fn test_validate_webhook_url_accepts_metadata_lookalike_dns_names() {
    // A registrable external name that merely contains a metadata label as a subdomain (not the
    // exact reserved name) must NOT be over-blocked.
    for ok in [
        "https://metadata.google.internal.example.com/x", // distinct registrable name
        "https://my-metadata.internal.example.org/x",
    ] {
        assert!(
            validate_webhook_url(Some(ok.to_string())).is_ok(),
            "metadata-lookalike external name '{ok}' must be accepted (no over-block)"
        );
    }
}

#[test]
fn test_validate_webhook_url_accepts_mapped_public_and_localhost_substring() {
    // An IPv4-mapped IPv6 of a PUBLIC address stays allowed (canonicalization must not over-block),
    // and a hostname that merely CONTAINS "localhost" as a substring of a real label (not the
    // `localhost` label itself) is a distinct external name and must not be falsely rejected.
    for ok in [
        "https://[::ffff:93.184.216.34]/log", // mapped public IP literal -> allowed
        "https://mylocalhost.example.com/log", // label is `mylocalhost`, not `localhost`
        "https://localhost.example.com/log", // registrable name under example.com, TLD != localhost
    ] {
        assert!(
            validate_webhook_url(Some(ok.to_string())).is_ok(),
            "external webhook URL '{ok}' must be accepted (no SSRF over-block)"
        );
    }
}

#[test]
fn test_validate_webhook_url_accepts_https_external_host() {
    // An https URL to a public DNS name / public IP literal is allowed.
    for ok in [
        "https://hook.example.com/log",
        "https://collector.internal.example.org/v1/logs", // DNS name -> allowed
        "https://93.184.216.34/log",                      // public IP literal
    ] {
        assert!(
            validate_webhook_url(Some(ok.to_string())).is_ok(),
            "https external webhook URL '{ok}' must be accepted"
        );
    }
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

/// POSITIVE CONTROL (call site 5/5: `observability.rs`, the webhook / OTLP guard).
///
/// The same three planted targets every other call site is driven with. This guard is the one that
/// used to keep its OWN two-name `METADATA_HOSTS`; it now reads `net_guard::METADATA_HOSTS`, so the
/// four names it had never heard of are refused here too.
#[test]
fn planted_blocked_targets_are_refused_by_the_telemetry_guard() {
    for target in [
        "http://169.254.169.254/v1/traces",
        "https://metadata.platformequinix.com/v1/traces",
        "http://100.64.1.1/v1/traces",
        "https://metadata.tencentyun.com/v1/traces",
        "https://instance-data.ec2.internal/v1/traces",
    ] {
        let u = url::Url::parse(target).expect("planted URL parses");
        assert!(
            host_is_internal(&u),
            "observability guard did NOT refuse planted target {target}"
        );
        println!("observability::host_is_internal  REFUSED  {target}");
    }
}
