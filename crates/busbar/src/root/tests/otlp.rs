// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The collector egress policy's tests — the OTLP endpoint guard's, moved with it from the kernel
//! (K9e-1) unchanged. The credential split and the "enabled" line moved with the exporter into the
//! `busbar-export-otlp` plugin (K9e-2), whose own suite carries their tests.

use super::*;

/// The guard's full verdict — name resolution included — in the shape 1.5.x's endpoint validator
/// answered it: `None` (no endpoint) is valid; an accepted endpoint comes back as written.
fn validate_otlp_endpoint(endpoint: Option<&str>) -> Result<Option<String>, String> {
    endpoint.map_or(Ok(None), |e| {
        collector_policy(e, true).map(|()| Some(e.to_string()))
    })
}

#[test]
fn test_validate_otlp_endpoint_error_masks_userinfo() {
    // Regression: the OTLP validation error is logged when the sink starts, so a
    // rejected endpoint with userinfo must not leak credentials there either.
    let err = validate_otlp_endpoint(Some("https://svc:topsecret@10.0.0.1/v1/traces"))
        .expect_err("internal host must be rejected");
    assert!(
        !err.contains("topsecret"),
        "OTLP SSRF-rejection error must mask embedded userinfo; leaked: {err}"
    );
    // Bad-scheme path also masks.
    let err = validate_otlp_endpoint(Some("ftp://svc:s3cr3t@collector.example.com/x"))
        .expect_err("bad scheme must be rejected");
    assert!(
        !err.contains("s3cr3t"),
        "OTLP scheme-rejection error must mask embedded userinfo; leaked: {err}"
    );
    // Plaintext-to-remote path also masks.
    let err = validate_otlp_endpoint(Some(
        "http://svc:pw0rd@collector.example.com:4318/v1/traces",
    ))
    .expect_err("plaintext remote must be rejected");
    assert!(
        !err.contains("pw0rd"),
        "OTLP plaintext-remote error must mask embedded userinfo; leaked: {err}"
    );
}

#[test]
fn test_validate_otlp_endpoint_accepts_none_and_external() {
    // OTLP disabled is always valid; an external collector over https is accepted verbatim.
    assert_eq!(validate_otlp_endpoint(None), Ok(None));
    assert_eq!(
        validate_otlp_endpoint(Some("https://collector.example.com:4318/v1/traces")),
        Ok(Some(
            "https://collector.example.com:4318/v1/traces".to_string()
        ))
    );
}

#[test]
fn test_validate_otlp_endpoint_allows_loopback_collectors() {
    // The localhost-collector carve-out: the standard OTLP deployment is a co-located plaintext
    // loopback hop. http:// is permitted, and loopback v4/v6/`localhost` must be accepted.
    for ok in [
        "http://localhost:4318/v1/traces",
        "http://LOCALHOST:4318",
        "https://localhost:4318/v1/traces",
        "http://127.0.0.1:4318/v1/traces",
        "http://[::1]:4318/v1/traces",
        "http://api.localhost:4318", // *.localhost -> loopback per RFC 6761
    ] {
        let res = validate_otlp_endpoint(Some(ok));
        assert!(
            res.is_ok(),
            "loopback OTLP collector '{ok}' must be accepted; got {res:?}"
        );
    }
}

/// The literal-text guard cannot see through a NAME, which is what the resolve half is for.
/// `localhost` is the one name that resolves identically everywhere, and it resolves to
/// loopback — which is ALLOWED for a collector, so this pins the carve-out rather than a block.
#[test]
fn otlp_resolve_check_allows_a_name_resolving_to_loopback() {
    let url = url::Url::parse("http://localhost:4318/v1/traces").unwrap();
    assert_eq!(
        otlp_resolves_to_internal(&url),
        None,
        "a loopback collector reached by name is the documented carve-out"
    );
    assert!(validate_otlp_endpoint(Some("http://localhost:4318/v1/traces")).is_ok());
}

/// An IP literal has already been ruled on textually; resolving it could only agree with itself.
#[test]
fn otlp_resolve_check_skips_ip_literals() {
    for raw in [
        "https://93.184.216.34:4318/v1/traces",
        "https://[2606:2800:220:1:248:1893:25c8:1946]:4318/v1/traces",
        "https://169.254.169.254/v1/traces",
    ] {
        let url = url::Url::parse(raw).unwrap();
        assert_eq!(
            otlp_resolves_to_internal(&url),
            None,
            "an IP literal must not be resolved: {raw}"
        );
    }
}

/// The resolved-address verdict must match the literal-text verdict for the SAME address —
/// otherwise a name and a literal spelling of one address disagree, which is exactly what makes
/// a guard bypassable.
#[test]
fn otlp_resolved_and_literal_verdicts_agree() {
    let cases: [(&str, bool); 8] = [
        ("127.0.0.1", false),      // loopback collector: allowed
        ("::1", false),            // ditto, v6
        ("10.0.0.1", true),        // RFC 1918
        ("192.168.1.1", true),     // RFC 1918
        ("169.254.169.254", true), // link-local / IMDS
        ("100.64.0.1", true),      // CGNAT
        ("fd00::1", true),         // unique-local v6
        ("93.184.216.34", false),  // ordinary public collector
    ];
    for (raw, want_internal) in cases {
        let ip: std::net::IpAddr = raw.parse().unwrap();
        assert_eq!(
            otlp_addr_is_internal(&ip),
            want_internal,
            "resolved-address verdict for {raw}"
        );
        let url = url::Url::parse(&if ip.is_ipv6() {
            format!("https://[{raw}]/v1/traces")
        } else {
            format!("https://{raw}/v1/traces")
        })
        .unwrap();
        assert_eq!(
            otlp_host_is_blocked(&url),
            want_internal,
            "literal-text verdict for {raw} must match the resolved one"
        );
    }
}

/// A collector whose DNS is down is an availability event, not a security one: it cannot reach
/// anything, and disabling trace export over a transient blip would be the wrong trade.
#[test]
fn otlp_resolve_check_allows_a_name_that_does_not_resolve() {
    let url = url::Url::parse("https://this-collector-must-not-resolve.invalid/v1/traces").unwrap();
    assert_eq!(otlp_resolves_to_internal(&url), None);
}

#[test]
fn test_validate_otlp_endpoint_rejects_cloud_metadata_and_internal() {
    // Span data carries key_ids, pool names, and governance
    // decisions, so the OTLP sink must block cloud-metadata / RFC1918 / CGNAT / link-local
    // targets exactly like the webhook guard (only loopback is the intentional exception).
    for bad in [
        "https://169.254.169.254/v1/traces", // IMDS (link-local)
        "http://169.254.169.254/v1/traces",  // IMDS over plaintext too
        "https://10.0.0.1/collect",          // RFC1918
        "http://10.0.0.1/collect",
        "https://192.168.1.10/v1/traces",             // RFC1918
        "https://172.16.5.4/v1/traces",               // RFC1918
        "https://100.64.0.1/v1/traces",               // RFC6598 CGNAT
        "https://0.0.0.0/v1/traces",                  // unspecified
        "https://[fe80::1]/v1/traces",                // IPv6 link-local
        "https://[fc00::1]/v1/traces",                // IPv6 unique-local
        "https://metadata.google.internal/v1/traces", // cloud-metadata DNS name
        // The same gaps the webhook guard's hand-written v6 arm had — this arm was a THIRD copy of
        // the same lines and carried the same omissions.
        "https://[ff02::1]/v1/traces", // IPv6 multicast (all-nodes)
        "https://[::169.254.169.254]/v1/traces", // IPv4-COMPATIBLE metadata
        "https://168.63.129.16/v1/traces", // Azure WireServer (a PUBLIC address)
        "https://192.0.0.192/v1/traces", // OCI IMDS (a PUBLIC-shaped address)
        "https://0.1.2.3/v1/traces",   // 0.0.0.0/8 "this network"
        "https://198.18.0.1/v1/traces", // benchmarking 198.18.0.0/15
        "http://2130706433/v1/traces", // 127.0.0.1 alt encoding is loopback -> allowed below
    ] {
        // The last entry is a loopback alternate encoding and is deliberately exercised in the
        // allow-test; here we only assert the genuinely-internal set is rejected.
        if bad.contains("2130706433") {
            continue;
        }
        let res = validate_otlp_endpoint(Some(bad));
        assert!(
            res.is_err(),
            "internal/cloud-metadata OTLP endpoint '{bad}' must be rejected; got {res:?}"
        );
    }
}

#[test]
fn test_validate_otlp_endpoint_rejects_alternate_encoded_internal() {
    // Alternate IPv4 encodings of an INTERNAL target must be blocked (e.g. decimal/hex of an
    // RFC1918 host), while the loopback alternate encodings are the only ones permitted.
    for bad in [
        "http://0xa000001/v1/traces", // 10.0.0.1 in hex
        "http://167772161/v1/traces", // 10.0.0.1 in decimal
        "http://2852039166/collect",  // 169.254.169.254 in decimal
    ] {
        let res = validate_otlp_endpoint(Some(bad));
        assert!(
            res.is_err(),
            "alternate-encoded internal OTLP endpoint '{bad}' must be rejected; got {res:?}"
        );
    }
    // Loopback alternate encodings ARE the localhost-collector exception -> allowed.
    for ok in [
        "http://2130706433/v1/traces", // 127.0.0.1 decimal
        "http://0x7f000001/v1/traces", // 127.0.0.1 hex
    ] {
        let res = validate_otlp_endpoint(Some(ok));
        assert!(
                res.is_ok(),
                "loopback alternate encoding '{ok}' must be accepted (localhost collector); got {res:?}"
            );
    }
}

#[test]
fn test_validate_otlp_endpoint_accepts_uppercase_scheme() {
    // The OTLP scheme check is also
    // case-insensitive, so `HTTP://localhost:4318` / `HTTPS://collector...` are valid and must
    // be accepted. The old literal lowercase `starts_with` rejected them.
    for ok in [
        "HTTP://localhost:4318/v1/traces",
        "HTTPS://collector.example.com:4318/v1/traces",
        "Http://127.0.0.1:4318",
    ] {
        assert!(
            validate_otlp_endpoint(Some(ok)).is_ok(),
            "uppercase/mixed-case scheme OTLP endpoint '{ok}' must be accepted"
        );
    }
    // ...but an uppercase scheme still does not bypass the SSRF host guard.
    assert!(
        validate_otlp_endpoint(Some("HTTPS://169.254.169.254/v1/traces")).is_err(),
        "uppercase scheme must not bypass the OTLP SSRF guard"
    );
}

#[test]
fn test_validate_otlp_endpoint_rejects_bad_scheme() {
    // Only http/https export targets are valid; anything else (or a non-URL) is rejected.
    for bad in [
        "file:///etc/shadow",
        "ftp://collector.example.com",
        "grpc://collector:4317",
        "not-a-url",
        "",
    ] {
        let res = validate_otlp_endpoint(Some(bad));
        assert!(
            res.is_err(),
            "non-http(s) OTLP endpoint '{bad}' must be rejected; got {res:?}"
        );
    }
}

#[test]
fn test_validate_otlp_endpoint_requires_https_for_remote_collector() {
    // Regression: the plaintext-`http://` allowance exists ONLY for the co-located
    // loopback collector. A plaintext hop to a REMOTE collector would put span data (key_ids,
    // pool names, governance decisions) on the wire in cleartext, so `http://` to a non-loopback
    // host must be rejected; `https://` to the same host is accepted, and `http://` stays valid
    // for loopback/localhost. Old code accepted `http://<external>` unconditionally.

    // http:// to a NON-loopback external host -> rejected (would be cleartext over the network).
    for bad in [
        "http://1.2.3.4/v1/traces",
        "http://1.2.3.4:4318",
        "http://collector.example.com:4318/v1/traces",
        "HTTP://collector.example.com/v1/traces", // case-insensitive scheme, still gated
    ] {
        let res = validate_otlp_endpoint(Some(bad));
        assert!(
            res.is_err(),
            "plaintext http:// to a remote OTLP collector '{bad}' must be rejected; got {res:?}"
        );
    }

    // https:// to the same remote hosts -> accepted (TLS protects the span data on the wire).
    for ok in [
        "https://1.2.3.4/v1/traces",
        "https://1.2.3.4:4318",
        "https://collector.example.com:4318/v1/traces",
    ] {
        let res = validate_otlp_endpoint(Some(ok));
        assert!(
            res.is_ok(),
            "https:// to a remote OTLP collector '{ok}' must be accepted; got {res:?}"
        );
    }

    // http:// to a loopback/localhost target stays valid (the co-located-collector exception).
    for ok in [
        "http://localhost:4318/v1/traces",
        "http://127.0.0.1:4318/v1/traces",
        "http://[::1]:4318/v1/traces",
        "http://api.localhost:4318", // *.localhost -> loopback (RFC 6761)
        "http://2130706433/v1/traces", // 127.0.0.1 alternate encoding
    ] {
        let res = validate_otlp_endpoint(Some(ok));
        assert!(
            res.is_ok(),
            "plaintext http:// to a loopback OTLP collector '{ok}' must stay accepted; got {res:?}"
        );
    }
}

/// The OTLP twin of the kernel's `test_validate_webhook_url_rejects_trailing_dot_internal_hosts`,
/// moved with the guard (K9e-1): a trailing FQDN-root dot must not slip an internal target past it.
#[test]
fn test_validate_otlp_endpoint_rejects_trailing_dot_internal_hosts() {
    // OTLP twin: link-local/metadata trailing-dot hosts blocked; loopback collector still allowed.
    for bad in [
        "https://169.254.169.254./v1/traces",
        "https://metadata.google.internal./v1/traces",
    ] {
        assert!(
            validate_otlp_endpoint(Some(bad)).is_err(),
            "trailing-dot internal OTLP endpoint '{bad}' must be rejected"
        );
    }
    // The loopback collector carve-out survives the dot strip (allowed for OTLP).
    assert!(
        validate_otlp_endpoint(Some("https://127.0.0.1./v1/traces")).is_ok(),
        "trailing-dot loopback OTLP collector must remain allowed (carve-out)"
    );
}
