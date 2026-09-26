// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The OTLP span exporter's own tests, moved with it from the kernel (K9e-1) unchanged.

use super::*;

#[test]
fn test_validate_otlp_endpoint_error_masks_userinfo() {
    // Regression: the OTLP validation error is printed to stderr (`init_logging`), so a
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

/// NO PROVIDER, NO "ENABLED" LINE (item 570).
///
/// The "OTLP tracing enabled" info line used to be gated on the endpoint being configured, so an
/// endpoint whose exporter failed to build — `build_otlp` prints its failure to stderr and returns
/// `None` — still logged "enabled" while no provider was installed and no span would ever leave the
/// process. The line is now the installing step's own, so an endpoint with nothing built behind it
/// says nothing, and nothing global is touched.
#[test]
fn an_endpoint_whose_exporter_did_not_build_never_logs_enabled() {
    use busbar_kernel::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;
    let cap = WarnCapture::capturing_debug();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    tracing::subscriber::with_default(subscriber, || {
        install_otlp(None, Some("https://collector.example:4318/v1/traces"));
    });
    assert!(
        !cap.contains("OTLP tracing enabled"),
        "no provider was built, so nothing may claim tracing is enabled; captured: {:?}",
        cap.messages()
    );
    assert!(
        TRACER_PROVIDER.get().is_none(),
        "a failed build must not install a provider"
    );
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
