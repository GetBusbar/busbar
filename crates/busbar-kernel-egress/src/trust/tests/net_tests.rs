// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The network guard, tested where it now lives: the pure predicates with every literal case they

use crate::trust::net::*;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn http_scheme_case_does_not_change_url_spelling_or_authority_rules() {
    for (scheme, secure, port) in [
        ("HTTPS", true, 443),
        ("hTtPs", true, 443),
        ("HTTP", false, 80),
    ] {
        let url = format!("{scheme}://Mixed.Example/Case/Path?Key=VaL");
        assert_eq!(
            split_url(&url).unwrap(),
            (
                secure,
                "Mixed.Example".to_string(),
                port,
                "/Case/Path?Key=VaL".to_string()
            )
        );
        assert!(matches!(
            split_url(&format!("{scheme}://user:password@host/Case")),
            Err(AddressRefusal::NoHost(_))
        ));
    }
    for url in ["HTTP:host/Case", "HTTPS:/host/Case", "FTP://host/Case"] {
        assert!(matches!(split_url(url), Err(AddressRefusal::Scheme { .. })));
    }
}

#[test]
fn is_cgnat_shared_v4_covers_rfc6598_only() {
    assert!(is_cgnat_shared_v4(&Ipv4Addr::new(100, 64, 0, 0)));
    assert!(is_cgnat_shared_v4(&Ipv4Addr::new(100, 100, 100, 200)));
    assert!(is_cgnat_shared_v4(&Ipv4Addr::new(100, 127, 255, 255)));

    assert!(!is_cgnat_shared_v4(&Ipv4Addr::new(100, 63, 255, 255)));
    assert!(!is_cgnat_shared_v4(&Ipv4Addr::new(100, 128, 0, 0)));
    assert!(!is_cgnat_shared_v4(&Ipv4Addr::new(99, 64, 0, 0)));
    assert!(!is_cgnat_shared_v4(&Ipv4Addr::new(8, 8, 8, 8)));
}

#[test]
fn is_unique_local_v6_covers_fc00_slash_7() {
    assert!(is_unique_local_v6(&"fc00::1".parse().unwrap()));
    assert!(is_unique_local_v6(&"fd00:ec2::254".parse().unwrap()));
    assert!(is_unique_local_v6(&"fdff:ffff::".parse().unwrap()));

    assert!(!is_unique_local_v6(&"fe80::1".parse().unwrap()));
    assert!(!is_unique_local_v6(&"2001:db8::1".parse().unwrap()));
    assert!(!is_unique_local_v6(&"::1".parse().unwrap()));
}

#[test]
fn is_link_local_v6_covers_fe80_slash_10() {
    assert!(is_link_local_v6(&"fe80::1".parse().unwrap()));
    assert!(is_link_local_v6(&"febf:ffff::".parse().unwrap()));

    assert!(!is_link_local_v6(&"fec0::1".parse().unwrap()));
    assert!(!is_link_local_v6(&"fc00::1".parse().unwrap()));
    assert!(!is_link_local_v6(&"2001:db8::1".parse().unwrap()));
}

#[test]
fn is_alternate_ipv4_encoding_flags_obfuscated_forms() {
    assert!(is_alternate_ipv4_encoding("2130706433"));
    assert!(is_alternate_ipv4_encoding("0x7f000001"));
    assert!(is_alternate_ipv4_encoding("0X7F000001"));
    assert!(is_alternate_ipv4_encoding("017700000001"));
    assert!(is_alternate_ipv4_encoding("127.1"));
    assert!(is_alternate_ipv4_encoding("10.0.1"));
    assert!(is_alternate_ipv4_encoding("0x7f.0.0.1"));
    assert!(is_alternate_ipv4_encoding("0177.0.0.1"));

    assert!(!is_alternate_ipv4_encoding("127.0.0.1"));
    assert!(!is_alternate_ipv4_encoding("8.8.8.8"));

    assert!(!is_alternate_ipv4_encoding("api.upstream.example"));
    assert!(!is_alternate_ipv4_encoding("example.com"));
    assert!(!is_alternate_ipv4_encoding(""));
}

/// EVERY range a busbar guard must refuse, in one table, asserted through the shared entry point.
#[test]
fn the_shared_internal_predicate_covers_every_range_any_plane_ever_checked() {
    use std::net::IpAddr;
    let cases: &[(&str, &str)] = &[
        ("loopback v4 127/8", "127.0.0.1"),
        ("private 10/8", "10.1.2.3"),
        ("private 172.16/12", "172.16.5.5"),
        ("private 192.168/16", "192.168.1.1"),
        ("link-local 169.254/16", "169.254.1.1"),
        ("AWS IMDS", "169.254.169.254"),
        ("ECS task metadata", "169.254.170.2"),
        ("Alibaba metadata (inside CGNAT)", "100.100.100.200"),
        ("CGNAT 100.64/10", "100.64.0.1"),
        ("Azure WireServer (a PUBLIC address)", "168.63.129.16"),
        ("OCI IMDS (a PUBLIC-shaped address)", "192.0.0.192"),
        ("unspecified", "0.0.0.0"),
        ("this-network 0/8", "0.1.2.3"),
        ("IETF protocol assignments 192.0.0/24", "192.0.0.8"),
        ("benchmarking 198.18/15", "198.18.0.1"),
        ("benchmarking 198.19/16", "198.19.0.1"),
        ("broadcast", "255.255.255.255"),
        ("multicast v4", "224.0.0.1"),
        ("documentation TEST-NET-1 192.0.2/24", "192.0.2.1"),
        ("documentation TEST-NET-2 198.51.100/24", "198.51.100.7"),
        ("documentation TEST-NET-3 203.0.113/24", "203.0.113.9"),
        ("loopback v6", "::1"),
        ("unspecified v6", "::"),
        ("unique-local v6 fc00::/7", "fd00::1"),
        ("link-local v6 fe80::/10", "fe80::1"),
        ("multicast v6", "ff02::1"),
        ("EC2 IMDSv6", "fd00:ec2::254"),
        ("IPv4-MAPPED metadata", "::ffff:169.254.169.254"),
        ("IPv4-COMPATIBLE metadata", "::169.254.169.254"),
        ("IPv4-COMPATIBLE loopback", "::127.0.0.1"),
    ];
    let mut checked = 0usize;
    for (what, spelling) in cases {
        let ip: IpAddr = spelling.parse().expect(what);
        assert!(
            ip_is_internal(&ip),
            "{what} ({spelling}) must be internal to the SHARED predicate — a plane that routes \
             through it inherits this row, and a plane that does not is the drift this test exists \
             to catch"
        );
        checked += 1;
    }

    assert!(
        checked >= 30,
        "the shared hostile table shrank; a deleted row is a range every plane silently stopped \
         guarding"
    );
}

/// The CONTROL. Without it a predicate that returned `true` unconditionally would pass the table

#[test]
fn the_shared_internal_predicate_admits_ordinary_public_addresses() {
    use std::net::IpAddr;
    for ok in [
        "93.184.216.34",
        "8.8.8.8",
        "1.1.1.1",
        "100.128.0.1",
        "198.20.0.1",
        "192.0.1.1",
        "2606:4700:4700::1111",
        "::ffff:93.184.216.34",
    ] {
        let ip: IpAddr = ok.parse().expect(ok);
        assert!(
            !ip_is_internal(&ip),
            "{ok} is ordinary public space and must remain reachable"
        );
    }
}

#[test]
fn metadata_preflight_uses_both_ec2_ipv6_endpoints_and_preserves_carveouts() {
    for host in ["fd00:ec2::254", "fd00:ec2::23"] {
        let url = format!("http://[{host}]/metadata");
        assert_eq!(
            ssrf_blocked_host(&url, &[], false, &[]).as_deref(),
            Some(host)
        );
        assert!(ssrf_blocked_host(&url, &[host.to_string()], false, &[]).is_none());
        assert!(ssrf_blocked_host(&url, &[], true, &[]).is_none());
    }
    assert!(ssrf_blocked_host("http://[fd00:ec2::24]/metadata", &[], false, &[]).is_none());
}

/// CLOUD METADATA IS A SEPARATE QUESTION FROM INTERNAL, because the two carry different policies:

#[test]
fn cloud_metadata_is_judged_separately_and_covers_every_vendor() {
    use std::net::IpAddr;
    for meta in [
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "168.63.129.16",
        "192.0.0.192",
        "fd00:ec2::254",
        "::ffff:169.254.169.254",
        "::169.254.169.254",
    ] {
        let ip: IpAddr = meta.parse().expect(meta);
        assert!(
            ip_is_cloud_metadata(&ip),
            "{meta} is a cloud-metadata endpoint and no policy flag may reach it"
        );
    }
    assert!(!ip_is_cloud_metadata(
        &"93.184.216.34".parse::<IpAddr>().unwrap()
    ));

    assert!(!ip_is_cloud_metadata(
        &"10.0.0.1".parse::<IpAddr>().unwrap()
    ));
}

/// NAT64 / RFC 6052 EMBEDDING MUST BE JUDGED, not left to fall through to the v6 range checks that

#[test]
fn nat64_embedded_ipv4_is_judged_by_the_shared_predicates() {
    use std::net::Ipv6Addr;

    for meta in [
        "64:ff9b::a9fe:a9fe",
        "64:ff9b:1::a9fe:a9fe",
        "64:ff9b:1:fffe::a9fe:a9fe",
    ] {
        let addr: IpAddr = meta.parse().expect(meta);
        assert!(
            ip_is_cloud_metadata(&addr),
            "{meta} is the NAT64 synthesis of the IMDS target 169.254.169.254 and must be judged \
             metadata"
        );
        assert!(
            ip_is_internal(&addr),
            "{meta} is also internal — every cloud-metadata address is internal"
        );
    }
    for internal in [
        "64:ff9b::7f00:1",
        "64:ff9b::a01:203",
        "64:ff9b:1::7f00:1",
        "64:ff9b:1:fffe::a01:203",
    ] {
        let addr: IpAddr = internal.parse().expect(internal);
        assert!(
            ip_is_internal(&addr),
            "{internal} is a NAT64 embedding of an internal IPv4 target and must be internal"
        );
        assert!(
            !ip_is_cloud_metadata(&addr),
            "{internal} is internal but not metadata"
        );
    }

    assert_eq!(
        embedded_ipv4(&"64:ff9b:1:fffe::a9fe:a9fe".parse::<Ipv6Addr>().unwrap()),
        Some(Ipv4Addr::new(169, 254, 169, 254)),
    );

    assert_eq!(
        embedded_ipv4(&"64:ff9b::1:0:a9fe:a9fe".parse::<Ipv6Addr>().unwrap()),
        None,
    );
}

/// Every name on the one metadata-name list is blocked by the config-side guard.
#[test]
fn every_metadata_name_is_refused_by_the_config_guard() {
    assert_eq!(
        METADATA_HOSTS.len(),
        6,
        "the metadata-name list must not shrink"
    );
    for name in METADATA_HOSTS {
        assert_eq!(
            ssrf_blocked_host(&format!("https://{name}/"), &[], false, &[]),
            Some((*name).to_string()),
            "`{name}` must still be blocked by the config-side guard"
        );
    }
}

#[test]
fn only_http_and_https_are_recognised() {
    let banned = [
        "file:///etc/passwd",
        "gopher://x/",
        "smb://host/share",
        "ftp://host/",
        "data:text/plain,hi",
        "ws://host/",
        "/no-scheme",
        "host.example/rpc",
    ];
    assert_eq!(banned.len(), 8, "the banned-scheme set must not shrink");
    for url in banned {
        assert!(
            matches!(split_url(url), Err(AddressRefusal::Scheme { .. })),
            "`{url}` must be refused on its scheme"
        );
    }
    assert!(split_url("https://ok.example/rpc").is_ok());
}

#[test]
fn userinfo_is_refused_rather_than_stripped() {
    assert!(matches!(
        split_url("https://evil.test@good.example/rpc"),
        Err(AddressRefusal::NoHost(_))
    ));
}

/// A refusal names the URL, and a URL's authority is where a password goes.

#[test]
fn a_refusal_never_repeats_the_credential_in_the_authority() {
    let refusals = [
        split_url("https://svc:hunter2@good.example/rpc").expect_err("userinfo is refused"),
        split_url("ftp://svc:hunter2@good.example/x").expect_err("the scheme is refused"),
    ];
    for refusal in refusals {
        let text = refusal.to_string();
        assert!(
            !text.contains("hunter2") && !text.contains("svc"),
            "the refusal repeated the credential: {text}"
        );
        assert!(
            text.contains("good.example"),
            "the refusal must still name the host it is about: {text}"
        );
    }

    let path_at = split_url("ftp://good.example/mail@archive").expect_err("the scheme is refused");
    assert!(path_at.to_string().contains("mail@archive"));
}

/// A provider base URL's userinfo is STRIPPED, as 1.5.5's `host_from_base` stripped

#[test]
fn a_base_url_userinfo_is_stripped_to_the_host_it_names() {
    for (written, stripped) in [
        (
            "https://svcuser:hunter2-P4ss@api.example.com",
            "https://api.example.com",
        ),
        (
            "https://svcuser:hunter2-P4ss@api.example.com:8443/v1",
            "https://api.example.com:8443/v1",
        ),
        (
            "https://svcuser:hun@ter2@api.example.com/v1",
            "https://api.example.com/v1",
        ),
        ("https://svcuser@api.example.com", "https://api.example.com"),
        ("https://api.example.com/x@y", "https://api.example.com/x@y"),
        (
            "https://api.example.com?q=a@b",
            "https://api.example.com?q=a@b",
        ),
        ("https://api.example.com", "https://api.example.com"),
        ("api.example.com", "api.example.com"),
    ] {
        assert_eq!(strip_userinfo(written), stripped, "{written}");
    }

    assert!(matches!(
        strip_userinfo("https://api.example.com/v1"),
        std::borrow::Cow::Borrowed(_)
    ));

    let (https, host, port, path) = split_url(&strip_userinfo(
        "https://svcuser:hunter2-P4ss@api.example.com:8443/v1",
    ))
    .expect("the stripped base reads");
    assert!(https && host == "api.example.com" && port == 8443 && path == "/v1");

    assert!(matches!(
        split_url("https://svcuser:hunter2-P4ss@api.example.com"),
        Err(AddressRefusal::NoHost(_))
    ));
}

#[test]
fn default_ports_are_derived_from_the_scheme_and_ipv6_comes_back_unbracketed() {
    let (https, host, port, path) = split_url("https://a.example/rpc").unwrap();
    assert!(https && host == "a.example" && port == 443 && path == "/rpc");
    let (https, _, port, path) = split_url("http://a.internal").unwrap();
    assert!(!https && port == 80 && path == "/");
    let (_, host, port, _) = split_url("https://[::1]:9443/x").unwrap();
    assert_eq!((host.as_str(), port), ("::1", 9443));
    assert_eq!((default_port(true), default_port(false)), (443, 80));
}

/// A `%XX` escape naming a dot is the same host as the dot, which is the whole SSRF claim.
#[test]
fn a_percent_encoded_metadata_host_normalizes_to_the_address_it_will_dial() {
    assert_eq!(
        extract_normalized_host("https://169%2E254%2E169%2E254/").as_deref(),
        Some("169.254.169.254"),
        "an escaped dot must be read as the dot the connecting stack will read"
    );

    assert_eq!(
        extract_normalized_host("https://169%2e254%2e169%2e254/").as_deref(),
        Some("169.254.169.254")
    );

    assert!("169.254.169.254".parse::<IpAddr>().is_ok());
}

/// An escape this decoder cannot read stays VERBATIM rather than being dropped or guessed at.

#[test]
fn a_malformed_percent_escape_is_left_exactly_as_it_was_written() {
    assert_eq!(
        extract_normalized_host("https://host.example%/").as_deref(),
        Some("host.example%")
    );
    assert_eq!(
        extract_normalized_host("https://host.exampl%4/").as_deref(),
        Some("host.exampl%4")
    );

    assert_eq!(
        extract_normalized_host("https://host%ZZexample/").as_deref(),
        Some("host%ZZexample")
    );

    assert!("host.example%".parse::<IpAddr>().is_err());
}

/// The decode runs EXACTLY ONCE. `%252E` is the escape for the literal text `%2E`, and a decoder

#[test]
fn the_decode_runs_once_and_does_not_unwrap_a_double_encoding() {
    assert_eq!(
        extract_normalized_host("https://169%252E254%252E169%252E254/").as_deref(),
        Some("169%2E254%2E169%2E254"),
        "one pass, so a double encoding decodes to the literal escape text and no further"
    );
}

/// A decoding that would not be TEXT is abandoned and the original stands.

#[test]
fn a_decoding_that_would_not_be_text_leaves_the_host_as_it_was() {
    assert_eq!(
        extract_normalized_host("https://host%FFexample.test/").as_deref(),
        Some("host%FFexample.test"),
        "bytes that are not UTF-8 abandon the decode rather than mangling the host"
    );
}

/// A NUL, by contrast, IS text and therefore DOES decode — pinned because the two escapes look

#[test]
fn an_escaped_nul_decodes_and_does_not_truncate_the_host() {
    assert_eq!(
        extract_normalized_host("https://169.254.169.254%00.evil.example/").as_deref(),
        Some("169.254.169.254\u{0}.evil.example"),
        "the NUL decodes in place; the host is not cut short at it"
    );
    assert!(
        "169.254.169.254\u{0}.evil.example"
            .parse::<IpAddr>()
            .is_err(),
        "and the decoded host is still not the metadata address"
    );
}

/// The decode happens BEFORE the trailing-root-dot strip, so an escaped trailing dot is stripped

#[test]
fn an_escaped_trailing_root_dot_is_stripped_because_the_decode_comes_first() {
    assert_eq!(
        extract_normalized_host("https://169.254.169.254%2E/").as_deref(),
        Some("169.254.169.254")
    );

    assert_eq!(
        extract_normalized_host("https://169.254.169.254./").as_deref(),
        Some("169.254.169.254")
    );
}

/// A host with no `%` in it at all comes back unchanged — the ordinary case, pinned so the

#[test]
fn a_host_with_no_escape_in_it_is_returned_unchanged() {
    assert_eq!(
        extract_normalized_host("https://api.upstream.example/v1").as_deref(),
        Some("api.upstream.example")
    );
}

/// WHITESPACE AROUND A URL MUST NOT BUY A METADATA HOP. The WHATWG basic URL parser begins by

#[test]
fn whitespace_padded_metadata_urls_are_still_refused() {
    for spelling in [
        "http://169.254.169.254/latest/meta-data/ ",
        "http://169.254.169.254 ",
        " http://169.254.169.254/latest/meta-data/",
        "\u{1}http://169.254.169.254/",
        "http://169.254.169.254/\u{1f}",
        "http://169.254.169\t.254/",
        "http://169.254.169.254\r\n/",
        "\t http://169.254.169.254/ \r\n",
    ] {
        assert_eq!(
            ssrf_blocked_host(spelling, &[], false, &[]).as_deref(),
            Some("169.254.169.254"),
            "{spelling:?} is dialled as the IMDS target once the parser trims and deletes the \
             whitespace the guard must trim and delete the same way"
        );
    }
}

/// The CONTROL for the trim: whitespace INSIDE a host (not at either end of the input, and not one

#[test]
fn interior_spaces_are_not_trimmed_away() {
    assert_eq!(
        extract_normalized_host("http://169.254.169 .254/").as_deref(),
        Some("169.254.169 .254")
    );
    assert_eq!(
        ssrf_blocked_host("http://169.254.169 .254/", &[], false, &[]),
        None
    );
    assert_eq!(
        extract_normalized_host("  https://api.upstream.example/v1  ").as_deref(),
        Some("api.upstream.example")
    );
}

/// THE OPERATOR'S DENYLIST IS THE THING THE PADDING DEFEATED. The metadata refusals above are

#[test]
fn a_padded_authority_does_not_slip_past_the_operator_denylist() {
    let blocked = vec!["10.99.99.99".to_string()];
    for spelling in [
        "https://10.99.99.99",
        "https://10.99.99.99 ",
        " https://10.99.99.99",
        "https://10.99.99.99\u{1f}",
        "10.99.99.99",
        "10.99.99.99 ",
        " 10.99.99.99:8443",
    ] {
        assert_eq!(
            ssrf_blocked_host(spelling, &[], false, &blocked).as_deref(),
            Some("10.99.99.99"),
            "{spelling:?} must fire the operator's denylist entry"
        );
    }
}

/// The authority ends where the dialling stack ends it — at `/`, `?`, `#` or `\` — and the host is

#[test]
fn split_url_ends_the_authority_where_the_dialler_does() {
    for (url, host, port, path) in [
        ("https://127.0.0.1?x", "127.0.0.1", 443, "/?x"),
        ("https://localhost#a", "localhost", 443, "/#a"),
        ("https://127.0.0.1./", "127.0.0.1", 443, "/"),
        ("https://%6c%6fcalhost/", "localhost", 443, "/"),
        ("https://10.0.0.5\\x/", "10.0.0.5", 443, "/x/"),
        ("http://host.example?q=1", "host.example", 80, "/?q=1"),
        ("https://host.example:8443#f", "host.example", 8443, "/#f"),
    ] {
        let (_, h, p, pa) = split_url(url).unwrap_or_else(|e| panic!("{url}: {e}"));
        assert_eq!((h.as_str(), p, pa.as_str()), (host, port, path), "{url}");
    }

    assert!(matches!(
        split_url("https://svc@10.0.0.5\\x/"),
        Err(AddressRefusal::NoHost(_))
    ));
}

/// This pins the dialled host; the signed host is pinned equal to it by the plane driver's far-end

#[test]
fn test_host_from_base_backslash_authority_matches_wire_host() {
    for (url, host, port, path) in [
        (
            "https://evil.example.com\\@victim.example/path",
            "evil.example.com",
            443,
            "/@victim.example/path",
        ),
        (
            "https://host.example.com\\some\\path",
            "host.example.com",
            443,
            "/some/path",
        ),
        (
            "https://host.example.com:8443\\v1\\foo",
            "host.example.com",
            8443,
            "/v1/foo",
        ),
    ] {
        let (https, h, p, pa) = split_url(url).unwrap_or_else(|e| panic!("{url}: {e}"));
        assert!(https, "{url}");
        assert_eq!((h.as_str(), p, pa.as_str()), (host, port, path), "{url}");
    }
    assert!(matches!(
        split_url("https://user:pass@host.example.com\\p"),
        Err(AddressRefusal::NoHost(_))
    ));
}

/// THE HOST-STRING GUARDS MUST JUDGE THE NAT64 EMBEDDING TOO, not just the address predicates.

#[test]
fn nat64_embedded_ipv4_is_judged_by_the_host_string_guards() {
    for meta in [
        "169.254.169.254",
        "::ffff:169.254.169.254",
        "64:ff9b::a9fe:a9fe",
        "64:ff9b:1::a9fe:a9fe",
        "64:ff9b:1:fffe::a9fe:a9fe",
    ] {
        let url = format!("http://[{meta}]/latest/meta-data/");
        let url = if meta.contains(':') {
            url
        } else {
            format!("http://{meta}/latest/meta-data/")
        };
        assert!(
            ssrf_blocked_host(&url, &[], false, &[]).is_some(),
            "{meta} reaches the cloud-metadata service and must be refused pre-flight; \
             a NAT64 spelling is the same target as the bare form"
        );
    }

    for internal in [
        "64:ff9b::7f00:1",
        "64:ff9b::a01:203",
        "64:ff9b:1:fffe::c0a8:1",
    ] {
        assert!(
            host_is_private_or_loopback(internal),
            "{internal} is a NAT64 embedding of an internal target and must read as internal"
        );
    }

    const NAT64_OF_10_99_99_99: &str = "https://[64:ff9b::a63:6363]/";
    assert!(
        ssrf_blocked_host(
            NAT64_OF_10_99_99_99,
            &[],
            false,
            &["10.99.99.99".to_string()]
        )
        .is_some(),
        "a denylist entry naming the v4 address must match its NAT64 embedding"
    );
    assert!(
        ssrf_blocked_host(NAT64_OF_10_99_99_99, &[], false, &[]).is_none(),
        "the control: without the operator entry this host is an ordinary private upstream, so the \
         assertion above is about the entry and not about the hardcoded denylist"
    );

    assert!(
        !host_is_private_or_loopback("64:ff9b::808:808"),
        "64:ff9b::808:808 embeds public 8.8.8.8 and must NOT read as internal"
    );
}

/// 1.5.5 PARITY: an entry that names no host the guard judges (UTS #46 refuses it, a `%` outside an

#[test]
fn a_list_entry_that_names_no_host_is_dropped_and_lifts_no_real_target() {
    let entries: Vec<String> = [
        "b\u{fc}cher\u{ff1c}.example",
        "%6c%6fcalhost",
        "169%2e254%2e169%2e254",
        "1.2.3.4.5",
        "999.1.1.1",
        "foo.127",
        "x.0",
        "0x",
    ]
    .iter()
    .map(|e| e.to_string())
    .collect();
    for target in [
        "https://169.254.169.254/latest/meta-data/",
        "https://metadata.google.internal/computeMetadata/v1/",
        "169.254.169.254:80",
    ] {
        assert!(
            ssrf_blocked_host(target, &entries, false, &entries).is_some(),
            "`{target}` stays blocked"
        );
    }
}

/// RED (HIGH): an operator's list entry is read as a target's host is read. A full-width blocked

#[test]
fn a_list_entry_is_read_as_a_targets_host_is_read() {
    let full_width_ip = "\u{ff11}\u{ff10}.\u{ff19}\u{ff19}.\u{ff19}\u{ff19}.\u{ff19}\u{ff19}";
    let full_width_name = "\u{ff4d}\u{ff45}\u{ff54}\u{ff41}.example";
    for (entry, target) in [
        (full_width_ip, "https://10.99.99.99/"),
        (full_width_ip, "https://[::ffff:10.99.99.99]/"),
        (full_width_ip, "10.99.99.99:443"),
        (full_width_name, "https://meta.example/"),
        (full_width_name, "https://META.example./"),
        (full_width_name, "meta.example:443"),
    ] {
        let blocked = [entry.to_string()];
        assert!(
            ssrf_blocked_host(target, &[], false, &blocked).is_some(),
            "`{entry}` blocks `{target}`"
        );
    }

    let full_width_meta = "\u{ff4d}\u{ff45}\u{ff54}\u{ff41}\u{ff44}\u{ff41}\u{ff54}\u{ff41}.\
                           \u{ff47}\u{ff4f}\u{ff4f}\u{ff47}\u{ff4c}\u{ff45}.\
                           \u{ff49}\u{ff4e}\u{ff54}\u{ff45}\u{ff52}\u{ff4e}\u{ff41}\u{ff4c}";
    let url = "https://metadata.google.internal/";
    assert!(ssrf_blocked_host(url, &[], false, &[]).is_some());
    assert_eq!(
        ssrf_blocked_host(url, &[full_width_meta.to_string()], false, &[]),
        None
    );

    assert_eq!(
        list_entry_host("  META.example. ").as_deref(),
        Ok("META.example.")
    );
    assert_eq!(
        list_entry_host("%6c%6fcalhost").as_deref(),
        Ok("%6c%6fcalhost")
    );
    assert_eq!(list_entry_host(full_width_ip).as_deref(), Ok("10.99.99.99"));
    assert_eq!(
        list_entry_host(full_width_name).as_deref(),
        Ok("meta.example")
    );
    for unmappable in ["b\u{fc}cher\u{ff1c}.example", "\u{3002}"] {
        assert_eq!(
            list_entry_host(unmappable),
            Err(UrlRefusal::NoHost),
            "{unmappable:?}"
        );
        assert!(
            ssrf_blocked_host(
                "https://example.com/",
                &[],
                false,
                &[unmappable.to_string()]
            )
            .is_none(),
            "an unmappable entry names nothing"
        );
    }
}
