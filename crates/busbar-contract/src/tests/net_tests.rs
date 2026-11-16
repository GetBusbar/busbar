// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The URL and host reader, over every bypass spelling the host-parsing audit found: each row is a

use super::*;
use std::net::{IpAddr, Ipv4Addr};

/// One row: the input, then what [`parse_url`] reads (scheme, userinfo, host, port, path), then
type Row = (
    &'static str,
    (&'static str, bool, &'static str, Option<u16>, &'static str),
    bool,
    bool,
);

/// Every audit bypass input, and the spellings around it, read the way the dialling stack reads it.
#[test]
fn every_bypass_spelling_reads_the_host_the_dialler_reads() {
    let rows: &[Row] = &[
        (
            "ldaps://evil.example#@127.0.0.1",
            ("ldaps", false, "evil.example", None, "#@127.0.0.1"),
            false,
            false,
        ),
        (
            "https://127.0.0.1?x",
            ("https", false, "127.0.0.1", None, "/?x"),
            true,
            false,
        ),
        (
            "https://localhost#a",
            ("https", false, "localhost", None, "/#a"),
            true,
            false,
        ),
        (
            "https://127.0.0.1./",
            ("https", false, "127.0.0.1", None, "/"),
            true,
            false,
        ),
        (
            "https://%6c%6fcalhost/",
            ("https", false, "localhost", None, "/"),
            true,
            false,
        ),
        (
            "https://\x310.0.0.5\\x/",
            ("https", false, "\x310.0.0.5", None, "/x/"),
            true,
            false,
        ),
        (
            "wss://127.0.0.1\\x/",
            ("wss", false, "127.0.0.1", None, "/x/"),
            true,
            false,
        ),
        (
            "https://evil.example\\@trusted.example/cb",
            ("https", false, "evil.example", None, "/@trusted.example/cb"),
            false,
            false,
        ),
        (
            "https://user:pw@host.example/",
            ("https", true, "host.example", None, "/"),
            false,
            false,
        ),
        (
            "ldaps://:pw@\x310.0.0.1:636/0",
            ("ldaps", true, "\x310.0.0.1", Some(636), "/0"),
            true,
            false,
        ),
        (
            "ldaps://u\x40db.internal:389/x",
            ("ldaps", true, "db.internal", Some(389), "/x"),
            false,
            false,
        ),
        (
            "https://[::1]:8443/x",
            ("https", false, "::1", Some(8443), "/x"),
            true,
            false,
        ),
        (
            "https://[::ffff:127.0.0.1]/",
            ("https", false, "::ffff:127.0.0.1", None, "/"),
            true,
            false,
        ),
        (
            "ldaps://[::1]",
            ("ldaps", false, "::1", None, ""),
            true,
            false,
        ),
        (
            "https://[fd00:ec2::254]/",
            ("https", false, "fd00:ec2::254", None, "/"),
            true,
            true,
        ),
        (
            "https://[fd00:ec2::23]/",
            ("https", false, "fd00:ec2::23", None, "/"),
            true,
            true,
        ),
        (
            "https://2130706433/",
            ("https", false, "2130706433", None, "/"),
            true,
            false,
        ),
        (
            "https://0x7f000001/",
            ("https", false, "0x7f000001", None, "/"),
            true,
            false,
        ),
        (
            "https://0177.0.0.1/",
            ("https", false, "0177.0.0.1", None, "/"),
            true,
            false,
        ),
        (
            "https://127.1/",
            ("https", false, "127.1", None, "/"),
            true,
            false,
        ),
        (
            "https://0x7f.1/",
            ("https", false, "0x7f.1", None, "/"),
            true,
            false,
        ),
        (
            "https://0xa9fea9fe/",
            ("https", false, "0xa9fea9fe", None, "/"),
            true,
            true,
        ),
        (
            "https://169.254.43518/",
            ("https", false, "169.254.43518", None, "/"),
            true,
            true,
        ),
        (
            "  https://\x310.0.0.1 ",
            ("https", false, "\x310.0.0.1", None, "/"),
            true,
            false,
        ),
        (
            "https://169.254.169\t.254/",
            ("https", false, "169.254.169.254", None, "/"),
            true,
            true,
        ),
        (
            "https:\\\\evil.example\\x",
            ("https", false, "evil.example", None, "/x"),
            false,
            false,
        ),
        (
            "HTTPS://Example.COM:/",
            ("https", false, "Example.COM", None, "/"),
            false,
            false,
        ),
        (
            "https://metadata.google.internal./",
            ("https", false, "metadata.google.internal", None, "/"),
            false,
            true,
        ),
        (
            "https://METADATA.internal",
            ("https", false, "METADATA.internal", None, "/"),
            false,
            true,
        ),
        (
            "https://168.63.129.16/",
            ("https", false, "168.63.129.16", None, "/"),
            false,
            true,
        ),
        (
            "https://api.example.com/v1",
            ("https", false, "api.example.com", None, "/v1"),
            false,
            false,
        ),
    ];
    for (input, (scheme, userinfo, host, port, path), private, metadata) in rows {
        let got = parse_url(input).unwrap_or_else(|e| panic!("{input:?}: {e}"));
        assert_eq!(got.scheme, *scheme, "{input:?} scheme");
        assert_eq!(got.userinfo, *userinfo, "{input:?} userinfo");
        assert_eq!(got.host, *host, "{input:?} host");
        assert_eq!(got.port, *port, "{input:?} port");
        assert_eq!(got.path, *path, "{input:?} path");
        assert_eq!(
            url_host(input).as_deref(),
            Some(*host),
            "{input:?} url_host"
        );
        assert_eq!(
            host_is_private_or_loopback(&got.host),
            *private,
            "{input:?} private-or-loopback"
        );
        assert_eq!(
            host_is_cloud_metadata(&got.host),
            *metadata,
            "{input:?} cloud metadata"
        );
    }
}

/// Every string the reader refuses, with the reason.
#[test]
fn a_string_with_no_readable_host_is_refused_with_its_reason() {
    for (input, want) in [
        ("https://[::1", UrlRefusal::Bracket),
        ("https://[::1]x/", UrlRefusal::Bracket),
        ("https://[not-v6]/", UrlRefusal::Bracket),
        ("https://::1/", UrlRefusal::Bracket),
        ("ldap://a\\@127.0.0.1/", UrlRefusal::Backslash),
        ("https://h.example:99999/", UrlRefusal::Port),
        ("https://h.example:+1/", UrlRefusal::Port),
        ("https://evil%40good.example/", UrlRefusal::NoHost),
        ("https://bad%zzhost/", UrlRefusal::NoHost),
        ("https:///", UrlRefusal::NoHost),
        ("https://", UrlRefusal::NoHost),
        ("127.0.0.1", UrlRefusal::NoScheme),
        ("//host/x", UrlRefusal::NoScheme),
        ("1ab://x/", UrlRefusal::NoScheme),
        ("ldap:host", UrlRefusal::NoAuthority),
    ] {
        assert_eq!(parse_url(input), Err(want), "{input:?}");
        assert_eq!(url_host(input), None, "{input:?}");
    }
}

/// A dial target reads as a URL when it is one and as a bare authority otherwise, so a scheme is
#[test]
fn a_dial_target_never_reads_its_scheme_as_the_host() {
    for (target, want) in [
        ("https://169.254.169.254/", Some("169.254.169.254")),
        ("169.254.169.254:80", Some("169.254.169.254")),
        ("[::1]:443", Some("::1")),
        ("::ffff:169.254.169.254", Some("::ffff:169.254.169.254")),
        (
            "[fd00:0ec2:0000::0254%eth0]:80",
            Some("fd00:0ec2:0000::0254%eth0"),
        ),
        (
            "METADATA.Google.Internal.",
            Some("METADATA.Google.Internal"),
        ),
        ("localhost:8080", Some("localhost")),
        ("ldap://evil.example#@127.0.0.1", Some("evil.example")),
        ("", None),
    ] {
        assert_eq!(target_host(target).as_deref(), want, "{target:?}");
    }
}

/// The literal spellings the resolver accepts all name one address; a DNS name names none.
#[test]
fn every_literal_spelling_names_its_address() {
    let loopback = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    for host in [
        "127.0.0.1",
        "2130706433",
        "0x7f000001",
        "0177.0.0.1",
        "127.1",
        "0x7f.1",
    ] {
        assert_eq!(host_ip(host), loopback, "{host}");
    }
    assert_eq!(
        host_ip("fd00:0ec2:0000::0254%eth0"),
        Some("fd00:ec2::254".parse().unwrap())
    );
    for host in ["api.example.com", "0x1ffffffff", "256.254.169.254", ""] {
        assert_eq!(host_ip(host), None, "{host}");
    }
}

/// IPv6 link-local is its own fact, not a metadata one: `host_is_link_local_v6` holds fe80::/10 in
#[test]
fn ipv6_link_local_is_its_own_predicate_not_a_metadata_one() {
    for host in ["fe80::1", "FE80::a9fe:a9fe", "fe80::1%eth0", "febf:ffff::1"] {
        assert!(host_is_link_local_v6(host), "{host}");
        assert!(!host_is_cloud_metadata(host), "{host}");
    }
    for host in [
        "fe7f:ffff::1",
        "fec0::1",
        "fd00:ec2::254",
        "169.254.169.254",
        "example.com",
    ] {
        assert!(!host_is_link_local_v6(host), "{host}");
    }
}

/// IPv6 site-local `fec0::/10` is internal: the one guard refuses it as hook-webrequest's own
/// literal check did, so that copy can go without widening what a dial may reach.
#[test]
fn ipv6_site_local_is_internal_and_its_neighbours_keep_their_reading() {
    for addr in ["fec0::1", "FEC0::a", "feff:ffff::1", "fef0::"] {
        let v6: std::net::Ipv6Addr = addr.parse().unwrap();
        assert!(is_site_local_v6(&v6), "{addr}");
        assert!(ipv6_is_internal(&v6), "{addr}");
        assert!(ip_is_internal(&IpAddr::V6(v6)), "{addr}");
        assert!(!ip_is_cloud_metadata(&IpAddr::V6(v6)), "{addr}");
    }
    for addr in ["febf:ffff::1", "ff00::1", "2001:db8::1", "2606:4700::1111"] {
        let v6: std::net::Ipv6Addr = addr.parse().unwrap();
        assert!(!is_site_local_v6(&v6), "{addr}");
    }
    let public: std::net::Ipv6Addr = "2606:4700::1111".parse().unwrap();
    assert!(!ipv6_is_internal(&public));
}

/// THE ONE AUTHORITY SPLIT reads v1.5.5's authority: it ends at `/`, `?`, `#` and (no scheme, or a
#[test]
fn the_authority_ends_where_the_dialling_stack_ends_it() {
    fn at(url: &str) -> (Option<&str>, Option<&str>, &str, &str) {
        let a = url_authority(url);
        (a.scheme, a.userinfo, a.host_port, a.tail)
    }
    assert_eq!(
        at("https://evil.example\\@victim.example/p"),
        (Some("https"), None, "evil.example", "\\@victim.example/p")
    );
    assert_eq!(
        at("https://u:p@w@host.example:8443/x?q#f"),
        (Some("https"), Some("u:p@w"), "host.example:8443", "/x?q#f")
    );
    assert_eq!(
        at("https://host.example#f@other.example"),
        (Some("https"), None, "host.example", "#f@other.example")
    );
    assert_eq!(
        at("host.example\\x@other"),
        (None, None, "host.example", "\\x@other")
    );
    assert_eq!(
        at("ftp://a\\b@dir.example/o"),
        (Some("ftp"), Some("a\\b"), "dir.example", "/o")
    );
    assert_eq!(
        at("HTTPS://h.example"),
        (Some("HTTPS"), None, "h.example", "")
    );

    for url in [
        "https://evil.example\\@victim.example/p",
        "https://u:p@host.example/x",
        "https://host.example?x@y",
    ] {
        assert_eq!(
            url_host(url).as_deref(),
            Some(url_authority(url).host_port.split(':').next().unwrap_or("")),
            "{url}"
        );
    }
}

/// The address value types a plugin names through the contract ARE `std::net`'s: a plugin that
#[test]
fn the_contract_address_values_are_the_std_types() {
    let v4: Result<super::Ipv4Addr, super::AddrParseError> = "127.0.0.1".parse();
    assert_eq!(v4, Ok(std::net::Ipv4Addr::LOCALHOST));
    let sock: Result<super::SocketAddr, super::AddrParseError> = "[::1]:443".parse();
    assert_eq!(
        sock,
        Ok(std::net::SocketAddr::from((
            std::net::Ipv6Addr::LOCALHOST,
            443
        )))
    );
    assert!("example.com:443".parse::<super::SocketAddr>().is_err());
    let v6: super::SocketAddrV6 = super::SocketAddrV6::new(super::Ipv6Addr::LOCALHOST, 1, 0, 0);
    let ip: super::IpAddr = (*v6.ip()).into();
    assert!(ip.is_loopback());
    let _: Option<super::SocketAddrV4> = None;
}

/// An IDN host reads as its UTS #46 punycode name, the name busbar 1.5.5 dialled and sent as its
#[test]
fn an_idn_host_reads_as_its_punycode_name() {
    for (input, host, port) in [
        (
            "https://b\u{fc}cher.example/",
            "xn--bcher-kva.example",
            None,
        ),
        (
            "https://b%C3%BCcher.example:8443/x",
            "xn--bcher-kva.example",
            Some(8443),
        ),
        (
            "wss://m\u{fc}nchen.example/",
            "xn--mnchen-3ya.example",
            None,
        ),
        (
            "ftp://b\u{fc}cher.example:2121/",
            "xn--bcher-kva.example",
            Some(2121),
        ),
        (
            "https://b\u{fc}cher.example\u{ff0e}/",
            "xn--bcher-kva.example",
            None,
        ),
        (
            "https://user@b\u{fc}cher.example/",
            "xn--bcher-kva.example",
            None,
        ),
    ] {
        let got = parse_url(input).unwrap_or_else(|e| panic!("{input:?}: {e}"));
        assert_eq!((got.host.as_str(), got.port), (host, port), "{input:?}");
        assert_eq!(url_host(input).as_deref(), Some(host), "{input:?}");
        assert_eq!(target_host(input).as_deref(), Some(host), "{input:?}");
    }
    assert_eq!(
        url_host_to_ascii("b\u{fc}cher.example").as_deref(),
        Ok("xn--bcher-kva.example")
    );
}

/// A mixed-case IDN normalises the way `url` normalises it: UTS #46 lower-cases the whole name,
#[test]
fn a_mixed_case_idn_normalises_the_way_url_does() {
    for (input, host) in [
        ("https://B\u{dc}CHER.Example/", "xn--bcher-kva.example"),
        ("https://b\u{fc}cher.EXAMPLE/", "xn--bcher-kva.example"),
        ("https://M\u{dc}nchen.De/", "xn--mnchen-3ya.de"),
        (
            "https://\u{ff11}\u{ff12}\u{ff17}.\u{ff10}.\u{ff10}.\u{ff11}/",
            "127.0.0.1",
        ),
    ] {
        assert_eq!(url_host(input).as_deref(), Some(host), "{input:?}");
    }
    let loopback = url_host("https://\u{ff11}\u{ff12}\u{ff17}\u{ff0e}0.0.1/").expect("a host");
    assert_eq!(loopback, "127.0.0.1");
    assert!(host_is_private_or_loopback(&loopback));
}

/// A WHATWG-forbidden host is refused, written as itself or produced by the UTS #46 mapping, and
#[test]
fn a_whatwg_forbidden_host_is_refused() {
    for input in [
        "https://exa<mple.com/",
        "https://exa^mple.com/",
        "https://exa|mple.com/",
        "https://b\u{fc}cher\u{ff1c}.example/",
        "https://b\u{fc}cher.\u{2100}.example/",
        "https://b\u{fc}cher\u{fffd}.example/",
        "https://\u{ad}/",
    ] {
        assert_eq!(parse_url(input), Err(UrlRefusal::NoHost), "{input:?}");
        assert_eq!(url_host(input), None, "{input:?}");
    }
    assert_eq!(
        url_host_to_ascii("b\u{fc}cher\u{ff1c}.example"),
        Err(UrlRefusal::NoHost)
    );
}

/// An ASCII host is read as it was before: its case as written, an ACE label untouched.
#[test]
fn an_ascii_host_is_unchanged() {
    for (input, host) in [
        ("https://Api.Example.COM/v1", "Api.Example.COM"),
        ("https://xn--bcher-kva.example/", "xn--bcher-kva.example"),
        ("ldap://Dir.Example:389", "Dir.Example"),
        ("https://127.0.0.1./", "127.0.0.1"),
        ("http://example.com./x", "example.com"),
    ] {
        assert_eq!(url_host(input).as_deref(), Some(host), "{input:?}");
    }
    assert!(matches!(
        url_host_to_ascii("Api.Example.COM"),
        Ok(std::borrow::Cow::Borrowed("Api.Example.COM"))
    ));
}

/// A non-special scheme's non-ASCII host is `url` 2.5.8's OPAQUE host, byte for byte
#[test]
fn a_non_special_idn_host_reads_as_urls_opaque_host() {
    for (input, host, port) in [
        ("ldap://b\u{fc}cher.example", "b%C3%BCcher.example", None),
        (
            "ldaps://b\u{fc}cher.example:636",
            "b%C3%BCcher.example",
            Some(636),
        ),
        ("ldap://B\u{dc}CHER.Example/x", "B%C3%9CCHER.Example", None),
        ("ldap://b%C3%BCcher.example", "b%C3%BCcher.example", None),
        ("ldap://\u{4f8b}.example.", "%E4%BE%8B.example.", None),
    ] {
        let got = parse_url(input).unwrap_or_else(|e| panic!("{input:?}: {e}"));
        assert_eq!((got.host.as_str(), got.port), (host, port), "{input:?}");
        assert_eq!(target_host(input).as_deref(), Some(host), "{input:?}");
    }

    for (input, host, port) in [
        ("ldap://a%25b.example:389", "a%25b.example", Some(389)),
        ("ldaps://dir%25.example", "dir%25.example", None),
        ("ldap://evil%40good.example", "evil%40good.example", None),
        (
            "ldapi://%2Fvar%2Frun%2Fslapd%2Fldapi",
            "%2Fvar%2Frun%2Fslapd%2Fldapi",
            None,
        ),
    ] {
        let got = parse_url(input).unwrap_or_else(|e| panic!("{input:?}: {e}"));
        assert_eq!((got.host.as_str(), got.port), (host, port), "{input:?}");
        assert_eq!(url_host(input).as_deref(), Some(host), "{input:?}");
        assert_eq!(target_host(input), None, "{input:?}");
    }
    assert_eq!(
        parse_url("ldap://b\u{fc}<cher.example"),
        Err(UrlRefusal::NoHost)
    );
}

/// A bare `host[:port]` dial target with a non-ASCII host reads as its punycode name, as a URL
#[test]
fn a_bare_idn_authority_reads_as_its_punycode_name() {
    for (input, host) in [
        ("b\u{fc}cher.example", "xn--bcher-kva.example"),
        ("b\u{fc}cher.example:8443", "xn--bcher-kva.example"),
        ("B\u{dc}CHER.Example.:443", "xn--bcher-kva.example"),
        ("b%C3%BCcher.example:443", "xn--bcher-kva.example"),
        ("Plain.Example:443", "Plain.Example"),
    ] {
        assert_eq!(
            extract_normalized_authority_host(input).as_deref(),
            Some(host),
            "{input:?}"
        );
        assert_eq!(target_host(input).as_deref(), Some(host), "{input:?}");
    }
    assert_eq!(
        extract_normalized_authority_host("b\u{fc}cher\u{ff1c}.example:1"),
        None
    );

    assert_eq!(
        extract_normalized_host("https://b\u{fc}cher.example/").as_deref(),
        Some("xn--bcher-kva.example")
    );
    assert_eq!(
        extract_normalized_host("https://Plain.Example./").as_deref(),
        Some("Plain.Example")
    );
    assert_eq!(
        extract_normalized_host("https://b\u{fc}cher\u{ff1c}.example/"),
        None
    );
}

/// `url` 2.5.8'S IPv4 READING (`url/src/host.rs` `ends_in_a_number`, `parse_ipv4addr`): the short,
#[test]
fn url_host_ipv4_reads_a_host_as_url_2_5_8_reads_it() {
    let v4 = |s: &str| s.parse::<Ipv4Addr>().expect("an address");
    for (host, addr) in [
        ("127.0.0.1", "127.0.0.1"),
        ("127.1", "127.0.0.1"),
        ("0x7f.1", "127.0.0.1"),
        ("0X7F.1", "127.0.0.1"),
        ("017700000001", "127.0.0.1"),
        ("2130706433", "127.0.0.1"),
        ("0177.0.0.1", "127.0.0.1"),
        ("169.254.169.254.", "169.254.169.254"),
        ("0x", "0.0.0.0"),
        ("1.0x", "1.0.0.0"),
        ("0xffffffff", "255.255.255.255"),
    ] {
        assert_eq!(url_host_ipv4(host), Ok(Some(v4(addr))), "{host}");
    }
    for domain in ["localhost", "example.com", "0x7g", "1.2.x", "", "."] {
        assert_eq!(url_host_ipv4(domain), Ok(None), "{domain:?}");
    }
    for refused in [
        "1.2.3.4.5",
        "999.1.1.1",
        "09",
        "1.256.0x10000",
        "4294967296",
        "x.0",
        "1..2",
    ] {
        assert_eq!(url_host_ipv4(refused), Err(UrlRefusal::NoHost), "{refused}");
    }
}

/// THE HOST A DESTINATION JUDGE COMPARES: a non-ASCII host is the ASCII name or address UTS #46
#[test]
fn judged_host_maps_to_what_a_url_client_dials() {
    for (host, judged) in [
        ("\u{ff4c}\u{ff4f}\u{ff43}\u{ff41}\u{ff4c}\u{ff48}\u{ff4f}\u{ff53}\u{ff54}", "localhost"),
        ("\u{2460}\u{2461}\u{2466}.0.0.1", "127.0.0.1"),
        (
            "\u{2460}\u{2465}\u{2468}.\u{2461}\u{2464}\u{2463}.\u{2460}\u{2465}\u{2468}.\u{2461}\u{2464}\u{2463}",
            "169.254.169.254",
        ),
        ("LOCALHOST\u{3002}", "localhost"),
        ("\u{ff10}x7f.1", "0x7f.1"),
        ("b\u{fc}cher.example", "xn--bcher-kva.example"),
        ("Api.Example.COM.", "api.example.com"),
        ("0x7f.1", "0x7f.1"),
        ("017700000001", "017700000001"),
        ("08", "08"),
        ("[::1]", "::1"),
        ("[FE80::1%25ETH0]", "fe80::1%25eth0"),
        ("fe80::1%eth0", "fe80::1%eth0"),
        ("::ffff:1.2.3.4", "::ffff:1.2.3.4"),
        ("x.0x7f-a", "x.0x7f-a"),
    ] {
        assert_eq!(judged_host(host).as_deref(), Ok(judged), "{host:?}");
    }
    for unjudgeable in [
        "0x",
        "1.0x",
        "0x.0x.0x.0x",
        "1.2.3.4.5",
        "999.1.1.1",
        "b\u{fc}cher\u{ff1c}.example",
        "\u{ff4c}\u{ff4f}\u{ff43}\u{ff41}\u{ff4c}\u{ff48}\u{ff4f}\u{ff53}\u{ff54}:80",
    ] {
        assert_eq!(
            judged_host(unjudgeable),
            Err(UrlRefusal::NoHost),
            "{unjudgeable:?}"
        );
    }
}

/// file: hosts are read opaque; no file: URL is dialled or judged. A non-ASCII local-file URL host
#[test]
fn a_local_file_url_host_reads_opaque() {
    for (input, host, path) in [
        ("file://b\u{fc}cher.example/x", "b%C3%BCcher.example", "/x"),
        ("file://B\u{dc}CHER.Example/", "B%C3%9CCHER.Example", "/"),
        ("file://Host.Example/a", "Host.Example", "/a"),
        ("file://host.example./x", "host.example", "/x"),
    ] {
        let got = parse_url(input).unwrap_or_else(|e| panic!("{input:?}: {e}"));
        assert_eq!(got.family, UrlFamily::Generic, "{input:?}");
        assert_eq!(
            (got.host.as_str(), got.path.as_str()),
            (host, path),
            "{input:?}"
        );
    }
}

/// Host validation refuses a percent escape outside an IPv6 zone ID.
#[test]
fn judged_host_refuses_a_percent_outside_an_ipv6_zone_id() {
    for escaped in [
        "%6c%6fcalhost",
        "%6C%6FCALHOST.",
        "127.0.0.1%2e",
        "%31%32%37.0.0.1",
        "api.example.com%",
        "[%6c%6fcalhost]",
        "a:b%c",
    ] {
        assert_eq!(judged_host(escaped), Err(UrlRefusal::NoHost), "{escaped:?}");
    }
    for (zoned, judged) in [
        ("[fe80::1%25eth0]", "fe80::1%25eth0"),
        ("fe80::1%eth0", "fe80::1%eth0"),
        ("[FE80::1%25ETH0]", "fe80::1%25eth0"),
    ] {
        assert_eq!(judged_host(zoned).as_deref(), Ok(judged), "{zoned:?}");
    }
}

#[test]
fn bc2_private_or_loopback_zoned_and_alternate_spellings() {
    assert!(host_is_private_or_loopback("fe80::1%eth0"));
    assert!(!host_is_private_or_loopback("0x08080808"));
    assert!(!host_is_private_or_loopback("8.8.8"));
    assert!(host_is_private_or_loopback("0x7f000001"));
}

#[test]
fn url_family_is_exact_protocol_grammar_independent_of_transport_inventory() {
    for scheme in ["http", "https", "ws", "wss"] {
        assert_eq!(UrlFamily::of(scheme), UrlFamily::Web, "{scheme}");
    }
    for scheme in [
        "",
        "HTTP",
        "Ws",
        "ftp",
        "sqlite",
        "http:",
        "ws+fixture",
        " http",
        "http/",
    ] {
        assert_eq!(UrlFamily::of(scheme), UrlFamily::Generic, "{scheme}");
    }
}

#[test]
fn the_shared_cidr_reader_parses_matches_and_refuses() {
    let net = IpNet::parse("\x310.0.0.0/8").unwrap();
    assert!(net.covers("\x310.255.0.1".parse().unwrap()));
    assert!(
        net.covers("::ffff:\x310.1.2.3".parse().unwrap()),
        "an embedded IPv4 is its IPv4"
    );
    assert!(!net.covers("11.0.0.1".parse().unwrap()));
    let v6 = IpNet::parse("[2001:db8::]/32").unwrap();
    assert!(v6.covers("2001:db8:ffff::1".parse().unwrap()));
    assert!(!v6.covers("2001:db9::1".parse().unwrap()));
    assert!(IpNet::parse("192.0.2.7").unwrap().is_host());
    assert_eq!(IpNet::parse("\x310.0.0.1/8"), Err(IpNetError::HostBitsSet));
    assert_eq!(IpNet::parse("\x310.0.0.0/33"), Err(IpNetError::NotNetwork));
    assert_eq!(IpNet::parse("proxy.internal"), Err(IpNetError::NotNetwork));
    assert_eq!(IpNet::read("proxy.internal"), Ok(None));
}

/// DEPENDENCY-LADDER C6 (percent-encoding) pins the host decoder before the hand loop goes: `%XX`
/// decoded in either case, a short or non-hex escape kept, and the host left as spelled when the
/// decoded bytes are not UTF-8.
#[test]
fn host_percent_decoding_pins_every_escape_shape() {
    for (raw, normalized) in [
        ("example.com", "example.com"),
        ("ex%41mple.com.", "exAmple.com"),
        ("ex%61mple.com", "example.com"),
        ("a%zz", "a%zz"),
        ("a%4", "a%4"),
        ("%FF.example", "%FF.example"),
        ("%C3%A9.example", "\u{e9}.example"),
    ] {
        assert_eq!(normalize_host(raw), normalized, "{raw:?}");
    }
}
