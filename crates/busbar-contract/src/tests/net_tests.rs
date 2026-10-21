// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The URL and host reader, over every bypass spelling the host-parsing audit found: each row is a
//! string two parsers read differently, and the row states the reading the dialling stack takes.

use super::*;
use std::net::{IpAddr, Ipv4Addr};

/// One row: the input, then what [`parse_url`] reads (scheme, userinfo, host, port, path), then
/// whether the host is private-or-loopback and whether it is a cloud-metadata endpoint.
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
        // The authority ends at `#` under RFC 3986, so the `@` after it is not a userinfo marker.
        (
            "ldap://evil.example#@127.0.0.1",
            ("ldap", false, "evil.example", None, "#@127.0.0.1"),
            false,
            false,
        ),
        // `?`, `#`, a trailing dot, a percent-encoded name and a `\` all end or reshape the host.
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
            "https://10.0.0.5\\x/",
            ("https", false, "10.0.0.5", None, "/x/"),
            true,
            false,
        ),
        (
            "wss://127.0.0.1\\x/",
            ("wss", false, "127.0.0.1", None, "/x/"),
            true,
            false,
        ),
        // The consent-screen case: the browser dials `evil.example`, not `trusted.example`.
        (
            "https://evil.example\\@trusted.example/cb",
            ("https", false, "evil.example", None, "/@trusted.example/cb"),
            false,
            false,
        ),
        // A real userinfo is reported, split at the last `@`, and never kept.
        (
            "https://user:pw@host.example/",
            ("https", true, "host.example", None, "/"),
            false,
            false,
        ),
        (
            "ldaps://:pw@10.0.0.1:636/0",
            ("ldaps", true, "10.0.0.1", Some(636), "/0"),
            true,
            false,
        ),
        (
            "ldap://u@db.internal:389/x",
            ("ldap", true, "db.internal", Some(389), "/x"),
            false,
            false,
        ),
        // IPv6 brackets.
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
            "ldap://[::1]",
            ("ldap", false, "::1", None, ""),
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
        // The alternate IPv4 spellings: the host reads as written, and means the address.
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
        // The WHATWG first step: padding trimmed, tabs deleted, slashes after the scheme skipped.
        (
            "  https://10.0.0.1 ",
            ("https", false, "10.0.0.1", None, "/"),
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
        // The one metadata list: names with a trailing dot and any case, Azure's public address.
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
/// never read as the host.
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
/// every spelling the reader takes, and `host_is_cloud_metadata` does not claim it.
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

/// THE ONE AUTHORITY SPLIT reads v1.5.5's authority: it ends at `/`, `?`, `#` and (no scheme, or a
/// web scheme) `\`; the userinfo runs to the authority's last `@`; a generic scheme keeps its `\`.
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
    // The authority the split reads is the host the WHATWG reader reads.
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
/// switches its `std::net::SocketAddr` to `busbar_contract::net::SocketAddr` reads the same value.
#[test]
fn the_contract_address_values_are_the_std_types() {
    let v4: Result<super::Ipv4Addr, super::AddrParseError> = "127.0.0.1".parse();
    assert_eq!(v4, Ok(std::net::Ipv4Addr::LOCALHOST));
    let sock: Result<super::SocketAddr, super::AddrParseError> = "[::1]:443".parse();
    assert_eq!(
        sock,
        Ok(std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 443)))
    );
    assert!("example.com:443".parse::<super::SocketAddr>().is_err());
    let v6: super::SocketAddrV6 = super::SocketAddrV6::new(super::Ipv6Addr::LOCALHOST, 1, 0, 0);
    let ip: super::IpAddr = (*v6.ip()).into();
    assert!(ip.is_loopback());
    let _: Option<super::SocketAddrV4> = None;
}
