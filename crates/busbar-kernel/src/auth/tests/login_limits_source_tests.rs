// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use axum::http::HeaderValue;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.append(
            axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_str(v).unwrap(),
        );
    }
    h
}

fn trusted(nets: &[&str], header: Option<&str>) -> TrustedProxies {
    TrustedProxies::read(
        &nets.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
        header,
    )
    .unwrap()
}

#[test]
fn v4_mapped_peer_is_grouped_as_ipv4() {
    let none = TrustedProxies::default();
    assert_eq!(
        client_source(Some(ip("::ffff:203.0.113.9")), &HeaderMap::new(), &none),
        ClientSource::Known(ip("203.0.113.9"))
    );
    assert_eq!(
        SourceBucket::base(ip("::ffff:203.0.113.9")),
        SourceBucket::V4("203.0.113.9".parse().unwrap()),
        "a dual-stack socket's v4 client is bucketed by its own address, not the ::/64 every \
         IPv4 client would share"
    );
    assert_ne!(
        SourceBucket::base(ip("::ffff:203.0.113.9")),
        SourceBucket::base(ip("::ffff:198.51.100.7"))
    );
}

#[test]
fn ipv6_is_bucketed_by_64_with_48_and_32_aggregates() {
    let h = SourceBucket::hierarchy(ip("2001:db8:aaaa:bbbb:1:2:3:4"));
    assert_eq!(
        h,
        vec![
            SourceBucket::V6(64, "2001:db8:aaaa:bbbb::".parse().unwrap()),
            SourceBucket::V6(48, "2001:db8:aaaa::".parse().unwrap()),
            SourceBucket::V6(32, "2001:db8::".parse().unwrap()),
        ]
    );
    assert_eq!(
        SourceBucket::base(ip("2001:db8:aaaa:bbbb:ffff::1")),
        h[0],
        "one /64 is one source"
    );
    assert_eq!(SourceBucket::hierarchy(ip("192.0.2.1")).len(), 1);
}

#[test]
fn xff_from_an_untrusted_peer_is_ignored() {
    let t = trusted(&["\x310.0.0.0/8"], None);
    let h = headers(&[("x-forwarded-for", "198.51.100.1")]);
    assert_eq!(
        client_source(Some(ip("203.0.113.5")), &h, &t),
        ClientSource::Known(ip("203.0.113.5")),
        "a public peer outside trusted_proxies cannot choose its own source"
    );
}

#[test]
fn xff_from_a_trusted_peer_walks_right_to_left_past_trusted_hops() {
    let t = trusted(&["\x310.0.0.0/8", "192.0.2.10"], None);
    let h = headers(&[
        ("x-forwarded-for", "198.51.100.66, 203.0.113.7"),
        ("x-forwarded-for", "192.0.2.10"),
    ]);
    assert_eq!(
        client_source(Some(ip("\x310.1.2.3")), &h, &t),
        ClientSource::Known(ip("203.0.113.7")),
        "the right-most untrusted hop is the client; the spoofable left part is ignored"
    );
    let all_trusted = headers(&[("x-forwarded-for", "\x310.9.9.9")]);
    assert_eq!(
        client_source(Some(ip("\x310.1.2.3")), &all_trusted, &t),
        ClientSource::Known(ip("\x310.9.9.9"))
    );
    assert_eq!(
        client_source(Some(ip("\x310.1.2.3")), &HeaderMap::new(), &t),
        ClientSource::Known(ip("\x310.1.2.3")),
        "a trusted peer that forwards nothing is itself the source"
    );
}

#[test]
fn an_unparseable_first_untrusted_hop_is_unknown_not_the_proxy() {
    let t = trusted(&["\x310.0.0.0/8"], None);
    for hop in ["unknown", "_hidden", "garbage", "300.1.1.1"] {
        let h = headers(&[("x-forwarded-for", &format!("{hop}, \x310.0.0.2"))]);
        assert_eq!(
            client_source(Some(ip("\x310.1.2.3")), &h, &t),
            ClientSource::Unknown(UnknownSource::Unparseable),
            "{hop}"
        );
    }
}

#[test]
fn only_the_configured_header_is_read() {
    let t = trusted(&["\x310.0.0.0/8"], Some("forwarded"));
    let h = headers(&[
        ("x-forwarded-for", "198.51.100.1"),
        (
            "forwarded",
            "for=\"[2001:db8::1]:4711\";proto=https, for=203.0.113.9:443",
        ),
    ]);
    assert_eq!(
        client_source(Some(ip("\x310.1.2.3")), &h, &t),
        ClientSource::Known(ip("203.0.113.9"))
    );
    let obfuscated = headers(&[("forwarded", "for=_hidden")]);
    assert_eq!(
        client_source(Some(ip("\x310.1.2.3")), &obfuscated, &t),
        ClientSource::Unknown(UnknownSource::Unparseable)
    );
}

#[test]
fn private_peer_with_xff_and_no_trusted_proxies_is_unknown() {
    let none = TrustedProxies::default();
    for peer in [
        "\x310.0.0.1",
        "127.0.0.1",
        "::1",
        "fd00::1",
        "::ffff:\x3192.168.1.1",
    ] {
        for header in ["x-forwarded-for", "forwarded"] {
            let h = headers(&[(header, "for=198.51.100.1")]);
            assert_eq!(
                client_source(Some(ip(peer)), &h, &none),
                ClientSource::Unknown(UnknownSource::UnconfiguredProxy),
                "{peer} {header}: an ingress in front of busbar must not put everyone in one bucket"
            );
        }
        assert_eq!(
            client_source(Some(ip(peer)), &HeaderMap::new(), &none),
            ClientSource::Known(canonical(ip(peer))),
            "{peer} without forwarding headers is an ordinary client"
        );
    }
    // A public peer (documentation ranges count as internal to the guard) is itself the client.
    let public = headers(&[("x-forwarded-for", "198.51.100.1")]);
    assert_eq!(
        client_source(Some(ip("9.9.9.9")), &public, &none),
        ClientSource::Known(ip("9.9.9.9"))
    );
}

#[test]
fn no_peer_is_unknown() {
    assert_eq!(
        client_source(None, &HeaderMap::new(), &TrustedProxies::default()),
        ClientSource::Unknown(UnknownSource::NoPeer)
    );
}

#[test]
fn trusted_proxies_reuse_the_guard_cidr_reader() {
    assert!(TrustedProxies::read(&["\x310.0.0.0/8".into(), "2001:db8::/32".into()], None).is_ok());
    let host_bits = TrustedProxies::read(&["\x310.0.0.1/8".into()], None).unwrap_err();
    assert!(host_bits.contains("trusted_proxies[0]") && host_bits.contains("prefix"));
    assert!(TrustedProxies::read(&["proxy.internal".into()], None).is_err());
    assert!(TrustedProxies::read(&[], Some("x-real-ip")).is_err());
    assert_eq!(
        TrustedProxies::read(&[], Some("Forwarded")).unwrap().header,
        ForwardedHeader::Forwarded
    );
}
