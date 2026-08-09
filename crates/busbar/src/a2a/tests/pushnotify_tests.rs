// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/a2a/pushnotify.rs`.
//!
//! Every hostile case here is a case a real network makes hard to stage on demand — a nameserver
//! that answers differently on the second lookup, a host that resolves to four addresses of which
//! one is the metadata service. The guard is a pure function over the resolved addresses precisely
//! so that these are unit tests rather than a network fixture nobody runs.

use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}
const PUBLIC: fn() -> IpAddr = || IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

/// The happy path, and it is asserted on the PIN: validation returns the addresses the connect must
/// use, because a caller that re-resolves has thrown the whole guarantee away.
#[test]
fn a_public_https_callback_is_accepted_and_its_addresses_are_pinned() {
    let ok = validate("https://caller.example/cb", &[PUBLIC()], false).expect("accepted");
    assert_eq!(ok.url, "https://caller.example/cb");
    assert_eq!(ok.host, "caller.example");
    assert_eq!(
        ok.addrs,
        vec![PUBLIC()],
        "the vetted addresses are returned so the connect never resolves again"
    );
}

/// EVERY internal range is refused, and the table is exhaustive by intent rather than by whichever
/// addresses somebody remembered.
#[test]
fn every_internal_range_is_refused() {
    let cases: &[(&str, IpAddr)] = &[
        ("loopback v4", v4(127, 0, 0, 1)),
        ("private 10/8", v4(10, 1, 2, 3)),
        ("private 172.16/12", v4(172, 16, 5, 5)),
        ("private 192.168/16", v4(192, 168, 1, 1)),
        ("link-local 169.254/16", v4(169, 254, 1, 1)),
        ("CLOUD METADATA", v4(169, 254, 169, 254)),
        ("CGNAT 100.64/10", v4(100, 100, 0, 1)),
        ("unspecified", v4(0, 0, 0, 0)),
        ("this-network 0/8", v4(0, 1, 2, 3)),
        ("multicast", v4(224, 0, 0, 1)),
        ("broadcast", v4(255, 255, 255, 255)),
        ("IETF protocol 192.0.0/24", v4(192, 0, 0, 8)),
        ("benchmarking 198.18/15", v4(198, 19, 0, 1)),
        ("loopback v6", IpAddr::V6(Ipv6Addr::LOCALHOST)),
        ("unspecified v6", IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        (
            "unique-local v6 fc00::/7",
            IpAddr::V6("fd00::1".parse().unwrap()),
        ),
        (
            "link-local v6 fe80::/10",
            IpAddr::V6("fe80::1".parse().unwrap()),
        ),
        (
            "IPv4-MAPPED metadata (an IPv4 address wearing a hat)",
            IpAddr::V6("::ffff:169.254.169.254".parse().unwrap()),
        ),
    ];
    let mut checked = 0usize;
    for (what, ip) in cases {
        assert!(
            is_internal_addr(ip),
            "{what} ({ip}) must be classified internal"
        );
        assert_eq!(
            validate("https://caller.example/cb", &[*ip], false),
            Err(PushNotifyError::InternalAddress(*ip)),
            "{what} must be refused as a callback destination"
        );
        checked += 1;
    }
    assert_eq!(checked, cases.len());
    assert!(checked >= 18, "the hostile table did not shrink");
}

/// ONE bad address in the set is a refusal. A hostname resolving to a public address AND the
/// metadata service is the whole trick: the client is free to try any of them and the attacker is
/// free to order them, so "the first one was fine" is not a check.
#[test]
fn one_internal_address_among_several_refuses_the_whole_url() {
    let mixed = [PUBLIC(), v4(8, 8, 8, 8), v4(169, 254, 169, 254)];
    assert_eq!(
        validate("https://caller.example/cb", &mixed, false),
        Err(PushNotifyError::InternalAddress(v4(169, 254, 169, 254))),
        "there is no `prefer the public one`"
    );
}

/// An EMPTY resolution is refused. "Checked nothing" must never read as "found nothing wrong".
#[test]
fn an_unresolved_host_is_refused_rather_than_allowed_by_default() {
    assert_eq!(
        validate("https://caller.example/cb", &[], false),
        Err(PushNotifyError::Unresolved("caller.example".to_string()))
    );
}

/// The alternate IPv4 encodings are refused on the HOST STRING, before resolution — they bypass a
/// canonical IP-literal check while the OS resolver still expands them.
#[test]
fn obfuscated_ipv4_hosts_are_refused_before_anything_is_resolved() {
    for host in [
        "2130706433",          // decimal 127.0.0.1
        "0x7f000001",          // hex
        "017700000001",        // octal
        "127.1",               // short dotted
        "0xa9.0xfe.0xa9.0xfe", // per-octet hex metadata
    ] {
        let url = format!("https://{host}/cb");
        // Resolved deliberately supplied as a PUBLIC address: if the guard were consulting the
        // resolution instead of the host string, this would pass.
        assert_eq!(
            validate(&url, &[PUBLIC()], false),
            Err(PushNotifyError::ObfuscatedHost(host.to_ascii_lowercase())),
            "`{host}` must be refused on its shape"
        );
    }
}

/// An IP LITERAL is judged directly and never gets to benefit from a friendly resolution — there is
/// nothing to rebind, and the resolver's answer is irrelevant.
#[test]
fn an_ip_literal_is_judged_on_itself_not_on_the_supplied_resolution() {
    assert_eq!(
        validate("https://127.0.0.1:8080/cb", &[PUBLIC()], false),
        Err(PushNotifyError::InternalAddress(v4(127, 0, 0, 1))),
        "a supplied public resolution must not launder a loopback literal"
    );
    let ok = validate("https://93.184.216.34/cb", &[], false).expect("a public literal is fine");
    assert_eq!(ok.addrs, vec![PUBLIC()]);
    // Bracketed IPv6, with and without a port.
    assert_eq!(
        validate("https://[::1]/cb", &[], false),
        Err(PushNotifyError::InternalAddress(IpAddr::V6(
            Ipv6Addr::LOCALHOST
        )))
    );
    assert_eq!(
        validate("https://[fd00::1]:9000/cb", &[], false),
        Err(PushNotifyError::InternalAddress(IpAddr::V6(
            "fd00::1".parse().unwrap()
        )))
    );
}

/// Plaintext is OFF by default: a callback carries task ids and caller attribution, and putting that
/// on the wire in the clear by default would be busbar choosing convenience over the operator's data.
#[test]
fn plaintext_is_refused_unless_the_operator_opted_in() {
    assert_eq!(
        validate("http://caller.example/cb", &[PUBLIC()], false),
        Err(PushNotifyError::Scheme("http".to_string()))
    );
    assert!(validate("http://caller.example/cb", &[PUBLIC()], true).is_ok());
    // And no other scheme is ever acceptable, opt-in or not.
    for scheme in ["file", "gopher", "ftp", "ws"] {
        let url = format!("{scheme}://caller.example/cb");
        assert_eq!(
            validate(&url, &[PUBLIC()], true),
            Err(PushNotifyError::Scheme(scheme.to_string()))
        );
    }
}

/// USERINFO is REFUSED, not stripped. `https://metadata.internal@example.com/` reads one way to a
/// human skimming a config and another way to a parser, and that ambiguity is the entire trick.
#[test]
fn a_url_with_userinfo_is_refused_rather_than_normalised() {
    let url = "https://169.254.169.254@caller.example/cb";
    assert_eq!(
        validate(url, &[PUBLIC()], false),
        Err(PushNotifyError::Malformed(url.to_string()))
    );
}

/// Malformed input is refused, never guessed at. The guard's job is to agree with what the HTTP
/// client will do, and the safe way to disagree is to refuse.
#[test]
fn malformed_urls_are_refused() {
    for url in ["not-a-url", "https:/caller.example", "https://", "://x"] {
        assert!(
            validate(url, &[PUBLIC()], false).is_err(),
            "`{url}` must not be accepted"
        );
    }
}

/// DNS REBINDING ACROSS A RESTART. The stored pin is re-checked against a FRESH resolution: an
/// answer that has moved to an internal address is refused, and an answer that has moved entirely to
/// a different (still public) address set is held for an operator rather than followed.
#[test]
fn revalidation_defeats_a_rebind_and_reports_a_wholesale_move_separately() {
    let pinned = validate("https://caller.example/cb", &[PUBLIC()], false).unwrap();

    // The nameserver now answers with the metadata service — the rebind.
    assert_eq!(
        revalidate(&pinned, &[v4(169, 254, 169, 254)], false),
        Err(PushNotifyError::InternalAddress(v4(169, 254, 169, 254))),
        "a rebind to an internal address is refused across the restart boundary"
    );

    // A legitimate additional address alongside the pinned one is fine.
    let widened = revalidate(&pinned, &[PUBLIC(), v4(93, 184, 216, 35)], false)
        .expect("an overlapping answer is a legitimate DNS change");
    assert_eq!(widened.addrs.len(), 2);

    // A wholesale move to a different public address is its OWN finding, not an SSRF one: both
    // answers were public, and telling an operator a public address is "internal" is a lie that
    // trains them to ignore the message.
    assert_eq!(
        revalidate(&pinned, &[v4(198, 51, 100, 7)], false),
        Err(PushNotifyError::PinDrifted {
            host: "caller.example".to_string()
        })
    );
}

/// Every error renders a message that names the property that failed. An operator debugging a
/// legitimate callback that will not register needs to know WHICH rule refused it.
#[test]
fn every_refusal_explains_itself() {
    let cases = [
        PushNotifyError::Malformed("x".into()),
        PushNotifyError::Scheme("ftp".into()),
        PushNotifyError::NoHost,
        PushNotifyError::ObfuscatedHost("127.1".into()),
        PushNotifyError::Unresolved("h".into()),
        PushNotifyError::InternalAddress(v4(127, 0, 0, 1)),
        PushNotifyError::PinDrifted { host: "h".into() },
    ];
    for e in &cases {
        let msg = e.to_string();
        assert!(
            msg.len() > 20,
            "`{e:?}` renders an unhelpfully short message"
        );
    }
    assert_eq!(cases.len(), 7, "every variant is rendered above");
}
