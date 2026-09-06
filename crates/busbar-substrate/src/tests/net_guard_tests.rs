// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-substrate/src/net_guard.rs`.

use super::*;

#[test]
fn is_cgnat_shared_v4_covers_rfc6598_only() {
    // 100.64.0.0/10 = first octet 100, second octet's top two bits == 01 (i.e. 64..=127).
    assert!(is_cgnat_shared_v4(&Ipv4Addr::new(100, 64, 0, 0)));
    assert!(is_cgnat_shared_v4(&Ipv4Addr::new(100, 100, 100, 200))); // Alibaba metadata
    assert!(is_cgnat_shared_v4(&Ipv4Addr::new(100, 127, 255, 255)));
    // Outside the /10: second octet below 64 or above 127, or different first octet.
    assert!(!is_cgnat_shared_v4(&Ipv4Addr::new(100, 63, 255, 255)));
    assert!(!is_cgnat_shared_v4(&Ipv4Addr::new(100, 128, 0, 0)));
    assert!(!is_cgnat_shared_v4(&Ipv4Addr::new(99, 64, 0, 0)));
    assert!(!is_cgnat_shared_v4(&Ipv4Addr::new(8, 8, 8, 8)));
}

#[test]
fn is_unique_local_v6_covers_fc00_slash_7() {
    // fc00::/7 — first 7 bits 1111110, so fc00.. and fd00.. are in-range.
    assert!(is_unique_local_v6(&"fc00::1".parse().unwrap()));
    assert!(is_unique_local_v6(&"fd00:ec2::254".parse().unwrap())); // EC2 IMDSv6
    assert!(is_unique_local_v6(&"fdff:ffff::".parse().unwrap()));
    // Outside fc00::/7.
    assert!(!is_unique_local_v6(&"fe80::1".parse().unwrap())); // link-local, not ULA
    assert!(!is_unique_local_v6(&"2001:db8::1".parse().unwrap()));
    assert!(!is_unique_local_v6(&"::1".parse().unwrap()));
}

#[test]
fn is_link_local_v6_covers_fe80_slash_10() {
    // fe80::/10 — first 10 bits 1111111010.
    assert!(is_link_local_v6(&"fe80::1".parse().unwrap()));
    assert!(is_link_local_v6(&"febf:ffff::".parse().unwrap()));
    // Outside fe80::/10.
    assert!(!is_link_local_v6(&"fec0::1".parse().unwrap())); // site-local (deprecated), not fe80::/10
    assert!(!is_link_local_v6(&"fc00::1".parse().unwrap())); // ULA, not link-local
    assert!(!is_link_local_v6(&"2001:db8::1".parse().unwrap()));
}

#[test]
fn is_alternate_ipv4_encoding_flags_obfuscated_forms() {
    assert!(is_alternate_ipv4_encoding("2130706433")); // decimal 127.0.0.1
    assert!(is_alternate_ipv4_encoding("0x7f000001")); // hex
    assert!(is_alternate_ipv4_encoding("0X7F000001")); // hex, uppercase prefix
    assert!(is_alternate_ipv4_encoding("017700000001")); // leading-zero octal
    assert!(is_alternate_ipv4_encoding("127.1")); // short dotted
    assert!(is_alternate_ipv4_encoding("10.0.1")); // short dotted
    assert!(is_alternate_ipv4_encoding("0x7f.0.0.1")); // per-octet hex
    assert!(is_alternate_ipv4_encoding("0177.0.0.1")); // per-octet octal

    // Canonical dotted-quads are left to the `parse::<IpAddr>()` path, not flagged here.
    assert!(!is_alternate_ipv4_encoding("127.0.0.1"));
    assert!(!is_alternate_ipv4_encoding("8.8.8.8"));
    // DNS names and the empty string are not alternate encodings.
    assert!(!is_alternate_ipv4_encoding("api.openai.com"));
    assert!(!is_alternate_ipv4_encoding("example.com"));
    assert!(!is_alternate_ipv4_encoding(""));
}

// ══ THE CLASS TEST FOR THE GUARDED-FETCH CHOKE POINT ═════════════════════════════════════════════
//
// `ip_is_internal` is the ONE address predicate every plane's outbound guard is required to route
// through (structure-lint choke point `H-net-guard`). Its table therefore has to be the UNION of
// what every plane-local copy ever checked, because the tear-out of a copy is only safe if the
// shared predicate already covers everything that copy covered. Two of the rows below arrived here
// exactly that way — from `a2a::pushnotify`'s private copy, which checked ranges this one did not.
//
// The floor at the end is what stops the table quietly shrinking: a row deleted with the range it
// guarded is the failure mode this whole exercise exists to prevent.

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
        // FROM `a2a::pushnotify`'s copy: 0.0.0.0/8 is "this network", and several stacks route the
        // whole block to the local host — so `is_unspecified()` alone (which is only 0.0.0.0) left
        // 0.1.2.3 reachable on every plane that used this predicate.
        ("this-network 0/8", "0.1.2.3"),
        // FROM `a2a::pushnotify`'s copy: 192.0.0.0/24 IETF protocol assignments (the /24 OCI's
        // 192.0.0.192 sits inside) and 198.18.0.0/15 benchmarking. Neither is a legitimate
        // destination and both are reachable inside some fabrics.
        ("IETF protocol assignments 192.0.0/24", "192.0.0.8"),
        ("benchmarking 198.18/15", "198.18.0.1"),
        ("benchmarking 198.19/16", "198.19.0.1"),
        ("broadcast", "255.255.255.255"),
        ("multicast v4", "224.0.0.1"),
        // ALL THREE DOCUMENTATION BLOCKS (RFC 5737), not just TEST-NET-1. `is_documentation()`
        // covers the other two as well, and leaving them unasserted is how a floor gets written
        // above the table it guards: these were the rows the count was already reserving room for.
        ("documentation TEST-NET-1 192.0.2/24", "192.0.2.1"),
        ("documentation TEST-NET-2 198.51.100/24", "198.51.100.7"),
        ("documentation TEST-NET-3 203.0.113/24", "203.0.113.9"),
        ("loopback v6", "::1"),
        ("unspecified v6", "::"),
        ("unique-local v6 fc00::/7", "fd00::1"),
        ("link-local v6 fe80::/10", "fe80::1"),
        ("multicast v6", "ff02::1"),
        ("EC2 IMDSv6", "fd00:ec2::254"),
        // The two embedded-v4 spellings. The COMPATIBLE one is the literal that got through a copy
        // unwrapping with `to_ipv4_mapped()`; it matches no v6 range at all.
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
    // `checked` equals `cases.len()` by construction (one increment per row, no early `continue`),
    // so the anti-shrink guard is a FLOOR on that count, not an equality that could only restate it.
    assert!(
        checked >= 30,
        "the shared hostile table shrank; a deleted row is a range every plane silently stopped \
         guarding"
    );
}

/// The CONTROL. Without it a predicate that returned `true` unconditionally would pass the table
/// above, and every legitimate upstream in the fleet would be refused.
#[test]
fn the_shared_internal_predicate_admits_ordinary_public_addresses() {
    use std::net::IpAddr;
    for ok in [
        "93.184.216.34",
        "8.8.8.8",
        "1.1.1.1",
        // 100.128/9 is OUTSIDE the RFC 6598 /10 and is ordinary public space.
        "100.128.0.1",
        // 198.20/16 is outside the 198.18/15 benchmarking block.
        "198.20.0.1",
        // 192.0.1.0/24 sits between the IETF-assignments /24 and the documentation /24.
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

/// CLOUD METADATA IS A SEPARATE QUESTION FROM INTERNAL, because the two carry different policies:
/// an operator may opt into internal addressing with `allow_private`, and may never opt into IMDS.
#[test]
fn cloud_metadata_is_judged_separately_and_covers_every_vendor() {
    use std::net::IpAddr;
    for meta in [
        "169.254.169.254", // AWS / Azure / GCP / OpenStack / DigitalOcean
        "169.254.170.2",   // ECS task metadata
        "100.100.100.200", // Alibaba
        "168.63.129.16",   // Azure WireServer
        "192.0.0.192",     // OCI
        "fd00:ec2::254",   // EC2 IMDSv6
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
    // An internal address that is NOT metadata: `allow_private` may reach this one.
    assert!(!ip_is_cloud_metadata(
        &"10.0.0.1".parse::<IpAddr>().unwrap()
    ));
}

/// A NAT64 TRANSLATION IS AN EMBEDDED-V4 SPELLING, and the connecting stack routes it to the v4
/// target exactly as the mapped and compatible forms do. `Ipv6Addr::to_ipv4()` models only the
/// `::ffff:a.b.c.d` and `::a.b.c.d` forms, so `64:ff9b::a9fe:a9fe` — the RFC 6052 well-known
/// prefix wrapping `169.254.169.254` — matched no v6 range, unwrapped to nothing, and was PINNED
/// and dialled on any IPv6-only deployment behind a NAT64 gateway (the default shape of an
/// IPv6-only cloud subnet, where DNS64 synthesises exactly these answers for a v4-only name). The
/// RFC 8215 local-use prefix `64:ff9b:1::/96` is the same translation with an operator-run gateway.
#[test]
fn nat64_translated_metadata_and_internal_addresses_are_refused() {
    use std::net::IpAddr;
    for (what, spelling) in [
        ("NAT64 well-known IMDS", "64:ff9b::a9fe:a9fe"),
        ("NAT64 well-known ECS task creds", "64:ff9b::a9fe:aa02"),
        ("NAT64 well-known Azure WireServer", "64:ff9b::a83f:8110"),
        ("NAT64 well-known OCI IMDS", "64:ff9b::c000:c0"),
        ("NAT64 local-use IMDS", "64:ff9b:1::a9fe:a9fe"),
    ] {
        let ip: IpAddr = spelling.parse().expect(what);
        assert!(
            ip_is_cloud_metadata(&ip),
            "{what} ({spelling}) translates to a cloud-metadata v4 target and must be refused \
             unconditionally, exactly as the mapped and compatible spellings are"
        );
        assert!(
            ip_is_internal(&ip),
            "{what} ({spelling}) must also be internal to the shared predicate"
        );
    }
    for (what, spelling) in [
        ("NAT64 well-known loopback", "64:ff9b::7f00:1"),
        ("NAT64 well-known RFC1918", "64:ff9b::a00:1"),
        ("NAT64 local-use loopback", "64:ff9b:1::7f00:1"),
    ] {
        let ip: IpAddr = spelling.parse().expect(what);
        assert!(
            ip_is_internal(&ip),
            "{what} ({spelling}) translates to an internal v4 target and must be refused without \
             `allow_private`"
        );
    }
    // THE CONTROL: a NAT64 translation of ordinary public space stays reachable, and an address
    // that merely LOOKS like the prefix (a different second group) is untouched public v6.
    let public_via_nat64: IpAddr = "64:ff9b::5db8:d822".parse().unwrap();
    assert!(!ip_is_internal(&public_via_nat64));
    assert!(!ip_is_cloud_metadata(&public_via_nat64));
    let not_the_prefix: IpAddr = "64:ff9c::a9fe:a9fe".parse().unwrap();
    assert!(!ip_is_internal(&not_the_prefix));
    assert!(!ip_is_cloud_metadata(&not_the_prefix));
}

/// The operator-facing metadata denylist reads the SAME embedded-v4 answer: a `base_url` written
/// with a NAT64 spelling of IMDS is the same credential-leaking destination as the dotted-quad one.
#[test]
fn ssrf_blocked_host_reads_the_nat64_spelling_of_metadata() {
    assert_eq!(
        ssrf_blocked_host(
            "https://[64:ff9b::a9fe:a9fe]/latest/meta-data/",
            &[],
            false,
            &[]
        ),
        Some("64:ff9b::a9fe:a9fe".to_string())
    );
    // A NAT64 translation of ordinary public space is a legitimate upstream and stays allowed.
    assert_eq!(
        ssrf_blocked_host("https://[64:ff9b::5db8:d822]/v1", &[], false, &[]),
        None
    );
}
