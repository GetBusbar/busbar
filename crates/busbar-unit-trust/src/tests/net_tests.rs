// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The network guard, tested where it now lives: the pure predicates with every literal case they
//! were written with, the resolve-then-pin discipline against a scripted resolver, and the check
//! over a sealed destination that the whole thing exists to serve.
//!
//! The rebinding cases are the reason the resolver is a seam. They are driven through a SCRIPTED
//! resolver that answers differently on the second lookup, because that is the only way to state
//! the claim the guard actually makes: the name is resolved EXACTLY ONCE and the socket goes to the
//! address that was judged. A guard tested against a resolver that answers the same thing twice
//! cannot tell a resolve-then-pin from a check-then-re-resolve — both pass — which is precisely the
//! mistake that looks right in review.

use crate::net::*;
use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr};

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

const PUBLIC: &str = "93.184.216.34";
const PUBLIC_2: &str = "93.184.216.35";

fn ip(s: &str) -> IpAddr {
    s.parse().expect("a test address must parse")
}

fn strict() -> GuardPolicy {
    GuardPolicy::default()
}

fn private_ok() -> GuardPolicy {
    GuardPolicy {
        allow_private: true,
        ..GuardPolicy::default()
    }
}

/// A resolver that answers a SCRIPT: the first lookup gets one answer, every later lookup gets the
/// next. It also records what it was asked, so "the guard resolved exactly once" is an assertion
/// about a number rather than about intent.
struct ScriptedResolver {
    answers: RefCell<Vec<Result<Vec<IpAddr>, String>>>,
    asked: RefCell<Vec<String>>,
}

impl ScriptedResolver {
    fn new(answers: Vec<Result<Vec<IpAddr>, String>>) -> Self {
        Self {
            answers: RefCell::new(answers),
            asked: RefCell::new(Vec::new()),
        }
    }
    fn asked(&self) -> usize {
        self.asked.borrow().len()
    }
}

impl Resolver for ScriptedResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        self.asked.borrow_mut().push(host.to_string());
        let mut answers = self.answers.borrow_mut();
        if answers.len() > 1 {
            answers.remove(0)
        } else {
            answers
                .first()
                .cloned()
                .unwrap_or_else(|| Err("the script is exhausted".to_string()))
        }
    }
}

/// A resolver that PANICS. Nothing refusable from the URL alone may reach it: a case that needed a
/// lookup would be a case where the guard depends on what the attacker's nameserver says.
struct NeverAsked;
impl Resolver for NeverAsked {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        panic!("the guard resolved `{host}`, which it must refuse structurally");
    }
}

// ══ THE REBINDING PROOFS ═════════════════════════════════════════════════════════════════════════

/// **THE DNS-REBINDING CASE.** The name answers a PUBLIC address on the first lookup and a
/// LOOPBACK address on the second. A guard that checks the name and then lets the client resolve
/// again connects to the second answer; a guard that resolves once and pins connects to the first.
///
/// The assertion is on BOTH halves, and both are needed: the pinned address must be the judged one,
/// AND the resolver must have been asked exactly once. Asserting only the address would pass
/// against a guard that resolved twice and happened to be handed the good answer first; asserting
/// only the count would pass against a guard that resolved once and pinned the wrong element.
#[test]
fn a_name_that_answers_a_private_address_on_the_second_lookup_never_gets_a_second_lookup() {
    let r = ScriptedResolver::new(vec![Ok(vec![ip(PUBLIC)]), Ok(vec![ip("127.0.0.1")])]);
    let target = resolve_and_pin("rebind.example", 443, true, &r, strict())
        .expect("the first answer is public and admissible");
    assert_eq!(
        target.addr(),
        ip(PUBLIC),
        "the pin must carry the address that was JUDGED, not one a later lookup would return"
    );
    assert_eq!(
        r.asked(),
        1,
        "the name must be resolved EXACTLY ONCE; a second lookup is the window a rebind wins in"
    );
    assert_eq!(target.host(), "rebind.example", "the name is kept for SNI");
    assert_eq!(target.socket_addr(), "93.184.216.34:443".parse().unwrap());
}

/// The other order, which is the one an attacker actually serves: the FIRST answer is already
/// hostile. There is no "and then it rebinds" to reach, because the fetch never happens.
#[test]
fn a_name_that_answers_the_metadata_address_first_is_refused_outright() {
    let r = ScriptedResolver::new(vec![Ok(vec![ip("169.254.169.254")]), Ok(vec![ip(PUBLIC)])]);
    let err = resolve_and_pin("rebind.example", 443, true, &r, strict())
        .expect_err("an IMDS answer must refuse");
    assert_eq!(
        err,
        AddressRefusal::CloudMetadataAddress {
            host: "rebind.example".to_string(),
            addr: ip("169.254.169.254"),
        }
    );
}

/// A MIXED ANSWER IS A HOSTILE ANSWER. One reply carrying a public address and a loopback one is
/// refused whole rather than filtered to the address that happens to pass — otherwise the same name
/// is sometimes fine and sometimes not, decided by an ordering the upstream chooses.
#[test]
fn a_mixed_answer_is_refused_whole_in_either_order() {
    let forward = [ip(PUBLIC), ip("127.0.0.1")];
    let err = judge_addresses("mixed.example", &forward, strict())
        .expect_err("a loopback address in the answer must refuse the resolution");
    assert_eq!(
        err,
        AddressRefusal::InternalAddress {
            host: "mixed.example".to_string(),
            addr: ip("127.0.0.1"),
        }
    );
    let reversed = [ip("127.0.0.1"), ip(PUBLIC)];
    assert!(
        judge_addresses("mixed.example", &reversed, strict()).is_err(),
        "order must not decide the verdict"
    );
    // The CONTROL: an all-public answer passes, so the two above are not passing because everything
    // is refused.
    assert!(judge_addresses("mixed.example", &[ip(PUBLIC), ip(PUBLIC_2)], strict()).is_ok());
}

// ══ THE ADDRESS JUDGEMENT ════════════════════════════════════════════════════════════════════════

#[test]
fn every_internal_range_is_refused() {
    let internal = [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.1.1",
        "100.64.0.1",
        "0.0.0.0",
        "0.1.2.3",
        "255.255.255.255",
        "224.0.0.1",
        "198.18.0.1",
        "192.0.2.1",
        "::1",
        "fc00::1",
        "fe80::1",
        "::",
        // An IPv4-mapped loopback: the v4 ruleset must not be bypassable via a AAAA record.
        "::ffff:127.0.0.1",
    ];
    assert_eq!(internal.len(), 17, "the internal-range set must not shrink");
    for a in internal {
        assert!(
            judge_address("h", ip(a), strict()).is_err(),
            "{a} must be refused"
        );
    }
    // The CONTROL.
    assert!(judge_address("h", ip(PUBLIC), strict()).is_ok());
}

/// CLOUD METADATA IS REFUSED EVEN UNDER `allow_private`, and it is refused AS METADATA — the arm
/// runs BEFORE the flag is consulted. Merging it into the internal-range arm would make
/// `allow_private` a config flag that hands out cloud credentials.
#[test]
fn cloud_metadata_is_refused_unconditionally_and_as_metadata() {
    let metadata = [
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "168.63.129.16",
        "192.0.0.192",
        "fd00:ec2::254",
        // The IPv4-COMPATIBLE and IPv4-MAPPED spellings of IMDS: neither matches a v6 range, and a
        // guard that unwrapped only the mapped form connected to the compatible one.
        "::169.254.169.254",
        "::ffff:169.254.169.254",
    ];
    assert_eq!(metadata.len(), 8, "the metadata set must not shrink");
    for a in metadata {
        for policy in [strict(), private_ok()] {
            let err = judge_address("meta", ip(a), policy)
                .expect_err("metadata is refused under every policy");
            assert!(
                matches!(err, AddressRefusal::CloudMetadataAddress { .. }),
                "{a} must be refused AS METADATA, not merely as internal: {err:?}"
            );
        }
    }
    // And a private address that is NOT metadata IS permitted under `allow_private`, so the
    // unconditional refusal above is specific to metadata rather than to everything.
    assert!(judge_address("h", ip("10.0.0.1"), private_ok()).is_ok());
}

// ══ THE STRUCTURAL REFUSALS ══════════════════════════════════════════════════════════════════════

/// The metadata NAMES are refused before any resolver is consulted, and `allow_private` does not
/// speak for them. The `localhost` family is the population it DOES speak for, and the split
/// between the two lists is the whole point of having two arms.
#[test]
fn the_metadata_names_are_refused_under_every_policy_and_localhost_only_by_default() {
    for name in [
        "metadata.google.internal",
        "metadata.google.internal.",
        "METADATA.GOOGLE.INTERNAL",
        "metadata.internal",
    ] {
        for policy in [strict(), private_ok()] {
            assert_eq!(
                judge_host_name(name, policy),
                Err(AddressRefusal::MetadataName(name.to_string())),
                "`{name}` is a cloud-metadata name and `allow_private` may not reach it"
            );
        }
    }
    for name in ["localhost", "localhost.", "api.localhost"] {
        assert!(
            matches!(
                judge_host_name(name, strict()),
                Err(AddressRefusal::LoopbackName(_))
            ),
            "`{name}` is the loopback family and is refused by default"
        );
        assert!(
            judge_host_name(name, private_ok()).is_ok(),
            "`{name}` is what `allow_private` is for"
        );
    }
    assert!(judge_host_name("a2a.vendor", strict()).is_ok());
}

#[test]
fn alternate_ipv4_encodings_are_refused_before_the_resolver_sees_them() {
    for host in ["2130706433", "0x7f000001", "017700000001", "127.1"] {
        for policy in [strict(), private_ok()] {
            assert_eq!(
                judge_host_name(host, policy),
                Err(AddressRefusal::ObfuscatedHost(host.to_string())),
                "`{host}` is an encoding the resolver expands and the check cannot read"
            );
        }
    }
}

#[test]
fn a_literal_is_judged_and_pinned_without_a_resolver() {
    let t = resolve_and_pin(PUBLIC, 8443, true, &NeverAsked, strict())
        .expect("a public literal is its own answer");
    assert_eq!(t.addr(), ip(PUBLIC));
    assert_eq!(t.port(), 8443);
    assert!(t.is_https());

    assert!(matches!(
        resolve_and_pin("127.0.0.1", 9000, true, &NeverAsked, strict()),
        Err(AddressRefusal::InternalAddress { .. })
    ));
    let t = resolve_and_pin("127.0.0.1", 9000, false, &NeverAsked, private_ok())
        .expect("an opted-in private literal pins");
    assert_eq!(t.socket_addr(), "127.0.0.1:9000".parse().unwrap());
    assert!(!t.is_https());
}

// ══ RESOLUTION FAILURE IS NOT ABSENCE ════════════════════════════════════════════════════════════

#[test]
fn a_resolution_failure_and_an_empty_answer_are_different_facts() {
    let failing = ScriptedResolver::new(vec![Err("NXDOMAIN".to_string())]);
    assert_eq!(
        resolve_and_pin("a.example", 443, true, &failing, strict()),
        Err(AddressRefusal::Unresolvable {
            host: "a.example".to_string(),
            reason: "NXDOMAIN".to_string(),
        })
    );
    let empty = ScriptedResolver::new(vec![Ok(vec![])]);
    assert_eq!(
        resolve_and_pin("a.example", 443, true, &empty, strict()),
        Err(AddressRefusal::NoAddresses("a.example".to_string())),
        "an empty answer has nothing to connect to and nothing to have judged"
    );
}

// ══ THE STRICT RECOGNISER ════════════════════════════════════════════════════════════════════════

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
        "host.example/mcp",
    ];
    assert_eq!(banned.len(), 8, "the banned-scheme set must not shrink");
    for url in banned {
        assert!(
            matches!(split_url(url), Err(AddressRefusal::Scheme { .. })),
            "`{url}` must be refused on its scheme"
        );
    }
    assert!(split_url("https://ok.example/mcp").is_ok());
}

#[test]
fn userinfo_is_refused_rather_than_stripped() {
    assert!(matches!(
        split_url("https://evil.test@good.example/mcp"),
        Err(AddressRefusal::NoHost(_))
    ));
}

#[test]
fn default_ports_are_derived_from_the_scheme_and_ipv6_comes_back_unbracketed() {
    let (https, host, port, path) = split_url("https://a.example/mcp").unwrap();
    assert!(https && host == "a.example" && port == 443 && path == "/mcp");
    let (https, _, port, path) = split_url("http://a.internal").unwrap();
    assert!(!https && port == 80 && path == "/");
    let (_, host, port, _) = split_url("https://[::1]:9443/x").unwrap();
    assert_eq!((host.as_str(), port), ("::1", 9443));
    assert_eq!((default_port(true), default_port(false)), (443, 80));
}

#[test]
fn plaintext_is_refused_unless_the_policy_admits_it() {
    assert!(matches!(
        judge_scheme("http://public.example/x", false, strict()),
        Err(AddressRefusal::Plaintext { .. })
    ));
    assert!(judge_scheme("https://public.example/x", true, strict()).is_ok());
    // Either knob admits it, because opting an upstream into private addressing at all is one
    // decision rather than two.
    assert!(judge_scheme("http://x.internal/x", false, private_ok()).is_ok());
    assert!(judge_scheme(
        "http://public.example/x",
        false,
        GuardPolicy {
            allow_plaintext: true,
            ..GuardPolicy::default()
        }
    )
    .is_ok());
}

// ══ REDIRECTS, HOPS AND CAPS ═════════════════════════════════════════════════════════════════════

#[test]
fn a_redirect_is_refused_and_names_its_target() {
    for status in [301u16, 302, 303, 307, 308] {
        assert_eq!(
            refuse_redirect(status, Some("http://169.254.169.254/latest/meta-data/")),
            Err(AddressRefusal::Redirect {
                status,
                location: "http://169.254.169.254/latest/meta-data/".to_string(),
            })
        );
    }
    // Non-3xx passes, so the check is about redirects rather than about everything.
    for ok in [200u16, 404, 500] {
        assert!(refuse_redirect(ok, None).is_ok());
    }
    assert_eq!(
        refuse_redirect(302, None),
        Err(AddressRefusal::Redirect {
            status: 302,
            location: "<absent>".to_string(),
        })
    );
}

#[test]
fn the_hop_bound_refuses_at_the_limit_rather_than_past_it() {
    let three = GuardPolicy {
        max_redirects: 3,
        ..GuardPolicy::default()
    };
    for hops in 0..3u32 {
        assert!(refuse_hop_overflow(hops, "https://a.example/", three).is_ok());
    }
    assert_eq!(
        refuse_hop_overflow(3, "https://a.example/", three),
        Err(AddressRefusal::TooManyRedirects {
            limit: 3,
            at: "https://a.example/".to_string(),
        })
    );
    // Zero redirects is a legitimate setting and means "the document must be where I said".
    assert!(refuse_hop_overflow(0, "https://a.example/", GuardPolicy::default()).is_err());
}

#[test]
fn the_body_cap_refuses_over_the_ceiling_and_not_at_it() {
    let policy = GuardPolicy {
        max_body_bytes: 5 * 1024,
        ..GuardPolicy::default()
    };
    assert!(refuse_oversized_body("https://a.example/", 5 * 1024, policy).is_ok());
    assert_eq!(
        refuse_oversized_body("https://a.example/", 5 * 1024 + 1, policy),
        Err(AddressRefusal::BodyTooLarge {
            url: "https://a.example/".to_string(),
            bytes: 5 * 1024 + 1,
        })
    );
}

/// The default is FAIL-CLOSED in every direction, so a caller that forgets a knob gets the strict
/// answer. A default that permitted anything would make "forgot to set it" indistinguishable from
/// "decided to allow it".
#[test]
fn the_default_policy_is_closed_in_every_direction() {
    let d = GuardPolicy::default();
    assert!(!d.allow_private);
    assert!(!d.allow_plaintext);
    assert!(!d.plaintext_admissible());
    assert_eq!(d.max_redirects, 0);
    assert_eq!(d.max_body_bytes, 64 * 1024);
    assert_eq!(d.timeout, std::time::Duration::from_secs(10));
}

/// `pin_answer` is the one door every resolution goes through, so its own refusals are asserted
/// here rather than only through its callers.
#[test]
fn the_pin_carries_the_first_admissible_address_and_the_scheme_it_was_judged_under() {
    let t = pin_answer(
        "a.example",
        8443,
        true,
        &[ip(PUBLIC), ip(PUBLIC_2)],
        strict(),
    )
    .expect("an all-public answer pins");
    assert_eq!(t.addr(), ip(PUBLIC), "the resolver's own ordering is kept");
    assert_eq!(t.host(), "a.example");
    assert!(t.is_https());
    assert_eq!(
        pin_answer("a.example", 443, true, &[], strict()),
        Err(AddressRefusal::NoAddresses("a.example".to_string()))
    );
}

// =================================================================================================
//   THE CHECK OVER A SEALED DESTINATION: the precedence rule, the denylist, the base+path re-check.
// =================================================================================================

/// The seal these tests build sealed values with: the capability crate's own trust token.
///
/// A test that declared a private type and implemented the contract's sealing trait on it was
/// forging kernel evidence to test something else, and it read as if that were the ordinary way in.
/// The token is the ordinary way in — the loop lends one to the trust unit for the length of a
/// verify call — so a test that seals with one is testing the seam the deployment uses.
fn trust_token() -> busbar_caps::TrustToken {
    busbar_caps::TrustToken::mint(&busbar_caps::KernelSeal::acquire_for_kernel())
}

/// A sealed destination naming `authority`, as a plane proposed it and the trust unit sealed it.
fn dest(authority: &'static str) -> busbar_contract::VerifiedDestination {
    busbar_contract::VerifiedDestination::seal(
        &trust_token(),
        busbar_contract::DestinationFacts::Upstream {
            transport: "https",
            address: busbar_contract_transport::dest::UpstreamAddress::socket(authority),
            lane: busbar_contract::LaneId::new("test"),
        },
        "https",
        None,
    )
}

/// The locked one-rule matrix, exercised over all four of its corners.
///
/// A host is blocked IFF `!allow_all` AND on-denylist AND NOT in the allow overrides. Every one of
/// those three has been the whole answer in some earlier reading of this rule, which is why all
/// four corners are asserted rather than the interesting one.
#[test]
fn the_denylist_precedence_is_allow_all_then_allow_override_then_block() {
    let base = "https://169.254.169.254/latest/meta-data";
    let none = Denylist::default();

    // On the denylist, nothing overriding it: blocked.
    assert_eq!(
        check_destination(&dest(base), &[], &NeverAsked, strict(), &none),
        Err(NetworkRefusal::MetadataDenied(
            "169.254.169.254".to_string()
        ))
    );

    // A surgical carve-out and the nuclear override both get the destination PAST the denylist —
    // and the address guard below it still refuses, because this address is IMDS. That is the whole
    // point of the two being separate checks: a deployment can say "this host is not a metadata
    // host to me", and it still cannot say "hand out cloud credentials". Neither knob is a way to
    // reach `169.254.169.254`, and there is deliberately no knob that is.
    for past_the_denylist in [
        Denylist {
            allowed: vec!["169.254.169.254".to_string()],
            ..Denylist::default()
        },
        Denylist {
            allow_all: true,
            ..Denylist::default()
        },
    ] {
        assert!(
            matches!(
                check_destination(
                    &dest(base),
                    &[],
                    &NeverAsked,
                    private_ok(),
                    &past_the_denylist
                ),
                Err(NetworkRefusal::Guard(
                    AddressRefusal::CloudMetadataAddress { .. }
                ))
            ),
            "the denylist is not the only thing standing between a caller and IMDS"
        );
    }

    // The same two knobs DO carry a host that is merely internal, which is what they are for.
    let allowed = Denylist {
        allowed: vec!["10.0.0.7".to_string()],
        ..Denylist::default()
    };
    let blocked_then_allowed = Denylist {
        blocked: vec!["10.0.0.7".to_string()],
        ..allowed.clone()
    };
    assert!(
        matches!(
            check_destination(
                &dest("https://10.0.0.7/"),
                &[],
                &NeverAsked,
                private_ok(),
                &blocked_then_allowed
            ),
            Ok(Some(_))
        ),
        "allow wins over block for the same host"
    );

    // An operator addition blocks a host the hardcoded list never named.
    let extra = Denylist {
        blocked: vec!["10.99.99.99".to_string()],
        ..Denylist::default()
    };
    assert_eq!(
        check_destination(
            &dest("https://10.99.99.99/"),
            &[],
            &NeverAsked,
            private_ok(),
            &extra
        ),
        Err(NetworkRefusal::MetadataDenied("10.99.99.99".to_string()))
    );
}

/// An operator's IP entry blocks every spelling of that address, not just the one they typed.
#[test]
fn an_operator_block_entry_covers_the_obfuscated_spellings_too() {
    let extra = Denylist {
        blocked: vec!["10.99.99.99".to_string()],
        ..Denylist::default()
    };
    for spelling in [
        "https://[::ffff:10.99.99.99]/",
        "https://174285667/",
        "https://0x0a636363/",
    ] {
        assert!(
            matches!(
                check_destination(&dest(spelling), &[], &NeverAsked, private_ok(), &extra),
                Err(NetworkRefusal::MetadataDenied(_))
            ),
            "{spelling} spells the same address the operator blocked"
        );
    }
}

/// The base and the path are re-checked TOGETHER, because a path can move the host boundary.
///
/// A backslash terminates the authority in a WHATWG-normalizing stack exactly as a slash does. A
/// guard that only ever looked at the configured base saw the host `metadata.example`; the socket
/// saw `169.254.169.254`. This is the re-check that closes the difference.
#[test]
fn the_base_and_path_are_re_checked_together() {
    let base = "https://metadata.example";
    let none = Denylist::default();

    // The base alone is not on the denylist.
    assert!(matches!(
        check_destination(
            &dest(base),
            &[],
            &ScriptedResolver::new(vec![Ok(vec![ip(PUBLIC)])]),
            strict(),
            &none
        ),
        Ok(Some(_))
    ));

    // Joined with a path whose first byte re-opens the authority, it is.
    assert_eq!(
        check_destination(
            &dest("https://169.254.169.254\\@metadata.example"),
            &[],
            &NeverAsked,
            strict(),
            &none
        ),
        Err(NetworkRefusal::MetadataDenied(
            "169.254.169.254".to_string()
        ))
    );
}

/// A bare `host:port` authority reaches the same judgement a URL does, and fails closed on the
/// scheme it never named.
#[test]
fn a_bare_authority_is_judged_as_a_secure_one() {
    let pinned = check_destination(
        &dest("93.184.216.34:8443"),
        &[],
        &NeverAsked,
        strict(),
        &Denylist::default(),
    )
    .expect("a public literal passes")
    .expect("a socket target is pinned");
    assert_eq!(pinned.port(), 8443);
    assert!(
        pinned.is_https(),
        "an authority naming no scheme fails closed"
    );
    assert_eq!(pinned.addr(), ip(PUBLIC));
}

/// A destination that spawns a program is not a network hop: nothing is resolved and nothing is
/// pinned, rather than a guard being run over an address that does not exist.
#[test]
fn a_program_destination_has_no_address_to_judge() {
    let program = busbar_contract::VerifiedDestination::seal(
        &trust_token(),
        busbar_contract::DestinationFacts::Upstream {
            transport: "stdio",
            address: busbar_contract_transport::dest::UpstreamAddress::Program {
                path: "/usr/local/bin/server",
                args: &[],
                env: &[],
            },
            lane: busbar_contract::LaneId::new("test"),
        },
        "stdio",
        None,
    );
    assert_eq!(
        check_destination(&program, &[], &NeverAsked, strict(), &Denylist::default()),
        Ok(None)
    );
}

/// The rebinding case, at the level the transports now sit behind: the destination is judged once
/// and the address handed on is the one that was judged.
#[test]
fn a_destination_is_resolved_exactly_once_and_the_pin_is_what_was_judged() {
    let resolver =
        ScriptedResolver::new(vec![Ok(vec![ip(PUBLIC)]), Ok(vec![ip("169.254.169.254")])]);
    let pinned = check_destination(
        &dest("https://rebind.example/"),
        &[],
        &resolver,
        strict(),
        &Denylist::default(),
    )
    .expect("the first answer is public")
    .expect("a socket target is pinned");
    assert_eq!(pinned.addr(), ip(PUBLIC));
    assert_eq!(resolver.asked(), 1, "exactly one resolution, ever");
    assert_eq!(pinned.host(), "rebind.example", "the name travels for SNI");
}

/// Only an upstream is dialled at an address; every other destination kind is answered elsewhere.
#[test]
fn a_destination_that_is_not_an_upstream_has_no_address_check() {
    let verb = busbar_contract::VerifiedDestination::seal(
        &trust_token(),
        busbar_contract::DestinationFacts::KernelVerb { verb: "status" },
        "http",
        None,
    );
    assert_eq!(
        check_destination(&verb, &[], &NeverAsked, strict(), &Denylist::default()),
        Err(NetworkRefusal::NotAnUpstream)
    );
}

/// The sealed door and the facts door are one implementation, not two that agree today.
///
/// `check_destination` is a projection onto `check_destination_facts`, so this cannot drift the way
/// the composition root's own copy did. It is asserted rather than assumed because "these two agree"
/// is exactly the claim that was false before the projection existed.
///
/// The metadata row is spelled as a URL on purpose: the denylist's host extraction strips a scheme
/// first and answers `None` for a string that carries none, so a schemeless `169.254.169.254:80`
/// would pass that arm and prove nothing about the arm under test.
#[test]
fn the_sealed_door_and_the_facts_door_are_one_implementation() {
    let cases: [busbar_contract::DestinationFacts; 4] = [
        busbar_contract::DestinationFacts::Upstream {
            transport: "https",
            address: busbar_contract_transport::dest::UpstreamAddress::socket(
                "https://169.254.169.254/latest/meta-data",
            ),
            lane: busbar_contract::LaneId::new("test"),
        },
        busbar_contract::DestinationFacts::Upstream {
            transport: "https",
            address: busbar_contract_transport::dest::UpstreamAddress::socket(
                "https://private.example/",
            ),
            lane: busbar_contract::LaneId::new("test"),
        },
        busbar_contract::DestinationFacts::Upstream {
            transport: "stdio",
            address: busbar_contract_transport::dest::UpstreamAddress::Program {
                path: "/usr/local/bin/server",
                args: &[],
                env: &[],
            },
            lane: busbar_contract::LaneId::new("test"),
        },
        busbar_contract::DestinationFacts::KernelVerb { verb: "status" },
    ];
    for facts in cases {
        let sealed = busbar_contract::VerifiedDestination::seal(&trust_token(), facts, "https", None);
        let resolver = ScriptedResolver::new(vec![Ok(vec![ip("127.0.0.1")])]);
        let through_the_seal =
            check_destination(&sealed, &[], &resolver, strict(), &Denylist::default());
        let facts_resolver = ScriptedResolver::new(vec![Ok(vec![ip("127.0.0.1")])]);
        let through_the_facts = check_destination_facts(
            &facts,
            &[],
            &facts_resolver,
            strict(),
            &Denylist::default(),
        );
        assert_eq!(
            through_the_seal, through_the_facts,
            "the two doors disagree about {facts:?}"
        );
    }
}
