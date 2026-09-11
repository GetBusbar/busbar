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

/// THE WHOLE LINK-LOCAL /16 IS METADATA, not just the five literals a list can name.
///
/// Clouds put their instance-metadata service anywhere inside `169.254.0.0/16` (Tencent answers on
/// `169.254.0.23`, AWS's IPv6-era ECS endpoint on `169.254.170.3`, the IMDS v6 alias on
/// `169.254.169.253`), and nothing legitimate runs on link-local at all. An address-side predicate
/// that enumerates literals leaves every other link-local address to the internal-range arm, which
/// `allow_private: true` switches off — so the operator flag that says "our upstream is on the
/// internal network" would pin and dial an unlisted metadata endpoint. The config-side predicate in
/// this same module already asks the RANGE question; the address side must ask the same one.
#[test]
fn unlisted_link_local_metadata_is_refused_as_metadata_under_allow_private() {
    let unlisted = [
        ("Tencent IMDS", "169.254.0.23"),
        ("IMDS v6-alias endpoint", "169.254.169.253"),
        ("ECS task metadata (v6-era)", "169.254.170.3"),
        // The IPv4-COMPATIBLE spelling reaches the same target through `to_ipv4()`.
        ("IPv4-COMPATIBLE Tencent", "::169.254.0.23"),
        ("IPv4-MAPPED Tencent", "::ffff:169.254.0.23"),
    ];
    for (what, a) in unlisted {
        for policy in [strict(), private_ok()] {
            let err = judge_address("meta", ip(a), policy)
                .expect_err("link-local metadata is refused under every policy");
            assert!(
                matches!(err, AddressRefusal::CloudMetadataAddress { .. }),
                "{what} ({a}) must be refused AS METADATA, not merely as internal: {err:?}"
            );
        }
    }
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

/// THERE IS ONE METADATA-NAME LIST, and both name guards read it.
///
/// The module-level list and the one the config-side SSRF check kept privately had drifted to two
/// and six entries: a name an operator could not reach through config validation was reachable
/// through the resolved-name guard, purely because the second list was declared inside a function.
/// Every name on the list must be refused by BOTH arms, under every policy — `allow_private` speaks
/// for the `localhost` family and never for metadata.
#[test]
fn every_metadata_name_is_refused_by_both_the_name_guard_and_the_config_guard() {
    assert_eq!(
        METADATA_HOSTS.len(),
        6,
        "the metadata-name list must not shrink"
    );
    for name in METADATA_HOSTS {
        for policy in [strict(), private_ok()] {
            assert_eq!(
                judge_host_name(name, policy),
                Err(AddressRefusal::MetadataName((*name).to_string())),
                "`{name}` is a cloud-metadata name and `allow_private` may not reach it"
            );
        }
        assert_eq!(
            ssrf_blocked_host(&format!("https://{name}/"), &[], false, &[]),
            Some((*name).to_string()),
            "`{name}` must still be blocked by the config-side guard"
        );
    }
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

/// A refusal names the URL, and a URL's authority is where a password goes.
///
/// The refusal text is written into a card and a log, both read by more people than a config is and
/// kept for longer. Repeating the credential there would make the refusal the one place the secret
/// is written down twice — so the authority's userinfo is replaced by a marker, and the host, which
/// is the whole diagnosis, stays.
#[test]
fn a_refusal_never_repeats_the_credential_in_the_authority() {
    let refusals = [
        split_url("https://svc:hunter2@good.example/mcp").expect_err("userinfo is refused"),
        split_url("ftp://svc:hunter2@good.example/x").expect_err("the scheme is refused"),
        judge_scheme("http://svc:hunter2@good.example/x", false, strict())
            .expect_err("plaintext is refused"),
        refuse_oversized_body("https://svc:hunter2@good.example/x", 1 << 30, strict())
            .expect_err("the body is over the ceiling"),
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

    // A `@` in the path is not a credential and is left as the operator wrote it.
    let path_at = split_url("ftp://good.example/mail@archive").expect_err("the scheme is refused");
    assert!(path_at.to_string().contains("mail@archive"));
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
        Denylist::new(&[], &["169.254.169.254".to_string()], false),
        Denylist::new(&[], &[], true),
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
    let blocked_then_allowed =
        Denylist::new(&["10.0.0.7".to_string()], &["10.0.0.7".to_string()], false);
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
    let extra = Denylist::new(&["10.99.99.99".to_string()], &[], false);
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
    let extra = Denylist::new(&["10.99.99.99".to_string()], &[], false);
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

/// An operator's entries are canonicalized the same way whenever that canonicalization happens.
///
/// Surrounding whitespace, a trailing FQDN dot and letter case are all noise in a written entry, and
/// an entry that is nothing but whitespace names no host at all — an empty entry that matched would
/// block or unblock every destination a deployment has.
#[test]
fn an_entry_is_canonicalized_the_same_way_however_it_was_written() {
    for written in [
        "Metadata.Example",
        "  metadata.example  ",
        "metadata.example.",
        " METADATA.EXAMPLE. ",
    ] {
        let blocked = Denylist::new(&[written.to_string()], &[], false);
        assert_eq!(
            check_destination(
                &dest("https://METADATA.example./"),
                &[],
                &NeverAsked,
                strict(),
                &blocked
            ),
            Err(NetworkRefusal::MetadataDenied(
                "METADATA.example".to_string()
            )),
            "`{written}` names the same host however it was written"
        );
    }

    // An IP entry, likewise — and it still covers every spelling of that address.
    let spaced = Denylist::new(&[" 10.99.99.99. ".to_string()], &[], false);
    assert!(matches!(
        check_destination(
            &dest("https://[::ffff:10.99.99.99]/"),
            &[],
            &NeverAsked,
            private_ok(),
            &spaced
        ),
        Err(NetworkRefusal::MetadataDenied(_))
    ));

    // An empty or whitespace-only entry names nothing and matches nothing, on either list.
    let blank = Denylist::new(&[String::new(), "   ".to_string()], &[], false);
    assert!(
        matches!(
            check_destination(
                &dest("https://example.com/"),
                &[],
                &ScriptedResolver::new(vec![Ok(vec![ip(PUBLIC)])]),
                strict(),
                &blank
            ),
            Ok(Some(_))
        ),
        "a blank block entry must not block every host"
    );
    let blank_allow = Denylist::new(&[], &[String::new(), "  ".to_string()], false);
    assert_eq!(
        check_destination(
            &dest("https://169.254.169.254/"),
            &[],
            &NeverAsked,
            strict(),
            &blank_allow
        ),
        Err(NetworkRefusal::MetadataDenied(
            "169.254.169.254".to_string()
        )),
        "a blank allow entry must not unblock every host"
    );
}

/// An authority itself carrying the WHATWG backslash/userinfo trick is denied.
///
/// A backslash terminates the authority in a WHATWG-normalizing stack exactly as a slash does, so
/// `169.254.169.254\@metadata.example` is read the same way a connecting stack reads it: host
/// `169.254.169.254`, with `@metadata.example` dropped as the (fake) tail of an authority that
/// already ended. This is a property of the AUTHORITY itself, exercised here with an empty `paths`
/// so nothing about `join_path` is in play — see
/// [`a_denylisted_path_is_not_smuggled_past_the_check_by_the_base_it_is_joined_to`] below for the
/// base-plus-path re-check the name of that test used to (wrongly) claim this one covered.
#[test]
fn an_authority_carrying_the_backslash_trick_is_denied() {
    assert_eq!(
        check_destination(
            &dest("https://169.254.169.254\\@metadata.example"),
            &[],
            &NeverAsked,
            strict(),
            &Denylist::default()
        ),
        Err(NetworkRefusal::MetadataDenied(
            "169.254.169.254".to_string()
        ))
    );
}

/// `join_path` and the re-check loop over `paths` (`net.rs:1531`) are only exercised when `paths` is
/// non-empty. A prior version of this test passed `paths: &[]` and put the entire attack string
/// directly into the destination's OWN authority — which is caught by the bare-authority candidate
/// alone (see the test above) and never reaches `join_path` at all, despite the test's name claiming
/// to cover the base-plus-path case.
///
/// `join_path` always inserts a real `/` (or uses the one `path` already opens with) between the
/// base and the path it is given, so nothing a path carries — the backslash trick included — can
/// ever land BEFORE that separator and re-open the authority the base already closed: the
/// backslash-folded authority segment `split(['/', '?', '#']).next()` reads stops at the join's own
/// separator every time. So the provable claim about the base-plus-path re-check is the opposite of
/// an attack succeeding: the joined candidate resolves to the SAME host the base alone does, and the
/// declared path cannot smuggle a different one past it — while still genuinely exercising
/// `join_path` and the loop, unlike the version of this test that never called them.
#[test]
fn a_denylisted_path_is_not_smuggled_past_the_check_by_the_base_it_is_joined_to() {
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

    // The SAME backslash/userinfo trick, now carried in a declared PATH rather than the authority,
    // still resolves the joined candidate to the base's own host — `join_path` and the denylist loop
    // both ran (a non-empty `paths` slice is what makes that true), and neither was fooled.
    let pinned = check_destination(
        &dest(base),
        &["\\@169.254.169.254"],
        &ScriptedResolver::new(vec![Ok(vec![ip(PUBLIC)])]),
        strict(),
        &none,
    )
    .expect("the base's own host, unaffected by the path")
    .expect("a socket target is pinned");
    assert_eq!(pinned.host(), "metadata.example");
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

/// The operator's denylist judges a bare `host:port` authority too.
///
/// Which of the two spellings a lane's configuration used is not a security question, and the
/// scheme and address checks already treat them alike. The denylist ran off a host extraction that
/// required a `://`, so it silently returned nothing for the bare form and the operator's entry
/// never fired for it.
#[test]
fn an_operator_block_entry_covers_the_bare_authority_spelling() {
    let extra = Denylist::new(&["203.0.113.7".to_string()], &[], false);

    assert_eq!(
        check_destination(
            &dest("203.0.113.7:80"),
            &[],
            &NeverAsked,
            private_ok(),
            &extra
        ),
        Err(NetworkRefusal::MetadataDenied("203.0.113.7".to_string())),
        "the bare authority names the address the operator blocked"
    );

    // The URL spelling of the same address is refused as it always was.
    assert_eq!(
        check_destination(
            &dest("https://203.0.113.7/"),
            &[],
            &NeverAsked,
            private_ok(),
            &extra
        ),
        Err(NetworkRefusal::MetadataDenied("203.0.113.7".to_string()))
    );

    // And a bare authority the operator did not name is still judged on its merits.
    assert!(
        matches!(
            check_destination(
                &dest("203.0.113.9:80"),
                &[],
                &NeverAsked,
                private_ok(),
                &extra
            ),
            Ok(Some(_))
        ),
        "an unlisted bare authority still passes"
    );
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
                extras: &[],
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
                extras: &[],
            },
            lane: busbar_contract::LaneId::new("test"),
        },
        busbar_contract::DestinationFacts::KernelVerb { verb: "status" },
    ];
    for facts in cases {
        let sealed =
            busbar_contract::VerifiedDestination::seal(&trust_token(), facts, "https", None);
        let resolver = ScriptedResolver::new(vec![Ok(vec![ip("127.0.0.1")])]);
        let through_the_seal =
            check_destination(&sealed, &[], &resolver, strict(), &Denylist::default());
        let facts_resolver = ScriptedResolver::new(vec![Ok(vec![ip("127.0.0.1")])]);
        let through_the_facts =
            check_destination_facts(&facts, &[], &facts_resolver, strict(), &Denylist::default());
        assert_eq!(
            through_the_seal, through_the_facts,
            "the two doors disagree about {facts:?}"
        );
    }
}

// ── the percent-decode arm of the host normalization ────────────────────────────────────────────
//
// `extract_normalized_host` percent-decodes before it answers, and nothing in this crate said so.
// Reducing the decode to an identity left the whole suite green while
// `https://169%2E254%2E169%2E254/` reached the range checks as a host that parses as no `IpAddr`,
// matches no metadata name, and is therefore waved through — after which the `url` crate reqwest
// uses decodes the dots and dials the real IMDS address. The rows below are the decision table the
// decode actually implements, not one happy case: what decodes, what deliberately does NOT, and
// where the decode sits relative to the trailing-root-dot strip that runs after it.

/// A `%XX` escape naming a dot is the same host as the dot, which is the whole SSRF claim.
#[test]
fn a_percent_encoded_metadata_host_normalizes_to_the_address_it_will_dial() {
    assert_eq!(
        extract_normalized_host("https://169%2E254%2E169%2E254/").as_deref(),
        Some("169.254.169.254"),
        "an escaped dot must be read as the dot the connecting stack will read"
    );
    // Lower-case hex is the same escape. A decoder that accepted only one case would leave the
    // other spelling as the bypass it replaced.
    assert_eq!(
        extract_normalized_host("https://169%2e254%2e169%2e254/").as_deref(),
        Some("169.254.169.254")
    );
    // And the decoded literal really is an address, which is what makes every range check below it
    // apply at all.
    assert!("169.254.169.254".parse::<IpAddr>().is_ok());
}

/// An escape this decoder cannot read stays VERBATIM rather than being dropped or guessed at.
///
/// Dropping a malformed escape would be the same bypass in reverse: the host would collapse toward
/// a shorter string the stack never produces, and a guard that reads a host the socket does not
/// connect to is not a guard.
#[test]
fn a_malformed_percent_escape_is_left_exactly_as_it_was_written() {
    // A `%` with nothing behind it, and one with only a single character behind it: no two hex
    // digits, so no escape.
    assert_eq!(
        extract_normalized_host("https://host.example%/").as_deref(),
        Some("host.example%")
    );
    assert_eq!(
        extract_normalized_host("https://host.exampl%4/").as_deref(),
        Some("host.exampl%4")
    );
    // Two characters that are not hex.
    assert_eq!(
        extract_normalized_host("https://host%ZZexample/").as_deref(),
        Some("host%ZZexample")
    );
    // None of these is an address, which is the point: they stay non-matching rather than becoming
    // a different host.
    assert!("host.example%".parse::<IpAddr>().is_err());
}

/// The decode runs EXACTLY ONCE. `%252E` is the escape for the literal text `%2E`, and a decoder
/// that looped would turn it into a dot — reading a host the connecting stack never dials.
#[test]
fn the_decode_runs_once_and_does_not_unwrap_a_double_encoding() {
    assert_eq!(
        extract_normalized_host("https://169%252E254%252E169%252E254/").as_deref(),
        Some("169%2E254%2E169%2E254"),
        "one pass, so a double encoding decodes to the literal escape text and no further"
    );
}

/// A decoding that would not be TEXT is abandoned and the original stands.
///
/// `%FF` is a legal escape and an illegal UTF-8 byte on its own, so the decode produces bytes that
/// are not a string. The rule is that the host reverts to exactly what was written rather than
/// being lossily patched up: a replacement character substituted here would be a host that neither
/// the config nor the connecting stack ever names, and every list comparison below would be made
/// against a string nobody can produce.
#[test]
fn a_decoding_that_would_not_be_text_leaves_the_host_as_it_was() {
    assert_eq!(
        extract_normalized_host("https://host%FFexample.test/").as_deref(),
        Some("host%FFexample.test"),
        "bytes that are not UTF-8 abandon the decode rather than mangling the host"
    );
}

/// A NUL, by contrast, IS text and therefore DOES decode — pinned because the two escapes look
/// alike and behave differently, and because the decoded form is what the guard must compare.
///
/// The decoded host is `169.254.169.254\0.evil.example`, which is not the metadata address and is
/// not meant to be: the escape does not truncate the host, so it cannot be used to make a longer
/// attacker-controlled name compare equal to a shorter blocked one.
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
/// too. Ordered the other way, `169.254.169.254%2E` would keep the escape, parse as no `IpAddr`,
/// and defeat every range check while glibc resolved it as the rooted FQDN it is.
#[test]
fn an_escaped_trailing_root_dot_is_stripped_because_the_decode_comes_first() {
    assert_eq!(
        extract_normalized_host("https://169.254.169.254%2E/").as_deref(),
        Some("169.254.169.254")
    );
    // The unescaped spelling of the same thing, so the two are pinned as one answer.
    assert_eq!(
        extract_normalized_host("https://169.254.169.254./").as_deref(),
        Some("169.254.169.254")
    );
}

/// A host with no `%` in it at all comes back unchanged — the ordinary case, pinned so the
/// borrowing fast path cannot start rewriting hosts nobody escaped.
#[test]
fn a_host_with_no_escape_in_it_is_returned_unchanged() {
    assert_eq!(
        extract_normalized_host("https://api.openai.com/v1").as_deref(),
        Some("api.openai.com")
    );
}

/// WHITESPACE AROUND A URL MUST NOT BUY A METADATA HOP. The WHATWG basic URL parser begins by
/// trimming leading and trailing C0 controls AND spaces from the input, and by deleting every ASCII
/// tab / CR / LF from anywhere inside it — so a connecting stack sees `169.254.169.254` for every
/// spelling below. Any spelling this guard reads differently from the stack that will dial it is a
/// bypass: a token endpoint POSTs client credentials to the URL verbatim, so a host the guard failed
/// to recognize as IMDS is a host that receives those credentials.
///
/// Ported byte-for-byte from the live sibling copy's own coverage
/// (`busbar-substrate/src/tests/net_guard_tests.rs`), because the extraction dropped half of that
/// first step and kept the tests that would have said so on the other side of the move.
#[test]
fn whitespace_padded_metadata_urls_are_still_refused() {
    for spelling in [
        "http://169.254.169.254/latest/meta-data/ ", // trailing space after the path
        "http://169.254.169.254 ",                   // trailing space directly after the host
        " http://169.254.169.254/latest/meta-data/", // leading space (would hide the scheme)
        "\u{1}http://169.254.169.254/",              // leading C0 control
        "http://169.254.169.254/\u{1f}",             // trailing C0 control
        "http://169.254.169\t.254/",                 // interior tab, deleted by the parser
        "http://169.254.169.254\r\n/",               // interior CR/LF
        "\t http://169.254.169.254/ \r\n",           // mixed padding, both ends
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
/// of the three deleted bytes) is left alone, so a malformed host stays malformed rather than being
/// silently repaired into something that matches.
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
        extract_normalized_host("  https://api.openai.com/v1  ").as_deref(),
        Some("api.openai.com")
    );
}

/// THE OPERATOR'S DENYLIST IS THE THING THE PADDING DEFEATED. The metadata refusals above are
/// hard-coded ranges; an operator's own `blocked_metadata_hosts` entry is a `HostSet` match on the
/// extracted host, so a host that carries a trailing space matches no entry and the block silently
/// does not fire while the connecting stack trims and dials it.
#[test]
fn a_padded_authority_does_not_slip_past_the_operator_denylist() {
    let blocked = vec!["10.99.99.99".to_string()];
    for spelling in [
        "https://10.99.99.99",
        "https://10.99.99.99 ",
        " https://10.99.99.99",
        "https://10.99.99.99\u{1f}",
        // The bare-authority spelling of the same destination, which `judge_against_lists` falls
        // back to and which runs the same first step.
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

// =================================================================================================
//   THE STRUCTURAL LITERAL ARM — the judgement of an UNRESOLVED authority.
//
//   `judge_host_name` is names-only and judges addresses nowhere: it asks the metadata NAME list,
//   the `localhost` NAME family and the alternate-encoding shape, and everything else it answers
//   `Ok`. The address arms live in `judge_address`, which runs against a RESOLVED answer. That is
//   the right shape for a guard that is about to dial, because that guard resolves.
//
//   It is the WRONG shape for a guard that resolves nothing. The host-vtable's URL-argument slot
//   judges a URL-shaped tool ARGUMENT — attacker-influenced data — from the string alone and
//   deliberately performs no lookup, because the host is not the connecting party there and an
//   advisory answer rebinding defeats is worse than an honest structural one. Handed only
//   `judge_host_name`, that slot would wave `http://169.254.169.254/` through: the dotted quad is
//   not a metadata NAME, `dns_name_is_internal` is a name predicate, and a canonical quad is not an
//   alternate encoding. Three `Ok`s and a credential endpoint on the other end.
//
//   These cells pin the arm that closes it, and they pin the ORDER, because two of the arms
//   overlap: `host_is_private_or_loopback` deliberately answers `true` for an alternate encoding,
//   so which of `ObfuscatedHost` and `InternalHost` a caller sees for `0x7f000001` is decided by
//   which question is asked first, not by the host.
// =================================================================================================

/// THE GAP, stated as the input that falls through every name arm.
///
/// Each of these is an address a connecting stack reaches and `judge_host_name` answers `Ok` for.
/// The literal judge must refuse all of them.
#[test]
fn the_name_judge_answers_ok_for_every_literal_the_literal_judge_refuses() {
    let policy = GuardPolicy::default();
    for host in [
        "169.254.169.254",  // IMDS, the whole reason the arm exists
        "169.254.170.2",    // ECS task metadata
        "100.100.100.200",  // Alibaba metadata
        "168.63.129.16",    // Azure WireServer
        "192.0.0.192",      // OCI metadata
        "10.0.0.1",         // RFC1918
        "127.0.0.1",        // loopback literal
        "::ffff:127.0.0.1", // IPv4-mapped loopback
        "::ffff:169.254.169.254",
        "fd00:ec2::254", // EC2 IMDSv6
    ] {
        assert!(
            judge_host_name(host, policy).is_ok(),
            "{host}: the name judge is names-only; if it started refusing literals this cell is \
             restating the literal judge instead of motivating it"
        );
        assert!(
            judge_host(host, false).is_err(),
            "{host}: the literal judge waved through an address a connecting stack reaches — this \
             is the metadata bypass on a tool argument"
        );
    }
}

/// The metadata arm: first, and unconditional. `allow_private` does not speak for it.
#[test]
fn the_literal_judge_refuses_metadata_however_it_is_spelled_and_whatever_the_policy() {
    for (host, why) in [
        ("169.254.169.254", "the canonical IMDS quad"),
        (
            "169.254.169.254.",
            "the trailing FQDN root dot getaddrinfo resolves the same",
        ),
        ("metadata.google.internal", "the GCP metadata name"),
        (
            "metadata.tencentyun.com",
            "a metadata name the SUBSTRATE's 2-entry const never held",
        ),
        ("instance-data", "the EC2 short name"),
        (
            "[::ffff:169.254.169.254]",
            "the IPv4-mapped v6 spelling of IMDS",
        ),
        ("fd00:ec2::254", "EC2 IMDSv6"),
        ("0xA9FEA9FE", "IMDS as whole-host hex"),
        ("2852039166", "IMDS as a decimal int"),
        ("0251.0376.0251.0376", "IMDS in octal"),
    ] {
        for allow_private in [false, true] {
            assert_eq!(
                judge_host(host, allow_private),
                Err(LiteralRefusal::CloudMetadata(
                    normalized_for(host).to_string()
                )),
                "{host} ({why}) with allow_private={allow_private}: metadata is refused FIRST and \
                 unconditionally, or a target that opted into private addressing has opted into \
                 the one endpoint whose whole value to an attacker is that it hands out credentials"
            );
        }
    }
}

/// The obfuscated arm: SECOND, unconditional, and ahead of the private arm.
///
/// `host_is_private_or_loopback` answers `true` for an alternate encoding by design, so both arms
/// match `0x7f000001`. The substrate's structural judge asks obfuscated first. The unit's NAME
/// judge asks private first and would answer `LoopbackName`. The literal judge takes the
/// substrate's order, because a value spelled so the check cannot read it is refused for being
/// unreadable rather than for whatever it happens to decode to.
#[test]
fn the_obfuscated_arm_is_asked_before_the_private_arm() {
    for host in ["0x7f000001", "2130706433", "127.1", "0177.0.0.1"] {
        assert!(
            host_is_private_or_loopback(host),
            "{host}: both arms must match, or this cell is not testing an order"
        );
        assert_eq!(
            judge_host(host, false),
            Err(LiteralRefusal::ObfuscatedHost(host.to_string())),
            "{host}: the private arm answered first and the caller was told the wrong thing about \
             why its argument was refused"
        );
    }
    // Unconditional: the knob speaks for private addressing, not for unreadable spellings.
    assert_eq!(
        judge_host("0x7f000001", true),
        Err(LiteralRefusal::ObfuscatedHost("0x7f000001".to_string())),
        "allow_private turned the obfuscated arm off; a target that admits private addressing has \
         not thereby admitted addresses the guard cannot read"
    );
}

/// The private arm: LAST, and the only one `allow_private` speaks for.
#[test]
fn the_private_arm_is_last_and_is_the_one_the_policy_opts_into() {
    for host in [
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "localhost",
    ] {
        assert_eq!(
            judge_host(host, false),
            Err(LiteralRefusal::InternalHost(host.to_string())),
            "{host}: a private literal reached through a tool argument"
        );
        assert!(
            judge_host(host, true).is_ok(),
            "{host}: allow_private is the target's deliberate opt-in and must be honoured"
        );
    }
    // The `localhost` family, including the rooted spelling that misses an exact compare by a byte.
    assert_eq!(
        judge_host("localhost.", false),
        Err(LiteralRefusal::InternalHost("localhost".to_string())),
        "the trailing root dot must be normalized away before the compare, or `localhost.` is a \
         one-byte bypass of the loopback arm"
    );
    assert_eq!(
        judge_host("db.localhost", false),
        Err(LiteralRefusal::InternalHost("db.localhost".to_string())),
        "RFC 6761 reserves the whole `.localhost` TLD to loopback"
    );
}

/// An ordinary public destination is admissible, which is the control this whole arm needs.
#[test]
fn the_literal_judge_admits_a_public_host() {
    for host in ["api.openai.com", "example.com", "8.8.8.8", "1.1.1.1"] {
        assert!(
            judge_host(host, false).is_ok(),
            "{host}: the literal judge refused an ordinary public destination — a guard that \
             refuses everything is not a guard"
        );
    }
}

/// The URL door: the scheme allowlist, then the host, in that order.
#[test]
fn the_literal_url_judge_asks_the_scheme_before_the_host() {
    // Refused by ABSENCE from the allowlist, not by a blocklist somebody has to maintain.
    for url in [
        "file:///etc/passwd",
        "gopher://169.254.169.254/",
        "ftp://10.0.0.1/",
    ] {
        assert_eq!(
            judge_literal(url, false),
            Err(LiteralRefusal::Scheme(url.to_string())),
            "{url}: the scheme arm is first, so a non-http(s) URL is refused for its scheme even \
             when its host would also have been refused"
        );
    }
    assert_eq!(
        judge_literal("https://169.254.169.254/latest/meta-data/", false),
        Err(LiteralRefusal::CloudMetadata("169.254.169.254".to_string()))
    );
    assert!(judge_literal("http://api.openai.com/v1", false).is_ok());
    assert!(judge_literal("HTTPS://api.openai.com/v1", false).is_ok());
    // No usable host at all.
    assert_eq!(
        judge_literal("https://", false),
        Err(LiteralRefusal::NoHost("https://".to_string()))
    );
}

/// The literal judge reads the host through the SAME reader the denylist does.
///
/// Not a second normalization: the whole obfuscation defence is `extract_normalized_host`, and a
/// structural judge that re-derived any of it would be the third copy of the thing this file
/// exists to stop being two of.
#[test]
fn the_literal_judge_reads_the_host_through_the_shared_reader() {
    for url in [
        "https://169.254.169.254 ",                // WHATWG trailing trim
        "https://169.254.169\t.254/",              // interior tab, deleted from anywhere
        "https://169%2E254%2E169%2E254/",          // percent-encoded dots
        "https://10.0.0.1\\x.allowed.com/",        // the backslash authority-boundary fold
        "https://api.openai.com@169.254.169.254/", // userinfo prefix
        "https://169.254.169.254:80/?q=#frag",     // port, query, fragment
    ] {
        assert!(
            matches!(
                judge_literal(url, false),
                Err(LiteralRefusal::CloudMetadata(_) | LiteralRefusal::InternalHost(_))
            ),
            "{url}: the literal judge read a different host than the shared reader does, which is \
             the drift the extraction was unified to prevent"
        );
    }
    // THE LEADING-PADDING SPELLING REFUSES AT THE SCHEME ARM, NOT THE HOST ARM, and that is the
    // faithful answer rather than a gap. The leading trim is the half of the WHATWG first step that
    // hides the SCHEME rather than the host: `" https://169.254.169.254/"` splits on `://` into the
    // scheme `" https"`, which is in no allowlist. Since the scheme is asked FIRST, the refusal
    // says scheme. It is still a refusal — fail-closed — and it is the same arm the host-vtable's
    // structural judge answers on, so a re-point changes no caller's verdict. Pinned with its
    // reason so a later change that "fixes" it into a host refusal is a decision and not a drift.
    for url in [" https://169.254.169.254/", "\u{1}http://169.254.169.254/"] {
        assert_eq!(
            judge_literal(url, false),
            Err(LiteralRefusal::Scheme(url.to_string())),
            "{url}: leading padding hides the scheme, so the scheme arm is the one that must fire"
        );
    }
}

/// The host bytes a refusal carries are the NORMALIZED host, not the raw spelling.
///
/// The vtable slot copies these bytes back to the plane as the refusal reason, so what they are is
/// an operator-visible fact and not an implementation detail.
#[test]
fn a_refusal_carries_the_normalized_host_bytes() {
    assert_eq!(
        judge_host("169.254.169.254.", false),
        Err(LiteralRefusal::CloudMetadata("169.254.169.254".to_string())),
        "the rooted spelling must report the host the guard actually judged"
    );
    assert_eq!(
        judge_literal("https://user:pass@10.0.0.1:8443/v1", false),
        Err(LiteralRefusal::InternalHost("10.0.0.1".to_string())),
        "the userinfo must not survive into a refusal string: a refusal naming a rejected \
         credential would be the one place a password is written down twice"
    );
}

/// The normalized spelling of a host, for the cells above that state an expected refusal payload.
fn normalized_for(host: &str) -> String {
    let bracketed = host.strip_prefix('[').and_then(|h| h.strip_suffix(']'));
    let bare = bracketed.unwrap_or(host);
    bare.strip_suffix('.').unwrap_or(bare).to_string()
}
