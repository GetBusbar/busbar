// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The network guard, on the inputs an attacker chooses rather than the ones a config file does.
//!
//! Three separate claims are checked here, each of which the crate makes in prose and none of which
//! it had a test for at the boundary an attacker actually reaches:
//!
//! - **The alternate-encoding recogniser is exact.** It has to say yes to every spelling
//!   `getaddrinfo` expands and no to everything else. A yes it should not give turns a legitimate
//!   hostname into a refused destination; a no it should not give is the whole SSRF bypass. The
//!   malformed near-misses — `0x` with nothing after it, `0x` followed by a non-hex digit, an empty
//!   dotted part — are where the two clauses of each check can be swapped without any existing
//!   assertion noticing.
//! - **Metadata is refused before the operator's knob is consulted.** `allow_private` says "this
//!   upstream is on our internal network"; it does not say anything about IMDS, and a build where
//!   it did would be a config flag that hands out cloud credentials.
//! - **Resolve then pin, and a mixed answer is refused whole.** The address that comes back is one
//!   this module already judged, and a resolver that answers with a good address and a bad one in
//!   one reply is refused rather than filtered down to the good one.

use std::net::IpAddr;

use busbar_unit_trust::net::{
    dns_name_is_internal, ip_is_cloud_metadata, ip_is_internal, is_alternate_ipv4_encoding,
    judge_address, judge_host_name, pin_answer, resolve_and_pin, AddressRefusal, Resolver,
};
use busbar_unit_trust::GuardPolicy;

fn ip(s: &str) -> IpAddr {
    s.parse().expect("a literal address")
}

fn strict() -> GuardPolicy {
    GuardPolicy::default()
}

fn permissive() -> GuardPolicy {
    GuardPolicy {
        allow_private: true,
        allow_plaintext: true,
        ..GuardPolicy::default()
    }
}

/// A resolver stated as data: what each name answers with, or a failure.
struct Answers(Vec<(&'static str, Result<Vec<IpAddr>, String>)>);
impl Resolver for Answers {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        self.0
            .iter()
            .find(|(n, _)| *n == host)
            .map(|(_, a)| a.clone())
            .unwrap_or_else(|| Err(format!("no answer configured for {host}")))
    }
}

/// The spellings `getaddrinfo` expands, and the near-misses that only LOOK like them.
///
/// Each `false` row is a host the recogniser must let through: it is either an ordinary DNS name or
/// a malformed string no resolver expands to an address, and refusing it takes a working upstream
/// off the wire for a reason an operator cannot read off the message. Each `true` row is an
/// encoding that reaches loopback, link-local or private space through a canonical-literal check
/// that never fires.
#[test]
fn the_alternate_encoding_recogniser_says_yes_to_exactly_the_expanded_spellings() {
    for (host, want, why) in [
        // Whole-host encodings that DO expand.
        ("2130706433", true, "decimal 127.0.0.1"),
        ("0x7f000001", true, "hex, lowercase prefix"),
        ("0X7F000001", true, "hex, uppercase prefix"),
        ("017700000001", true, "leading-zero octal"),
        ("0", true, "the shortest decimal encoding there is"),
        // Whole-host strings that only look like them.
        ("0x", false, "a hex prefix with no digits after it"),
        ("0X", false, "an uppercase hex prefix with no digits"),
        ("0xg", false, "a hex prefix followed by a non-hex letter"),
        ("0x7f00zz01", false, "a hex prefix with a non-hex tail"),
        ("0xdead-beef", false, "a hex prefix with punctuation in it"),
        ("localhost", false, "an ordinary name"),
        ("api.openai.com", false, "an ordinary dotted name"),
        ("", false, "the empty host"),
        // Dotted forms.
        ("127.1", true, "short dotted"),
        ("10.0.1", true, "short dotted, three parts"),
        ("0x7f.0.0.1", true, "per-octet hex"),
        ("0177.0.0.1", true, "per-octet octal"),
        (
            "127.0.0.1",
            false,
            "a canonical dotted-quad, left to the literal path",
        ),
        ("8.8.8.8", false, "a canonical public dotted-quad"),
        (
            "0x.1.2.3",
            false,
            "a part that is a bare hex prefix with no digits",
        ),
        ("0xg.1.2.3", false, "a part whose hex tail is not hex"),
        ("1..2", false, "an empty dotted part"),
        (".1.2", false, "a leading empty part"),
        ("1.2.", false, "a trailing empty part"),
        ("v1.2", false, "a part with a letter in it"),
        (
            "1.2.3.4.5",
            false,
            "five numeric parts, none of them encoded",
        ),
    ] {
        assert_eq!(is_alternate_ipv4_encoding(host), want, "`{host}` ({why})");
    }
}

/// Every alternate encoding the recogniser flags is refused at the name check, before any resolver
/// is consulted — and refused even under the operator's private-addressing opt-in, because the
/// obfuscation says nothing about which network the operator meant.
#[test]
fn an_obfuscated_host_is_refused_before_resolution_under_either_policy() {
    for host in ["2130706433", "0x7f000001", "127.1", "0177.0.0.1"] {
        for policy in [strict(), permissive()] {
            assert_eq!(
                judge_host_name(host, policy),
                Err(AddressRefusal::ObfuscatedHost(host.to_string())),
                "`{host}`"
            );
        }
    }
}

/// Cloud-metadata NAMES are refused before `allow_private` is consulted; the `localhost` family is
/// the only population that knob speaks for.
#[test]
fn metadata_names_are_refused_whatever_the_private_addressing_knob_says() {
    for host in [
        "metadata.google.internal",
        "METADATA.GOOGLE.INTERNAL",
        "metadata.google.internal.",
        "instance-data",
        "metadata.tencentyun.com",
    ] {
        assert!(
            matches!(
                judge_host_name(host, permissive()),
                Err(AddressRefusal::MetadataName(_))
            ),
            "`{host}` reached a resolver with allow_private set"
        );
        assert!(matches!(
            judge_host_name(host, strict()),
            Err(AddressRefusal::MetadataName(_))
        ));
        assert!(dns_name_is_internal(host), "`{host}`");
    }

    // localhost is the population the knob DOES speak for: refused strictly, admitted on opt-in.
    for host in ["localhost", "localhost.", "api.localhost", "LOCALHOST"] {
        assert!(
            matches!(
                judge_host_name(host, strict()),
                Err(AddressRefusal::LoopbackName(_))
            ),
            "`{host}`"
        );
        assert!(judge_host_name(host, permissive()).is_ok(), "`{host}`");
    }

    // And an ordinary name is neither.
    assert!(judge_host_name("api.openai.com", strict()).is_ok());
    assert!(!dns_name_is_internal("api.openai.com"));
    assert!(!dns_name_is_internal("notlocalhost"));
    assert!(!dns_name_is_internal("localhost.evil.example"));
}

/// Metadata ADDRESSES are refused before the knob too, and the internal ranges are the only
/// population it speaks for.
#[test]
fn metadata_addresses_are_refused_whatever_the_private_addressing_knob_says() {
    for addr in [
        "169.254.169.254", // AWS IMDS
        "169.254.170.2",   // ECS task metadata
        "169.254.0.23",    // Tencent
        "100.100.100.200", // Alibaba, inside the otherwise-allowed CGNAT /10
        "168.63.129.16",   // Azure WireServer
        "192.0.0.192",     // Oracle Cloud
        "::ffff:169.254.169.254",
        "::169.254.169.254",
        "fd00:ec2::254",
    ] {
        let a = ip(addr);
        assert!(ip_is_cloud_metadata(&a), "{addr}");
        for policy in [strict(), permissive()] {
            assert!(
                matches!(
                    judge_address("upstream.example", a, policy),
                    Err(AddressRefusal::CloudMetadataAddress { .. })
                ),
                "{addr} was admitted"
            );
        }
    }
}

/// The private / loopback / link-local / CGNAT / reserved populations are refused strictly, and
/// admitted only under the opt-in.
#[test]
fn the_internal_ranges_are_refused_strictly_and_admitted_only_on_the_opt_in() {
    for addr in [
        "127.0.0.1",
        "127.1.2.3",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "100.64.0.1",    // CGNAT
        "100.127.255.1", // CGNAT, top of the /10
        "0.0.0.0",
        "0.1.2.3", // 0.0.0.0/8, which is_unspecified alone misses
        "255.255.255.255",
        "224.0.0.1",  // multicast
        "192.0.2.1",  // documentation
        "192.0.0.1",  // IETF protocol assignments /24
        "198.18.0.1", // benchmarking
        "198.19.0.1", // benchmarking
        "::1",
        "fc00::1", // unique-local
        "fe80::1", // link-local
        "::",
        "ff02::1", // multicast
        "::ffff:127.0.0.1",
        "::127.0.0.1",
    ] {
        let a = ip(addr);
        assert!(ip_is_internal(&a), "{addr} is not recognised as internal");
        assert!(
            matches!(
                judge_address("upstream.example", a, strict()),
                Err(AddressRefusal::InternalAddress { .. })
            ),
            "{addr} was admitted under the strict policy"
        );
    }

    // A public address is admitted under both, so the assertions above are about the RANGE and not
    // about the judgement refusing everything.
    for addr in [
        "93.184.216.34",
        "8.8.8.8",
        "2606:2800:220:1:248:1893:25c8:1946",
    ] {
        let a = ip(addr);
        assert!(!ip_is_internal(&a), "{addr}");
        assert!(
            judge_address("upstream.example", a, strict()).is_ok(),
            "{addr}"
        );
    }

    // The opt-in admits the private populations — and, as the test above pins, never IMDS.
    assert!(judge_address("upstream.example", ip("10.0.0.1"), permissive()).is_ok());
    assert!(judge_address("upstream.example", ip("127.0.0.1"), permissive()).is_ok());
}

/// A mixed answer is refused whole, in either order, rather than pinned to whichever address the
/// resolver happened to put first.
///
/// This is the rebinding shape that a check-the-first-address guard cannot see: the resolver
/// chooses the ordering, so a guard that reads only `addrs[0]` is a guard the resolver decides the
/// outcome of.
#[test]
fn a_mixed_answer_is_refused_whole_in_either_order() {
    let public = ip("93.184.216.34");
    let imds = ip("169.254.169.254");
    let private = ip("10.0.0.5");

    for (what, answer) in [
        ("public then metadata", vec![public, imds]),
        ("metadata then public", vec![imds, public]),
        ("public, public, then metadata", vec![public, public, imds]),
    ] {
        assert!(
            matches!(
                pin_answer("upstream.example", 443, true, &answer, strict()),
                Err(AddressRefusal::CloudMetadataAddress { .. })
            ),
            "{what} was not refused"
        );
        // And still refused with the operator's opt-in set, because it is metadata.
        assert!(
            pin_answer("upstream.example", 443, true, &answer, permissive()).is_err(),
            "{what} was admitted under the opt-in"
        );
    }

    for (what, answer) in [
        ("public then private", vec![public, private]),
        ("private then public", vec![private, public]),
    ] {
        assert!(
            matches!(
                pin_answer("upstream.example", 443, true, &answer, strict()),
                Err(AddressRefusal::InternalAddress { .. })
            ),
            "{what} was not refused"
        );
    }

    // An all-public answer pins the resolver's own first choice.
    let pinned = pin_answer(
        "upstream.example",
        443,
        true,
        &[public, ip("8.8.8.8")],
        strict(),
    )
    .expect("an all-public answer pins");
    assert_eq!(pinned.addr(), public);
    assert_eq!(pinned.host(), "upstream.example");
    assert_eq!(pinned.port(), 443);
    assert!(pinned.is_https());
    assert_eq!(pinned.socket_addr(), std::net::SocketAddr::new(public, 443));

    // An empty answer is a distinct fact from a failure, and neither is a pin.
    assert_eq!(
        pin_answer("upstream.example", 443, true, &[], strict()),
        Err(AddressRefusal::NoAddresses("upstream.example".to_string()))
    );
}

/// Resolve then pin: the name is resolved exactly once, the pinned address is one this module
/// judged, and the name travels with it so the certificate is still checked against the name the
/// operator registered.
#[test]
fn resolution_happens_once_and_the_pinned_address_is_the_one_that_was_judged() {
    let public = ip("93.184.216.34");
    let resolver = Answers(vec![
        ("upstream.example", Ok(vec![public])),
        ("rebound.example", Ok(vec![ip("169.254.169.254")])),
        ("broken.example", Err("SERVFAIL".to_string())),
        ("silent.example", Ok(Vec::new())),
    ]);

    let pinned = resolve_and_pin("upstream.example", 443, true, &resolver, strict()).unwrap();
    assert_eq!(pinned.addr(), public);
    assert_eq!(
        pinned.host(),
        "upstream.example",
        "the name travels with the pin, so TLS still validates against it"
    );

    // A name that answers with IMDS is refused however innocent the name itself looks.
    assert!(matches!(
        resolve_and_pin("rebound.example", 443, true, &resolver, strict()),
        Err(AddressRefusal::CloudMetadataAddress { .. })
    ));

    // Resolution failure and an empty answer are different facts and stay different.
    assert!(matches!(
        resolve_and_pin("broken.example", 443, true, &resolver, strict()),
        Err(AddressRefusal::Unresolvable { .. })
    ));
    assert!(matches!(
        resolve_and_pin("silent.example", 443, true, &resolver, strict()),
        Err(AddressRefusal::NoAddresses(_))
    ));

    // An IP literal is its own answer: judged and pinned without the resolver being asked, which is
    // why a resolver with no entry for it still succeeds.
    let literal = resolve_and_pin("93.184.216.34", 443, true, &resolver, strict()).unwrap();
    assert_eq!(literal.addr(), public);
    // And a literal in a refused range is refused on the same path.
    assert!(matches!(
        resolve_and_pin("169.254.169.254", 443, true, &resolver, strict()),
        Err(AddressRefusal::CloudMetadataAddress { .. })
    ));
    assert!(matches!(
        resolve_and_pin("127.0.0.1", 443, true, &resolver, strict()),
        Err(AddressRefusal::InternalAddress { .. })
    ));

    // A structurally refused name never reaches the resolver at all: `2130706433` has no entry, so
    // an ObfuscatedHost refusal rather than an Unresolvable one is the proof it was not asked.
    assert_eq!(
        resolve_and_pin("2130706433", 80, false, &resolver, permissive()),
        Err(AddressRefusal::ObfuscatedHost("2130706433".to_string()))
    );
}
