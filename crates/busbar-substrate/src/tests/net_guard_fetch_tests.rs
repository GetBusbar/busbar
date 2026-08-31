// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE GUARDED FETCH: resolve-then-pin, the address judgement, the redirect policy and the
//! caps, tested where they now live rather than once per plane.
//!
//! The rebinding cases are the reason this file exists. They are driven through a SCRIPTED RESOLVER
//! that answers differently on the second lookup, because that is the only way to state the claim
//! the guard actually makes: the name is resolved EXACTLY ONCE and the socket goes to the address
//! that was judged. A guard tested against a resolver that answers the same thing twice cannot tell
//! a resolve-then-pin from a check-then-re-resolve — both pass — which is precisely the mistake
//! that looks right in review.

use super::{
    default_port, judge_address, judge_addresses, judge_host_name, judge_scheme, pin_answer,
    refuse_hop_overflow, refuse_oversized_body, refuse_redirect, resolve_and_pin, split_url,
    GuardPolicy, GuardRefusal, Resolver,
};
use std::cell::RefCell;
use std::net::IpAddr;

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
        GuardRefusal::CloudMetadataAddress {
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
        GuardRefusal::InternalAddress {
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
                matches!(err, GuardRefusal::CloudMetadataAddress { .. }),
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
                Err(GuardRefusal::MetadataName(name.to_string())),
                "`{name}` is a cloud-metadata name and `allow_private` may not reach it"
            );
        }
    }
    for name in ["localhost", "localhost.", "api.localhost"] {
        assert!(
            matches!(
                judge_host_name(name, strict()),
                Err(GuardRefusal::LoopbackName(_))
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
                Err(GuardRefusal::ObfuscatedHost(host.to_string())),
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
        Err(GuardRefusal::InternalAddress { .. })
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
        Err(GuardRefusal::Unresolvable {
            host: "a.example".to_string(),
            reason: "NXDOMAIN".to_string(),
        })
    );
    let empty = ScriptedResolver::new(vec![Ok(vec![])]);
    assert_eq!(
        resolve_and_pin("a.example", 443, true, &empty, strict()),
        Err(GuardRefusal::NoAddresses("a.example".to_string())),
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
            matches!(split_url(url), Err(GuardRefusal::Scheme { .. })),
            "`{url}` must be refused on its scheme"
        );
    }
    assert!(split_url("https://ok.example/mcp").is_ok());
}

#[test]
fn userinfo_is_refused_rather_than_stripped() {
    assert!(matches!(
        split_url("https://evil.test@good.example/mcp"),
        Err(GuardRefusal::NoHost(_))
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
        Err(GuardRefusal::Plaintext { .. })
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
            Err(GuardRefusal::Redirect {
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
        Err(GuardRefusal::Redirect {
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
        Err(GuardRefusal::TooManyRedirects {
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
        Err(GuardRefusal::BodyTooLarge {
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
        Err(GuardRefusal::NoAddresses("a.example".to_string()))
    );
}
