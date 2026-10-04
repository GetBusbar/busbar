// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The egress unit's network guard over a sealed destination, moved from
//! `busbar-kernel-egress`'s `trust/tests/net_tests.rs`: these tests seal with a minted trust token.

use busbar_kernel_egress::trust::net::*;
use std::cell::RefCell;
use std::net::IpAddr;

const PUBLIC: &str = "93.184.216.34";

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

// =================================================================================================
//   THE CHECK OVER A SEALED DESTINATION: the precedence rule, the denylist, the base+path re-check.
// =================================================================================================

/// The seal these tests build sealed values with: the capability crate's own trust token.
///
/// A test that declared a private type and implemented the contract's sealing trait on it was
/// forging kernel evidence to test something else, and it read as if that were the ordinary way in.
/// The token is the ordinary way in — the loop lends one to the trust unit for the length of a
/// verify call — so a test that seals with one is testing the seam the deployment uses.
fn trust_token() -> busbar_contract::caps::Grant<busbar_contract::caps::Dial> {
    busbar_contract::caps::Grant::<busbar_contract::caps::Dial>::mint(
        &busbar_contract::caps::KernelSeal::acquire_for_kernel(),
    )
}

/// A sealed destination naming `authority`, as a plane proposed it and the trust unit sealed it.
fn dest(authority: &'static str) -> busbar_contract::VerifiedDestination {
    busbar_contract::VerifiedDestination::seal(
        &trust_token(),
        busbar_contract::DestinationFacts::Upstream {
            transport: "https",
            address: busbar_contract::transport::dest::UpstreamAddress::socket(authority),
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
///
/// THE OVERRIDES ARE 1.5.5'S, AND THEY REACH THE ADDRESS TOO. 1.5.5 (`crates/busbar/src/config/
/// mod.rs:445`) stated the nuclear override as:
///
/// > Nuclear override (`security.allow_all_metadata`): when true the metadata SSRF guard is fully
/// > DISABLED — every cloud-metadata endpoint is reachable by every provider. Logs a startup WARN.
///
/// So IMDS is reachable only with an explicit operator opt-in, and with one it is reachable: no
/// override, refused; `allow_all`, admitted; a carve-out naming `169.254.169.254`, admitted. The
/// address arm judges through the same list decision ([`judge_addresses_under`]) the denylist arm
/// does, so the two cannot disagree. IPv6 link-local had no knob in 1.5.5 and gets none here: it is
/// not on the metadata list, so `allow_all` leaves its internal-address refusal exactly as it was.
#[test]
fn the_denylist_precedence_is_allow_all_then_allow_override_then_block() {
    let base = "https://169.254.169.254/latest/meta-data";
    let none = Denylist::default();

    // No override: refused.
    assert_eq!(
        check_destination(&dest(base), &[], &NeverAsked, strict(), &none),
        Err(NetworkRefusal::MetadataDenied(
            "169.254.169.254".to_string()
        ))
    );

    // An explicit carve-out for the address, and the nuclear override: admitted.
    for opted_in in [
        Denylist::new(&[], &["169.254.169.254".to_string()], false),
        Denylist::new(&[], &[], true),
    ] {
        assert!(
            matches!(
                check_destination(&dest(base), &[], &NeverAsked, strict(), &opted_in),
                Ok(Some(_))
            ),
            "an explicit operator opt-in reaches IMDS, as in 1.5.5"
        );
    }

    // IPv6 link-local is not on the metadata list, so the nuclear override does not touch it: the
    // internal-address refusal is the same with the override as without.
    let link_local = "https://[fe80::1]/";
    for lists in [Denylist::default(), Denylist::new(&[], &[], true)] {
        assert!(
            matches!(
                check_destination(&dest(link_local), &[], &NeverAsked, strict(), &lists),
                Err(NetworkRefusal::Guard(
                    AddressRefusal::InternalAddress { .. }
                ))
            ),
            "allow_all leaves link-local as it was"
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
            address: busbar_contract::transport::dest::UpstreamAddress::Program {
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
            address: busbar_contract::transport::dest::UpstreamAddress::socket(
                "https://169.254.169.254/latest/meta-data",
            ),
            lane: busbar_contract::LaneId::new("test"),
        },
        busbar_contract::DestinationFacts::Upstream {
            transport: "https",
            address: busbar_contract::transport::dest::UpstreamAddress::socket(
                "https://private.example/",
            ),
            lane: busbar_contract::LaneId::new("test"),
        },
        busbar_contract::DestinationFacts::Upstream {
            transport: "stdio",
            address: busbar_contract::transport::dest::UpstreamAddress::Program {
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
