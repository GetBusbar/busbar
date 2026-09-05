//! One boot cell per route of the previous release's protocol-detection ladder.
//!
//! The claims section of the design pins that ladder at fourteen rungs and requires a boot cell per
//! route. A rung is a claim; a request is a concrete selector of the same family; and the cell
//! asserts two things — that the rung accepts the requests it is meant to accept, and that it
//! rejects the ones belonging to a different rung. Both halves matter: a predicate that accepted
//! everything would keep every rung green while making the ladder meaningless.

use busbar_contract::grammar::{Claim, PathSeg, Selector};

/// One rung: what it claims, one request it must take, and one it must not.
struct Rung {
    what: &'static str,
    selector: Selector,
    takes: Selector,
    leaves: Selector,
}

/// The ladder, rung by rung, in the order the previous release walks it.
fn ladder() -> Vec<Rung> {
    vec![
        Rung {
            what: "a named upstream's own path space",
            selector: Selector::PathPattern(&[PathSeg::Var, PathSeg::Lit("v1"), PathSeg::Tail]),
            takes: Selector::ExactPath("/openai/v1/chat/completions"),
            leaves: Selector::ExactPath("/openai/v2/chat/completions"),
        },
        Rung {
            what: "an upstream and a named model",
            selector: Selector::PathPattern(&[
                PathSeg::Var,
                PathSeg::Var,
                PathSeg::Lit("v1"),
                PathSeg::Tail,
            ]),
            takes: Selector::ExactPath("/vendor/some-model/v1/messages"),
            leaves: Selector::ExactPath("/vendor/v1/messages"),
        },
        Rung {
            what: "a model-scoped converse route",
            selector: Selector::PathPattern(&[
                PathSeg::Lit("model"),
                PathSeg::Var,
                PathSeg::Lit("converse"),
            ]),
            takes: Selector::ExactPath("/model/some-model/converse"),
            leaves: Selector::ExactPath("/model/some-model/invoke"),
        },
        Rung {
            what: "a versioned model collection with a trailing remainder",
            selector: Selector::PathPattern(&[
                PathSeg::Lit("v1beta"),
                PathSeg::Lit("models"),
                PathSeg::Tail,
            ]),
            takes: Selector::ExactPath("/v1beta/models/some-model:generateContent"),
            leaves: Selector::ExactPath("/v1alpha/models/some-model:generateContent"),
        },
        Rung {
            what: "the version header of one dialect",
            selector: Selector::HeaderPresent("anthropic-version"),
            takes: Selector::HeaderExact("anthropic-version", "2023-06-01"),
            leaves: Selector::HeaderExact("x-goog-api-key", "abc"),
        },
        Rung {
            what: "a key header of one dialect",
            selector: Selector::HeaderPresent("x-api-key"),
            takes: Selector::HeaderExact("x-api-key", "abc"),
            leaves: Selector::HeaderExact("authorization", "Bearer abc"),
        },
        Rung {
            what: "a key header of another dialect",
            selector: Selector::HeaderPresent("x-goog-api-key"),
            takes: Selector::HeaderExact("x-goog-api-key", "abc"),
            leaves: Selector::HeaderExact("x-api-key", "abc"),
        },
        Rung {
            what: "a signed-request authorization prefix",
            selector: Selector::HeaderPrefix("authorization", "AWS4-HMAC-SHA256"),
            takes: Selector::HeaderExact("authorization", "AWS4-HMAC-SHA256 Credential=…"),
            leaves: Selector::HeaderExact("authorization", "Bearer abc"),
        },
        Rung {
            what: "the completions suffix",
            selector: Selector::PathSuffix("/v1/chat/completions"),
            takes: Selector::ExactPath("/upstream/v1/chat/completions"),
            leaves: Selector::ExactPath("/upstream/v1/responses"),
        },
        Rung {
            what: "the generate-content marker anywhere in the path",
            selector: Selector::PathContains(":generateContent"),
            takes: Selector::ExactPath("/v1beta/models/m:generateContent"),
            leaves: Selector::ExactPath("/v1beta/models/m:countTokens"),
        },
        Rung {
            what: "the converse marker anywhere in the path",
            selector: Selector::PathContains("/converse"),
            takes: Selector::ExactPath("/model/m/converse-stream"),
            leaves: Selector::ExactPath("/model/m/invoke"),
        },
        Rung {
            what: "a fixed administrative path",
            selector: Selector::ExactPath("/healthz"),
            takes: Selector::ExactPath("/healthz"),
            leaves: Selector::ExactPath("/stats"),
        },
        Rung {
            what: "a one-level collection",
            selector: Selector::PrefixOneLevel("/v1"),
            takes: Selector::ExactPath("/v1/models"),
            leaves: Selector::ExactPath("/v1/models/some-model"),
        },
        Rung {
            what: "a named stream on a multiplexed transport",
            selector: Selector::StreamName("control"),
            takes: Selector::StreamName("control"),
            leaves: Selector::StreamName("media"),
        },
    ]
}

/// The ladder has fourteen rungs, and each one takes what it claims and leaves what it does not.
#[test]
fn every_rung_of_the_ladder_routes() {
    let ladder = ladder();
    assert_eq!(ladder.len(), 14, "the ladder is pinned at fourteen rungs");
    for rung in &ladder {
        assert!(
            rung.selector.overlaps(&rung.takes),
            "the rung for {} does not accept the request it is for",
            rung.what
        );
        assert!(
            !rung.selector.overlaps(&rung.leaves),
            "the rung for {} accepts a request that is not its own",
            rung.what
        );
    }
}

/// Every rung is a well-formed claim, and every claim overlaps itself.
#[test]
fn every_rung_is_a_claim_that_a_boot_would_check() {
    for rung in ladder() {
        let claim = Claim {
            transport: "http",
            selector: rung.selector,
            scheme: Some("bearer"),
            scheme_alternatives: &[],
            idempotency: None,
        };
        assert!(
            claim.overlaps(&claim),
            "the rung for {} does not overlap itself",
            rung.what
        );
    }
}

/// Two rungs of the path family that share a prefix are still told apart.
///
/// This is the case the design's most-specific-wins precedence exists for: the rungs *do* overlap,
/// so a boot that only asked "do these overlap" would refuse a configuration the previous release
/// serves. Overlap is the question for two claims of *different* planes; within one plane the
/// ordered pattern set decides, literal before variable, longer before shorter.
#[test]
fn overlapping_rungs_within_one_plane_are_an_ordering_question_not_a_refusal() {
    let general = Selector::PathPattern(&[PathSeg::Var, PathSeg::Lit("v1"), PathSeg::Tail]);
    let specific =
        Selector::PathPattern(&[PathSeg::Lit("openai"), PathSeg::Lit("v1"), PathSeg::Tail]);
    assert!(general.overlaps(&specific));

    let request = Selector::ExactPath("/openai/v1/chat/completions");
    assert!(general.overlaps(&request));
    assert!(specific.overlaps(&request));

    // Most specific wins: the literal-headed pattern is the narrower of the two, and it is the
    // one that does not accept a request the other does.
    let other = Selector::ExactPath("/anthropic/v1/messages");
    assert!(general.overlaps(&other));
    assert!(!specific.overlaps(&other));
}

/// A registration interns each configured key exactly once, and reuses it after that.
///
/// This is the leak-once rule as a value rather than as a sentence. A plane's declarations are
/// associated constants, so a configured lane or host has to become a static name somewhere; here
/// is where, and here only. The idempotence is the whole point: a key interned per unit would be a
/// leak that grows with traffic, which is precisely what one transport was doing per dial.
#[test]
fn a_registration_interns_a_configured_key_exactly_once() {
    let mut reg = busbar_contract::ids::Registration::new();
    assert!(reg.is_empty());

    let lane = String::from("openai-frontier");
    let first = reg.key(&lane);
    let second = reg.key(&lane);

    assert_eq!(first, "openai-frontier");
    assert_eq!(first, second);
    // The SAME name, not an equal one: interning twice leaks once.
    assert!(std::ptr::eq(first, second));
    assert_eq!(reg.len(), 1);

    // A different key is a second entry, and the fixed term is readable from the count.
    let other = reg.key("anthropic-frontier");
    assert_ne!(first, other);
    assert_eq!(reg.len(), 2);
}

/// Registration refuses a transport that publishes a reserved fact key it did not declare.
///
/// The six reserved keys are the structural values the arrival grammar resolves against, and a
/// plane cannot see a connection, so the request target reaches it as one of them. A transport that
/// writes one without declaring it is a value a plane reads and no boot check knows about.
#[test]
fn a_transport_must_declare_every_reserved_key_it_publishes() {
    use busbar_contract::transport::facts;

    assert_eq!(facts::RESERVED.len(), 6);
    for key in facts::RESERVED {
        assert!(facts::is_reserved(key));
    }
    // A transport's own facts are open vocabulary, and none of this applies to them.
    assert!(!facts::is_reserved("tls_session_ticket"));

    // Declared and published agree: nothing to report.
    let declared = [facts::PATH, facts::METHOD, facts::PEER];
    assert_eq!(facts::undeclared(&declared, &[facts::PATH]), None);
    // A transport's own key is published freely, declared or not.
    assert_eq!(facts::undeclared(&declared, &["retries"]), None);
    // A reserved key published without a declaration is named, and it is the one at fault.
    assert_eq!(
        facts::undeclared(&declared, &["retries", facts::SNI, facts::PATH]),
        Some(facts::SNI)
    );
    // A transport declaring nothing may still publish its own; it may not publish a reserved key.
    assert_eq!(facts::undeclared(&[], &[facts::PEER]), Some(facts::PEER));
}
