//! The overlap predicate is reflexive, symmetric and total over the cross-product of forms.
//!
//! The claims section of the design puts three demands on this predicate, and all three are here.
//! Total means every pair of forms has an answer — the walk below visits all one hundred and
//! sixty-nine ordered pairs and every one of them returns. Reflexive means a claim overlaps
//! itself, which is what makes "two identical claims" a boot refusal rather than a race. Symmetric
//! means the answer does not depend on which claim the boot check happens to visit first.
//!
//! There is also a fixture per form pair, because "it returned" is a weaker claim than "it
//! returned the right answer", and a conservative predicate that answered *true* everywhere would
//! pass the first three properties while refusing every configuration.

use busbar_contract::grammar::{PathSeg, Selector, SelectorFamily, SelectorForm};

/// One selector of each form, for walking the cross-product.
fn one_of_each() -> Vec<Selector> {
    vec![
        Selector::ExactPath("/v1/chat/completions"),
        Selector::PrefixOneLevel("/v1"),
        Selector::Sni("api.example"),
        Selector::ClientCertSubject("CN=fixture"),
        Selector::PathPattern(&[PathSeg::Var, PathSeg::Lit("v1"), PathSeg::Tail]),
        Selector::HeaderExact("x-api-key", "abc"),
        Selector::HeaderPresent("x-api-key"),
        Selector::HeaderPrefix("authorization", "AWS4-HMAC-SHA256"),
        Selector::PathSuffix("/v1/chat/completions"),
        Selector::PathContains(":generateContent"),
        Selector::StreamName("control"),
        Selector::Alpn("h2"),
        Selector::Port(443),
    ]
}

/// Every form has a representative, so the walk really is over the whole cross-product.
#[test]
fn the_walk_covers_every_form() {
    let forms: Vec<SelectorForm> = one_of_each().iter().map(Selector::form).collect();
    assert_eq!(forms.len(), SelectorForm::ALL.len());
    for form in SelectorForm::ALL {
        assert!(forms.contains(form), "no representative for {form}");
    }
}

/// Total: every ordered pair of forms returns an answer.
#[test]
fn overlaps_is_total_over_the_cross_product() {
    let selectors = one_of_each();
    let mut pairs = 0usize;
    for a in &selectors {
        for b in &selectors {
            // Calling it at all is the assertion: a predicate with a hole would not return here.
            let _ = a.overlaps(b);
            pairs += 1;
        }
    }
    assert_eq!(pairs, SelectorForm::ALL.len() * SelectorForm::ALL.len());
}

/// Reflexive: a claim overlaps itself, so two identical claims are refused at boot.
#[test]
fn overlaps_is_reflexive() {
    for s in one_of_each() {
        assert!(s.overlaps(&s), "{s:?} does not overlap itself");
    }
}

/// Symmetric: the answer does not depend on visit order.
#[test]
fn overlaps_is_symmetric() {
    let selectors = one_of_each();
    for a in &selectors {
        for b in &selectors {
            assert_eq!(
                a.overlaps(b),
                b.overlaps(a),
                "asymmetric answer for {a:?} against {b:?}"
            );
        }
    }
}

/// Selectors that read different parts of a request overlap, because both can be true at once.
#[test]
fn different_families_always_overlap() {
    let selectors = one_of_each();
    for a in &selectors {
        for b in &selectors {
            if a.form().family() != b.form().family() {
                assert!(
                    a.overlaps(b),
                    "{a:?} and {b:?} read different parts of one request and must overlap"
                );
            }
        }
    }
}

/// Fixture per pair within the path family.
#[test]
fn the_path_family_is_decided_rather_than_assumed() {
    // Two exact paths.
    assert!(Selector::ExactPath("/a").overlaps(&Selector::ExactPath("/a")));
    assert!(!Selector::ExactPath("/a").overlaps(&Selector::ExactPath("/b")));

    // An exact path under a one-level prefix, and one too deep for it.
    assert!(Selector::PrefixOneLevel("/v1").overlaps(&Selector::ExactPath("/v1/models")));
    assert!(!Selector::PrefixOneLevel("/v1").overlaps(&Selector::ExactPath("/v1/models/x")));
    assert!(!Selector::PrefixOneLevel("/v1").overlaps(&Selector::ExactPath("/v2/models")));

    // A pattern against a path it matches and one it does not.
    let pat = Selector::PathPattern(&[PathSeg::Var, PathSeg::Lit("v1"), PathSeg::Tail]);
    assert!(pat.overlaps(&Selector::ExactPath("/openai/v1/chat/completions")));
    assert!(!pat.overlaps(&Selector::ExactPath("/openai/v2/chat/completions")));

    // Two patterns that differ in a literal segment cannot both match.
    let a = Selector::PathPattern(&[
        PathSeg::Lit("model"),
        PathSeg::Var,
        PathSeg::Lit("converse"),
    ]);
    let b = Selector::PathPattern(&[
        PathSeg::Lit("agent"),
        PathSeg::Var,
        PathSeg::Lit("converse"),
    ]);
    assert!(!a.overlaps(&b));

    // A variable segment overlaps a literal in the same position.
    let c = Selector::PathPattern(&[PathSeg::Var, PathSeg::Var, PathSeg::Lit("converse")]);
    assert!(a.overlaps(&c));

    // Suffix and substring against exact paths.
    assert!(Selector::PathSuffix("/converse").overlaps(&Selector::ExactPath("/model/x/converse")));
    assert!(!Selector::PathSuffix("/converse").overlaps(&Selector::ExactPath("/model/x/invoke")));
    assert!(Selector::PathContains(":generateContent")
        .overlaps(&Selector::ExactPath("/v1beta/models/m:generateContent")));
    assert!(!Selector::PathContains(":generateContent")
        .overlaps(&Selector::ExactPath("/v1beta/models/m:streamGenerate")));
}

/// Fixture per pair within the header family.
#[test]
fn the_header_family_is_decided_rather_than_assumed() {
    // Different header names never collide.
    assert!(!Selector::HeaderPresent("x-api-key")
        .overlaps(&Selector::HeaderPresent("anthropic-version")));

    // Same name, present against anything: overlaps.
    assert!(
        Selector::HeaderPresent("x-api-key").overlaps(&Selector::HeaderExact("x-api-key", "abc"))
    );

    // Same name, two exact values.
    assert!(!Selector::HeaderExact("x-api-key", "abc")
        .overlaps(&Selector::HeaderExact("x-api-key", "def")));

    // Same name, prefix against a value that starts with it, and one that does not.
    assert!(
        Selector::HeaderPrefix("authorization", "AWS4-").overlaps(&Selector::HeaderExact(
            "authorization",
            "AWS4-HMAC-SHA256 …"
        ))
    );
    assert!(!Selector::HeaderPrefix("authorization", "AWS4-")
        .overlaps(&Selector::HeaderExact("authorization", "Bearer xyz")));

    // Header names are compared without regard to case, as the wire treats them.
    assert!(
        Selector::HeaderPresent("X-Api-Key").overlaps(&Selector::HeaderExact("x-api-key", "abc"))
    );
}

/// Fixture per pair within the handshake, stream and port families.
#[test]
fn the_remaining_families_are_decided_rather_than_assumed() {
    assert!(Selector::Sni("api.example").overlaps(&Selector::Sni("API.EXAMPLE")));
    assert!(!Selector::Sni("api.example").overlaps(&Selector::Sni("other.example")));
    assert!(!Selector::Alpn("h2").overlaps(&Selector::Alpn("http/1.1")));
    // A name and a protocol are independent facts of one handshake.
    assert!(Selector::Sni("api.example").overlaps(&Selector::Alpn("h2")));
    assert!(!Selector::StreamName("control").overlaps(&Selector::StreamName("media")));
    assert!(!Selector::Port(443).overlaps(&Selector::Port(8443)));
    assert!(Selector::Port(443).overlaps(&Selector::Port(443)));
}

/// A claim on one transport cannot collide with a claim on another.
#[test]
fn claims_on_different_transports_never_collide() {
    use busbar_contract::grammar::Claim;
    let a = Claim {
        transport: "http",
        selector: Selector::ExactPath("/v1/chat/completions"),
        scheme: Some("bearer"),
        scheme_alternatives: &[],
        idempotency: None,
    };
    let b = Claim {
        transport: "stdio",
        ..a
    };
    assert!(a.overlaps(&a));
    assert!(!a.overlaps(&b));
}

/// One table writes both the ladder and the claim list, so the two cannot disagree.
///
/// A claim carries exactly one selector, which is right, and a plane whose protocol detection is a
/// fourteen-rung ladder therefore has two dozen claims. Transcribing them twice by hand -- once as
/// rungs and once as the narrower declaration -- is where a rung gets added to one list and
/// forgotten in the other. Here the two are the same table read twice by the compiler.
#[test]
fn one_ladder_table_writes_both_lists() {
    #[derive(Debug)]
    struct Rung {
        rung: u16,
        dialect: &'static str,
        claim: busbar_contract::grammar::Claim,
    }

    const fn build(selector: Selector) -> busbar_contract::grammar::Claim {
        busbar_contract::grammar::Claim {
            transport: "http",
            selector,
            scheme: Some("inbound"),
            scheme_alternatives: &["bearer"],
            idempotency: None,
        }
    }

    busbar_contract::claims_from_ladder! {
        /// The ladder, tightest first.
        FIXTURE_LADDER,
        /// The same list, one field narrower.
        FIXTURE_CLAIMS,
        Rung,
        build,
        // Rung 1: the tightest evidence there is.
        1 => "alpha", Selector::HeaderPrefix("authorization", "AWS4-HMAC-SHA256"),
        // Rung 2: a vendor header.
        2 => "beta", Selector::HeaderPresent("x-beta-version"),
        2 => "beta", Selector::HeaderPresent("x-beta-key"),
        // Rung 3: the loosest.
        3 => "alpha", Selector::PathSuffix("/v1/chat"),
    }

    assert_eq!(FIXTURE_LADDER.len(), 4);
    assert_eq!(FIXTURE_CLAIMS.len(), FIXTURE_LADDER.len());
    for (claim, entry) in FIXTURE_CLAIMS.iter().zip(FIXTURE_LADDER) {
        assert_eq!(*claim, entry.claim, "the two lists drifted");
    }

    // Order is the table's order, and the rung numbers ascend.
    let rungs: Vec<u16> = FIXTURE_LADDER.iter().map(|r| r.rung).collect();
    assert_eq!(rungs, vec![1, 2, 2, 3]);
    assert_eq!(FIXTURE_LADDER[0].dialect, "alpha");
    assert_eq!(FIXTURE_LADDER[1].dialect, "beta");

    // The builder is the caller's, so scheme and alternatives are declared once, not per row.
    for claim in FIXTURE_CLAIMS {
        assert_eq!(claim.scheme, Some("inbound"));
        assert_eq!(claim.scheme_alternatives, &["bearer"]);
    }
}

/// A claim says "no credential" by declaring no scheme, and that keeps the narrowing check honest.
///
/// The authenticate step may only narrow within a claim's declared alternatives. If the absence of
/// a credential were a scheme key the registry knew, it would sit in that set and a plane could
/// narrow an AUTHENTICATED claim down to it with the check still passing. Carried on the claim, the
/// two cases stay apart: an authenticated claim has a non-empty set to narrow within, and an open
/// claim has an empty one, so there is nothing for anything to narrow to.
#[test]
fn a_claim_with_no_scheme_offers_nothing_to_narrow_to() {
    use busbar_contract::grammar::Claim;
    let authenticated = Claim {
        transport: "http",
        selector: Selector::ExactPath("/v1/chat/completions"),
        scheme: Some("inbound"),
        scheme_alternatives: &["bearer", "api-key"],
        idempotency: None,
    };
    let open = Claim {
        selector: Selector::ExactPath("/.well-known/openid-configuration"),
        scheme: None,
        scheme_alternatives: &[],
        ..authenticated
    };

    assert!(!authenticated.is_anonymous());
    assert!(open.is_anonymous());

    // The check the step runs, written out: narrowing is membership of the declared set.
    let narrows_to = |claim: &Claim, alt: &str| claim.scheme_alternatives.contains(&alt);
    assert!(narrows_to(&authenticated, "bearer"));
    assert!(!narrows_to(&authenticated, "anonymous"));
    // Nothing narrows within an open claim, including the word the planes used to invent.
    assert!(!narrows_to(&open, "bearer"));
    assert!(!narrows_to(&open, "anonymous"));
}

/// The family a form belongs to is fixed, and every form belongs to exactly one.
#[test]
fn every_form_has_one_family() {
    for form in SelectorForm::ALL {
        let family = form.family();
        assert!(matches!(
            family,
            SelectorFamily::Path
                | SelectorFamily::Header
                | SelectorFamily::Handshake
                | SelectorFamily::Stream
                | SelectorFamily::Port
        ));
    }
}
