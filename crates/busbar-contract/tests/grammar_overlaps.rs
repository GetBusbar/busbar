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

    // A sibling whose name merely STARTS with the prefix is not under it: one level down begins
    // at a segment boundary, not at a byte offset.
    assert!(!Selector::PrefixOneLevel("/v1").overlaps(&Selector::ExactPath("/v1models")));
    assert!(!Selector::PrefixOneLevel("/api").overlaps(&Selector::ExactPath("/apikeys")));
    assert!(!Selector::PrefixOneLevel("/v1").overlaps(&Selector::ExactPath("/v1")));

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

/// A one-level prefix read as the pattern it is: the prefix's literals, then one more segment.
///
/// The two forms used to fall through to the catch-all and answer "they might", which made a prefix
/// on one root and a pattern on another read as a contest. They are comparable segment by segment
/// exactly as two patterns are, because a one-level prefix IS a pattern.
#[test]
fn a_one_level_prefix_and_a_pattern_are_compared_segment_by_segment() {
    let prefix = Selector::PrefixOneLevel("/a2a");

    // Same root, one level down: the prefix's own shape.
    assert!(prefix.overlaps(&Selector::PathPattern(&[PathSeg::Lit("a2a"), PathSeg::Var])));
    // A different root cannot be reached from this prefix.
    assert!(!prefix.overlaps(&Selector::PathPattern(&[PathSeg::Lit("mcp"), PathSeg::Var])));
    // Right root, wrong depth: a prefix takes exactly one segment, never two.
    assert!(!prefix.overlaps(&Selector::PathPattern(&[
        PathSeg::Lit("a2a"),
        PathSeg::Var,
        PathSeg::Var,
    ])));
    // A tail swallows whatever is left, so it reaches one level down as well.
    assert!(prefix.overlaps(&Selector::PathPattern(&[
        PathSeg::Lit("a2a"),
        PathSeg::Tail
    ])));
}

/// Two suffixes collide only when one of them ends the other.
#[test]
fn two_suffixes_collide_only_when_one_ends_the_other() {
    assert!(Selector::PathSuffix("/v1/chat/completions")
        .overlaps(&Selector::PathSuffix("/completions")));
    assert!(Selector::PathSuffix("/completions")
        .overlaps(&Selector::PathSuffix("/v1/chat/completions")));
    assert!(!Selector::PathSuffix("/v1/embeddings").overlaps(&Selector::PathSuffix("/v1/speech")));
}

/// A suffix against a pattern, decided rather than assumed.
///
/// A suffix's slashes are the path's own slashes, so a suffix pins the pattern's LAST segments: the
/// pieces between its slashes are whole segments, counted from the end. A pattern whose segment in
/// one of those positions is a literal that does not match cannot produce a path ending that way,
/// however the rest of it is filled in.
#[test]
fn a_suffix_against_a_pattern_pins_the_patterns_last_segments() {
    let a2a_tasks =
        Selector::PathPattern(&[PathSeg::Lit("a2a"), PathSeg::Lit("tasks"), PathSeg::Var]);
    // `/a2a/tasks/<id>` has three segments and the last two are `tasks` and one variable: no path
    // it matches can end `/v1/embeddings`, because that would need the second-from-last segment to
    // be `v1`.
    assert!(!Selector::PathSuffix("/v1/embeddings").overlaps(&a2a_tasks));
    assert!(!a2a_tasks.overlaps(&Selector::PathSuffix("/v1/audio/speech")));
    // The variable IS the last segment, so a suffix inside one segment still reaches it.
    assert!(Selector::PathSuffix("-draft").overlaps(&a2a_tasks));
    // And the pinned literals, when they do line up.
    assert!(Selector::PathSuffix("/tasks/live").overlaps(&a2a_tasks));

    // A tail is open-ended: whatever the suffix asks for, the tail can supply.
    let admin = Selector::PathPattern(&[
        PathSeg::Lit("api"),
        PathSeg::Lit("v1"),
        PathSeg::Lit("admin"),
        PathSeg::Tail,
    ]);
    assert!(Selector::PathSuffix("/v1/audio/speech").overlaps(&admin));

    // A pattern shorter than the suffix's own segment count cannot end with it.
    assert!(!Selector::PathSuffix("/v1/audio/speech")
        .overlaps(&Selector::PathPattern(&[PathSeg::Var, PathSeg::Var])));
    // And the whole-path alignment: the suffix may start at the leading slash itself.
    assert!(
        Selector::PathSuffix("/v1/audio/speech").overlaps(&Selector::PathPattern(&[
            PathSeg::Lit("v1"),
            PathSeg::Lit("audio"),
            PathSeg::Var,
        ]))
    );
}

/// A substring against a pattern, decided rather than assumed.
///
/// A substring carrying a slash asks for consecutive whole segments, so it can be placed against a
/// pattern the same way a suffix can — anywhere rather than at the end. A substring with no slash
/// at all lands inside one segment, and any variable segment can be that one.
#[test]
fn a_substring_against_a_pattern_asks_for_consecutive_segments() {
    let a2a_agents =
        Selector::PathPattern(&[PathSeg::Lit("a2a"), PathSeg::Lit("agents"), PathSeg::Var]);

    // `/v1/audio/` needs the whole segments `v1` and `audio` next to each other, with something
    // after them. Nothing this pattern matches has that shape.
    assert!(!Selector::PathContains("/v1/audio/").overlaps(&a2a_agents));
    assert!(!Selector::PathContains("/v1/messages").overlaps(&a2a_agents));
    // With no slash it lives inside a segment, and the variable is one.
    assert!(Selector::PathContains(":predict").overlaps(&a2a_agents));
    // One leading slash asks only that a segment START with the rest, and the variable can.
    assert!(Selector::PathContains("/converse").overlaps(&a2a_agents));
    // A literal segment that starts with it works too.
    assert!(Selector::PathContains("/agen").overlaps(&a2a_agents));
    // And one that does not, does not.
    assert!(!Selector::PathContains("/a2a/agents/x/y").overlaps(&a2a_agents));

    // A tail answers anything.
    assert!(
        Selector::PathContains("/v1/audio/").overlaps(&Selector::PathPattern(&[
            PathSeg::Lit("api"),
            PathSeg::Tail
        ]))
    );
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

/// The property the whole tightening rests on: DISJOINT means no arrival matches both.
///
/// The overlap rule is allowed to be conservative — to answer "they might" where it cannot prove
/// otherwise — and every tightening above narrows that. What must never happen is the other
/// direction: a pair reported disjoint that one arriving request satisfies, because that is a route
/// decided by declaration accident with the boot check saying nothing about it. So the corpus below
/// is walked against every pair of path-family selectors, and a disjoint answer is checked against
/// every path in it.
///
/// The corpus is generated rather than listed: every path the fixtures' own literals can spell, to
/// the depth the fixtures reach, plus the shapes the segment reasoning is delicate about — a
/// trailing slash and a doubled one.
#[test]
fn a_disjoint_answer_is_never_contradicted_by_an_arrival() {
    let selectors = path_fixtures();
    let corpus = arrival_corpus();
    for left in &selectors {
        for right in &selectors {
            if left.overlaps(right) {
                continue;
            }
            for path in &corpus {
                assert!(
                    !(matches_path(left, path) && matches_path(right, path)),
                    "{left:?} and {right:?} were called disjoint, and `{path}` matches both"
                );
            }
        }
    }
}

/// Every path-family form, in the spellings the declared claim set actually uses.
fn path_fixtures() -> Vec<Selector> {
    const A2A_TASKS: &[PathSeg] = &[PathSeg::Lit("a2a"), PathSeg::Lit("tasks"), PathSeg::Var];
    const A2A_PUSH: &[PathSeg] = &[
        PathSeg::Lit("a2a"),
        PathSeg::Lit("tasks"),
        PathSeg::Var,
        PathSeg::Lit("pushNotificationConfigs"),
    ];
    const A2A_AGENTS: &[PathSeg] = &[PathSeg::Lit("a2a"), PathSeg::Lit("agents"), PathSeg::Var];
    const ADMIN: &[PathSeg] = &[
        PathSeg::Lit("api"),
        PathSeg::Lit("v1"),
        PathSeg::Lit("admin"),
        PathSeg::Tail,
    ];
    const V1_MODELS: &[PathSeg] = &[PathSeg::Lit("v1"), PathSeg::Lit("models"), PathSeg::Tail];
    const MODEL_INVOKE: &[PathSeg] = &[PathSeg::Lit("model"), PathSeg::Var, PathSeg::Lit("invoke")];
    vec![
        Selector::ExactPath("/mcp"),
        Selector::ExactPath("/a2a/tasks"),
        Selector::ExactPath("/v1/audio/speech"),
        Selector::PrefixOneLevel("/a2a"),
        Selector::PrefixOneLevel("/v1"),
        Selector::PathPattern(A2A_TASKS),
        Selector::PathPattern(A2A_PUSH),
        Selector::PathPattern(A2A_AGENTS),
        Selector::PathPattern(ADMIN),
        Selector::PathPattern(V1_MODELS),
        Selector::PathPattern(MODEL_INVOKE),
        Selector::PathSuffix("/v1/audio/speech"),
        Selector::PathSuffix("/v1/audio/transcriptions"),
        Selector::PathSuffix("/v1/chat/completions"),
        Selector::PathSuffix("/v1/embeddings"),
        Selector::PathSuffix("/v2/chat"),
        Selector::PathSuffix("-draft"),
        Selector::PathContains("/v1/audio/"),
        Selector::PathContains("/v1/messages"),
        Selector::PathContains("/converse"),
        Selector::PathContains(":predict"),
        Selector::PathContains(":generateContent"),
    ]
}

/// Every path the fixtures' own vocabulary can spell, to the depth they reach.
fn arrival_corpus() -> Vec<String> {
    let vocabulary = [
        "a2a",
        "mcp",
        "tasks",
        "agents",
        "pushNotificationConfigs",
        "api",
        "v1",
        "v2",
        "admin",
        "models",
        "model",
        "invoke",
        "audio",
        "speech",
        "transcriptions",
        "chat",
        "completions",
        "embeddings",
        "messages",
        "converse",
        "m:predict",
        "m:generateContent",
        "x-draft",
        "id",
    ];
    let mut corpus: Vec<String> = vec![String::from("/")];
    let mut level: Vec<String> = vec![String::new()];
    // Four segments deep is one past the deepest fixture, which is what makes "the pattern runs out
    // before the suffix does" a case the corpus actually contains.
    for depth in 0..4 {
        let mut next = Vec::new();
        for stem in &level {
            for segment in vocabulary {
                next.push(format!("{stem}/{segment}"));
            }
        }
        // The two shapes the segment reasoning is delicate about, at the deepest level only: the
        // cross-product is already large, and the awkward shapes are about slashes, not depth.
        if depth == 3 {
            let awkward: Vec<String> = next
                .iter()
                .flat_map(|p| [format!("{p}/"), p.replacen('/', "//", 1)])
                .collect();
            corpus.extend(awkward);
        }
        corpus.extend(next.iter().cloned());
        level = next;
    }
    corpus
}

/// Whether one path-family selector matches a concrete path, as the transports evaluate it.
///
/// The pattern arm is the contract's own rule, read through the exact-path pair of the overlap
/// predicate rather than spelled a second time here: an evaluator that disagreed with the boot's
/// own reading would be testing something other than the boot.
fn matches_path(selector: &Selector, path: &str) -> bool {
    match selector {
        Selector::ExactPath(p) => *p == path,
        Selector::PrefixOneLevel(prefix) => busbar_contract::grammar::one_level_under(prefix, path),
        Selector::PathSuffix(s) => path.ends_with(s),
        Selector::PathContains(s) => path.contains(s),
        Selector::PathPattern(_) => selector.overlaps(&Selector::ExactPath(leak(path))),
        _ => false,
    }
}

/// A corpus path as the `'static` string the exact-path form takes.
///
/// The corpus is built once per test process and every path in it is compared against every
/// selector, so leaking it is the lifetime the fixture already has.
fn leak(path: &str) -> &'static str {
    Box::leak(path.to_owned().into_boxed_str())
}
