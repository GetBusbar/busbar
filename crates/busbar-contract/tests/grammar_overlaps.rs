//! The overlap predicate is reflexive, symmetric and total over the cross-product of forms.

use busbar_contract::grammar::{PathSeg, Selector, SelectorFamily, SelectorForm};

/// Every selector form, for walking the cross-product.
const ALL_FORMS: &[SelectorForm] = &[
    SelectorForm::ExactPath,
    SelectorForm::PrefixOneLevel,
    SelectorForm::Sni,
    SelectorForm::ClientCertSubject,
    SelectorForm::PathPattern,
    SelectorForm::HeaderExact,
    SelectorForm::HeaderPresent,
    SelectorForm::HeaderPrefix,
    SelectorForm::PathSuffix,
    SelectorForm::PathContains,
    SelectorForm::StreamName,
    SelectorForm::Alpn,
    SelectorForm::Port,
];

/// The table's own totality check: an exhaustive match, so a form added to the enum stops this
fn is_listed(form: SelectorForm) -> bool {
    let listed = match form {
        SelectorForm::ExactPath
        | SelectorForm::PrefixOneLevel
        | SelectorForm::Sni
        | SelectorForm::ClientCertSubject
        | SelectorForm::PathPattern
        | SelectorForm::HeaderExact
        | SelectorForm::HeaderPresent
        | SelectorForm::HeaderPrefix
        | SelectorForm::PathSuffix
        | SelectorForm::PathContains
        | SelectorForm::StreamName
        | SelectorForm::Alpn
        | SelectorForm::Port => true,
    };
    listed && ALL_FORMS.contains(&form)
}

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
    assert_eq!(forms.len(), ALL_FORMS.len());
    for form in ALL_FORMS {
        assert!(is_listed(*form), "{form} is missing from the table");
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
            let _ = a.overlaps(b);
            pairs += 1;
        }
    }
    assert_eq!(pairs, ALL_FORMS.len() * ALL_FORMS.len());
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
    assert!(Selector::ExactPath("/a").overlaps(&Selector::ExactPath("/a")));
    assert!(!Selector::ExactPath("/a").overlaps(&Selector::ExactPath("/b")));

    assert!(Selector::PrefixOneLevel("/v1").overlaps(&Selector::ExactPath("/v1/models")));
    assert!(!Selector::PrefixOneLevel("/v1").overlaps(&Selector::ExactPath("/v1/models/x")));
    assert!(!Selector::PrefixOneLevel("/v1").overlaps(&Selector::ExactPath("/v2/models")));

    assert!(!Selector::PrefixOneLevel("/v1").overlaps(&Selector::ExactPath("/v1models")));
    assert!(!Selector::PrefixOneLevel("/api").overlaps(&Selector::ExactPath("/apikeys")));
    assert!(!Selector::PrefixOneLevel("/v1").overlaps(&Selector::ExactPath("/v1")));

    let pat = Selector::PathPattern(&[PathSeg::Var, PathSeg::Lit("v1"), PathSeg::Tail]);
    assert!(pat.overlaps(&Selector::ExactPath("/openai/v1/chat/completions")));
    assert!(!pat.overlaps(&Selector::ExactPath("/openai/v2/chat/completions")));

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

    let c = Selector::PathPattern(&[PathSeg::Var, PathSeg::Var, PathSeg::Lit("converse")]);
    assert!(a.overlaps(&c));

    assert!(Selector::PathSuffix("/converse").overlaps(&Selector::ExactPath("/model/x/converse")));
    assert!(!Selector::PathSuffix("/converse").overlaps(&Selector::ExactPath("/model/x/invoke")));
    assert!(Selector::PathContains(":generateContent")
        .overlaps(&Selector::ExactPath("/v1beta/models/m:generateContent")));
    assert!(!Selector::PathContains(":generateContent")
        .overlaps(&Selector::ExactPath("/v1beta/models/m:streamGenerate")));
}

/// A one-level prefix read as the pattern it is: the prefix's literals, then one more segment.
#[test]
fn a_one_level_prefix_and_a_pattern_are_compared_segment_by_segment() {
    let prefix = Selector::PrefixOneLevel("/mesh");

    assert!(prefix.overlaps(&Selector::PathPattern(&[
        PathSeg::Lit("mesh"),
        PathSeg::Var
    ])));

    assert!(!prefix.overlaps(&Selector::PathPattern(&[
        PathSeg::Lit("grid"),
        PathSeg::Var
    ])));

    assert!(!prefix.overlaps(&Selector::PathPattern(&[
        PathSeg::Lit("mesh"),
        PathSeg::Var,
        PathSeg::Var,
    ])));

    assert!(prefix.overlaps(&Selector::PathPattern(&[
        PathSeg::Lit("mesh"),
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
#[test]
fn a_suffix_against_a_pattern_pins_the_patterns_last_segments() {
    let mesh_tasks =
        Selector::PathPattern(&[PathSeg::Lit("mesh"), PathSeg::Lit("tasks"), PathSeg::Var]);

    assert!(!Selector::PathSuffix("/v1/embeddings").overlaps(&mesh_tasks));
    assert!(!mesh_tasks.overlaps(&Selector::PathSuffix("/v1/audio/speech")));

    assert!(Selector::PathSuffix("-draft").overlaps(&mesh_tasks));

    assert!(Selector::PathSuffix("/tasks/live").overlaps(&mesh_tasks));

    let admin = Selector::PathPattern(&[
        PathSeg::Lit("api"),
        PathSeg::Lit("v1"),
        PathSeg::Lit("admin"),
        PathSeg::Tail,
    ]);
    assert!(Selector::PathSuffix("/v1/audio/speech").overlaps(&admin));

    assert!(!Selector::PathSuffix("/v1/audio/speech")
        .overlaps(&Selector::PathPattern(&[PathSeg::Var, PathSeg::Var])));

    assert!(
        Selector::PathSuffix("/v1/audio/speech").overlaps(&Selector::PathPattern(&[
            PathSeg::Lit("v1"),
            PathSeg::Lit("audio"),
            PathSeg::Var,
        ]))
    );
}

/// A substring against a pattern, decided rather than assumed.
#[test]
fn a_substring_against_a_pattern_asks_for_consecutive_segments() {
    let mesh_agents =
        Selector::PathPattern(&[PathSeg::Lit("mesh"), PathSeg::Lit("agents"), PathSeg::Var]);

    assert!(!Selector::PathContains("/v1/audio/").overlaps(&mesh_agents));
    assert!(!Selector::PathContains("/v1/messages").overlaps(&mesh_agents));

    assert!(Selector::PathContains(":predict").overlaps(&mesh_agents));

    assert!(Selector::PathContains("/converse").overlaps(&mesh_agents));

    assert!(Selector::PathContains("/agen").overlaps(&mesh_agents));

    assert!(!Selector::PathContains("/mesh/agents/x/y").overlaps(&mesh_agents));

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
    assert!(!Selector::HeaderPresent("x-api-key")
        .overlaps(&Selector::HeaderPresent("anthropic-version")));

    assert!(
        Selector::HeaderPresent("x-api-key").overlaps(&Selector::HeaderExact("x-api-key", "abc"))
    );

    assert!(!Selector::HeaderExact("x-api-key", "abc")
        .overlaps(&Selector::HeaderExact("x-api-key", "def")));

    assert!(
        Selector::HeaderPrefix("authorization", "AWS4-").overlaps(&Selector::HeaderExact(
            "authorization",
            "AWS4-HMAC-SHA256 …"
        ))
    );
    assert!(!Selector::HeaderPrefix("authorization", "AWS4-")
        .overlaps(&Selector::HeaderExact("authorization", "Token xyz")));

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

    assert!(Selector::Sni("api.example").overlaps(&Selector::Alpn("h2")));
    assert!(!Selector::StreamName("control").overlaps(&Selector::StreamName("media")));
    assert!(!Selector::Port(443).overlaps(&Selector::Port(8443)));
    assert!(Selector::Port(443).overlaps(&Selector::Port(443)));
}

/// One table writes both the ladder and the claim list, so the two cannot disagree.
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
            scheme_alternatives: &["token"],
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

    let rungs: Vec<u16> = FIXTURE_LADDER.iter().map(|r| r.rung).collect();
    assert_eq!(rungs, vec![1, 2, 2, 3]);
    assert_eq!(FIXTURE_LADDER[0].dialect, "alpha");
    assert_eq!(FIXTURE_LADDER[1].dialect, "beta");

    for claim in FIXTURE_CLAIMS {
        assert_eq!(claim.scheme, Some("inbound"));
        assert_eq!(claim.scheme_alternatives, &["token"]);
    }
}

/// The public claim predicate distinguishes a declared credential scheme from an open surface.
#[test]
fn a_claim_with_no_scheme_is_anonymous() {
    use busbar_contract::grammar::Claim;
    let authenticated = Claim {
        transport: "http",
        selector: Selector::ExactPath("/v1/chat/completions"),
        scheme: Some("inbound"),
        scheme_alternatives: &["token", "api-key"],
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
}

/// The family a form belongs to is fixed, and this is WHICH one.
#[test]
fn every_form_has_one_family() {
    for form in ALL_FORMS {
        let expected = match form {
            SelectorForm::ExactPath
            | SelectorForm::PrefixOneLevel
            | SelectorForm::PathPattern
            | SelectorForm::PathSuffix
            | SelectorForm::PathContains => SelectorFamily::Path,
            SelectorForm::HeaderExact
            | SelectorForm::HeaderPresent
            | SelectorForm::HeaderPrefix => SelectorFamily::Header,
            SelectorForm::Sni | SelectorForm::ClientCertSubject | SelectorForm::Alpn => {
                SelectorFamily::Handshake
            }
            SelectorForm::StreamName => SelectorFamily::Stream,
            SelectorForm::Port => SelectorFamily::Port,
        };
        assert_eq!(
            form.family(),
            expected,
            "{form} reads a different part of a request than its family says"
        );
    }
}

/// The property the whole tightening rests on: DISJOINT means no arrival matches both.
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

/// Every path-family form, in the shapes the declared claim set actually uses (plane roots
fn path_fixtures() -> Vec<Selector> {
    const MESH_TASKS: &[PathSeg] = &[PathSeg::Lit("mesh"), PathSeg::Lit("tasks"), PathSeg::Var];
    const MESH_PUSH: &[PathSeg] = &[
        PathSeg::Lit("mesh"),
        PathSeg::Lit("tasks"),
        PathSeg::Var,
        PathSeg::Lit("pushNotificationConfigs"),
    ];
    const MESH_AGENTS: &[PathSeg] = &[PathSeg::Lit("mesh"), PathSeg::Lit("agents"), PathSeg::Var];
    const ADMIN: &[PathSeg] = &[
        PathSeg::Lit("api"),
        PathSeg::Lit("v1"),
        PathSeg::Lit("admin"),
        PathSeg::Tail,
    ];
    const V1_MODELS: &[PathSeg] = &[PathSeg::Lit("v1"), PathSeg::Lit("models"), PathSeg::Tail];
    const MODEL_INVOKE: &[PathSeg] = &[PathSeg::Lit("model"), PathSeg::Var, PathSeg::Lit("invoke")];
    vec![
        Selector::ExactPath("/grid"),
        Selector::ExactPath("/mesh/tasks"),
        Selector::ExactPath("/v1/audio/speech"),
        Selector::PrefixOneLevel("/mesh"),
        Selector::PrefixOneLevel("/v1"),
        Selector::PathPattern(MESH_TASKS),
        Selector::PathPattern(MESH_PUSH),
        Selector::PathPattern(MESH_AGENTS),
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
        "mesh",
        "grid",
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

    for depth in 0..4 {
        let mut next = Vec::new();
        for stem in &level {
            for segment in vocabulary {
                next.push(format!("{stem}/{segment}"));
            }
        }

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
fn leak(path: &str) -> &'static str {
    Box::leak(path.to_owned().into_boxed_str())
}
