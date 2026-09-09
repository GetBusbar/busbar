//! Tests for `registry.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_contract::grammar::{Claim, Selector};
use busbar_kernel::registry::{check_claims, claims_overlap, ConflictReason, PluginKind};

/// The sealed walk over the forty-eight declared claims, most specific first.
///
/// Pinned as text rather than as indices so that a diff of it reads as a routing change. See
/// the test that reads it for what a change to this array means.
#[cfg(feature = "plane-voice")]
const SEALED_ORDER: &[&str] = &[
    "mcp ExactPath(\"/.well-known/oauth-protected-resource/mcp\")",
    "a2a ExactPath(\"/.well-known/oauth-protected-resource/a2a\")",
    "a2a ExactPath(\"/.well-known/agent-card.json\")",
    "a2a ExactPath(\"/a2a/extendedAgentCard\")",
    "a2a ExactPath(\"/a2a/message:stream\")",
    "a2a ExactPath(\"/a2a/message:send\")",
    "a2a ExactPath(\"/a2a/tasks\")",
    "a2a ExactPath(\"/a2a/push\")",
    "a2a ExactPath(\"/a2a/\")",
    "mcp ExactPath(\"/mcp\")",
    "mcp ExactPath(\"/mcp\")",
    "a2a ExactPath(\"/a2a\")",
    "a2a PathPattern([Lit(\"a2a\"), Lit(\"tasks\"), Var, Lit(\"pushNotificationConfigs\"), Var])",
    "a2a PathPattern([Lit(\"a2a\"), Lit(\"tasks\"), Var, Lit(\"pushNotificationConfigs\")])",
    "admin PathPattern([Lit(\"api\"), Lit(\"v1\"), Lit(\"admin\"), Tail])",
    "llm PathPattern([Lit(\"model\"), Var, Lit(\"invoke\")])",
    "a2a PathPattern([Lit(\"a2a\"), Lit(\"tasks\"), Var])",
    "a2a PathPattern([Lit(\"a2a\"), Lit(\"agents\"), Var])",
    "llm PathPattern([Lit(\"v1\"), Lit(\"models\"), Tail])",
    "llm PathPattern([Lit(\"v1beta\"), Lit(\"models\"), Tail])",
    "a2a PathPattern([Lit(\"lf.a2a.v1.A2AService\"), Var])",
    "llm HeaderPrefix(\"authorization\", \"AWS4-HMAC-SHA256\")",
    "llm HeaderPresent(\"anthropic-version\")",
    "llm HeaderPresent(\"anthropic-beta\")",
    "llm HeaderPresent(\"x-goog-api-key\")",
    "llm HeaderPresent(\"x-api-key\")",
    "voice PathSuffix(\"/v1/audio/transcriptions\")",
    "llm PathSuffix(\"/v1/audio/translations\")",
    "llm PathContains(\":streamGenerateContent\")",
    "llm PathSuffix(\"/v1/chat/completions\")",
    "llm PathContains(\":batchEmbedContents\")",
    "voice PathContains(\"BidiGenerateContent\")",
    "voice PathSuffix(\"/v1/audio/speech\")",
    "llm PathContains(\":generateContent\")",
    "llm PathSuffix(\"/v1/moderations\")",
    "llm PathSuffix(\"/v1/embeddings\")",
    "llm PathSuffix(\"/v1/responses\")",
    "llm PathContains(\":embedContent\")",
    "voice PathSuffix(\"/v1/realtime\")",
    "llm PathContains(\"/v1/messages\")",
    "llm PathContains(\"/v1/images/\")",
    "llm PathSuffix(\"/v2/rerank\")",
    "llm PathSuffix(\"/v2/embed\")",
    "llm PathContains(\"/converse\")",
    "llm PathSuffix(\"/v2/chat\")",
    "llm PathSuffix(\"/v1/chat\")",
    "llm PathContains(\":predict\")",
    "mcp StreamName(\"mcp\")",
];

/// Whether this build carries the voice plane — and therefore its WS transport, its registry row
/// and its four claims. Every pinned number below is a statement about ONE composition, and the
/// shipped one (voice on, since `plane-voice` is in `default`) is the one they are pinned
/// against; a build that compiled voice out is a different composition, not a smaller one.
const VOICE: bool = cfg!(feature = "plane-voice");

/// Every transport and every plane goes into one registry, and both counts are what the design
/// says they are. This is the half of the seal that does not depend on the claims.
#[test]
fn seven_transports_and_five_planes_register() {
    let transports = compose_transports(ClientSettings::default());
    let registry = register_all(&transports).expect("nothing collides on a key");
    assert_eq!(
        registry.count(PluginKind::Transport),
        if VOICE { 7 } else { 6 }
    );
    assert_eq!(registry.count(PluginKind::Plane), if VOICE { 5 } else { 4 });
    for key in ["tcp", "tls", "http", "sse", "grpc", "stdio"] {
        assert!(
            registry.resolve(PluginKind::Transport, key).is_some(),
            "transport `{key}` is not registered"
        );
    }
    for key in ["llm", "mcp", "a2a", "admin"] {
        assert!(
            registry.resolve(PluginKind::Plane, key).is_some(),
            "plane `{key}` is not registered"
        );
    }
    // The voice plane and its transport are present exactly together: neither is a thing this
    // root registers without the other.
    assert_eq!(
        registry.resolve(PluginKind::Transport, "ws").is_some(),
        VOICE
    );
    assert_eq!(
        registry.resolve(PluginKind::Plane, "voice").is_some(),
        VOICE
    );
}

/// The measured claim total, one row per plane. It is pinned as a number because the number is
/// what a reader checks the design's own table against; a plane that gains or loses a claim
/// should have to say so here.
// Pinned against the SHIPPED composition (voice on). Compiled out with the voice plane
// because the numbers below are that composition's, not a subset of it.
#[cfg(feature = "plane-voice")]
#[test]
fn the_planes_declare_forty_eight_claims() {
    let claims = plane_claims();
    let count = |plane: &str| claims.iter().filter(|c| c.plane == plane).count();
    assert_eq!(count("llm"), 25);
    assert_eq!(count("mcp"), 4);
    assert_eq!(count("a2a"), 14);
    assert_eq!(count("voice"), 4);
    assert_eq!(count("admin"), 1);
    assert_eq!(claims.len(), 48);
}

/// The measured overlap, split the way the rule splits it. Both counts are pinned because both
/// are what a reader checks the design's own account against.
///
/// The two numbers come apart deliberately. The cross-family pairs are the conservative arm of
/// the totality rule: a request has both a path and a header, so nothing proves a header claim
/// and a path claim cannot coincide. The same-family pairs are the substantive half, and they
/// are the half a tighter grammar moves: reading a suffix and a substring as the segment
/// constraints they are, rather than as fragments that overlap anything, takes them from 119 to
/// 65 without ever answering "disjoint" for a pair one arrival satisfies, and naming the audio
/// surface one path at a time rather than as a prefix took it from 65 to 63.
// Pinned against the SHIPPED composition (voice on). Compiled out with the voice plane
// because the numbers below are that composition's, not a subset of it.
#[cfg(feature = "plane-voice")]
#[test]
fn one_hundred_and_fifty_three_cross_plane_pairs_overlap() {
    use busbar_kernel::grammar::family;

    let claims = plane_claims();
    let mut cross_family = 0usize;
    let mut same_family = 0usize;
    for (i, left) in claims.iter().enumerate() {
        for right in &claims[i + 1..] {
            if left.plane == right.plane || !claims_overlap(&left.claim, &right.claim) {
                continue;
            }
            if family(&left.claim.selector) == family(&right.claim.selector) {
                same_family += 1;
            } else {
                cross_family += 1;
            }
        }
    }
    assert_eq!(cross_family, 90);
    assert_eq!(same_family, 63);
}

/// What the 63 path-family overlaps that remain actually ARE, one class at a time.
///
/// A count alone cannot say whether an overlap is a real shape or a gap in the reasoning, and
/// that distinction is the whole reason to tighten a grammar rather than to relax a check. So
/// each remaining pair is put in the class that explains it, and the classes are exhaustive:
///
/// * a pattern that ends in a TAIL, against a fragment — the tail can spell whatever the
///   fragment asks for, so a path satisfying both is written by filling the tail in;
/// * a pattern with a VARIABLE segment, against a fragment that fits inside one segment — the
///   variable takes any single segment, and a fragment with no slash of its own is one;
/// * two FRAGMENT forms — a suffix and a substring — which are satisfied together by writing a
///   path that ends the one way and contains the other.
///
/// A pair that fits none of these would be the interesting one: a conservative answer with no
/// account of itself. There is none, and the assertion is that there is none.
// Pinned against the SHIPPED composition (voice on). Compiled out with the voice plane
// because the numbers below are that composition's, not a subset of it.
#[cfg(feature = "plane-voice")]
#[test]
fn every_remaining_path_overlap_is_a_shape_and_not_a_gap() {
    use busbar_contract::grammar::PathSeg;
    use busbar_kernel::grammar::family;

    let claims = plane_claims();
    let (mut tail, mut variable, mut fragments) = (0usize, 0usize, 0usize);
    let ends_in_tail = |s: &Selector| matches!(s, Selector::PathPattern(p) if matches!(p.last(), Some(PathSeg::Tail)));
    let has_variable = |s: &Selector| matches!(s, Selector::PathPattern(p) if p.iter().any(|g| matches!(g, PathSeg::Var)));
    let is_fragment =
        |s: &Selector| matches!(s, Selector::PathSuffix(_) | Selector::PathContains(_));

    for (i, left) in claims.iter().enumerate() {
        for right in &claims[i + 1..] {
            if left.plane == right.plane
                || !claims_overlap(&left.claim, &right.claim)
                || family(&left.claim.selector) != family(&right.claim.selector)
            {
                continue;
            }
            let (a, b) = (&left.claim.selector, &right.claim.selector);
            if ends_in_tail(a) || ends_in_tail(b) {
                tail += 1;
            } else if (has_variable(a) && is_fragment(b)) || (has_variable(b) && is_fragment(a)) {
                variable += 1;
            } else if is_fragment(a) && is_fragment(b) {
                fragments += 1;
            } else {
                panic!("{a:?} and {b:?} overlap for no reason this file can name");
            }
        }
    }
    assert_eq!(tail, 23);
    assert_eq!(variable, 24);
    assert_eq!(fragments, 16);
}

/// **The finding, answered.** Every one of those 153 overlaps is settled by the sealed order,
/// and none of them is a refusal.
///
/// The resolved count is pinned against the overlap count above, so the two cannot drift apart
/// silently: a pair that stops being resolved has either stopped overlapping or become a tie,
/// and each of those is a different thing to have to explain. The refusal list is pinned empty,
/// which is the whole claim of this file — the declared set of five planes seals.
// Pinned against the SHIPPED composition (voice on). Compiled out with the voice plane
// because the numbers below are that composition's, not a subset of it.
#[cfg(feature = "plane-voice")]
#[test]
fn every_cross_plane_overlap_is_resolved_by_precedence_and_none_refuses() {
    let claims = plane_claims();
    let sealed = seal_claims(&claims);

    assert_eq!(sealed.resolved.len(), 153);
    assert!(
        sealed.refused.is_empty(),
        "the declared claims do not seal: {:?}",
        sealed.refused
    );

    // The winner of a resolved pair is one of its two sides, and it is the side the order puts
    // first. Said as a property rather than as 209 assertions.
    let rank = |i: usize| {
        sealed
            .order
            .iter()
            .position(|c| *c == i)
            .expect("the order is a permutation")
    };
    for pair in &sealed.resolved {
        assert!(pair.winner == pair.left || pair.winner == pair.right);
        let loser = pair.left + pair.right - pair.winner;
        assert!(
            rank(pair.winner) < rank(loser),
            "the winner of {pair:?} is not the one the order tries first"
        );
    }
}

/// The sealed order of the forty-eight, written out.
///
/// A snapshot, and deliberately a verbose one: the walk every arriving connection is matched
/// against is the thing this file produces, and a change to it is a change to which plane
/// answers which request. Each row is the plane and the selector, so a diff of this array reads
/// as a routing change rather than as a permutation of opaque indices. A claim added, removed or
/// respelled has to update it, on purpose, with the new order visible in the same diff.
// Pinned against the SHIPPED composition (voice on). Compiled out with the voice plane
// because the numbers below are that composition's, not a subset of it.
#[cfg(feature = "plane-voice")]
#[test]
fn the_sealed_order_of_the_forty_eight_claims_is_pinned() {
    let claims = plane_claims();
    let sealed = seal_claims(&claims);
    let walk: Vec<String> = sealed
        .order
        .iter()
        .map(|i| format!("{} {:?}", claims[*i].plane, claims[*i].claim.selector))
        .collect();
    assert_eq!(walk, SEALED_ORDER, "the sealed claim order moved");
}

/// The refusal is still the point of the check. Two planes claiming one path at the same
/// precedence is a composition nobody can resolve — the order has nothing to say about it — and
/// the node says so at boot with both planes named rather than picking a winner at the first
/// request.
#[test]
fn a_planted_equal_precedence_collision_refuses_at_boot() {
    let admin = plane_claims()
        .into_iter()
        .find(|c| c.plane == "admin")
        .expect("the admin plane claims one path");
    let impostor = PlaneClaim {
        plane: "impostor",
        claim: admin.claim,
    };
    // A clean two-claim base, so the refusal that comes back is the one that was planted and
    // not one the declared set already carries.
    let sealed = seal_claims(&[admin, impostor]);
    assert!(sealed.resolved.is_empty());
    assert_eq!(sealed.refused.len(), 1);
    assert_eq!(sealed.refused[0].reason, ConflictReason::EqualPrecedence);
}

/// And the other half of the same rule: the same two planes, one of them naming a tighter
/// selector, is not a refusal at all. The exact path is more specific than the pattern that
/// swallows it, so the order decides, the pair is recorded, and the boot goes on.
#[test]
fn a_planted_overlap_at_different_precedence_resolves_rather_than_refusing() {
    let admin = plane_claims()
        .into_iter()
        .find(|c| c.plane == "admin")
        .expect("the admin plane claims one path");
    let mut tighter = admin.claim;
    tighter.selector = Selector::ExactPath("/api/v1/admin/keys");
    let claims = vec![
        admin,
        PlaneClaim {
            plane: "impostor",
            claim: tighter,
        },
    ];
    let sealed = seal_claims(&claims);
    assert!(sealed.refused.is_empty());
    assert_eq!(sealed.resolved.len(), 1);
    assert_eq!(
        sealed.resolved[0].winner, 1,
        "the exact path is the tighter"
    );
}

/// Two claims whose scheme sets share nothing never overlap, however alike their selectors read:
/// one request carries one credential, and no credential answers both sets. Planted on the one
/// selector pair that is otherwise the hardest collision there is — the same exact path.
#[test]
fn claims_with_disjoint_scheme_sets_do_not_collide() {
    let one = PlaneClaim {
        plane: "one",
        claim: Claim {
            transport: "http",
            selector: Selector::ExactPath("/shared"),
            scheme: Some("one-key"),
            scheme_alternatives: &["bearer"],
            idempotency: None,
        },
    };
    let two = PlaneClaim {
        plane: "two",
        claim: Claim {
            transport: "http",
            selector: Selector::ExactPath("/shared"),
            scheme: Some("two-key"),
            scheme_alternatives: &["request-signature"],
            idempotency: None,
        },
    };
    assert!(one.claim.selector.overlaps(&two.claim.selector));
    assert!(!claims_overlap(&one.claim, &two.claim));
    let sealed = seal_claims(&[one.clone(), two.clone()]);
    assert!(sealed.refused.is_empty());
    assert!(sealed.resolved.is_empty());

    // And the moment one alternative is shared, the same pair is the collision it looks like.
    let mut shared = two;
    shared.claim.scheme_alternatives = &["bearer"];
    assert_eq!(seal_claims(&[one, shared]).refused.len(), 1);
}

/// Every claim is ordered, most specific first, and the order is a permutation of the claims —
/// no claim is dropped from the walk and none is tried twice.
#[test]
fn the_precedence_order_is_a_permutation_of_every_claim() {
    let claims = plane_claims();
    let mut seen = seal_claims(&claims).order;
    seen.sort_unstable();
    assert_eq!(seen, (0..claims.len()).collect::<Vec<_>>());
}

/// And it is an order, not a shuffle: specificity never increases as the walk goes on, so the
/// first claim that matches is the most specific one that could have.
#[test]
fn the_precedence_order_is_most_specific_first() {
    use busbar_kernel::grammar::specificity;

    let claims = plane_claims();
    let order = seal_claims(&claims).order;
    for pair in order.windows(2) {
        let earlier = specificity(&claims[pair[0]].claim.selector);
        let later = specificity(&claims[pair[1]].claim.selector);
        assert!(earlier >= later, "{earlier} came before {later}");
    }
}

/// The one-answer form of the same check, over the two claims the planted collision uses: a
/// caller that only needs to know whether a set seals gets the first refusal, with both planes
/// named in the message an operator reads.
#[test]
fn the_one_answer_form_names_both_planes() {
    let admin = plane_claims()
        .into_iter()
        .find(|c| c.plane == "admin")
        .expect("the admin plane claims one path");
    let impostor = PlaneClaim {
        plane: "impostor",
        claim: admin.claim,
    };
    let conflict = check_claims(&[admin, impostor]).expect_err("two planes cannot own one path");
    let planes = [conflict.left.plane, conflict.right.plane];
    assert!(planes.contains(&"admin"));
    assert!(planes.contains(&"impostor"));
    assert!(conflict.to_string().contains("equal precedence"));
}

/// A plane's own claims may overlap: within one plane they are an ordered pattern set with
/// most-specific-wins precedence, and that is what makes a catch-all tail legal beneath a
/// specific route. Only the cross-plane case is a refusal.
#[test]
fn a_planes_own_claims_may_overlap() {
    let claims = plane_claims();
    let admin = claims
        .iter()
        .find(|c| c.plane == "admin")
        .expect("the admin plane claims one path")
        .clone();
    let doubled = vec![admin.clone(), admin];
    assert!(check_claims(&doubled).is_ok());
}

/// The shipped stack composes: every layer the seven transports declare is registered, and the
/// three that were actually built over a lower layer were built over one they declare. This is
/// the composition half of the seal, and it passes today.
#[test]
fn the_shipped_transport_stack_composes() {
    let rows = registered_rows();
    assert!(check_composition(&rows).is_ok());
    let composed_over = |key: &str| {
        rows.iter()
            .find(|r| r.key == key)
            .expect("registered")
            .composed_over
    };
    // The two transports whose `new()` yields something that refuses every connection are the
    // two that must be built through `over`, and the rows say they were.
    if VOICE {
        assert_eq!(composed_over("ws"), Some("http"));
    }
    assert_eq!(composed_over("grpc"), Some("http"));
    assert_eq!(composed_over("sse"), Some("http"));
}

/// The other direction of the composition rule: a transport built over a layer it does not
/// declare describes a node nobody is running, and the check says so.
#[test]
fn an_undeclared_composition_refuses_at_boot() {
    let mut rows = registered_rows();
    let stdio = rows
        .iter_mut()
        .find(|r| r.key == StdioTransport::KEY)
        .expect("stdio is registered");
    stdio.composed_over = Some(TcpTransport::KEY);

    let err = check_composition(&rows).expect_err("stdio composes over nothing");
    assert_eq!(
        err,
        CompositionError::UndeclaredComposition {
            transport: "stdio",
            used: "tcp",
        }
    );
}

/// And the first direction: a declared layer that no registered transport provides.
#[test]
fn an_unregistered_layer_refuses_at_boot() {
    let rows = vec![Registered {
        key: "sse",
        composes_over: &["http"],
        composed_over: None,
    }];
    let err = check_composition(&rows).expect_err("nothing registered http");
    assert_eq!(
        err,
        CompositionError::UnregisteredLayer {
            transport: "sse",
            layer: "http",
        }
    );
}

/// A guard against a claim slice that quietly names a plane the registry never took: the
/// pairing in `plane_claims` is done by hand, so the one thing worth asserting about it is that
/// every key it produces is a key the registry actually resolves.
#[test]
fn every_claimed_plane_key_is_a_registered_plane() {
    let transports = compose_transports(ClientSettings::default());
    let registry = register_all(&transports).expect("nothing collides on a key");
    for claim in &plane_claims() {
        assert!(
            registry.resolve(PluginKind::Plane, claim.plane).is_some(),
            "claim names plane `{}`, which is not registered",
            claim.plane
        );
    }
}

/// **The second finding, now closed on the declaration side and kept alive on the check side.**
/// The other side of the pairing above: a claim on a transport no crate provides. The design
/// lists thirteen transports and seven exist, and the voice plane used to claim its telephony
/// dialect on one of the six that do not — which made the seal refuse, so no node built on this
/// root could boot at all.
///
/// The claim is gone (the plane's own claim table says why, and what has to land before it comes
/// back). The CHECK is not: it is the only thing in the tree that reads a claim and a registered
/// transport at the same time, and a check deleted along with the one claim that tripped it
/// would leave the next such claim to be discovered as a request that matched nothing. So it is
/// exercised here against a claim built for the purpose, on a transport deliberately not one of
/// the seven.
#[test]
fn a_claim_on_a_transport_with_no_crate_refuses_at_boot() {
    let telephony = vec![PlaneClaim {
        plane: "voice",
        claim: Claim {
            transport: "twilio-media",
            selector: Selector::PrefixOneLevel("/twilio"),
            scheme: Some("voice-key"),
            scheme_alternatives: &["twilio-signature"],
            idempotency: None,
        },
    }];
    let refusal = check_claim_transports(&telephony, &registered_rows())
        .expect_err("`twilio-media` has no crate");
    assert!(matches!(
        refusal,
        BootRefusal::UnregisteredClaimTransport {
            plane: "voice",
            transport: "twilio-media",
        }
    ));
}

/// And the whole boot, end to end, now that nothing declares a claim the root cannot place: the
/// seal answers. This is the assertion the previous shape of the test above could not make —
/// the claims sealed, and the one transport gap was all that stood between the declared
/// composition and a node that boots.
// Pinned against the SHIPPED composition (voice on). Compiled out with the voice plane
// because the numbers below are that composition's, not a subset of it.
#[cfg(feature = "plane-voice")]
#[test]
fn the_seal_answers_now_that_every_claim_names_a_registered_transport() {
    let sealed = seal(ClientSettings::default()).expect("every claim names a live transport");
    assert_eq!(sealed.claims.len(), 48);
    assert_eq!(sealed.precedence.len(), 48);
}

/// The operator's request-body cap reaches every mounted plane's transport.
///
/// A deployment that writes `limits.request_body_max_bytes: 1024` is asking for a node that
/// buffers a kilobyte, and it has to mean it on every plane at once — the door's inbound limit
/// and the transport's accumulation ceiling are the same number, so a plane served over a
/// transport built from a `Default` would take a body the door refused. The seal composes ONE
/// http instance from the settings it is handed and every http-carrying transport is over that
/// instance, so the cap is checked at the instance and the claim walk is what says no plane sits
/// anywhere else.
#[test]
fn the_operators_body_cap_reaches_every_mounted_planes_transport() {
    const CAP: usize = 1024;
    let limits = busbar_substrate::config::limits::LimitsResolved {
        request_body_max_bytes: CAP,
        ..busbar_substrate::config::limits::LimitsResolved::default()
    };
    let sealed = crate::root::registry::seal(crate::root::policy::client_settings(&limits))
        .expect("every claim names a live transport");

    assert_eq!(
        sealed.transports.http.max_body_bytes(),
        CAP,
        "the http transport must carry the operator's cap, not the crate's default"
    );

    for claim in &sealed.claims {
        let key = claim.claim.transport;
        let row = sealed
            .registered
            .iter()
            .find(|r| r.key == key)
            .unwrap_or_else(|| {
                panic!(
                    "claim of plane `{}` names unregistered `{key}`",
                    claim.plane
                )
            });
        let over_the_capped_instance =
            key == HttpTransport::KEY || row.composed_over == Some(HttpTransport::KEY);
        assert!(
            over_the_capped_instance || key == StdioTransport::KEY,
            "plane `{}` claims bytes on transport `{key}`, which neither is the capped http \
             instance nor is composed over it",
            claim.plane
        );
    }

    // The other direction: a deployment that set nothing is where it always was.
    let unset = crate::root::registry::seal(crate::root::policy::client_settings(
        &busbar_substrate::config::limits::LimitsResolved::default(),
    ))
    .expect("every claim names a live transport");
    assert_eq!(
        unset.transports.http.max_body_bytes(),
        ClientSettings::default().request_body_max_bytes
    );
}

/// The voice plane's realtime upstreams are `wss`, and this node must be able to dial one.
///
/// The ws transport refuses a secure target over a cleartext lower layer rather than put a
/// plain upgrade on a wire the caller was told was encrypted. That refusal is right, and with a
/// single `ws` instance composed over `http` it also means every `wss://` upstream this
/// deployment has — OpenAI Realtime, Gemini Live — is refused at the dial. So the root composes
/// the key twice: the ingress instance over `http`, which is what an in-band upgrade arrives
/// on, and a dial-side instance over `tls`, which is the only composition under which `wss` is
/// honest. A `ws://` destination still resolves to the ingress instance, so nothing that worked
/// over cleartext quietly moved onto a different stack.
#[cfg(feature = "plane-voice")]
#[test]
fn a_secure_realtime_upstream_resolves_to_the_tls_composed_instance() {
    let sealed = seal(ClientSettings::default()).expect("every claim names a live transport");
    let ws_key = <WsTransport as TransportMeta>::KEY;

    let secure = sealed
        .transports
        .dialer(
            ws_key,
            &UpstreamAddress::socket("wss://api.openai.com/v1/realtime"),
        )
        .expect("`ws` is a registered key");
    assert_eq!(
        secure.composed_over(),
        Some(TlsTransport::KEY),
        "a wss upstream must dial through the tls-composed instance, or the ws transport \
         refuses it as a downgrade and the voice plane cannot reach a realtime provider at all"
    );

    let cleartext = sealed
        .transports
        .dialer(
            ws_key,
            &UpstreamAddress::socket("ws://127.0.0.1:8080/duplex"),
        )
        .expect("`ws` is a registered key");
    assert_eq!(
        cleartext.composed_over(),
        Some(HttpTransport::KEY),
        "a cleartext ws destination stays on the instance the in-band upgrade arrives on"
    );

    // The two are different objects, not one instance answering two ways.
    assert!(!Arc::ptr_eq(&secure, &cleartext));

    // And every other key is unchanged: one composition, one instance, whatever the address.
    for (key, over) in [
        (TcpTransport::KEY, None),
        (HttpTransport::KEY, None),
        (SseTransport::KEY, Some(HttpTransport::KEY)),
        (GrpcTransport::KEY, Some(HttpTransport::KEY)),
        (StdioTransport::KEY, None),
    ] {
        let dialer = sealed
            .transports
            .dialer(key, &UpstreamAddress::socket("wss://api.openai.com"))
            .unwrap_or_else(|| panic!("`{key}` is a registered key"));
        assert_eq!(dialer.composed_over(), over, "`{key}` resolved elsewhere");
    }

    assert!(
        sealed
            .transports
            .dialer(
                "twilio-media",
                &UpstreamAddress::socket("wss://example.invalid")
            )
            .is_none(),
        "a key the root never registered resolves to no instance"
    );
}

/// And the same check over every declared claim, voice included now that its telephony row is
/// gone: nothing anywhere names a transport the root did not register.
#[test]
fn every_planes_claims_name_a_registered_transport() {
    let registered = registered_rows();
    let transports = compose_transports(ClientSettings::default());
    let registry = register_all(&transports).expect("nothing collides on a key");
    for claim in plane_claims().iter() {
        assert!(
            registered.iter().any(|r| r.key == claim.claim.transport),
            "claim of plane `{}` names transport `{}`, which is not registered",
            claim.plane,
            claim.claim.transport
        );
        // And the same question of the registry itself, which is what a request is served out
        // of: the rows are the root's own statement about what it built, and a name that
        // resolves in the statement but not in the registry would be a claim on a transport
        // nothing can answer with.
        assert!(
            registry
                .resolve(PluginKind::Transport, claim.claim.transport)
                .is_some(),
            "claim of plane `{}` names transport `{}`, which the registry does not resolve",
            claim.plane,
            claim.claim.transport
        );
    }
}

// ── THE REGISTERED DIALECTS ───────────────────────────────────────────────────────────────────

/// A BOOT SERVES ITS REGISTERED DIALECTS' RUNGS, at the numbers those dialects declared.
///
/// This is the assertion the gap between the carve-out and the seam was measured by. Cutting the
/// vendor rows out of the plane left the plane honest — it no longer names a vendor — and left the
/// BOOT short: the claims those rows carried belonged to a crate the root had not yet sealed, so a
/// real node would have refused `/v1/chat/completions` as claimed by nothing while the crate that
/// speaks it sat in the same binary.
///
/// It is written on the RUNG NUMBERS rather than on a count, because a count is satisfied by any
/// five claims and what has to be true is that these two rungs — the tight chat rung and the loose
/// non-chat rung — are the ones being served, under the PLANE's key. A dialect's claims are claims
/// on its plane: the rung scale is the plane's, and so is the key a request is routed by.
#[test]
fn the_boot_serves_the_registered_dialects_rungs() {
    let entries = super::super::dialects::LLM;
    assert!(
        !entries.is_empty(),
        "the root registered no dialect at all, so this test would pass vacuously"
    );

    let served = plane_claims();
    for entry in entries {
        for rung in entry.ladder {
            assert!(
                served
                    .iter()
                    .any(|c| c.plane == <LlmPlane as PlaneMeta>::KEY && c.claim == rung.claim),
                "rung {} of dialect `{}` is registered and not served",
                rung.rung,
                rung.dialect
            );
        }
    }

    // The two rungs by number, so the test says WHICH contests are being answered rather than only
    // that the loop ran. Rung 7 is the tight chat surface; rung 14 is the loosest rung the plane
    // has, and the one four separate non-chat paths sit on.
    let rungs: Vec<u16> = entries
        .iter()
        .flat_map(|e| e.ladder.iter())
        .map(|c| c.rung)
        .collect();
    assert!(rungs.contains(&7), "rung 7 is not registered");
    assert!(rungs.contains(&14), "rung 14 is not registered");
}

/// And the merged ladder resolves those two rungs to the dialect that declared them.
///
/// The claim being SERVED and the request being ROUTED to the right vocabulary are two facts, and
/// the second is the one a client notices: a boot that sealed the claims but handed the plane an
/// empty registry would answer the path and then decode it against a table that has no row for it.
#[test]
fn the_merged_ladder_answers_for_the_registered_dialect() {
    let plane = llm_plane();
    let no_headers = |_: &str| None;

    let chat = plane
        .dialect_for("/v1/chat/completions", &no_headers)
        .expect("the tight chat rung answers");
    let embeddings = plane
        .dialect_for("/v1/embeddings", &no_headers)
        .expect("the loose non-chat rung answers");

    // The name is read off the registered entry rather than written here, so this file names no
    // dialect either — the same rule the boot itself is held to.
    let registered = super::super::dialects::LLM[0].locations.name;
    assert_eq!(chat, registered);
    assert_eq!(embeddings, registered);

    // And the row the plane will decode those bytes with is the registered one, not a neighbour's.
    assert!(
        plane.locations(registered).is_some(),
        "the dialect answers for a path and the plane has no location row for it"
    );
}
