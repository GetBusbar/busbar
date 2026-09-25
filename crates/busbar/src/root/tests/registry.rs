//! Tests for `registry.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_contract::grammar::{Claim, Selector};
use busbar_kernel::registry::{check_claims, claims_overlap, ConflictReason, PluginKind};

/// The sealed walk over the fifty declared claims, most specific first. The decision plane's two
/// exact paths (item 251) sit among the other exact paths, ahead of every pattern that could also
/// describe them.
///
/// Pinned as text rather than as indices so that a diff of it reads as a routing change. See
/// the test that reads it for what a change to this snapshot means. The rows are fixture DATA
/// (`fixtures/sealed_order.txt`, one `<plane key> <selector>` row per claim), so this source names
/// no plane.
#[cfg(all(feature = "plane-voice", feature = "plane-decision"))]
const SEALED_ORDER: &str = include_str!("fixtures/sealed_order.txt");

/// The claim count each plane of the shipped composition declares (`<plane key> <claims>` rows).
#[cfg(all(feature = "plane-voice", feature = "plane-decision"))]
const CLAIMS_PER_PLANE: &str = include_str!("fixtures/claims_per_plane.txt");

/// Whether this build links a plane on the kernel's SESSION loop (the `gauntlet-session` axis of the
/// linked table) — and with it its WS transport, its registry row and its four claims. Every pinned
/// number below is a statement about ONE composition, and the shipped one (the session plane linked,
/// since its row's feature is in `default`) is the one they are pinned against; a build that
/// compiled it out is a different composition, not a smaller one. Read off `LINKED`, so this source
/// names no plane.
fn session_linked() -> bool {
    !crate::LINKED.gauntlet_session.is_empty()
}

/// The non-comment rows of a fixture file, in order. Read only by the shipped-composition pins,
/// which a build that compiled a plane out does not compile.
#[allow(dead_code)]
fn fixture_rows(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Whether this build carries the decision plane — its registry row and its two claims (item 251).
const DECISION: bool = cfg!(feature = "plane-decision");

/// Every transport and every plane goes into one registry, and both counts are what the design
/// says they are. This is the half of the seal that does not depend on the claims.
#[test]
fn seven_transports_and_five_planes_register() {
    let transports = compose_transports(ClientSettings::default());
    let registry = register_all(&transports).expect("nothing collides on a key");
    assert_eq!(
        registry.count(PluginKind::Transport),
        if session_linked() { 7 } else { 6 }
    );
    assert_eq!(
        registry.count(PluginKind::Plane),
        4 + usize::from(session_linked()) + usize::from(DECISION)
    );
    for key in ["tcp", "tls", "http", "sse", "grpc", "stdio"] {
        assert!(
            registry.resolve(PluginKind::Transport, key).is_some(),
            "transport `{key}` is not registered"
        );
    }
    // Every plane that claims bytes is registered, and nothing else is: the claimed keys are
    // read off the planes' own declarations, so this names none of them. With the per-plane claim
    // counts pinned in `fixtures/claims_per_plane.txt`, the registered set is pinned key by key.
    let mut claimed: Vec<&str> = plane_claims().iter().map(|c| c.plane).collect();
    claimed.sort_unstable();
    claimed.dedup();
    for key in &claimed {
        assert!(
            registry.resolve(PluginKind::Plane, key).is_some(),
            "plane `{key}` is not registered"
        );
    }
    assert_eq!(
        claimed.len(),
        registry.count(PluginKind::Plane),
        "a registered plane claims nothing, or a claimed plane is not registered: {claimed:?}"
    );
    // The decision plane is registered exactly when its crate edge is in the build. The key is the
    // crate's own, so it can only be named on a build that links the crate; on a build without it,
    // the plane count above (no fifth row beyond voice) is the statement that nothing registered.
    #[cfg(feature = "plane-decision")]
    assert!(
        registry
            .resolve(
                PluginKind::Plane,
                <busbar_plane_decision::DecisionPlane as PlaneMeta>::KEY
            )
            .is_some(),
        "the decision plane is linked and not registered"
    );
    // The voice plane and its transport are present exactly together: neither is a thing this
    // root registers without the other.
    assert_eq!(
        registry.resolve(PluginKind::Transport, "ws").is_some(),
        session_linked()
    );
    // And its plane: the claimed-set check above resolves every claimed key and ties the claimed
    // count to the registered count, and the plane count moves by exactly one with the session
    // plane — so its row is registered exactly when it is linked.
}

/// The measured claim total, one row per plane. It is pinned as a number because the number is
/// what a reader checks the design's own table against; a plane that gains or loses a claim
/// should have to say so here.
// Pinned against the SHIPPED composition (voice on). Compiled out with the voice plane
// because the numbers below are that composition's, not a subset of it.
#[cfg(all(feature = "plane-voice", feature = "plane-decision"))]
#[test]
fn the_planes_declare_fifty_claims() {
    let claims = plane_claims();
    let count = |plane: &str| claims.iter().filter(|c| c.plane == plane).count();
    // One `<plane key> <claims>` row per plane, pinned as fixture DATA so this source names none.
    let pinned: Vec<(String, usize)> = fixture_rows(CLAIMS_PER_PLANE)
        .iter()
        .map(|row| {
            let (key, n) = row.split_once(' ').expect("`<plane key> <claims>`");
            (key.to_string(), n.parse().expect("a claim count"))
        })
        .collect();
    assert_eq!(pinned.len(), 6, "six planes are pinned: {pinned:?}");
    for (key, n) in &pinned {
        assert_eq!(
            count(key),
            *n,
            "plane `{key}` declares {} claims",
            count(key)
        );
    }
    // The decision plane's key is its crate's own, so it is also asserted by that name.
    assert_eq!(
        count(<busbar_plane_decision::DecisionPlane as PlaneMeta>::KEY),
        2
    );
    assert_eq!(
        pinned.iter().map(|(_, n)| n).sum::<usize>(),
        claims.len(),
        "every claim belongs to a pinned plane"
    );
    assert_eq!(claims.len(), 50);
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
/// surface one path at a time rather than as a prefix took it from 65 to 63. Joining the decision
/// plane (item 251) added one more — its `/v1/models` against the llm plane's tail pattern — for 64.
// Pinned against the SHIPPED composition (voice on). Compiled out with the voice plane
// because the numbers below are that composition's, not a subset of it.
#[cfg(all(feature = "plane-voice", feature = "plane-decision"))]
#[test]
fn one_hundred_and_sixty_four_cross_plane_pairs_overlap() {
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
    // The decision plane's two exact paths add ten cross-family pairs (a header claim can be true
    // of the same arrival) and one path-family pair: `/v1/models` inside the llm plane's
    // `v1/models/<tail>` pattern.
    assert_eq!(cross_family, 100);
    assert_eq!(same_family, 64);
}

/// What the 64 path-family overlaps that remain actually ARE, one class at a time.
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
#[cfg(all(feature = "plane-voice", feature = "plane-decision"))]
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
    assert_eq!(tail, 24);
    assert_eq!(variable, 24);
    assert_eq!(fragments, 16);
}

/// **The finding, answered.** Every one of those 164 overlaps is settled by the sealed order,
/// and none of them is a refusal.
///
/// The resolved count is pinned against the overlap count above, so the two cannot drift apart
/// silently: a pair that stops being resolved has either stopped overlapping or become a tie,
/// and each of those is a different thing to have to explain. The refusal list is pinned empty,
/// which is the whole claim of this file — the declared set of planes seals.
// Pinned against the SHIPPED composition (voice on). Compiled out with the voice plane
// because the numbers below are that composition's, not a subset of it.
#[cfg(all(feature = "plane-voice", feature = "plane-decision"))]
#[test]
fn every_cross_plane_overlap_is_resolved_by_precedence_and_none_refuses() {
    let claims = plane_claims();
    let sealed = seal_claims(&claims);

    assert_eq!(sealed.resolved.len(), 164);
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

/// The sealed order of the fifty, written out.
///
/// A snapshot, and deliberately a verbose one: the walk every arriving connection is matched
/// against is the thing this file produces, and a change to it is a change to which plane
/// answers which request. Each row is the plane and the selector, so a diff of this array reads
/// as a routing change rather than as a permutation of opaque indices. A claim added, removed or
/// respelled has to update it, on purpose, with the new order visible in the same diff.
// Pinned against the SHIPPED composition (voice on). Compiled out with the voice plane
// because the numbers below are that composition's, not a subset of it.
#[cfg(all(feature = "plane-voice", feature = "plane-decision"))]
#[test]
fn the_sealed_order_of_the_fifty_claims_is_pinned() {
    let claims = plane_claims();
    let sealed = seal_claims(&claims);
    let walk: Vec<String> = sealed
        .order
        .iter()
        .map(|i| format!("{} {:?}", claims[*i].plane, claims[*i].claim.selector))
        .collect();
    assert_eq!(
        walk,
        fixture_rows(SEALED_ORDER),
        "the sealed claim order moved"
    );
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
    if session_linked() {
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
    // Planted on a REAL registered plane (the first that claims anything), so the refusal is about
    // the transport and nothing else.
    let plane = plane_claims()
        .first()
        .expect("the shipped planes claim bytes")
        .plane;
    let telephony = vec![PlaneClaim {
        plane,
        claim: Claim {
            transport: "twilio-media",
            selector: Selector::PrefixOneLevel("/twilio"),
            scheme: Some("streaming-key"),
            scheme_alternatives: &["twilio-signature"],
            idempotency: None,
        },
    }];
    let refusal = check_claim_transports(&telephony, &registered_rows())
        .expect_err("`twilio-media` has no crate");
    assert!(matches!(
        refusal,
        BootRefusal::UnregisteredClaimTransport {
            plane: refused,
            transport: "twilio-media",
        } if refused == plane
    ));
}

/// And the whole boot, end to end, now that nothing declares a claim the root cannot place: the
/// seal answers. This is the assertion the previous shape of the test above could not make —
/// the claims sealed, and the one transport gap was all that stood between the declared
/// composition and a node that boots.
// Pinned against the SHIPPED composition (voice on). Compiled out with the voice plane
// because the numbers below are that composition's, not a subset of it.
#[cfg(all(feature = "plane-voice", feature = "plane-decision"))]
#[test]
fn the_seal_answers_now_that_every_claim_names_a_registered_transport() {
    let sealed = seal(ClientSettings::default()).expect("every claim names a live transport");
    assert_eq!(sealed.claims.len(), 50);
    assert_eq!(sealed.precedence.len(), 50);
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
    let limits = busbar_kernel::config::limits::LimitsResolved {
        request_body_max_bytes: CAP,
        ..busbar_kernel::config::limits::LimitsResolved::default()
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
        &busbar_kernel::config::limits::LimitsResolved::default(),
    ))
    .expect("every claim names a live transport");
    assert_eq!(
        unset.transports.http.max_body_bytes(),
        ClientSettings::default().request_body_max_bytes
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

/// THE SEAL IS ON THE BOOT PATH, NEUTRALLY. `run()` seals the composition off the resolved limits
/// before the root units' configuration step, in every build: the call is not behind a feature and
/// is not a root unit's, so a build that links no plane's root unit still refuses a composition
/// that does not seal, rather than booting past a check only one plane's unit ran.
#[test]
fn the_boot_path_seals_the_composition_in_every_build() {
    let main = include_str!("../../main.rs");
    let run = &main[main.find("async fn run(").expect("the boot's run()")..];
    let call = "root::registry::seal_or_exit(root::policy::client_settings(&cfg.limits));";
    let sealed = run.find(call).expect("run() seals the composition");
    let units = run
        .find("ROOT_UNITS.iter().filter_map(|u| u.on_config)")
        .expect("the root units' configuration step");
    assert!(
        sealed < units,
        "the seal answers before any root unit composes"
    );
    let line_before = run[..sealed]
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty() && !l.trim_start().starts_with("//"))
        .unwrap_or_default();
    assert!(
        !line_before.trim_start().starts_with("#[cfg"),
        "the seal is not behind a feature: {line_before}"
    );
}
