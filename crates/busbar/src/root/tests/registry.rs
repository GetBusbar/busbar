//! Tests for `registry.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_contract::grammar::{Claim, Selector};
use busbar_kernel::registry::{check_claims, claims_overlap, ConflictReason, PluginKind};

/// Every linked plane's claims and the core plane's, as the boot seal pairs them.
fn linked_claims() -> Vec<PlaneClaim> {
    plane_claims(crate::LINKED.claims)
}

/// The linked transports folded bottom-up, as the boot seal folds them.
fn linked_fold() -> Vec<Built> {
    compose(
        crate::LINKED.transports,
        Dropped::NONE,
        &TransportSettings::default(),
    )
    .expect("the stack composes")
}

/// Every linked transport as the composition check reads it.
fn linked_rows() -> Vec<Registered> {
    linked_fold().into_iter().map(|(row, _)| row).collect()
}

/// The registry the seal fills: the folded transports, then every linked plane and the core one.
fn linked_registry() -> Registry {
    let (rows, transports): (Vec<Registered>, Vec<Arc<dyn Transport>>) =
        linked_fold().into_iter().unzip();
    register_all(&rows, &transports, crate::LINKED.claims).expect("nothing collides on a key")
}

/// The shipped transport fold (`<wire key> <composed over, or ->` rows, in build order), as data.
const TRANSPORT_FOLD: &str = include_str!("fixtures/transport_fold.txt");

/// The sealed walk over the forty declared claims, most specific first. The decisions plane's
/// claim is its door snapshot's (FLIP-DECISIONS), mounted by the serve fold, as the MCP plane's are
/// (FLIP-MCP) and every other door plane's are, so none of them is here.
///
/// Pinned as text rather than as indices so that a diff of it reads as a routing change. See
/// the test that reads it for what a change to this snapshot means. The rows are fixture DATA
/// (`fixtures/sealed_order.txt`, one `<plane key> <selector>` row per claim), so this source names
/// no plane.
#[cfg(linked_every_plane)]
const SEALED_ORDER: &str = include_str!("fixtures/sealed_order.txt");

/// The claim count each plane of the shipped composition declares (`<plane key> <claims>` rows).
#[cfg(linked_every_plane)]
const CLAIMS_PER_PLANE: &str = include_str!("fixtures/claims_per_plane.txt");

/// Whether this build links a wire that opens at an upgrade (a transport row stating an upgrade
/// claim, on the `transport` and `connector-door` axes): the sixth wire. No plane rides the
/// kernel's SESSION loop: the session plane is a door plane (`plane-door` axis) whose claims are
/// its snapshot's and are mounted by the serve fold, not declared in the linked claims table, so
/// the wire is the transport row's alone. Every pinned number below is a statement about ONE
/// composition, the shipped one. Read off `LINKED`, so this source names no wire.
fn upgrade_wire_linked() -> bool {
    crate::LINKED
        .transports
        .iter()
        .any(|t| !(t.upgrades)().is_empty())
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

/// Every transport and every plane goes into one registry, and both counts are what the design
/// says they are. This is the half of the seal that does not depend on the claims.
// THE SHIPPED STACK NEEDS ITS FLOOR WIRE: the http rows compose over the linked transport door
// (tcp); a build that links none (`--no-default-features`) has no stack to fold or seal, so this
// cell gates on the transport-door axis, read off the linked table.
#[cfg(linked_axis_transport_door)]
#[test]
fn six_transports_and_five_planes_register() {
    let registry = linked_registry();
    assert_eq!(
        registry.count(PluginKind::Transport),
        if upgrade_wire_linked() { 6 } else { 5 }
    );
    // Every linked plane and the core one: a plane this build does not link registers nothing.
    assert_eq!(
        registry.count(PluginKind::Plane),
        crate::LINKED.claims.len() + 1
    );
    for key in ["tcp", "http", "sse", "grpc", "stdio"] {
        assert!(
            registry.resolve(PluginKind::Transport, key).is_some(),
            "transport `{key}` is not registered"
        );
    }
    // Every plane that claims bytes is registered, and nothing else is: the claimed keys are
    // read off the planes' own declarations, so this names none of them. With the per-plane claim
    // counts pinned in `fixtures/claims_per_plane.txt`, the registered set is pinned key by key.
    let mut claimed: Vec<&str> = linked_claims().iter().map(|c| c.plane).collect();
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
    // The decisions plane is not on this table: it registers through its door (`plane-door` axis),
    // whose Statement the kernel folds into its row, and its claim is its door snapshot's
    // (FLIP-DECISIONS).
    // The upgrade wire is registered exactly when its transport row is linked.
    assert_eq!(
        registry.resolve(PluginKind::Transport, "ws").is_some(),
        upgrade_wire_linked()
    );
}

/// The measured claim total, one row per plane. It is pinned as a number because the number is
/// what a reader checks the design's own table against; a plane that gains or loses a claim
/// should have to say so here.
// Pinned against the SHIPPED composition (every linked plane on). Compiled out with any of them
// because the numbers below are that composition's, not a subset of it. A door plane's claims are
// its door snapshot's, mounted by the serve fold, so they are not counted here.
#[cfg(linked_every_plane)]
#[test]
fn the_planes_declare_forty_claims() {
    let claims = linked_claims();
    let count = |plane: &str| claims.iter().filter(|c| c.plane == plane).count();
    // One `<plane key> <claims>` row per plane, pinned as fixture DATA so this source names none.
    let pinned: Vec<(String, usize)> = fixture_rows(CLAIMS_PER_PLANE)
        .iter()
        .map(|row| {
            let (key, n) = row.split_once(' ').expect("`<plane key> <claims>`");
            (key.to_string(), n.parse().expect("a claim count"))
        })
        .collect();
    // Three rows: each plane that became a door plane took its claims out of the linked table (its
    // door's snapshot claims them, mounted by the serve fold).
    assert_eq!(pinned.len(), 3, "three planes are pinned: {pinned:?}");
    for (key, n) in &pinned {
        assert_eq!(
            count(key),
            *n,
            "plane `{key}` declares {} claims",
            count(key)
        );
    }
    // The decisions plane's claim is its door snapshot's (FLIP-DECISIONS), not this table's.
    assert_eq!(
        count(<busbar_plane_decisions::DecisionPlane as busbar_contract::plane::PlaneMeta>::KEY),
        0
    );
    assert_eq!(
        pinned.iter().map(|(_, n)| n).sum::<usize>(),
        claims.len(),
        "every claim belongs to a pinned plane"
    );
    assert_eq!(claims.len(), 40);
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
/// FLIP-MCP took the MCP plane's four claims out of the linked table (its door's snapshot claims
/// them, mounted by the serve fold behind the data listener's guest list): ten cross-family pairs;
/// the same-family pairs were unchanged. FLIP-DECISIONS took the decisions plane's two claims out of
/// it too (its door's snapshot claims `POST /v1/systemone` alone, mounted by the serve fold): ten
/// cross-family pairs and one same-family pair. The session plane's flip to its door took its five
/// claims out (its door's snapshot claims them, mounted by the serve fold): ten cross-family and 22
/// same-family pairs. The three planes' claims never overlapped one another (none of them states a
/// header claim, the tool plane's stream name is not on the path planes' transport, and no exact
/// path of one matches another's suffix, substring or prefix selectors), so 100 cross-family and 64
/// same-family became 70 and 41.
// Pinned against the SHIPPED composition (every linked plane on). Compiled out with any of them
// because the numbers below are that composition's, not a subset of it. A door plane's claims are
// its door snapshot's, mounted by the serve fold, so they are not counted here.
#[cfg(linked_every_plane)]
#[test]
fn one_hundred_and_eleven_cross_plane_pairs_overlap() {
    use busbar_kernel::grammar::family;

    let claims = linked_claims();
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
    assert_eq!(cross_family, 70);
    assert_eq!(same_family, 41);
}

/// What the 41 path-family overlaps that remain actually ARE, one class at a time.
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
// Pinned against the SHIPPED composition (every linked plane on). Compiled out with any of them
// because the numbers below are that composition's, not a subset of it. A door plane's claims are
// its door snapshot's, mounted by the serve fold, so they are not counted here.
#[cfg(linked_every_plane)]
#[test]
fn every_remaining_path_overlap_is_a_shape_and_not_a_gap() {
    use busbar_contract::grammar::PathSeg;
    use busbar_kernel::grammar::family;

    let claims = linked_claims();
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
    // The decisions plane's `/v1/models` against the llm plane's tail pattern left with its claims
    // (FLIP-DECISIONS).
    assert_eq!(tail, 17);
    assert_eq!(variable, 24);
    // The fragment pairs were the session plane's audio suffixes against the model plane's; its
    // claims left this table when it became a door plane.
    assert_eq!(fragments, 0);
}

/// **The finding, answered.** Every one of those 111 overlaps is settled by the sealed order,
/// and none of them is a refusal.
///
/// The resolved count is pinned against the overlap count above, so the two cannot drift apart
/// silently: a pair that stops being resolved has either stopped overlapping or become a tie,
/// and each of those is a different thing to have to explain. The refusal list is pinned empty,
/// which is the whole claim of this file — the declared set of planes seals.
// Pinned against the SHIPPED composition (every linked plane on). Compiled out with any of them
// because the numbers below are that composition's, not a subset of it. A door plane's claims are
// its door snapshot's, mounted by the serve fold, so they are not counted here.
#[cfg(linked_every_plane)]
#[test]
fn every_cross_plane_overlap_is_resolved_by_precedence_and_none_refuses() {
    let claims = linked_claims();
    let sealed = seal_claims(&claims);

    assert_eq!(sealed.resolved.len(), 111);
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

/// The sealed order of the forty, written out.
///
/// A snapshot, and deliberately a verbose one: the walk every arriving connection is matched
/// against is the thing this file produces, and a change to it is a change to which plane
/// answers which request. Each row is the plane and the selector, so a diff of this array reads
/// as a routing change rather than as a permutation of opaque indices. A claim added, removed or
/// respelled has to update it, on purpose, with the new order visible in the same diff.
// Pinned against the SHIPPED composition (every linked plane on). Compiled out with any of them
// because the numbers below are that composition's, not a subset of it. A door plane's claims are
// its door snapshot's, mounted by the serve fold, so they are not counted here.
#[cfg(linked_every_plane)]
#[test]
fn the_sealed_order_of_the_forty_claims_is_pinned() {
    let claims = linked_claims();
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
    let admin = linked_claims()
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
    let admin = linked_claims()
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
    let claims = linked_claims();
    let mut seen = seal_claims(&claims).order;
    seen.sort_unstable();
    assert_eq!(seen, (0..claims.len()).collect::<Vec<_>>());
}

/// And it is an order, not a shuffle: specificity never increases as the walk goes on, so the
/// first claim that matches is the most specific one that could have.
#[test]
fn the_precedence_order_is_most_specific_first() {
    use busbar_kernel::grammar::specificity;

    let claims = linked_claims();
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
    let admin = linked_claims()
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
    let claims = linked_claims();
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
// THE SHIPPED STACK NEEDS ITS FLOOR WIRE: the http rows compose over the linked transport door
// (tcp); a build that links none (`--no-default-features`) has no stack to fold or seal, so this
// cell gates on the transport-door axis, read off the linked table.
#[cfg(linked_axis_transport_door)]
#[test]
fn the_shipped_transport_stack_composes() {
    let rows = linked_rows();
    assert!(check_composition(&rows).is_ok());
    let composed_over = |key: &str| {
        rows.iter()
            .find(|r| r.key == key)
            .expect("registered")
            .composed_over
    };
    // NO TRANSPORT NAMES ANOTHER (ARCHITECT Q128 U7; TRANSPORT-STACK (2), :4721): every row is
    // built over nothing, the carrier being the connector's choice from the target's scheme, and
    // `sse` is a claim of the http entry, served by its wire, not a layer over it.
    if upgrade_wire_linked() {
        assert_eq!(composed_over("ws"), None);
    }
    assert_eq!(composed_over("grpc"), None);
    assert_eq!(composed_over("sse"), None);
    for row in &rows {
        assert!(row.composes_over.is_empty(), "`{}` names a layer", row.key);
    }
}

/// The other direction of the composition rule: a transport built over a layer it does not
/// declare describes a node nobody is running, and the check says so.
// THE SHIPPED STACK NEEDS ITS FLOOR WIRE: the http rows compose over the linked transport door
// (tcp); a build that links none (`--no-default-features`) has no stack to fold or seal, so this
// cell gates on the transport-door axis, read off the linked table.
#[cfg(linked_axis_transport_door)]
#[test]
fn an_undeclared_composition_refuses_at_boot() {
    let mut rows = linked_rows();
    let used = rows[0].key;
    let own = rows
        .iter_mut()
        .rev()
        .find(|r| r.composes_over.is_empty())
        .expect("a wire that declares no layer");
    let transport = own.key;
    own.composed_over = Some(used);

    let err = check_composition(&rows).expect_err("the wire composes over nothing");
    assert_eq!(
        err,
        CompositionError::UndeclaredComposition { transport, used }
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
    let registry = linked_registry();
    for claim in &linked_claims() {
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
    let plane = linked_claims()
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
    let refusal = check_claim_transports(&telephony, &linked_rows())
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
// Pinned against the SHIPPED composition (every linked plane on). Compiled out with any of them
// because the numbers below are that composition's, not a subset of it. A door plane's claims are
// its door snapshot's, mounted by the serve fold, so they are not counted here.
#[cfg(linked_every_plane)]
#[test]
fn the_seal_answers_now_that_every_claim_names_a_registered_transport() {
    let sealed = seal(&crate::LINKED, Dropped::NONE, TransportSettings::default())
        .expect("every claim names a live transport");
    assert_eq!(sealed.claims.len(), 40);
    assert_eq!(sealed.precedence.len(), 40);
}

/// The operator's request-body cap reaches every linked transport.
///
/// A deployment that writes `limits.request_body_max_bytes: 1024` is asking for a node that
/// buffers a kilobyte, and it has to mean it on every plane at once — the door's inbound limit
/// and a transport's accumulation ceiling are the same number, so a wire built from a `Default`
/// would take a body the door refused. The fold hands every row's build the ONE settings value it
/// was given, and the capped composition still seals.
// THE SHIPPED STACK NEEDS ITS FLOOR WIRE: the http rows compose over the linked transport door
// (tcp); a build that links none (`--no-default-features`) has no stack to fold or seal, so this
// cell gates on the transport-door axis, read off the linked table.
#[cfg(linked_axis_transport_door)]
#[test]
fn the_operators_body_cap_reaches_every_mounted_planes_transport() {
    const CAP: usize = 1024;
    static SEEN: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());
    fn recording(
        _: Option<Arc<dyn Transport>>,
        settings: &TransportSettings,
    ) -> Arc<dyn Transport> {
        SEEN.lock()
            .expect("seen")
            .push(settings.request_body_max_bytes);
        let own = crate::LINKED
            .transports
            .iter()
            .find(|r| r.composes_over.is_empty());
        (own.expect("a wire that opens its own socket").build)(None, settings)
    }
    let limits = busbar_kernel::config::limits::LimitsResolved {
        request_body_max_bytes: CAP,
        ..busbar_kernel::config::limits::LimitsResolved::default()
    };
    let rows: Vec<LinkedTransport> = crate::LINKED
        .transports
        .iter()
        .map(|row| LinkedTransport {
            build: recording,
            ..*row
        })
        .collect();
    compose(
        &rows,
        Dropped::NONE,
        &crate::root::policy::client_settings(&limits),
    )
    .expect("the stack composes");
    assert_eq!(
        *SEEN.lock().expect("seen"),
        vec![CAP; rows.len()],
        "every linked wire is built from the operator's cap"
    );

    seal(
        &crate::LINKED,
        Dropped::NONE,
        crate::root::policy::client_settings(&limits),
    )
    .expect("the capped composition seals");
}

/// THE FOLD IS BOTTOM-UP, AND `COMPOSES_OVER` IS THE COMPOSITION ORDER. The shipped rows build in
/// the order they register — every wire after every layer it declares — and each entry's claims
/// past its own register right after it (`sse`, the http entry's). No shipped wire declares a
/// layer (no transport names another), so every row is built over nothing. The same rows handed
/// over in the reverse order build the same stack, because the order is the declarations' and not
/// the table's.
// THE SHIPPED STACK NEEDS ITS FLOOR WIRE: the http rows compose over the linked transport door
// (tcp); a build that links none (`--no-default-features`) has no stack to fold or seal, so this
// cell gates on the transport-door axis, read off the linked table.
#[cfg(linked_axis_transport_door)]
#[test]
fn the_fold_builds_bottom_up_in_composes_over_order() {
    let rows = linked_rows();
    let linked: Vec<&str> = crate::LINKED
        .transports
        .iter()
        .flat_map(|r| (r.claims)())
        .collect();
    let shipped: Vec<(&str, Option<&str>)> = TRANSPORT_FOLD
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once(' '))
        .map(|(key, over)| (key, (over != "-").then_some(over)))
        .filter(|(key, _)| linked.contains(key))
        .collect();
    let built: Vec<(&str, Option<&str>)> = rows.iter().map(|r| (r.key, r.composed_over)).collect();
    assert_eq!(built, shipped, "the fold's order or a wire's layer moved");
    for row in &rows {
        if let Some(over) = row.composed_over {
            let first = row.composes_over.iter().find(|l| linked.contains(l));
            assert_eq!(
                first,
                Some(&over),
                "`{}` not over its first linked layer",
                row.key
            );
        }
    }

    let mut reversed = crate::LINKED.transports.to_vec();
    reversed.reverse();
    let refolded: Vec<Registered> =
        compose(&reversed, Dropped::NONE, &TransportSettings::default())
            .expect("the reversed table composes")
            .into_iter()
            .map(|(row, _)| row)
            .collect();
    for (i, row) in refolded.iter().enumerate() {
        for layer in row.composes_over {
            if linked.contains(layer) {
                assert!(
                    refolded[..i].iter().any(|r| r.key == *layer),
                    "`{}` was built before its layer `{layer}`",
                    row.key
                );
            }
        }
        let same = rows.iter().find(|r| r.key == row.key).expect("same rows");
        assert_eq!(row.composed_over, same.composed_over, "`{}` moved", row.key);
    }
    assert!(check_composition(&refolded).is_ok());
}

/// Two rows that declare each other as their layer have no bottom: the fold refuses, naming one.
#[test]
fn transports_layered_over_each_other_refuse_at_boot() {
    let own = *crate::LINKED
        .transports
        .iter()
        .find(|r| r.composes_over.is_empty())
        .expect("a wire that opens its own socket");
    let rows = [
        LinkedTransport {
            key: "upper",
            composes_over: &["lower"],
            ..own
        },
        LinkedTransport {
            key: "lower",
            composes_over: &["upper"],
            ..own
        },
    ];
    let refusal = compose(&rows, Dropped::NONE, &TransportSettings::default())
        .err()
        .expect("no order builds either");
    assert!(matches!(
        refusal,
        BootRefusal::Uncomposable { transport: "upper" }
    ));
    assert!(refusal.to_string().contains("`upper`"));
}

/// And the same check over every declared claim, voice included now that its telephony row is
/// gone: nothing anywhere names a transport the root did not register.
#[test]
fn every_planes_claims_name_a_registered_transport() {
    let registered = linked_rows();
    let registry = linked_registry();
    for claim in linked_claims().iter() {
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
    let call = "root::registry::seal_or_exit(&LINKED, root::policy::client_settings(&cfg.limits));";
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

// ── BOTH DOORS, ONE FOLD ────────────────────────────────────────────────────────────────────────

/// The dropped-in wire these proofs serve: the neutral frame door (the plugin loader's
/// `neutral_frame_door` example, an identity framer under a neutral claim), served over the host's
/// sockets as the boot serves a dropped-in door, once for the process. It names no transport, so the
/// root names none and no transport leaving this repo takes the fixture with it. Under CI a missing
/// artifact is a hard failure, never a silent skip.
fn dropped_doors() -> &'static [DroppedDoor] {
    static DOORS: std::sync::OnceLock<Vec<DroppedDoor>> = std::sync::OnceLock::new();
    let doors = DOORS.get_or_init(|| {
        crate::root::test_plugins::neutral_frame_door()
            .into_iter()
            .map(|(plugin, key)| DroppedDoor {
                key,
                claims: vec![key],
                composes_over: Vec::new(),
                wire: crate::root::doors::host_wire(
                    plugin,
                    &busbar_contract::transport::TransportSettings::default(),
                )
                .expect("the door serves"),
            })
            .collect()
    });
    assert!(
        !doors.is_empty() || std::env::var_os("CI").is_none(),
        "the neutral frame door cdylib is built beside the test binary under CI"
    );
    doors
}

/// The linked row the dropped-in wire stands in for: its key, composing over nothing, built in
/// process as the same served wire. The build's own linked table holds no row for the neutral
/// claim, so a proof that the dropped-in wire takes a linked row's place adds that row first.
fn the_wires_linked_row(wire: &DroppedDoor) -> LinkedTransport {
    LinkedTransport {
        key: wire.key,
        composes_over: &[],
        build: |_, _| dropped_doors()[0].wire.clone(),
        claims: || vec![dropped_doors()[0].key],
        upgrades: Vec::new,
    }
}

/// TWO LINKED DOOR ROWS ARE TWO INSTANCES: a linked transport door is bound under its own row name,
/// so no two linked rows share a label and the host services never take them for one instance
/// (ARCHITECT ruling 2026-09-30 (B)).
#[test]
fn two_linked_door_rows_are_bound_under_two_distinct_labels() {
    let (a, b) = (
        crate::root::doors::row_bind("first-row"),
        crate::root::doors::row_bind("second-row"),
    );
    assert_eq!(
        &*a.instance, "first-row",
        "a linked door is labelled by its row name"
    );
    assert_eq!(
        &*b.instance, "second-row",
        "a linked door is labelled by its row name"
    );
    assert_ne!(
        a.instance, b.instance,
        "two linked rows are bound under two labels"
    );
}

fn one_door() -> Dropped {
    Dropped {
        hot: &[],
        doors: &dropped_doors()[..1],
    }
}

/// A table of linked rows held for the process, as `Linked::transports` holds its own.
fn rows_of(
    slot: &'static std::sync::OnceLock<Vec<LinkedTransport>>,
    rows: impl FnOnce() -> Vec<LinkedTransport>,
) -> &'static [LinkedTransport] {
    slot.get_or_init(rows)
}

/// ONE FOLD, BOTH DOORS (#2 rule (1), #3): a build that links every wire but one, with that wire
/// DROPPED IN, seals to the SAME composition the build that links all of them seals to — the same
/// rows, each built over the same layer — and the dropped-in wire is registered through the same
/// registration, answers the registry by its key, and is the wire under the data door.
// THE SHIPPED STACK NEEDS ITS FLOOR WIRE: the http rows compose over the linked transport door
// (tcp); a build that links none (`--no-default-features`) has no stack to fold or seal, so this
// cell gates on the transport-door axis, read off the linked table.
#[cfg(linked_axis_transport_door)]
#[test]
fn a_dropped_in_wire_rides_the_one_fold_in_place_of_its_linked_row() {
    let Some(wire) = dropped_doors().first() else {
        eprintln!("skip: the neutral frame door is not built beside the test binary");
        return;
    };
    static ROWS: std::sync::OnceLock<Vec<LinkedTransport>> = std::sync::OnceLock::new();
    let with = crate::root::linked::Linked {
        transports: rows_of(&ROWS, || {
            [crate::LINKED.transports, &[the_wires_linked_row(wire)]].concat()
        }),
        ..crate::LINKED
    };
    let sealed = seal(&crate::LINKED, one_door(), TransportSettings::default())
        .expect("the composition seals");
    let linked = seal(&with, Dropped::NONE, TransportSettings::default()).expect("it seals linked");

    let by_key = |mut rows: Vec<Registered>| {
        rows.sort_by_key(|r| r.key);
        rows
    };
    assert_eq!(
        by_key(sealed.registered.clone()),
        by_key(linked.registered.clone()),
        "the dropped-in wire takes its linked row's place in the one composition"
    );
    assert_eq!(sealed.dropped, [wire.key]);
    assert!(linked.dropped.is_empty());
    assert!(sealed
        .registry
        .resolve(PluginKind::Transport, wire.key)
        .is_some());
}

/// A DROPPED-IN WIRE CLAIMING A LINKED KEY IS REFUSED EXACTLY AS A SECOND LINKED ROW IS: the same
/// refusal, from the same registration, naming the same key.
#[test]
fn a_dropped_in_wire_on_a_linked_key_is_refused_as_a_second_linked_row_is() {
    let Some(wire) = dropped_doors().first() else {
        eprintln!("skip: the neutral frame door is not built beside the test binary");
        return;
    };
    let row = the_wires_linked_row(wire);
    static ONCE: std::sync::OnceLock<Vec<LinkedTransport>> = std::sync::OnceLock::new();
    let with = crate::root::linked::Linked {
        transports: rows_of(&ONCE, || [crate::LINKED.transports, &[row]].concat()),
        ..crate::LINKED
    };
    let dropped = seal(&with, one_door(), Default::default())
        .err()
        .expect("a dropped-in wire on a linked key is refused");
    static TWICE: std::sync::OnceLock<Vec<LinkedTransport>> = std::sync::OnceLock::new();
    let twice = crate::root::linked::Linked {
        transports: rows_of(&TWICE, || [crate::LINKED.transports, &[row, row]].concat()),
        ..crate::LINKED
    };
    let linked = seal(&twice, Dropped::NONE, Default::default())
        .err()
        .expect("a second linked row on one key is refused");
    assert!(
        matches!(
            &dropped,
            BootRefusal::Registry(busbar_kernel::registry::RegistryError::DuplicateKey {
                kind: PluginKind::Transport,
                key,
            }) if *key == wire.key
        ),
        "{dropped}"
    );
    assert_eq!(dropped.to_string(), linked.to_string());
}

/// THE UPGRADE LINES ARE THE LINKED CLAIMS THAT OPEN AT AN UPGRADE, read off the door Statements
/// (ARCHITECT ruling Q128 U7; never a layer list): the session plane's wire, where this build links
/// it, and nothing else. (RED, at the loader: a claim row stating any other trigger is no line,
/// `an_upgrade_line_is_a_claim_whose_unit_zero_opens_at_the_upgrade`.)
#[test]
fn the_upgrade_lines_are_read_off_the_door_statements() {
    let lines = crate::root::serve::upgrade_carriers(crate::LINKED.transports);
    if upgrade_wire_linked() {
        assert_eq!(
            lines,
            ["ws"],
            "the session wire's claim opens at the upgrade"
        );
    } else {
        assert!(
            lines.is_empty(),
            "no session wire, no upgrade line: {lines:?}"
        );
    }
}
