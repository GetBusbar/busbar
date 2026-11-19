// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::grammar::{Claim, Selector};
use busbar_kernel::registry::{check_claims, claims_overlap, ConflictReason};

use std::sync::Arc;

fn linked_claims() -> Vec<PlaneClaim> {
    plane_claims(crate::LINKED.claims)
}

fn linked_keys() -> Vec<&'static str> {
    crate::LINKED
        .claims
        .iter()
        .map(|row| (row.plane)().key())
        .collect()
}

#[test]
fn every_linked_planes_claims_are_its_declared_claims() {
    let claims = linked_claims();
    let mut keys: Vec<&str> = Vec::new();
    let mut total = 0usize;
    for row in crate::LINKED.claims {
        let key = (row.plane)().key();
        assert!(
            !keys.contains(&key),
            "plane `{key}` has two rows in the linked claim table"
        );
        keys.push(key);
        assert!(
            !row.claims.is_empty(),
            "plane `{key}` is on the claim table but declares no claim"
        );
        assert_eq!(
            claims.iter().filter(|c| c.plane == key).count(),
            row.claims.len(),
            "plane `{key}`'s sealed claims are not its declared claims"
        );
        total += row.claims.len();
    }

    assert!(
        total <= claims.len(),
        "more linked claims than the seal holds"
    );
    assert!(
        claims
            .iter()
            .filter(|c| !keys.contains(&c.plane))
            .all(|c| core_claims().any(|core| core.plane == c.plane)),
        "a sealed claim belongs to no linked plane and is not the admin surface's route"
    );
}

#[test]
fn every_cross_plane_overlap_is_one_family_or_the_other_and_the_seal_resolves_them_all() {
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
    assert_eq!(
        cross_family + same_family,
        seal_claims(&claims).resolved.len(),
        "the overlaps ({cross_family} cross-family, {same_family} same-family) are not the pairs \
         the seal resolves"
    );
}

#[test]
fn every_remaining_path_overlap_is_a_shape_and_not_a_gap() {
    use busbar_contract::grammar::PathSeg;
    use busbar_kernel::grammar::family;

    let claims = linked_claims();
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
            assert!(
                ends_in_tail(a)
                    || ends_in_tail(b)
                    || (has_variable(a) && is_fragment(b))
                    || (has_variable(b) && is_fragment(a))
                    || (is_fragment(a) && is_fragment(b)),
                "{a:?} and {b:?} overlap for no reason this file can name"
            );
        }
    }
}

#[test]
fn every_cross_plane_overlap_is_resolved_by_precedence_and_none_refuses() {
    let claims = linked_claims();
    let sealed = seal_claims(&claims);

    assert!(
        sealed.refused.is_empty(),
        "the declared claims do not seal: {:?}",
        sealed.refused
    );

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

#[test]
fn the_sealed_order_is_most_specific_first_and_stable() {
    use busbar_kernel::registry::precedence;

    let claims = linked_claims();
    let sealed = seal_claims(&claims);
    let mut seen = sealed.order.clone();
    seen.sort();
    assert_eq!(
        seen,
        (0..claims.len()).collect::<Vec<_>>(),
        "the walk is every claim exactly once"
    );
    for pair in sealed.order.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        let (pa, pb) = (
            precedence(&claims[a].claim.selector),
            precedence(&claims[b].claim.selector),
        );
        assert!(
            pa > pb || (pa == pb && a < b),
            "{:?} is tried before {:?} against the precedence rule",
            claims[a],
            claims[b]
        );
    }

    let ranked = |claims: &[PlaneClaim]| -> Vec<(u32, u32)> {
        seal_claims(claims)
            .order
            .iter()
            .map(|i| precedence(&claims[*i].claim.selector))
            .collect()
    };
    let mut reversed = claims.clone();
    reversed.reverse();
    assert_eq!(
        ranked(&claims),
        ranked(&reversed),
        "the precedence walk moved"
    );
}

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

    let sealed = seal_claims(&[admin, impostor]);
    assert!(sealed.resolved.is_empty());
    assert_eq!(sealed.refused.len(), 1);
    assert_eq!(sealed.refused[0].reason, ConflictReason::EqualPrecedence);
}

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

#[test]
fn claims_with_disjoint_scheme_sets_do_not_collide() {
    let one = PlaneClaim {
        plane: "one",
        claim: Claim {
            transport: "planted-wire",
            selector: Selector::ExactPath("/shared"),
            scheme: Some("one-key"),
            scheme_alternatives: &["bearer"],
            idempotency: None,
        },
    };
    let two = PlaneClaim {
        plane: "two",
        claim: Claim {
            transport: "planted-wire",
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

    let mut shared = two;
    shared.claim.scheme_alternatives = &["bearer"];
    assert_eq!(seal_claims(&[one, shared]).refused.len(), 1);
}

#[test]
fn the_precedence_order_is_a_permutation_of_every_claim() {
    let claims = linked_claims();
    let mut seen = seal_claims(&claims).order;
    seen.sort();
    assert_eq!(seen, (0..claims.len()).collect::<Vec<_>>());
}

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

#[test]
fn every_claimed_plane_key_is_a_linked_plane() {
    let keys = linked_keys();
    for claim in &linked_claims() {
        if core_claims().any(|core| core.plane == claim.plane) {
            continue;
        }
        assert!(
            keys.contains(&claim.plane),
            "claim names plane `{}`, which is not a linked plane",
            claim.plane
        );
    }
}

#[test]
fn a_claim_on_a_transport_with_no_crate_refuses_at_boot() {
    let plane = linked_claims()
        .first()
        .expect("the shipped planes claim bytes")
        .plane;
    let telephony = vec![PlaneClaim {
        plane,
        claim: Claim {
            transport: "twilio-media",
            selector: Selector::PrefixOneLevel("/twilio"),
            scheme: Some("planted-key"),
            scheme_alternatives: &["twilio-signature"],
            idempotency: None,
        },
    }];
    let refusal = check_claim_transports(&telephony, &|s| s == "http")
        .expect_err("`twilio-media` has no crate");
    assert!(matches!(
        refusal,
        BootRefusal::UnregisteredClaimTransport {
            plane: refused,
            transport: "twilio-media",
        } if refused == plane
    ));
}

/// Core carries no transport of its own: a plane claiming a protocol no installed transport provides
/// is a deployment's plugin set, not a build fault. The refusal is coded, names the plane, the kind
/// and the protocol generically, and says what to install; it names no crate and no plugin.
#[test]
fn an_unprovided_transport_protocol_is_refused_as_a_missing_transport_plugin() {
    let refusal = BootRefusal::UnregisteredClaimTransport {
        plane: "admin",
        transport: "http",
    };
    let text = refusal.to_string();
    assert!(text.starts_with("BUSBAR-9201: "), "coded: {text}");
    assert!(
        text.contains(
            "plane `admin` needs a transport of kind `transport` that provides the protocol \
             `http`, and none is installed or admitted; install a transport plugin that provides \
             `http`"
        ),
        "says what is missing and what to install: {text}"
    );
    assert!(
        text.ends_with("See https://getbusbar.com/docs/1.6/errors/BUSBAR-9201"),
        "links its page: {text}"
    );
    assert!(!text.contains("crate"), "names no crate: {text}");
}

struct Plane(&'static str);

impl busbar_contract::Plugin for Plane {
    fn key(&self) -> &'static str {
        self.0
    }
    fn kind(&self) -> busbar_contract::Kind {
        busbar_contract::Kind::Plane
    }
    fn abi(&self) -> busbar_contract::AbiVersion {
        busbar_contract::AbiVersion::from_wire(1)
    }
}

fn plane_row(plane: fn() -> Arc<dyn busbar_contract::Plugin>) -> crate::root::linked::LinkedClaims {
    crate::root::linked::LinkedClaims { plane, claims: &[] }
}

#[test]
fn two_planes_declaring_one_key_are_refused_at_boot() {
    let rows = [
        plane_row(|| Arc::new(Plane("twice"))),
        plane_row(|| Arc::new(Plane("twice"))),
    ];
    let refused = check(&rows, &|_| true).expect_err("one key, two planes");
    assert!(
        matches!(
            refused,
            BootRefusal::DuplicateKey {
                kind: busbar_contract::Kind::Plane,
                key: "twice",
            }
        ),
        "{refused}"
    );
    assert_eq!(
        refused.to_string(),
        "two Plane plugins both declare the key \"twice\""
    );
}

#[test]
fn a_transport_and_a_plane_may_share_a_key() {
    let rows = [plane_row(|| Arc::new(Plane("shared")))];
    check(&rows, &|scheme| scheme == "shared").expect("a plane may share a transport's key");
}
