// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::grammar::{Claim, Selector};
use busbar_kernel::registry::{check_claims, claims_overlap, ConflictReason};

use crate::root::linked::LinkedTransport;

fn linked_claims() -> Vec<PlaneClaim> {
    plane_claims(crate::LINKED.claims)
}

/// Every scheme the linked transport rows serve, each row's own claim first.
fn linked_schemes() -> Vec<&'static str> {
    crate::LINKED
        .transports
        .iter()
        .flat_map(|t| (t.claims)())
        .collect()
}

fn linked_keys() -> Vec<&'static str> {
    crate::LINKED
        .claims
        .iter()
        .map(|row| (row.plane)().key())
        .collect()
}

fn upgrade_wire_linked() -> bool {
    crate::LINKED
        .transports
        .iter()
        .any(|t| !(t.upgrades)().is_empty())
}

#[cfg(linked_axis_transport_door)]
#[test]
fn every_linked_plane_is_one_key_and_every_claim_is_served() {
    let schemes = linked_schemes();
    check(crate::LINKED.claims, &|s| schemes.contains(&s))
        .expect("no two planes share a key and every claim names a served transport");

    let keys = linked_keys();
    for claim in &linked_claims() {
        assert!(
            keys.contains(&claim.plane) || core_claims().any(|core| core.plane == claim.plane),
            "claim names plane `{}`, which no linked plane row declares",
            claim.plane
        );
        assert!(
            schemes.contains(&claim.claim.transport),
            "plane `{}` claims on transport `{}`, which no linked row serves",
            claim.plane,
            claim.claim.transport
        );
    }
}

#[cfg(linked_every_plane_door)]
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

#[cfg(linked_every_plane_door)]
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

#[cfg(linked_every_plane_door)]
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

#[cfg(linked_every_plane_door)]
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

#[cfg(linked_every_plane_door)]
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

#[cfg(linked_axis_transport_door)]
#[test]
fn no_shipped_transport_names_a_layer() {
    for row in crate::LINKED.transports {
        assert!(
            (row.composes_over)().is_empty(),
            "`{}` names a layer",
            (row.claims)()[0]
        );
    }
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
    let schemes = linked_schemes();
    let refusal = check_claim_transports(&telephony, &|s| schemes.contains(&s))
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

#[cfg(linked_every_plane_door)]
#[test]
fn the_check_answers_now_that_every_claim_names_a_served_transport() {
    let schemes = linked_schemes();
    check(crate::LINKED.claims, &|s| schemes.contains(&s))
        .expect("every claim names a live transport");
    let claims = linked_claims();
    let sealed = seal_claims(&claims);
    assert!(sealed.refused.is_empty());
    assert_eq!(sealed.order.len(), claims.len());
}

#[test]
fn every_planes_claims_name_a_served_transport() {
    let schemes = linked_schemes();
    for claim in linked_claims().iter() {
        assert!(
            schemes.contains(&claim.claim.transport),
            "claim of plane `{}` names transport `{}`, which is not served",
            claim.plane,
            claim.claim.transport
        );
    }
}

fn dropped_doors() -> &'static [DroppedDoor] {
    use crate::root::test_plugins::{missing, neutral_frame_door, BUILD_LOADER_EXAMPLES};
    static DOORS: std::sync::OnceLock<Vec<DroppedDoor>> = std::sync::OnceLock::new();
    DOORS.get_or_init(|| {
        let (plugin, key) = neutral_frame_door()
            .unwrap_or_else(|| missing("neutral_frame_door", BUILD_LOADER_EXAMPLES));

        let facts = plugin
            .context::<crate::root::loader::dispatch::kinds::transport::TransportFacts>()
            .expect("the transport facts")
            .clone();
        let door = crate::root::doors::served(
            plugin,
            &busbar_contract::transport::TransportSettings::default(),
        )
        .expect("the door serves");
        vec![DroppedDoor {
            key,
            claims: vec![key],
            composes_over: Vec::new(),
            offered: facts.offered,
            upgrades: facts.upgrades,
            door,
        }]
    })
}

#[test]
fn a_dropped_in_transports_upgrade_lines_reach_the_guest_list_as_a_linked_ones_do() {
    use busbar_contract::abi::auth::AuthPoints;
    let fixture = &dropped_doors()[0];
    let door = |claim: &'static str, under: Vec<&'static str>, offered, upgrades| DroppedDoor {
        key: claim,
        claims: vec![claim],
        composes_over: under,
        offered,
        upgrades,
        door: fixture.door.clone(),
    };
    let dropped = [
        door("framed", Vec::new(), AuthPoints::PEER, Vec::new()),
        door(
            "upgraded",
            vec!["framed"],
            crate::root::doors::offers_unstated(),
            vec!["upgraded"],
        ),
    ];
    let linked = [
        LinkedTransport {
            composes_over: || &[],
            claims: || vec!["framed"],
            upgrades: Vec::new,
            lines: Vec::new,
            offered: || AuthPoints::PEER,
        },
        LinkedTransport {
            composes_over: || &["framed"],
            claims: || vec!["upgraded"],
            upgrades: || vec!["upgraded"],
            lines: Vec::new,
            offered: crate::root::doors::offers_unstated,
        },
    ];
    let carriers = crate::root::serve::upgrade_carriers(&[], &dropped);
    assert_eq!(
        carriers,
        ["upgraded"],
        "the dropped-in upgrade claim is a line"
    );
    assert_eq!(
        carriers,
        crate::root::serve::upgrade_carriers(&linked, &[]),
        "the same upgrade lines as the linked rows'"
    );
}

#[test]
fn two_linked_door_rows_are_bound_under_two_distinct_labels() {
    let (a, b) = (
        crate::root::doors::row_bind("first-row").expect("the row binds"),
        crate::root::doors::row_bind("second-row").expect("the row binds"),
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

#[cfg(linked_axis_transport_door)]
#[test]
fn a_dropped_in_wire_is_served_beside_the_linked_rows_and_answers_the_check() {
    let wire = &dropped_doors()[0];
    let entries = crate::root::connector::declared(Vec::new(), std::slice::from_ref(wire))
        .expect("the dropped-in door is declared");
    let view = busbar_core_connector::registry::Transports::new(entries)
        .expect("one dropped-in door claims its schemes once");
    assert!(
        view.serving(wire.key).is_some(),
        "the dropped-in key is served"
    );

    let mut schemes = linked_schemes();
    schemes.extend(wire.claims.iter().copied());
    check(crate::LINKED.claims, &|s| schemes.contains(&s))
        .expect("the composition answers with the dropped-in wire beside the linked rows");
}

#[test]
fn a_second_door_on_a_served_key_is_refused_at_the_connector() {
    let wire = &dropped_doors()[0];
    let entries = crate::root::connector::declared(Vec::new(), &[wire.clone(), wire.clone()])
        .expect("both doors are declared");
    let refused = busbar_core_connector::registry::Transports::new(entries)
        .err()
        .expect("a second door on one key is refused");
    assert!(
        matches!(
            &refused,
            busbar_core_connector::registry::ViewRefusal::ClaimedTwice { scheme, .. }
                if scheme == wire.key
        ),
        "{refused}"
    );
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
        busbar_contract::AbiVersion(1)
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

#[test]
fn the_upgrade_lines_are_read_off_the_door_statements() {
    let lines = crate::root::serve::upgrade_carriers(crate::LINKED.transports, &[]);
    if upgrade_wire_linked() {
        assert_eq!(
            lines,
            ["ws", "wss"],
            "the session wire's claims open at the upgrade, its secured scheme beside its own"
        );
    } else {
        assert!(
            lines.is_empty(),
            "no session wire, no upgrade line: {lines:?}"
        );
    }
}

#[test]
fn a_linked_transport_row_logs_to_its_own_plugin_log_file() {
    use crate::root::loader::dispatch::Diagnostic;
    let row = format!("transport-log-row-{}", std::process::id());
    let bound = crate::root::doors::row_bind(&row).expect("the row binds");
    bound.sink.diag(Diagnostic {
        id: busbar_contract::abi::mechanism::call::DIAG_LOG,
        name: b"",
        severity: 0,
        text: b"the linked transport logged a frame",
    });
    let path = crate::root::boot::plugin_logs()
        .path_for(&row, busbar_contract::abi::mechanism::KindCode::Transport);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut text = String::new();
    while std::time::Instant::now() < deadline {
        text = std::fs::read_to_string(&path).unwrap_or_default();
        if text.contains("the linked transport logged a frame") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let _ = std::fs::remove_file(&path);
    assert!(
        text.contains("the linked transport logged a frame"),
        "the row's plugin log file {} holds no record of its own: {text:?}",
        path.display()
    );
}
