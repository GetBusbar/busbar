use super::*;
use busbar_contract::grammar::{Claim, Selector};
use busbar_kernel::registry::{check_claims, claims_overlap, ConflictReason, PluginKind};

fn linked_claims() -> Vec<PlaneClaim> {
    plane_claims(crate::LINKED.claims)
}

fn linked_fold() -> Vec<Built> {
    compose(
        crate::LINKED.transports,
        Dropped::NONE,
        &TransportSettings::default(),
    )
    .expect("the stack composes")
}

fn linked_rows() -> Vec<Registered> {
    linked_fold().into_iter().map(|(row, _)| row).collect()
}

fn linked_registry() -> Registry {
    register_all(&linked_rows(), crate::LINKED.claims).expect("nothing collides on a key")
}

fn upgrade_wire_linked() -> bool {
    crate::LINKED
        .transports
        .iter()
        .any(|t| !(t.upgrades)().is_empty())
}

#[cfg(linked_axis_transport_door)]
#[test]
fn every_linked_transport_and_plane_registers() {
    let registry = linked_registry();

    let rows = linked_rows();
    assert_eq!(registry.count(PluginKind::Transport), rows.len());
    for row in &rows {
        assert!(
            registry.resolve(PluginKind::Transport, row.key).is_some(),
            "transport `{}` is not registered",
            row.key
        );
    }

    assert_eq!(
        registry.count(PluginKind::Plane),
        crate::LINKED.claims.len(),
        "the plane registry holds something no linked plane row declares"
    );

    let linked_keys: Vec<&str> = crate::LINKED
        .claims
        .iter()
        .map(|row| (row.plane)().key())
        .collect();
    let mut claimed: Vec<&str> = linked_claims().iter().map(|c| c.plane).collect();
    claimed.sort_unstable();
    claimed.dedup();
    for key in &claimed {
        let registered = registry.resolve(PluginKind::Plane, key).is_some();
        if linked_keys.contains(key) {
            assert!(registered, "plane `{key}` is not registered");
        } else {
            assert!(
                !registered,
                "the claimant `{key}` is no linked plane, yet it is registered as a plane-kind \
                 plugin"
            );
        }
    }

    for claim in &linked_claims() {
        assert!(
            registry
                .resolve(PluginKind::Transport, claim.claim.transport)
                .is_some(),
            "plane `{}` claims on transport `{}`, which is not registered",
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
    seen.sort_unstable();
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
    seen.sort_unstable();
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
fn the_shipped_transport_stack_composes() {
    let rows = linked_rows();
    assert!(check_composition(&rows).is_ok());
    let composed_over = |key: &str| {
        rows.iter()
            .find(|r| r.key == key)
            .expect("registered")
            .composed_over
    };

    for row in &rows {
        assert!(row.composes_over.is_empty(), "`{}` names a layer", row.key);
        assert_eq!(
            composed_over(row.key),
            None,
            "`{}` is built over a layer",
            row.key
        );
    }
}

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

#[test]
fn an_unregistered_layer_refuses_at_boot() {
    let rows = vec![Registered {
        key: "upper-wire",
        composes_over: std::borrow::Cow::Borrowed(&["floor-wire"]),
        composed_over: None,
    }];
    let err = check_composition(&rows).expect_err("nothing registered the floor wire");
    assert_eq!(
        err,
        CompositionError::UnregisteredLayer {
            transport: "upper-wire",
            layer: "floor-wire",
        }
    );
}

#[test]
fn every_claimed_plane_key_is_a_registered_plane() {
    let registry = linked_registry();
    for claim in &linked_claims() {
        if core_claims().any(|core| core.plane == claim.plane) {
            continue;
        }
        assert!(
            registry.resolve(PluginKind::Plane, claim.plane).is_some(),
            "claim names plane `{}`, which is not registered",
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

#[cfg(linked_every_plane_door)]
#[test]
fn the_seal_answers_now_that_every_claim_names_a_registered_transport() {
    let sealed = seal(&crate::LINKED, Dropped::NONE, TransportSettings::default())
        .expect("every claim names a live transport");
    assert_eq!(sealed.claims.len(), linked_claims().len());
    assert_eq!(sealed.precedence.len(), sealed.claims.len());
}

#[cfg(linked_axis_transport_door)]
#[test]
fn the_operators_body_cap_reaches_every_mounted_planes_transport() {
    const CAP: usize = 1024;
    static SEEN: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());
    fn recording(settings: &TransportSettings) -> Arc<HostWire> {
        SEEN.lock()
            .expect("seen")
            .push(settings.request_body_max_bytes);
        let own = crate::LINKED
            .transports
            .iter()
            .find(|r| (r.composes_over)().is_empty());
        (own.expect("a wire that opens its own socket").build)(settings)
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

#[cfg(linked_axis_transport_door)]
#[test]
fn the_fold_builds_bottom_up_in_composes_over_order() {
    let rows = linked_rows();
    let linked: Vec<&str> = crate::LINKED
        .transports
        .iter()
        .flat_map(|r| (r.claims)())
        .collect();
    let built: Vec<&str> = rows.iter().map(|r| r.key).collect();
    let position = |key: &str| built.iter().position(|k| *k == key);
    let mut last = None;
    for entry in crate::LINKED.transports {
        let key = (entry.key)();

        let at = position(key).unwrap_or_else(|| panic!("`{key}` is not built"));
        assert!(
            last.is_none_or(|l| l < at),
            "`{key}` was built out of the table's order: {built:?}"
        );
        last = Some(at);

        let past: Vec<&str> = (entry.claims)().into_iter().filter(|c| *c != key).collect();
        for (n, claim) in past.iter().enumerate() {
            assert_eq!(
                position(claim),
                Some(at + 1 + n),
                "`{claim}`, which `{key}` claims, is not registered right after it: {built:?}"
            );
        }
        if !past.is_empty() {
            last = Some(at + past.len());
        }
    }
    for row in &rows {
        assert_eq!(
            row.composed_over, None,
            "`{}` was built over a layer",
            row.key
        );
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
        for layer in row.composes_over.iter() {
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

#[test]
fn transports_layered_over_each_other_refuse_at_boot() {
    let own = *crate::LINKED
        .transports
        .iter()
        .find(|r| (r.composes_over)().is_empty())
        .expect("a wire that opens its own socket");
    let rows = [
        LinkedTransport {
            key: || "upper",
            composes_over: || &["lower"],
            ..own
        },
        LinkedTransport {
            key: || "lower",
            composes_over: || &["upper"],
            ..own
        },
    ];
    let Err(refusal) = compose(&rows, Dropped::NONE, &TransportSettings::default()) else {
        panic!("no order builds either");
    };
    assert!(matches!(
        refusal,
        BootRefusal::Uncomposable { transport: "upper" }
    ));
    assert!(refusal.to_string().contains("`upper`"));
}

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
        let (door, wire) = crate::root::doors::served(
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
            wire,
            door,
        }]
    })
}

#[test]
fn a_dropped_in_transports_offered_points_reach_the_guest_list_seal() {
    use busbar_contract::abi::auth::AuthPoints;
    use busbar_kernel::guest::{Claimant, GuestList, GuestRefusal, Line, LineAuth, Route};
    let fixture = &dropped_doors()[0];
    assert_eq!(
        crate::root::serve::transport_offers(&[], dropped_doors()),
        [(fixture.key, crate::root::doors::offers_unstated())],
        "a dropped-in door stating no record offers what an unstated record does"
    );
    let peer_only = DroppedDoor {
        key: fixture.key,
        claims: fixture.claims.clone(),
        composes_over: Vec::new(),
        offered: AuthPoints::PEER,
        upgrades: Vec::new(),
        wire: fixture.wire.clone(),
        door: fixture.door.clone(),
    };
    let offers = crate::root::serve::transport_offers(&[], std::slice::from_ref(&peer_only));
    assert_eq!(offers, [(fixture.key, AuthPoints::PEER)]);
    let line = Line {
        route: Route {
            methods: busbar_contract::abi::transport::route::METHOD_POST,
            path_form: busbar_contract::abi::transport::route::PATH_EXACT,
            path: "/a".into(),
            fields: Vec::new(),
            rung: 0,
        },
        claimant: Claimant::Plane("a".into()),
        dialect: 0,
        auth: LineAuth::Chain(vec!["chain".into()], AuthPoints::HEAD),
        upgrade: None,
        offered: offers[0].1,
    };
    assert!(
        matches!(
            GuestList::seal(vec![line]),
            Err(GuestRefusal::PointNotOffered(_))
        ),
        "a Head line on a dropped-in transport stating {{Peer}} only is refused"
    );
}

#[test]
fn a_dropped_in_transports_upgrade_lines_reach_the_guest_list_as_a_linked_ones_do() {
    use busbar_contract::abi::auth::AuthPoints;
    use busbar_kernel::guest::{Claimant, GuestList, GuestRefusal, Line, LineAuth, Route};
    let fixture = &dropped_doors()[0];
    let door = |claim: &'static str, under: Vec<&'static str>, offered, upgrades| DroppedDoor {
        key: claim,
        claims: vec![claim],
        composes_over: under,
        offered,
        upgrades,
        wire: fixture.wire.clone(),
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
            key: || "framed",
            composes_over: || &[],
            build: |_| dropped_doors()[0].wire.clone(),
            claims: || vec!["framed"],
            upgrades: Vec::new,
            lines: Vec::new,
            offered: || AuthPoints::PEER,
        },
        LinkedTransport {
            key: || "upgraded",
            composes_over: || &["framed"],
            build: |_| dropped_doors()[0].wire.clone(),
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
    let offers = crate::root::serve::transport_offers(&[], &dropped);
    assert_eq!(
        offers,
        crate::root::serve::transport_offers(&linked, &[]),
        "the same offered sets as the linked rows'"
    );
    let line = |carriers: &[&str], offers: &[crate::root::serve::TransportOffer]| Line {
        route: Route {
            methods: busbar_contract::abi::transport::route::METHOD_GET,
            path_form: busbar_contract::abi::transport::route::PATH_EXACT,
            path: "/a".into(),
            fields: Vec::new(),
            rung: 0,
        },
        claimant: Claimant::Plane("a".into()),
        dialect: 0,
        auth: LineAuth::Chain(vec!["chain".into()], AuthPoints::HEAD),
        upgrade: carriers
            .contains(&"upgraded")
            .then(|| "upgraded".to_string()),
        offered: offers
            .iter()
            .find(|(c, _)| *c == "upgraded")
            .expect("the upgrade claim offers")
            .1,
    };
    let on_dropped = line(&carriers, &offers);
    assert_eq!(on_dropped.upgrade.as_deref(), Some("upgraded"));
    assert_eq!(
        on_dropped.offered,
        AuthPoints::PEER,
        "it takes its framer's set"
    );
    assert_eq!(
        on_dropped,
        line(
            &crate::root::serve::upgrade_carriers(&linked, &[]),
            &crate::root::serve::transport_offers(&linked, &[])
        ),
        "the same line as on the linked rows"
    );
    assert!(
        matches!(
            GuestList::seal(vec![on_dropped]),
            Err(GuestRefusal::PointNotOffered(_))
        ),
        "a Head line on the dropped-in upgrade claim is refused as on the linked one"
    );
}

fn the_wires_linked_row() -> LinkedTransport {
    LinkedTransport {
        key: || dropped_doors()[0].key,
        composes_over: || &[],
        build: |_| dropped_doors()[0].wire.clone(),
        claims: || vec![dropped_doors()[0].key],
        upgrades: Vec::new,
        lines: Vec::new,
        offered: crate::root::doors::offers_unstated,
    }
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

fn one_door() -> Dropped {
    Dropped {
        doors: std::borrow::Cow::Borrowed(&dropped_doors()[..1]),
    }
}

#[test]
fn composing_an_owned_inventory_retains_its_dynamic_declaration_without_leaking_it() {
    let mut door = dropped_doors()[0].clone();
    door.composes_over = vec!["declared-layer"];
    let key = door.key;
    let built = compose(
        &[],
        Dropped {
            doors: std::borrow::Cow::Owned(vec![door]),
        },
        &TransportSettings::default(),
    )
    .unwrap();
    let row = &built.iter().find(|(row, _)| row.key == key).unwrap().0;
    assert_eq!(row.composes_over.as_ref(), &["declared-layer"]);
    assert!(matches!(&row.composes_over, std::borrow::Cow::Owned(_)));
    assert!(matches!(
        check_composition(&built.iter().map(|(r, _)| r.clone()).collect::<Vec<_>>()),
        Err(CompositionError::UnregisteredLayer { .. })
    ));
}

fn rows_of(
    slot: &'static std::sync::OnceLock<Vec<LinkedTransport>>,
    rows: impl FnOnce() -> Vec<LinkedTransport>,
) -> &'static [LinkedTransport] {
    slot.get_or_init(rows)
}

#[cfg(linked_axis_transport_door)]
#[test]
fn a_dropped_in_wire_rides_the_one_fold_in_place_of_its_linked_row() {
    let wire = &dropped_doors()[0];
    static ROWS: std::sync::OnceLock<Vec<LinkedTransport>> = std::sync::OnceLock::new();
    let with = crate::root::linked::Linked {
        transports: rows_of(&ROWS, || {
            [crate::LINKED.transports, &[the_wires_linked_row()]].concat()
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

#[test]
fn a_dropped_in_wire_on_a_linked_key_is_refused_as_a_second_linked_row_is() {
    let wire = &dropped_doors()[0];
    let row = the_wires_linked_row();
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
