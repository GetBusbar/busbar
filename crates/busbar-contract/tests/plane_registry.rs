//! THE PLANE DECLARATION LIST, proven from outside the crate: the pure folds and the claim guard
//! over a list a test writes, and the process slot exercised once — the only order this binary can
//! exercise it in, since a process has one slot.

use busbar_contract::plane::registry::*;

const fn decl(key: &'static str, config_section: &'static str) -> PlaneDeclaration {
    PlaneDeclaration {
        key,
        fallback: false,
        config_section,
        scope_kinds: &[],
        subject_noun: "thing",
        admin_noun: "thing",
        audit_kind: "thing",
        card_signing_domain: None,
        card_kid_prefix: None,
        owned_config_sections: &[],
        operator_routes: &[],
    }
}
const ONE: PlaneDeclaration = PlaneDeclaration {
    scope_kinds: &["pool", "one_thing"],
    ..decl("one", "ones")
};
const TWO: PlaneDeclaration = PlaneDeclaration {
    scope_kinds: &["two_thing"],
    ..decl("two", "twos")
};
const TWO_AGAIN: PlaneDeclaration = PlaneDeclaration {
    config_section: "twos-from-a-crate",
    ..TWO
};
const THREE_CLAIMS_POOLS: PlaneDeclaration = PlaneDeclaration {
    owned_config_sections: &["pools"],
    ..decl("three", "threes")
};

/// The installed copy wins a same-key collision, the survivors take the built-in order, and the
/// skipped key is reported rather than dropped on the floor.
#[test]
fn the_fold_dedups_by_key_reports_the_skip_and_keeps_canonical_order() {
    let fold = merged_boot_plane_decls(&[TWO_AGAIN], &[ONE, TWO]);
    let keys: Vec<&str> = fold.decls.iter().map(|d| d.key).collect();
    assert_eq!(keys, ["one", "two"]);
    assert_eq!(fold.decls[1].config_section, "twos-from-a-crate");
    assert_eq!(fold.skipped, ["two"]);
}

/// A plane registered after the canonical set sorts stably at the tail.
#[test]
fn a_key_outside_the_canonical_order_sorts_at_the_tail() {
    let fold = merged_boot_plane_decls(&[TWO], &[ONE]);
    let keys: Vec<&str> = fold.decls.iter().map(|d| d.key).collect();
    assert_eq!(keys, ["one", "two"]);
}

#[test]
fn the_section_fold_dedups_against_the_trailing_sections() {
    let sections = config_sections_from(&[ONE, TWO], &["export", "twos"]);
    assert_eq!(sections, ["ones", "twos", "export"]);
}

#[test]
fn a_claim_on_a_reserved_section_is_refused() {
    let err = check_owned_config_claims(&[THREE_CLAIMS_POOLS], CORE_OWNED_CONCRETE_SECTIONS)
        .expect_err("`pools` is reserved");
    assert!(err.contains("`three`") && err.contains("`pools`"), "{err}");
}

#[test]
#[should_panic(expected = "plane-owned-config dup-claim guard")]
fn the_fold_refuses_a_reserved_claim() {
    let _ = merged_boot_plane_decls(&[THREE_CLAIMS_POOLS], &[]);
}

/// The process slot, exercised once per test binary: install, freeze on first read, refuse a
/// second install, and index the scope kinds base-first without re-counting a re-declared base.
#[test]
fn the_process_slot_freezes_on_first_read_and_indexes_scope_kinds_base_first() {
    assert!(install(vec![ONE, TWO]));
    assert!(!first_read());
    let keys: Vec<&str> = plane_decls().iter().map(|d| d.key).collect();
    assert_eq!(keys, ["one", "two"]);
    assert!(first_read());
    assert!(!install(Vec::new()));
    assert_eq!(plane_key_index("two"), 1);
    assert_eq!(plane_key_index("none"), u8::MAX);
    assert_eq!(plane_key_at(0), Some("one"));
    assert_eq!(plane_key_at(9), None);
    assert_eq!(scope_kind_at(0), Some("pool"));
    assert_eq!(scope_kind_at(1), Some("one_thing"));
    assert_eq!(scope_kind_at(2), Some("two_thing"));
    assert_eq!(scope_kind_at(3), None);
    for idx in 0..3 {
        let kind = scope_kind_at(idx).unwrap();
        assert_eq!(scope_kind_index(kind), Some(idx));
    }
    assert_eq!(
        plane_decl_for_config_section("twos").map(|d| d.key),
        Some("two")
    );
    assert!(plane_decl_for("none").is_none());
}

// ── THE OPERATOR ROUTE ROWS ─────────────────────────────────────────────────────────────────────────

const CONNECT: OperatorRoute = OperatorRoute {
    method: "POST",
    path: "things/{name}/connect",
    summary: "Connect one thing",
    ok_description: "Connected",
};
const HEALTH: OperatorRoute = OperatorRoute {
    method: "GET",
    path: "things/{name}/health",
    summary: "One thing's reachability",
    ok_description: "OK (`reachable` may be null)",
};
const ONE_ROUTED: PlaneDeclaration = PlaneDeclaration {
    operator_routes: &[CONNECT, HEALTH],
    ..decl("one", "ones")
};
const TWO_ROUTED: PlaneDeclaration = PlaneDeclaration {
    operator_routes: &[HEALTH],
    ..decl("two", "twos")
};

/// A declaration's routes survive the fold in its own declared order, and the fold's order across
/// planes is the fold's — which is what a renderer folding one document out of the whole list needs,
/// because the document's order is then the list's order rather than a hash map's.
#[test]
fn operator_route_rows_fold_in_declaration_order_across_the_whole_list() {
    let fold = merged_boot_plane_decls(&[], &[ONE_ROUTED, decl("two", "twos")]);
    let rendered: Vec<(&str, &str, &str, &str)> = fold
        .decls
        .iter()
        .flat_map(|d| d.operator_routes)
        .map(|r| (r.method, r.path, r.summary, r.ok_description))
        .collect();
    assert_eq!(
        rendered,
        [
            (
                "POST",
                "things/{name}/connect",
                "Connect one thing",
                "Connected"
            ),
            (
                "GET",
                "things/{name}/health",
                "One thing's reachability",
                "OK (`reachable` may be null)"
            ),
        ]
    );
}

/// TWO PLANES MAY NOT ANSWER ONE ROUTE. A fold that inserts by path keeps whichever row it met last,
/// so the document would then name a surface the router does not mount — the refusal names both
/// planes so the composition root's author knows which two.
#[test]
fn two_planes_claiming_one_route_is_refused_and_names_both() {
    let err = check_operator_route_claims(&[ONE_ROUTED, TWO_ROUTED])
        .expect_err("two planes claim GET things/{name}/health");
    assert!(err.contains("GET things/{name}/health"), "{err}");
    assert!(err.contains("`one`") && err.contains("`two`"), "{err}");
}

/// The same set with the collision removed passes, so the test above is measuring the collision and
/// not the guard refusing everything it is handed.
#[test]
fn distinct_routes_across_planes_are_accepted() {
    assert_eq!(
        check_operator_route_claims(&[ONE_ROUTED, decl("two", "twos")]),
        Ok(())
    );
}
