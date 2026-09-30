// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A guest list's order and its match: CG-62 precedence first, predicates above none at an equal
//! path, a claimant's rung among its own lines; two claimants meeting at an equal precedence refused;
//! a path hit on another method is a method miss, not no-route.

use busbar_contract::abi::transport::route::{
    FIELD_PRESENT, FIELD_VALUE_PREFIX, METHOD_GET, METHOD_POST, PATH_EXACT, PATH_PATTERN,
};

use super::*;

fn route(methods: u32, path_form: u32, path: &str) -> Route {
    Route {
        methods,
        path_form,
        path: path.into(),
        fields: Vec::new(),
        rung: 0,
    }
}

fn line(claimant: &str, route: Route) -> Line {
    Line {
        route,
        claimant: Claimant::Plane(claimant.into()),
        dialect: 0,
        auth: LineAuth::None,
        upgrade: None,
    }
}

fn with_field(mut r: Route, op: u32, name: &str, value: &[u8]) -> Route {
    r.fields.push((op, name.into(), value.to_vec()));
    r
}

fn names(list: &GuestList) -> Vec<&str> {
    list.lines().iter().map(|l| l.route.path.as_str()).collect()
}

#[test]
fn the_most_specific_path_is_tried_first() {
    let list = GuestList::seal(vec![
        line("a", route(METHOD_POST, PATH_PATTERN, "/{name}/v1/messages")),
        line("b", route(METHOD_POST, PATH_EXACT, "/v1/messages")),
    ])
    .unwrap();
    assert_eq!(names(&list), ["/v1/messages", "/{name}/v1/messages"]);
    let Matched::Line(l) = list.matched("POST", "/v1/messages", &[]) else {
        panic!("matched");
    };
    assert_eq!(l.claimant, Claimant::Plane("b".into()));
}

/// RED: at an equal path, the line that names a field predicate ranks above the one that does not,
/// and is chosen only when its predicate holds.
#[test]
fn a_line_with_predicates_ranks_above_one_without() {
    let bare = route(METHOD_POST, PATH_EXACT, "/v1/chat/completions");
    let signed = with_field(bare.clone(), FIELD_VALUE_PREFIX, "authorization", b"AWS4-HMAC");
    let list = GuestList::seal(vec![line("plain", bare), line("signed", signed)]).unwrap();
    assert_eq!(list.lines()[0].claimant, Claimant::Plane("signed".into()));
    let hit = |fields: &[(&str, &[u8])]| match list.matched("POST", "/v1/chat/completions", fields) {
        Matched::Line(l) => l.claimant.clone(),
        other => panic!("{other:?}"),
    };
    assert_eq!(
        hit(&[("Authorization", b"AWS4-HMAC-SHA256 x")]),
        Claimant::Plane("signed".into())
    );
    assert_eq!(hit(&[("Authorization", b"Bearer x")]), Claimant::Plane("plain".into()));
}

/// RED: a claimant's rung orders its own lines at an equal precedence.
#[test]
fn a_claimants_rung_orders_its_own_lines() {
    let mut first = with_field(route(METHOD_POST, PATH_PATTERN, "/{*rest}"), FIELD_PRESENT, "x-a", b"");
    first.rung = 2;
    let mut second =
        with_field(route(METHOD_POST, PATH_PATTERN, "/{*rest}"), FIELD_PRESENT, "x-b", b"");
    second.rung = 1;
    let list = GuestList::seal(vec![line("llm", first), line("llm", second)]).unwrap();
    assert_eq!(list.lines()[0].route.fields[0].1, "x-b", "the lower rung first");
    let both: &[(&str, &[u8])] = &[("x-a", b"1"), ("x-b", b"1")];
    let Matched::Line(l) = list.matched("POST", "/anything", both) else {
        panic!("matched");
    };
    assert_eq!(l.route.fields[0].1, "x-b");
}

/// RED: two claimants whose lines could match one request at an equal precedence are refused,
/// naming both; disjoint methods, paths or predicate values never meet.
#[test]
fn two_claimants_at_an_equal_precedence_are_refused() {
    let r = || route(METHOD_POST, PATH_EXACT, "/v1/messages");
    let Err(GuestRefusal::EqualPrecedence(pair)) =
        GuestList::seal(vec![line("a", r()), line("b", r())])
    else {
        panic!("refused");
    };
    assert_eq!(
        (pair.0.claimant.clone(), pair.1.claimant.clone()),
        (Claimant::Plane("a".into()), Claimant::Plane("b".into()))
    );
    assert!(GuestList::seal(vec![line("a", r()), line("a", r())]).is_ok(), "one claimant");
    assert!(
        GuestList::seal(vec![
            line("a", r()),
            line("b", route(METHOD_GET, PATH_EXACT, "/v1/messages"))
        ])
        .is_ok(),
        "disjoint methods"
    );
    let pre = |v: &[u8]| with_field(r(), FIELD_VALUE_PREFIX, "authorization", v);
    assert!(
        GuestList::seal(vec![line("a", pre(b"AWS4")), line("b", pre(b"Bearer"))]).is_ok(),
        "prefixes that rule each other out"
    );
    assert!(
        GuestList::seal(vec![line("a", pre(b"AWS4")), line("b", pre(b"AWS4-HMAC"))]).is_err(),
        "prefixes that can both hold"
    );
}

/// RED: a path hit on another method is a method miss on that line (405), never no-route; a later
/// line that admits the method wins over the miss; nothing matching is no-route.
#[test]
fn a_path_hit_on_another_method_is_a_method_miss() {
    let list = GuestList::seal(vec![
        line("models", route(METHOD_GET, PATH_EXACT, "/v1/models")),
        line("msgs", route(METHOD_POST, PATH_EXACT, "/v1/messages")),
    ])
    .unwrap();
    match list.matched("POST", "/v1/models", &[]) {
        Matched::MethodMiss(l) => assert_eq!(l.claimant, Claimant::Plane("models".into())),
        other => panic!("{other:?}"),
    }
    assert_eq!(list.matched("GET", "/nope", &[]), Matched::NoRoute);

    let list = GuestList::seal(vec![
        line("get", route(METHOD_GET, PATH_EXACT, "/x")),
        line("any", route(METHOD_POST, PATH_PATTERN, "/{*rest}")),
    ])
    .unwrap();
    let Matched::Line(l) = list.matched("POST", "/x", &[]) else {
        panic!("the later line admits POST");
    };
    assert_eq!(l.claimant, Claimant::Plane("any".into()));
}
