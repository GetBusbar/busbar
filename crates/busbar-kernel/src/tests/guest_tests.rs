// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A guest list's order and its match: CG-62 precedence first, predicates above none at an equal
//! path, a claimant's rung among its own lines; two claimants meeting at an equal precedence refused;
//! a path hit on another method is a method miss, not no-route; a listener mixing lines that need
//! `Peer` with lines that need a per-request point refused, a `none` line neutral to that rule and
//! gated by the listener's `Peer` verdict; a line needing a point its transport does not offer
//! refused.

use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD, POINT_HEAD_BODY, POINT_PEER};
use busbar_contract::abi::transport::route::{
    FIELD_PRESENT, FIELD_VALUE_PREFIX, METHOD_GET, METHOD_POST, PATH_EXACT, PATH_PATTERN,
    PATH_PREFIX,
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
        offered: AuthPoints(POINT_PEER | POINT_HEAD | POINT_HEAD_BODY),
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
    let signed = with_field(
        bare.clone(),
        FIELD_VALUE_PREFIX,
        "authorization",
        b"AWS4-HMAC",
    );
    let list = GuestList::seal(vec![line("plain", bare), line("signed", signed)]).unwrap();
    assert_eq!(list.lines()[0].claimant, Claimant::Plane("signed".into()));
    let hit = |fields: &[(&str, &[u8])]| match list.matched("POST", "/v1/chat/completions", fields)
    {
        Matched::Line(l) => l.claimant.clone(),
        other => panic!("{other:?}"),
    };
    assert_eq!(
        hit(&[("Authorization", b"AWS4-HMAC-SHA256 x")]),
        Claimant::Plane("signed".into())
    );
    assert_eq!(
        hit(&[("Authorization", b"Bearer x")]),
        Claimant::Plane("plain".into())
    );
}

/// RED: path precedence is the first key; predicates break ties only at an equal path precedence. An
/// exact path without predicates is tried before a prefix line that names one, even when that
/// predicate holds for the request.
#[test]
fn an_exact_path_beats_a_prefix_line_with_predicates() {
    let exact = route(METHOD_POST, PATH_EXACT, "/v1/chat/completions");
    let prefix = with_field(
        route(METHOD_POST, PATH_PREFIX, "/v1/"),
        FIELD_PRESENT,
        "authorization",
        b"",
    );
    let list = GuestList::seal(vec![line("prefix", prefix), line("exact", exact)]).unwrap();
    assert_eq!(list.lines()[0].claimant, Claimant::Plane("exact".into()));
    let Matched::Line(l) = list.matched(
        "POST",
        "/v1/chat/completions",
        &[("Authorization", b"Bearer x")],
    ) else {
        panic!("matched");
    };
    assert_eq!(l.claimant, Claimant::Plane("exact".into()));
}

/// RED: a claimant's rung orders its own lines at an equal precedence.
#[test]
fn a_claimants_rung_orders_its_own_lines() {
    let mut first = with_field(
        route(METHOD_POST, PATH_PATTERN, "/{*rest}"),
        FIELD_PRESENT,
        "x-a",
        b"",
    );
    first.rung = 2;
    let mut second = with_field(
        route(METHOD_POST, PATH_PATTERN, "/{*rest}"),
        FIELD_PRESENT,
        "x-b",
        b"",
    );
    second.rung = 1;
    let list = GuestList::seal(vec![line("a", first), line("a", second)]).unwrap();
    assert_eq!(
        list.lines()[0].route.fields[0].1,
        "x-b",
        "the lower rung first"
    );
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
    assert!(
        GuestList::seal(vec![line("a", r()), line("a", r())]).is_ok(),
        "one claimant"
    );
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
        GuestList::seal(vec![line("a", pre(b"AWS4")), line("b", pre(b"AWS4"))]).is_err(),
        "the same prefix can hold for both, at one precedence"
    );
    // A longer prefix is more specific (its own precedence), so it is ordered ahead, never refused.
    let ordered =
        GuestList::seal(vec![line("a", pre(b"AWS4")), line("b", pre(b"AWS4-HMAC"))]).unwrap();
    assert_eq!(
        ordered.lines()[0].claimant,
        Claimant::Plane("b".into()),
        "the longer prefix is tried first"
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

/// A line whose auth is a one-auth chain over `points`.
fn authed(claimant: &str, path: &str, points: AuthPoints) -> Line {
    Line {
        auth: LineAuth::Chain(vec!["chain".into()], points),
        ..line(claimant, route(METHOD_POST, PATH_EXACT, path))
    }
}

/// RED (THE DESIGN §6 step 3, boot refusals): a listener where some lines need `Peer` and others
/// need a per-request point without it is refused, naming the lines on each side (a `none` line on
/// neither); a listener whose lines all need `Peer`, and one where none does, seal.
#[test]
fn a_listener_mixing_peer_and_non_peer_lines_is_refused() {
    let both = AuthPoints(AuthPoints::PEER.bits() | AuthPoints::HEAD.bits());
    let Err(GuestRefusal::PeerMix(mix)) = GuestList::seal(vec![
        authed("a", "/a", both),
        authed("b", "/b", AuthPoints::HEAD),
        line("open", route(METHOD_GET, PATH_EXACT, "/open")),
    ]) else {
        panic!("a mixed listener is refused");
    };
    let paths = |lines: &[Line]| -> Vec<String> {
        let mut p: Vec<String> = lines.iter().map(|l| l.route.path.clone()).collect();
        p.sort();
        p
    };
    assert_eq!(paths(&mix.0), ["/a"], "the lines that need Peer");
    assert_eq!(
        paths(&mix.1),
        ["/b"],
        "the lines that need a per-request point only"
    );

    assert!(
        GuestList::seal(vec![
            authed("a", "/a", AuthPoints::PEER),
            authed("b", "/b", both),
        ])
        .is_ok(),
        "every line needs Peer"
    );
    assert!(
        GuestList::seal(vec![
            authed("a", "/a", AuthPoints::HEAD),
            authed("b", "/b", AuthPoints::HEAD_BODY),
            line("open", route(METHOD_GET, PATH_EXACT, "/open")),
        ])
        .is_ok(),
        "no line needs Peer"
    );
}

/// RED (THE DESIGN §6 step 3, boot refusals): a line whose auth needs a point its transport does
/// not offer is refused, naming the line; one whose points its transport offers seals.
#[test]
fn an_auth_needing_a_point_its_transport_does_not_offer_is_refused() {
    let head_only = AuthPoints::HEAD;
    let on = |points: AuthPoints, offered: AuthPoints| Line {
        offered,
        ..authed("a", "/a", points)
    };
    let Err(GuestRefusal::PointNotOffered(refused)) =
        GuestList::seal(vec![on(AuthPoints::HEAD_BODY, head_only)])
    else {
        panic!("a point the transport does not offer is refused");
    };
    assert_eq!(refused.route.path, "/a");
    assert!(
        matches!(
            GuestList::seal(vec![on(AuthPoints::PEER, head_only)]),
            Err(GuestRefusal::PointNotOffered(_))
        ),
        "Peer on a transport offering only Head"
    );
    assert!(
        GuestList::seal(vec![on(AuthPoints::HEAD, head_only)]).is_ok(),
        "a point the transport offers seals"
    );
    let offered = AuthPoints(POINT_PEER | POINT_HEAD);
    assert!(
        GuestList::seal(vec![on(AuthPoints(POINT_PEER | POINT_HEAD), offered)]).is_ok(),
        "every needed point offered"
    );
}

/// RED (THE DESIGN §6 step 3, l.926-927; step 7, l.969-970): a `none` line needs no point, so it is
/// neutral to the `Peer` mix rule: a `Peer` chain and a `none` line on one listener seal, and the
/// sealed list is connection-gated, so the `none` line sits behind the connection's `Peer` verdict.
/// A `Peer` chain and a `Head` chain on one listener are still refused. A list with no `Peer` line
/// is not gated.
#[test]
fn a_none_line_is_neutral_to_the_peer_mix_and_sits_behind_the_peer_verdict() {
    let gated = GuestList::seal(vec![
        authed("a", "/a", AuthPoints::PEER),
        line("h", route(METHOD_GET, PATH_EXACT, "/healthz")),
    ])
    .expect("a Peer chain and a none line seal");
    assert!(
        gated.connection_gated(),
        "the none line sits behind the Peer verdict"
    );

    let Err(GuestRefusal::PeerMix(mix)) = GuestList::seal(vec![
        authed("a", "/a", AuthPoints::PEER),
        authed("b", "/b", AuthPoints::HEAD),
        line("h", route(METHOD_GET, PATH_EXACT, "/healthz")),
    ]) else {
        panic!("a Peer chain and a Head chain on one listener are refused");
    };
    assert_eq!(mix.0.len(), 1, "the Peer line");
    assert_eq!(
        mix.1.len(),
        1,
        "the Head line; the none line is on neither side"
    );
    assert_eq!(mix.1[0].route.path, "/b");

    let open = GuestList::seal(vec![
        authed("b", "/b", AuthPoints::HEAD),
        line("h", route(METHOD_GET, PATH_EXACT, "/healthz")),
    ])
    .expect("no line needs Peer");
    assert!(!open.connection_gated(), "no Peer line, no connection gate");
}

/// RED (ARCHITECT ruling (a) on #953; THE DESIGN §6 step 3, §11 extensions-blob defaults): the
/// offered set is what the transport's Statement `extensions` record states. A transport stating
/// `{Peer}` only refuses a line that needs `Head`; a transport stating no record offers `{Head,
/// HeadBody}`, so a `Head` line seals on it and a `Peer` line is refused: a transport offering
/// `Peer` states the record.
#[test]
fn the_offered_points_record_decides_what_a_line_may_need() {
    use busbar_contract::abi::mechanism::extensions::encode;
    use busbar_contract::abi::transport::check::check_offered_points;
    use busbar_contract::abi::transport::EXT_OFFERED_POINTS;
    let peer_only =
        check_offered_points(&encode(&[(EXT_OFFERED_POINTS, &POINT_PEER.to_le_bytes())]))
            .expect("a {Peer} record reads");
    let unstated = check_offered_points(&[]).expect("no record reads");
    let on = |points: AuthPoints, offered: AuthPoints| Line {
        offered,
        ..authed("a", "/a", points)
    };
    let Err(GuestRefusal::PointNotOffered(refused)) =
        GuestList::seal(vec![on(AuthPoints::HEAD, peer_only)])
    else {
        panic!("a Head line on a transport stating {{Peer}} only is refused");
    };
    assert_eq!(refused.route.path, "/a");
    assert!(
        GuestList::seal(vec![on(AuthPoints::PEER, peer_only)]).is_ok(),
        "a Peer line on a transport stating {{Peer}} seals"
    );
    assert_eq!(unstated, AuthPoints(POINT_HEAD | POINT_HEAD_BODY));
    assert!(
        GuestList::seal(vec![on(AuthPoints::HEAD, unstated)]).is_ok(),
        "no record offers Head"
    );
    assert!(
        matches!(
            GuestList::seal(vec![on(AuthPoints::PEER, unstated)]),
            Err(GuestRefusal::PointNotOffered(_))
        ),
        "no record offers no Peer"
    );
}

/// RED (audit contract-src #11, `check_route_view` never called): a line whose route no request can
/// match is refused when the list is sealed, naming the line and the rule, never mounted as a dead
/// route: no method, an unrooted exact path, a broken pattern, an upper-case field name.
#[test]
fn a_line_no_request_can_match_is_refused_at_seal() {
    let refused = |r: Route| match GuestList::seal(vec![
        line("ok", route(METHOD_GET, PATH_EXACT, "/ok")),
        line("bad", r),
    ]) {
        Err(GuestRefusal::Malformed(bad)) => {
            assert_eq!(bad.0.claimant, Claimant::Plane("bad".into()));
            bad.1.field
        }
        other => panic!("a dead route sealed: {other:?}"),
    };
    assert_eq!(refused(route(0, PATH_EXACT, "/v1/x")), "route.methods");
    assert_eq!(
        refused(route(METHOD_POST, PATH_EXACT, "v1/x")),
        "route.path"
    );
    assert_eq!(
        refused(route(METHOD_POST, PATH_PATTERN, "/a/{*rest}/b")),
        "route.path.pattern"
    );
    assert_eq!(
        refused(with_field(
            route(METHOD_POST, PATH_EXACT, "/v1/x"),
            FIELD_PRESENT,
            "Authorization",
            b"",
        )),
        "route.field.name"
    );
}
