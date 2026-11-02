// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::guest::{Claimant, Route};
use busbar_contract::abi::auth::AuthPoints;
use busbar_contract::abi::transport::route::{METHOD_GET, METHOD_POST, PATH_EXACT};

fn head(path: &str, fields: &[(&str, &str)], query: Option<&str>) -> Head {
    let mut h = Head::default();
    h.method = "POST".into();
    h.target = path.into();
    h.fields = fields
        .iter()
        .map(|(n, v)| (n.to_string(), v.as_bytes().to_vec()))
        .collect();
    h.query = query.map(str::to_owned);
    h
}

fn guests() -> GuestList {
    let line = |path: &str, methods, auth| Line {
        route: Route {
            methods,
            path_form: PATH_EXACT,
            path: path.into(),
            fields: Vec::new(),
            rung: 0,
        },
        claimant: Claimant::Plane("actual-owner-policy".into()),
        dialect: 0,
        auth,
        upgrade: None,
        offered: AuthPoints::HEAD,
    };
    GuestList::seal(vec![
        line(
            "/v1/messages",
            METHOD_POST,
            LineAuth::Chain(vec!["actual-auth".into()], AuthPoints::HEAD),
        ),
        line("/healthz", METHOD_GET, LineAuth::None),
    ])
    .unwrap()
}

fn handin(head: Head) -> HandIn {
    HandIn {
        owner: 7,
        generation: 3,
        auth: 7000,
        unit: UnitRef { id: 9, mac: 11 },
        line: 0,
        conn: 1,
        stream: 1,
        framing: Some(1),
        head,
    }
}

#[test]
fn handin_names_exactly_the_declared_line_and_the_lists_matched_method_and_path() {
    let list = guests();
    let original = head("/v1/messages", &[], None);
    assert!(matched_handin_line(&list, Some(0), 0, &original).is_some());
    assert!(matched_handin_line(&list, Some(1), 0, &original).is_none());
    assert!(matched_handin_line(&list, None, 0, &original).is_none());
    assert!(matched_handin_line(&list, Some(0), 99, &original).is_none());
    assert!(matched_handin_line(&list, Some(0), 0, &head("/different", &[], None)).is_none());
    let mut wrong_method = original.clone();
    wrong_method.method = "GET".into();
    assert!(matched_handin_line(&list, Some(0), 0, &wrong_method).is_none());
}

#[test]
fn an_auth_line_needs_a_fixed_identity_and_a_none_line_needs_no_auth_verdict() {
    let list = guests();
    let h = handin(head("/v1/messages", &[], None));
    let line = &list.lines()[0];
    for fixed in [None, Some(Fixed::Denied), Some(Fixed::Overloaded)] {
        assert!(!handin_state_admits(
            line,
            &h,
            0,
            3,
            false,
            None,
            &[],
            fixed
        ));
    }
    assert!(handin_state_admits(
        line,
        &h,
        0,
        3,
        false,
        None,
        &[],
        Some(Fixed::Admitted(0))
    ));
    assert!(!handin_state_admits(
        line,
        &h,
        1,
        3,
        false,
        None,
        &[],
        Some(Fixed::Admitted(0))
    ));
    assert!(!handin_state_admits(
        line,
        &h,
        0,
        4,
        false,
        None,
        &[],
        Some(Fixed::Admitted(0))
    ));
    assert!(!handin_state_admits(
        line,
        &h,
        0,
        3,
        true,
        None,
        &[],
        Some(Fixed::Admitted(0))
    ));
    let mut open = handin(head("/healthz", &[], None));
    open.head.method = "GET".into();
    open.line = 1;
    assert!(matched_handin_line(&list, Some(1), 1, &open.head).is_some());
    assert!(handin_state_admits(
        &list.lines()[1],
        &open,
        1,
        3,
        false,
        None,
        &[],
        None
    ));
}

#[test]
fn declared_credentials_must_be_absent_and_query_names_remain_case_sensitive() {
    let strips = [Strip::field("authorization"), Strip::query("key")];
    for (h, present) in [
        (head("/v1/messages", &[("Authorization", "x")], None), true),
        (head("/v1/messages", &[], Some("a=1&key=x")), true),
        (head("/v1/messages", &[], Some("Key=x&keys=1")), false),
        (
            head("/v1/messages", &[("x-other", "1")], Some("a=1")),
            false,
        ),
    ] {
        assert_eq!(still_present(&strips, &h), present);
        let list = guests();
        assert_eq!(
            handin_state_admits(
                &list.lines()[0],
                &handin(h),
                0,
                3,
                false,
                None,
                &strips,
                Some(Fixed::Admitted(0))
            ),
            !present
        );
    }
}

#[test]
fn handin_preserves_the_original_sanitized_request_bytes() {
    let list = guests();
    let original = head(
        "/v1/messages",
        &[("authorization", "credential"), ("x-safe", "kept")],
        Some("key=x&keep=1"),
    );
    let strips = [Strip::field("authorization"), Strip::query("key")];
    let sanitized = original.stripped(&strips).unwrap();
    assert!(handin_state_admits(
        &list.lines()[0],
        &handin(sanitized.clone()),
        0,
        3,
        false,
        Some(&original),
        &strips,
        Some(Fixed::Admitted(0))
    ));
    let mut changed = sanitized;
    changed.fields[0].1 = b"changed".to_vec();
    assert!(!handin_state_admits(
        &list.lines()[0],
        &handin(changed),
        0,
        3,
        false,
        Some(&original),
        &strips,
        Some(Fixed::Admitted(0))
    ));
}
