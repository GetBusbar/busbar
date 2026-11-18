// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6 section 7.1: the `k1` keyset cursor.

use std::collections::HashMap;

use super::*;

fn q(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn names(page: &Page<String>) -> Vec<&str> {
    page.items.iter().map(String::as_str).collect()
}

async fn refusal(resp: Response) -> (u16, String) {
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

fn all() -> Vec<String> {
    ["a", "b", "c", "d", "e"].map(String::from).to_vec()
}

#[test]
fn keyset_no_skip_on_delete() {
    let w = window(&q(&[("limit", "2")]), "keys", "f", 200)
        .ok()
        .unwrap();
    let p1 = keyset(all(), &w, "keys", "f", |s| s.clone(), false);
    assert_eq!(names(&p1), vec!["a", "b"]);
    let cursor = p1.next_cursor.expect("more rows remain");
    // The row the cursor points at is deleted before the next page is read.
    let remaining: Vec<String> = all().into_iter().filter(|s| s != "b").collect();
    let w2 = window(
        &q(&[("limit", "2"), ("cursor", cursor.as_str())]),
        "keys",
        "f",
        200,
    )
    .ok()
    .unwrap();
    let p2 = keyset(remaining, &w2, "keys", "f", |s| s.clone(), false);
    assert_eq!(
        names(&p2),
        vec!["c", "d"],
        "nothing skipped, nothing repeated"
    );
    let cursor = p2.next_cursor.expect("one row remains");
    let w3 = window(
        &q(&[("limit", "2"), ("cursor", cursor.as_str())]),
        "keys",
        "f",
        200,
    )
    .ok()
    .unwrap();
    let p3 = keyset(all(), &w3, "keys", "f", |s| s.clone(), false);
    assert_eq!(names(&p3), vec!["e"]);
    assert!(
        p3.next_cursor.is_none(),
        "a finite list ends with a null cursor"
    );
}

#[test]
fn desc_list_terminates() {
    let mut rows = all();
    rows.reverse();
    let w = window(&q(&[("limit", "3")]), "audit", "f", 200)
        .ok()
        .unwrap();
    let p1 = keyset(rows.clone(), &w, "audit", "f", |s| s.clone(), true);
    assert_eq!(names(&p1), vec!["e", "d", "c"]);
    let cursor = p1.next_cursor.expect("more rows remain");
    let w2 = window(&q(&[("cursor", cursor.as_str())]), "audit", "f", 200)
        .ok()
        .unwrap();
    let p2 = keyset(rows, &w2, "audit", "f", |s| s.clone(), true);
    assert_eq!(names(&p2), vec!["b", "a"]);
    assert!(p2.next_cursor.is_none());
}

#[tokio::test]
async fn cursor_bound_to_filter() {
    let w = window(&q(&[("limit", "1")]), "audit", "f1", 200)
        .ok()
        .unwrap();
    let cursor = keyset(all(), &w, "audit", "f1", |s| s.clone(), false)
        .next_cursor
        .unwrap();
    let other_filter = window(&q(&[("cursor", cursor.as_str())]), "audit", "f2", 200);
    let (status, body) = refusal(*other_filter.err().unwrap()).await;
    assert_eq!(status, 400);
    assert!(body.contains("cursor_mismatch"), "{body}");
    let other_op = window(&q(&[("cursor", cursor.as_str())]), "keys", "f1", 200);
    let (status, body) = refusal(*other_op.err().unwrap()).await;
    assert_eq!(status, 400);
    assert!(body.contains("cursor_mismatch"), "{body}");
    assert!(window(&q(&[("cursor", cursor.as_str())]), "audit", "f1", 200).is_ok());
}

#[tokio::test]
async fn legacy_offset_cursor_refused() {
    // The old cursor was hex("o:<n>").
    let legacy = hex::encode("o:10");
    for bad in [legacy.as_str(), "", "zz", "k1.audit", "k1.audit.f.nothex"] {
        let (status, body) = refusal(
            *window(&q(&[("cursor", bad)]), "audit", "f", 200)
                .err()
                .expect("refused"),
        )
        .await;
        assert_eq!(status, 400, "{bad}");
        assert!(body.contains("malformed_cursor"), "{bad}: {body}");
    }
}

#[test]
fn filter_digest_follows_the_filters() {
    let a = filter_digest(
        &q(&[("action", "hook"), ("limit", "5")]),
        &["action", "resource"],
    );
    let b = filter_digest(
        &q(&[("action", "hook"), ("limit", "9")]),
        &["action", "resource"],
    );
    let c = filter_digest(&q(&[("action", "key")]), &["action", "resource"]);
    assert_eq!(a, b, "limit is not a filter");
    assert_ne!(a, c);
}

#[test]
fn every_current_operation_and_filter_binding_round_trips() {
    for op in [
        "groups",
        "kinds.auth",
        "view.core.routing.pools",
        "view.auth.id.with.dots.state",
    ] {
        for filter in ["", "0123456789abcdef"] {
            let first = window(&q(&[("limit", "1")]), op, filter, 200).ok().unwrap();
            let page = keyset(all(), &first, op, filter, |item| item.clone(), false);
            let cursor = page.next_cursor.unwrap();
            let next = window(&q(&[("cursor", &cursor)]), op, filter, 200)
                .expect("a cursor issued by this list must be accepted by the same list");
            assert_eq!(next.after.as_deref(), Some("a"), "{op} {filter:?}");
            assert_eq!(
                names(&keyset(
                    all(),
                    &next,
                    op,
                    filter,
                    |item| item.clone(),
                    false
                )),
                vec!["b", "c", "d", "e"]
            );
        }
    }
}
