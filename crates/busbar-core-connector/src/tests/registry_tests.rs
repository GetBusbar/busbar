// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The registry view: which entry serves which scheme and as which claim; two entries claiming one
//! scheme, an entry with no claim and a layer nobody serves are refused.

use std::sync::Arc;

use super::*;
use crate::support::{Knobs, TestDoor};

fn entry(name: &str, claims: &[&'static str], under: &[&'static str]) -> Entry {
    Entry {
        door: Arc::new(TestDoor::new(name, claims, under, Knobs::default())),
        alpn: Vec::new(),
    }
}

#[test]
fn each_scheme_is_served_by_one_entry_as_one_claim() {
    let v = Transports::new(vec![
        entry("under", &["under"], &[]),
        entry("over", &["over", "over-s", "over-t"], &["under"]),
    ])
    .unwrap();
    let s = v.serving("over-s").unwrap();
    assert_eq!(s.entry.door.facts().name, "over");
    assert_eq!(s.claim, 1);
    assert_eq!(v.serving("under").unwrap().claim, 0);
    assert!(v.serving("nothing").is_none());
    assert_eq!(
        v.view(),
        [
            ("under".into(), "under".into(), 0),
            ("over".into(), "over".into(), 0),
            ("over-s".into(), "over".into(), 1),
            ("over-t".into(), "over".into(), 2),
        ]
    );
}

#[test]
fn two_entries_claiming_one_scheme_are_refused() {
    let r = Transports::new(vec![
        entry("a", &["x", "y"], &[]),
        entry("b", &["y"], &[]),
    ]);
    assert_eq!(
        r.unwrap_err(),
        ViewRefusal::ClaimedTwice {
            scheme: "y".into(),
            first: "a".into(),
            second: "b".into(),
        }
    );
}

#[test]
fn a_layer_nobody_serves_and_an_entry_with_no_claim_are_refused() {
    let r = Transports::new(vec![entry("over", &["over"], &["missing"])]);
    assert!(matches!(r, Err(ViewRefusal::UnservedLayer { .. })));
    let r = Transports::new(vec![entry("none", &[], &[])]);
    assert!(matches!(r, Err(ViewRefusal::NoClaim { .. })));
}
