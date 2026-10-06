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
        entry("lower", &["lower"], &[]),
        entry("upper", &["upper", "upper-s", "upper-t"], &["lower"]),
    ])
    .unwrap();
    let s = v.serving("upper-s").unwrap();
    assert_eq!(s.entry.door.facts().name, "upper");
    assert_eq!(s.claim, 1);
    assert_eq!(v.serving("lower").unwrap().claim, 0);
    assert!(v.serving("absent").is_none());
    assert_eq!(
        v.view(),
        [
            ("lower".into(), "lower".into(), 0),
            ("upper".into(), "upper".into(), 0),
            ("upper-s".into(), "upper".into(), 1),
            ("upper-t".into(), "upper".into(), 2),
        ]
    );
}

#[test]
fn two_entries_claiming_one_scheme_are_refused() {
    let r = Transports::new(vec![
        entry("first", &["p", "q"], &[]),
        entry("second", &["q"], &[]),
    ]);
    assert_eq!(
        r.unwrap_err(),
        ViewRefusal::ClaimedTwice {
            scheme: "q".into(),
            first: "first".into(),
            second: "second".into(),
        }
    );
}

#[test]
fn a_layer_nobody_serves_and_an_entry_with_no_claim_are_refused() {
    let r = Transports::new(vec![entry("upper", &["upper"], &["gone"])]);
    assert!(matches!(r, Err(ViewRefusal::UnservedLayer { .. })));
    let r = Transports::new(vec![entry("empty", &[], &[])]);
    assert!(matches!(r, Err(ViewRefusal::NoClaim { .. })));
}

fn door(d: TestDoor) -> Entry {
    Entry {
        door: Arc::new(d),
        alpn: Vec::new(),
    }
}

/// THE ADDRESS CARRIER IS THE DECLARATION'S (ARCHITECT, p2-transport-carrier): the first CARRIER, in
/// the order the entries are declared, whose claim serves a port. Never a framer (even one whose
/// claim reads a port), never a carrier that serves no port, never the one that happened to load
/// first: the same entries declared in the other order answer the other carrier.
#[test]
fn the_address_carrier_is_the_first_declared_carrier_serving_a_port() {
    use busbar_contract::abi::transport::ROLE_FRAMER;
    let framer = || door(TestDoor::identity("framed").with_role(ROLE_FRAMER));
    let pathed = || door(TestDoor::identity("pathed").unported());
    let (a, b) = (|| door(TestDoor::identity("a")), || door(TestDoor::identity("b")));
    let first = Transports::new(vec![framer(), pathed(), a(), b()]).unwrap();
    assert_eq!(
        first.address_carrier().map(|e| e.door.facts().name.clone()),
        Some("a".to_owned())
    );
    let swapped = Transports::new(vec![framer(), pathed(), b(), a()]).unwrap();
    assert_eq!(
        swapped.address_carrier().map(|e| e.door.facts().name.clone()),
        Some("b".to_owned())
    );
    // RED: a framer that states a port, and a carrier serving none, are never the address carrier.
    let ported_framer = TestDoor::identity("framed")
        .with_role(ROLE_FRAMER)
        .with_port();
    let none = Transports::new(vec![door(ported_framer), pathed()]).unwrap();
    assert!(none.address_carrier().is_none());
}
