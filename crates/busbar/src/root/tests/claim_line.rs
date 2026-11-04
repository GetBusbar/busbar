// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::transport::route::{METHOD_ANY, METHOD_POST};
use busbar_kernel::guest::{GuestList, Matched};

fn declared(verb: &str) -> crate::root::loader::dispatch::kinds::plane::OwnedClaim {
    crate::root::loader::dispatch::kinds::plane::OwnedClaim {
        verb: verb.into(),
        target: "/object/bucket/key with spaces".into(),
        carrier: "foreign-wire".into(),
        flags: CLAIM_EXACT | CLAIM_OPEN,
        refusal_dialect: 0,
        arrival_span: String::new(),
    }
}

#[test]
fn explicit_wildcard_claim_admits_an_opaque_method_and_target() {
    let claim = declared("*");
    let (line, adapter_method) = claim_line("foreign-plane", 4, &claim, &[], &[], &[]).unwrap();
    assert_eq!(line.route.methods, METHOD_ANY);
    assert_eq!(line.route.path, claim.target);
    assert_eq!(adapter_method, None);
    let guests = GuestList::seal(vec![line]).unwrap();
    let Matched::Line(admitted) = guests.matched("READ OBJECT", &claim.target, &[]) else {
        panic!("an explicitly declared wildcard must admit an opaque transport method");
    };
    assert_eq!(admitted.route.rung, 4);
    assert_eq!(
        guests.matched("READ OBJECT", "another object", &[]),
        Matched::NoRoute
    );
}

#[test]
fn exact_method_claims_keep_their_filter_and_unknown_verbs_refuse() {
    let claim = declared("POST");
    let (line, adapter_method) = claim_line("foreign-plane", 0, &claim, &[], &[], &[]).unwrap();
    assert_eq!(line.route.methods, METHOD_POST);
    assert_eq!(adapter_method, Some(RouteMethod::Post));
    let guests = GuestList::seal(vec![line]).unwrap();
    assert!(matches!(
        guests.matched("POST", &claim.target, &[]),
        Matched::Line(_)
    ));
    assert!(matches!(
        guests.matched("READ OBJECT", &claim.target, &[]),
        Matched::MethodMiss(_)
    ));
    for verb in ["READ OBJECT", "post", "", "**"] {
        let error = claim_line("foreign-plane", 0, &declared(verb), &[], &[], &[]).unwrap_err();
        assert!(error.contains("names a verb the data listener does not serve"));
    }
}
