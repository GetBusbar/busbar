// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TRUST-ADMIN-PRODUCER-DESIGN r3 §4.2a, condition B-C1, test R8 (gate half): the trust decision
//! authority a plane admin route may decide under comes only from the admin gate's own verdict,
//! under the rules the gate applies to `POST /trust/approve` and `/trust/revoke` themselves.

use super::{trust_decision_authority, AdminDoor, VerbAllowList};
use busbar_contract::auth::Principal;
use busbar_contract::authz::{Grants, Scope};

#[test]
fn an_open_door_is_anonymous_with_both_rulings() {
    let authority = trust_decision_authority(&AdminDoor::Open).expect("an open door grants");
    assert_eq!(authority.principal, "anonymous");
    assert!(authority.approve && authority.revoke);
}

#[test]
fn a_refused_door_grants_nothing() {
    assert_eq!(trust_decision_authority(&AdminDoor::Denied), None);
}

#[test]
fn a_read_only_grant_grants_nothing() {
    let door = AdminDoor::Identified(Principal::from_id("op"), Grants::of(Scope::ReadOnly));
    assert_eq!(trust_decision_authority(&door), None);
}

#[test]
fn a_full_grant_grants_both_rulings_to_its_principal() {
    let door = AdminDoor::Identified(Principal::from_id("op"), Grants::of(Scope::Full));
    let authority = trust_decision_authority(&door).expect("a full grant decides");
    assert_eq!(authority.principal, "op");
    assert!(authority.approve && authority.revoke);
}

#[test]
fn a_verb_list_naming_only_revoke_grants_only_revoke() {
    let door = AdminDoor::Listed(
        Principal::from_id("op"),
        Grants::of(Scope::Full),
        VerbAllowList {
            rungs: Grants::default(),
            named: std::collections::BTreeSet::from(["trust_revoke".to_string()]),
        },
    );
    let authority = trust_decision_authority(&door).expect("revoke is named");
    assert!(
        !authority.approve,
        "a non-empty verb list must name the verb"
    );
    assert!(authority.revoke);
}
