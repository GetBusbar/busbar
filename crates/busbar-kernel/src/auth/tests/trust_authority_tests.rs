// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TRUST-ADMIN-PRODUCER-DESIGN r3 §4.2a, condition B-C1, test R8 (gate half): the trust decision
//! authority a plane admin route may decide under comes only from the admin gate's own verdict,
//! under the rules the gate applies to `POST /trust/approve` and `/trust/revoke` themselves.

use super::{trust_decision_authority, AdminDoor};
use busbar_contract::auth::Principal;
use busbar_contract::authz::{Grants, Scope};

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
