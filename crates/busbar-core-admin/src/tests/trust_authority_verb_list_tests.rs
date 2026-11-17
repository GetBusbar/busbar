// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TRUST-ADMIN-PRODUCER-DESIGN r3 §4.2a, condition B-C1, test R8 (gate half, named verbs): with
//! the admin verb table installed, a non-empty verb list must name the trust verb itself.

use busbar_contract::auth::Principal;
use busbar_contract::authz::{Grants, Scope};
use busbar_kernel::auth::{trust_decision_authority, AdminDoor, VerbAllowList};

/// The production verb table this crate installs, so the gate can name a request's verb.
fn verb_table() {
    busbar_kernel::admin::seam::install_admin_verb_table(
        busbar_kernel::admin::seam::AdminVerbTable {
            rung_of: crate::admin_codec::verbs::named_rung,
            verb_at: crate::admin_codec::verbs::name_at,
        },
    );
}

#[test]
fn a_verb_list_naming_only_revoke_grants_only_revoke() {
    verb_table();
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
