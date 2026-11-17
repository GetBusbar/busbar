// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TRUST-ADMIN-PRODUCER-DESIGN r3 §4.2a, condition B-C1, test R8 (gate half, named verbs): the
//! admin gate, with this crate's production verb table installed, admits a token whose verb list
//! names only `trust_revoke` to revoke and refuses it approve. The trust decision authority a plane
//! route decides under is built from exactly these two gate answers
//! (`auth::trust_decision_authority`).

use busbar_contract::auth::Principal;
use busbar_contract::authz::Grants;
use busbar_kernel::auth::{admin_door_admits, AdminDoor, VerbAllowList};

#[test]
fn a_verb_list_naming_only_revoke_grants_only_revoke() {
    crate::ensure_seam();
    let named: std::collections::BTreeSet<String> = ["trust_revoke".to_string()].into();
    let reach = named
        .iter()
        .filter_map(|verb| crate::admin_codec::verbs::named_rung(verb))
        .fold(Grants::default(), Grants::with);
    let door = AdminDoor::Listed(
        Principal::from_id("key:vk_console"),
        reach,
        VerbAllowList {
            rungs: Grants::default(),
            named,
        },
    );
    assert!(
        admin_door_admits(&door, "POST", "/api/v1/admin/trust/revoke"),
        "revoke is named, so it is granted"
    );
    assert!(
        !admin_door_admits(&door, "POST", "/api/v1/admin/trust/approve"),
        "a non-empty verb list must name the verb: approve is refused"
    );
}
