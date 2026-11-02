// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[test]
fn auth_modules_list_inbound_rows_only() {
    crate::dist_root_install::install();
    let declares = busbar_kernel::preflight::root_rows()
        .auth_chain_module
        .expect("the actual root classifies inbound auth doors");
    let door = busbar_kernel::preflight::linked_auth_rows()
        .iter()
        .find(|row| declares(row.2))
        .expect("the actual distribution links an inbound auth row")
        .2;
    let inbound: busbar_kernel::preflight::LinkedAuth = ("inbound-row", "canonical-name", door);
    assert_eq!(
        busbar_kernel::preflight::inbound_auth_names(&[inbound]),
        vec!["inbound-row"]
    );
}
