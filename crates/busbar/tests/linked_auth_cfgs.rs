// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH-AXIS CFGS ARE THE MANIFEST'S ROWS, READ AS DATA. `build.rs` declares and sets three
//! cfgs off `[package.metadata.busbar.linked-axes]` and `[package.metadata.busbar.operator-auth]`,
//! and the root's auth suites gate on them instead of spelling a plugin's feature:
//!
//! - `linked_axis_auths`: SOME row on the auth axis is enabled;
//! - `linked_every_auth`: EVERY row on the auth axis is enabled (each scheme's style is served);
//! - `linked_operator_auth`: the row the `operator-auth` table names is enabled.
//!
//! RED: a cfg used but never declared is a compile error (`check-cfg`), and a cfg declared but set
//! from the wrong rows fails here — each is held to the rows and this build's enabled features.

mod common;

/// The auth axis's manifest name, as `[package.metadata.busbar.linked-axes]` writes it.
const AUTH_AXIS: &str = "auths";

#[test]
fn the_auth_axis_cfgs_are_read_off_the_manifest_rows() {
    let on = common::enabled_features();
    let auth_rows: Vec<String> = common::manifest_table("package.metadata.busbar.linked-axes")
        .into_iter()
        .filter(|(_, axes)| axes.split_whitespace().any(|a| a == AUTH_AXIS))
        .map(|(feature, _)| feature)
        .collect();
    assert!(
        !auth_rows.is_empty(),
        "the manifest links no row on the `{AUTH_AXIS}` axis"
    );
    assert_eq!(
        cfg!(linked_axis_auths),
        auth_rows.iter().any(|f| on.contains(f.as_str())),
        "linked_axis_auths: some of {auth_rows:?} enabled in {on:?}"
    );
    assert_eq!(
        cfg!(linked_every_auth),
        auth_rows.iter().all(|f| on.contains(f.as_str())),
        "linked_every_auth: all of {auth_rows:?} enabled in {on:?}"
    );
    let operator: String = common::manifest_table("package.metadata.busbar.operator-auth")
        .into_iter()
        .find(|(k, _)| k == "row")
        .map(|(_, row)| row)
        .expect("`[package.metadata.busbar.operator-auth]` states its `row`");
    assert!(
        auth_rows.contains(&operator),
        "the operator credential's row `{operator}` is on the `{AUTH_AXIS}` axis"
    );
    assert_eq!(
        cfg!(linked_operator_auth),
        on.contains(operator.as_str()),
        "linked_operator_auth: `{operator}` enabled in {on:?}"
    );
}
