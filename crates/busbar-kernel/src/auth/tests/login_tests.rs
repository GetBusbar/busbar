// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::off_path::auth::login::missing_login_axis;

#[test]
fn the_lent_settings_are_wiped() {
    let mut lent = serde_json::json!({
        "client_secret": "REAL-SECRET-XYZ",
        "client_id": "client-abc",
        "nested": {"token": "inner-secret", "list": ["a-secret", 7]},
    });
    crate::config::secret::wipe_strings(&mut lent);
    assert_eq!(
        lent,
        serde_json::json!({
            "client_secret": "",
            "client_id": "",
            "nested": {"token": "", "list": ["", 7]},
        })
    );
}

#[test]
fn a_login_method_with_no_auth_axis_is_refused_in_1_5_5_words() {
    let refusal = missing_login_axis("idp", "idp-plugin");
    assert_eq!(
        refusal,
        "identity-providers.idp (module 'idp-plugin') could not be loaded as a `kind: auth` login \
         plugin: no `kind: auth` plugin answers to 'idp-plugin'"
    );
    assert!(
        !refusal.contains("no plugin named or aliased"),
        "the registry's words stay internal: {refusal}"
    );
}

#[tokio::test]
async fn without_a_registered_flow_the_kernel_has_no_hosted_login_response() {
    let response = unregistered_browser_response();
    assert_eq!(
        response.status().as_u16(),
        404,
        "no flow registered, no page"
    );
    let body = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        axum::body::to_bytes(response.into_body(), 64 * 1024),
    )
    .await
    .expect("the fallback response body is bounded")
    .unwrap();
    assert!(
        !String::from_utf8(body.to_vec()).unwrap().contains("<html"),
        "the kernel renders no login page"
    );
}
