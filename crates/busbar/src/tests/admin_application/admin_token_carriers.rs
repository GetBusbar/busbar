// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::json;

const X_ADMIN_TOKEN: &str = "x-admin-token";

#[tokio::test]
async fn test_admin_blank_header_token_rejected() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_519C591CB1AB";
    const WITNESS: &str = "actual root case test_admin_blank_header_token_rejected completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_blank_header_token_rejected-actual-store",
    );
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([7u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root_unhydrated(document, &directory, &module).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    let r_blank = client
        .get(&url)
        .header(X_ADMIN_TOKEN, "")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_blank.status().as_u16(),
        401,
        "a blank x-admin-token must be rejected (treated as absent), got {}",
        r_blank.status()
    );

    let r_ok = client
        .get(&url)
        .header(X_ADMIN_TOKEN, "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_ok.status().as_u16(),
        200,
        "a correct x-admin-token must authorize, got {}",
        r_ok.status()
    );

    handle.abort();
    println!("{WITNESS}");
}

/// Regression for the admin-token carrier-level timing oracle: the two admin
/// carriers (Authorization: Bearer and x-admin-token) are combined with a bitwise-OR fold, NOT a
/// short-circuiting `||`. Behaviorally this means EITHER carrier alone authorizes, AND a request
/// presenting BOTH carriers is authorized whenever EITHER matches — regardless of which one. We
/// drive it through the real router so the inline fold in `auth_middleware` is exercised:
///   - correct Bearer + wrong x-admin-token  → authorized (header compare ran, didn't veto)
///   - wrong Bearer  + correct x-admin-token  → authorized (Bearer miss didn't short-circuit away
///                                               the header compare)
///   - wrong + wrong                          → 401
#[tokio::test]
async fn test_admin_token_both_carriers_or_fold_no_short_circuit() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_C0414CC4DE55";
    const WITNESS: &str =
        "actual root case test_admin_token_both_carriers_or_fold_no_short_circuit completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_token_both_carriers_or_fold_no_short_circuit-actual-store",
    );
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([7u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root_unhydrated(document, &directory, &module).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    let r = client
        .get(&url)
        .bearer_auth("admintok")
        .header(X_ADMIN_TOKEN, "wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "correct Authorization header + wrong x-admin-token must authorize (OR fold), got {}",
        r.status()
    );

    let r = client
        .get(&url)
        .bearer_auth("wrong")
        .header(X_ADMIN_TOKEN, "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "wrong Authorization header + correct x-admin-token must authorize (header compare must run), got {}",
        r.status()
    );

    let r = client
        .get(&url)
        .bearer_auth("wrong")
        .header(X_ADMIN_TOKEN, "also-wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        401,
        "both carriers wrong must be rejected"
    );

    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_token_not_acceptable_via_vendor_carriers() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_504D6DFEDC13";
    const WITNESS: &str =
        "actual root case test_admin_token_not_acceptable_via_vendor_carriers completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_token_not_acceptable_via_vendor_carriers-actual-store",
    );
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([7u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root_unhydrated(document, &directory, &module).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/v1/admin/keys");

    for carrier in ["x-api-key", "x-goog-api-key"] {
        let r_get = client
            .get(&url)
            .header(carrier, "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(
            r_get.status().as_u16(),
            401,
            "admin secret via {carrier} (GET) must NOT reach the admin surface, got {}",
            r_get.status()
        );

        let r_post = client
            .post(&url)
            .header(carrier, "admintok")
            .json(&json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r_post.status().as_u16(),
            401,
            "admin secret via {carrier} (POST) must NOT reach the admin surface, got {}",
            r_post.status()
        );
    }

    let r_authz = client
        .get(&url)
        .bearer_auth("admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_authz.status().as_u16(),
        200,
        "the Authorization-header credential must authorize the admin surface, got {}",
        r_authz.status()
    );
    let r_hdr = client
        .get(&url)
        .header(X_ADMIN_TOKEN, "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_hdr.status().as_u16(),
        200,
        "x-admin-token: admintok must authorize the admin surface, got {}",
        r_hdr.status()
    );

    handle.abort();
    println!("{WITNESS}");
}
