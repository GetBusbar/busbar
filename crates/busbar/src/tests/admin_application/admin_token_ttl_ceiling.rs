// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::json::{self, JsonValueTrait as _};

#[tokio::test]
async fn proof_max_ttl_ceiling_clamps_a_rotated_token() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_1E9A713B2A6E";
    const WITNESS: &str = "actual root case proof_max_ttl_ceiling_clamps_a_rotated_token completed";
    isolated!(CHILD, WITNESS);
    const CEIL: u64 = 24 * 3600;
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "proof_max_ttl_ceiling_clamps_a_rotated_token-actual-store",
    );
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    document["auth"]["policy"] = serde_json::json!({"max_ttl": "24h"});
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root(document, &directory, &module).await;
    let client = reqwest::Client::new();
    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };
    let created = admin(client.post(format!("http://{addr}/api/v1/admin/keys")))
        .body(json::json!({"name": "rotated-under-ceiling"}).to_string())
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let created = json::parse_value(&created).unwrap();
    let id = created["id"]
        .as_str()
        .expect("the mint answers an id")
        .to_string();
    let t0 = busbar_kernel::store::now();
    let rotated = admin(client.post(format!("http://{addr}/api/v1/admin/keys/{id}/rotate")))
        .send()
        .await
        .unwrap();
    assert_eq!(rotated.status().as_u16(), 200, "the rotate answers");
    let rotated = json::parse_value(&rotated.bytes().await.unwrap()).unwrap();
    let exp = rotated["expires_at"]
        .as_u64()
        .expect("a signed-token rotate answers expires_at");
    assert!(
        exp <= busbar_kernel::store::now() + CEIL,
        "the rotated token outlives the 24h max_ttl ceiling: exp={exp}, now={t0}, ceiling={CEIL}"
    );
    assert!(
        exp >= t0 + CEIL,
        "the rotated token's default lifetime is clamped TO the ceiling, not below it: exp={exp}"
    );
    handle.abort();
    println!("{WITNESS}");
}
