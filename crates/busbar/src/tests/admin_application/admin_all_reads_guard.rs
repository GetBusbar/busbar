// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::json::JsonContainerTrait as _;
use busbar_contract::json::{self, JsonValueTrait as _};

#[tokio::test]
async fn test_admin_v1_all_reads_require_admin_token() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_623A8A6529A7";
    const WITNESS: &str = "actual root case test_admin_v1_all_reads_require_admin_token completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_v1_all_reads_require_admin_token-actual-store",
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
    let document: json::Value =
        json::parse_value(busbar_core_admin::v1::json::openapi_document().as_bytes())
            .expect("the actual embedded admin document parses");
    let reads: Vec<&str> = document["paths"]
        .as_object()
        .expect("actual documented paths")
        .iter()
        .filter(|(path, operations)| !path.contains('{') && operations["get"].is_object())
        .map(|(path, _)| path)
        .collect();
    assert!(
        reads.len() >= 14,
        "the actual core static read surface cannot lose the original fourteen routes: {reads:?}"
    );
    for path in reads {
        let none = client
            .get(format!("http://{addr}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            none.status().as_u16(),
            401,
            "{path} must reject a request with NO admin token"
        );
        let body = json::parse_value(&none.bytes().await.unwrap()).unwrap();
        assert_eq!(
            body["error"]["code"], "unauthorized",
            "{path}: the admin 401 speaks the v1 envelope: {body}"
        );

        let wrong = client
            .get(format!("http://{addr}{path}"))
            .header("authorization", "Bearer not-the-token")
            .send()
            .await
            .unwrap();
        assert_eq!(
            wrong.status().as_u16(),
            401,
            "{path} must reject a request with the WRONG admin token"
        );
    }

    handle.abort();
    println!("{WITNESS}");
}
