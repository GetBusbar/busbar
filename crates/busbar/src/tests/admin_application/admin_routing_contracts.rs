// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::json::{self, JsonValueTrait as _};

#[tokio::test]
async fn test_api_root_unmatched_paths_speak_the_admin_envelope() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_A058FBB7CB1F";
    const WITNESS: &str =
        "actual root case test_api_root_unmatched_paths_speak_the_admin_envelope completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_api_root_unmatched_paths_speak_the_admin_envelope-actual-store",
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
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root_unhydrated(document, &directory, &module).await;
    let client = reqwest::Client::new();
    for path in ["/api/v1/admin/nonexistent", "/api/junk"] {
        let r = client
            .get(format!("http://{addr}{path}"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 404, "{path}");
        let body = json::parse_value(&r.bytes().await.unwrap()).unwrap();
        assert_eq!(body["error"]["code"], "not_found", "{path}: {body}");
        assert!(
            body["error"]["type"].is_null(),
            "{path}: never the vendor envelope: {body}"
        );
    }

    let r = client
        .delete(format!("http://{addr}/api/v1/admin/info"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 405);
    assert_eq!(
        json::parse_value(&r.bytes().await.unwrap()).unwrap()["error"]["code"],
        "method_not_allowed"
    );
    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn an_unmatched_admin_path_reads_no_body() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_A42D1FF17118";
    const WITNESS: &str = "actual root case an_unmatched_admin_path_reads_no_body completed";
    isolated!(CHILD, WITNESS);
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "an_unmatched_admin_path_reads_no_body-actual-store",
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
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root_unhydrated(document, &directory, &module).await;
    let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = "POST /api/v1/admin/nonexistent HTTP/1.1\r\nhost: x\r\nx-admin-token: admintok\r\n\
                content-length: 64\r\n\r\n";
    conn.write_all(head.as_bytes()).await.unwrap();
    let mut answer = [0u8; 12];
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        conn.read_exact(&mut answer),
    )
    .await;
    assert!(read.is_ok(), "the 404 answers before any body byte is sent");
    assert_eq!(&answer, b"HTTP/1.1 404");
    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_admin_auth_read() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_D97D7C9D0C7B";
    const WITNESS: &str = "actual root case test_admin_v1_admin_auth_read completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) =
        crate::distribution::rig::actual_store("test_admin_v1_admin_auth_read-actual-store");
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
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root_unhydrated(document, &directory, &module).await;
    let client = reqwest::Client::new();
    let body = json::parse_value(
        &client
            .get(format!("http://{addr}/api/v1/admin/admin-auth"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["configured"], true);

    assert!(body["modules"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m == busbar_kernel::config::operator_provider()));

    handle.abort();
    println!("{WITNESS}");
}
