// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DES-331 R21 (§B5.2, §B10.4, §B10.8), through the real root over the actual Store: a node in
//! restore quarantine serves admin reads and the allow-listed writes, refuses every other admin
//! write with the typed `restore_quarantine` refusal, answers `/readyz` with its reasons, and
//! refuses the data plane while `/livez` still answers.

use busbar_contract::json::{self, JsonContainerTrait as _, JsonValueTrait as _};

#[tokio::test]
async fn a_quarantined_node_serves_reads_and_the_allow_list_and_refuses_the_rest() {
    const CHILD: &str = "BUSBAR_ADMIN_RESTORE_QUARANTINE_R21";
    const WITNESS: &str = "actual root case a_quarantined_node_serves_reads_and_the_allow_list_and_refuses_the_rest completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) =
        crate::distribution::rig::actual_store_facade("admin-restore-quarantine-actual-store");
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    // Built as JSON text through the facade (DEP-3): every string is quoted by the facade itself.
    let quoted = |text: &str| json::to_string(text).expect("a string quotes");
    let document = json::parse_value(
        format!(
            r#"{{"providers":{{}},"models":{{}},"advanced":{{}},
               "auth":{{"chain":[],"admin_auth":[{op}],"signing_key":{{"file":{signing}}}}},
               "store":{{"module":{module},"settings":{settings}}},
               "identity-providers":{{{op}:{{"module":{op},"token":{{"file":{token}}}}}}}}}"#,
            op = quoted(operator),
            signing = quoted(&signing_key.to_string_lossy()),
            module = quoted(&module),
            settings = settings,
            token = quoted(&operator_token.to_string_lossy()),
        )
        .as_bytes(),
    )
    .expect("the deployment document parses");
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root_facade(&document, &directory, &module).await;

    // This process was launched with --restore-quarantine.
    let gate = busbar_kernel::persistence::restore::gate();
    assert_eq!(
        gate.boot(None, true),
        Some(busbar_kernel::persistence::restore::Reason::Flag)
    );

    let client = reqwest::Client::new();
    let admin = format!("http://{addr}/api/v1/admin");

    // Reads are served.
    let read = client
        .get(format!("{admin}/keys"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(read.status().as_u16(), 200);

    // A write outside the allow-list is refused, typed, without Retry-After.
    let refused = client
        .post(format!("{admin}/keys"))
        .header("x-admin-token", "admintok")
        .json(&json::json!({"name": "k"}))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status().as_u16(), 503);
    assert!(refused.headers().get("retry-after").is_none());
    let body = json::parse_value(&refused.bytes().await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"].as_str(), Some("unavailable"));
    assert_eq!(body["error"]["reason"].as_str(), Some("restore_quarantine"));
    assert_eq!(body["error"]["details"]["restore_epoch"].as_u64(), Some(0));
    assert!(body["error"]["details"]["allowed"]
        .as_array()
        .unwrap()
        .iter()
        .any(|allowed| allowed.as_str() == Some("POST /api/v1/admin/store-restore")));

    // An allow-listed delete passes the quarantine gate (and then answers on its own merits).
    let delete = client
        .delete(format!("{admin}/keys/vk_absent"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_ne!(delete.status().as_u16(), 503);

    // /readyz names the quarantine; /livez still answers; the data plane is refused.
    let ready = client
        .get(format!("http://{addr}/readyz"))
        .send()
        .await
        .unwrap();
    assert_eq!(ready.status().as_u16(), 503);
    let ready = json::parse_value(&ready.bytes().await.unwrap()).unwrap();
    assert_eq!(ready["ready"].as_bool(), Some(false));
    assert_eq!(ready["reasons"][0].as_str(), Some("store_restored"));
    let live = client
        .get(format!("http://{addr}/livez"))
        .send()
        .await
        .unwrap();
    assert_eq!(live.status().as_u16(), 200);
    let data = client
        .post(format!("http://{addr}/v1/chat/completions"))
        .json(&json::json!({"model": "m", "messages": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(data.status().as_u16(), 503);
    let data = json::parse_value(&data.bytes().await.unwrap()).unwrap();
    assert_eq!(data["error"]["reason"].as_str(), Some("restore_quarantine"));

    handle.abort();
    println!("{WITNESS}");
}
