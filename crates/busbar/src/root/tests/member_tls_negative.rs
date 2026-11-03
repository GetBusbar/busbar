// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Actual Root → MCP trust failures. The CA is configured only on the named member.

use crate::root::door_steps::tests::tool_door::{
    send, send_as, try_rig_tools, Rig, TlsToolServer, CALL,
};
use axum::http::StatusCode;
use busbar_contract::secret_ref::SecretRef;
use serde_yaml::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

fn member(server: &TlsToolServer) -> Value {
    let mut tools = server.section();
    tools["fs"]["allow_private"] = Value::Bool(true);
    tools["fs"]["tls"] = serde_yaml::to_value(serde_json::json!({
        "ca_cert_pem": server.ca_pem,
    }))
    .unwrap();
    tools
}

fn root_rig(instance: &'static str, port: u16, tools: Value) -> Result<Rig, String> {
    let rig = try_rig_tools(instance, port, tools)?;
    assert!(
        rig.live.served_facts.need_trust.contains(&"settings.*.tls"),
        "the actual MCP descriptor must select member TLS settings"
    );
    Ok(rig)
}

async fn call(rig: &Rig, name: &str) -> serde_json::Value {
    let request = CALL.replace("fs_read_file", name);
    let (status, bytes) = tokio::time::timeout(
        Duration::from_secs(5),
        send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &request,
            "tools/call",
            Some(name),
        ),
    )
    .await
    .expect("the actual MCP call settles within its existing request budget");
    assert_eq!(
        status,
        StatusCode::OK,
        "the tool result keeps its JSON-RPC response"
    );
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("a JSON-RPC answer");
    assert_eq!(body["id"], 30);
    assert!(rig.all_ended(), "the actual admitted unit retires");
    body
}

async fn refused_before_http(rig: &Rig, server: &mut TlsToolServer, name: &str) {
    let before = server.http_bytes.load(Ordering::SeqCst);
    let body = call(rig, name).await;
    assert_eq!(
        body["result"]["isError"], true,
        "TLS failure is a tool error: {body}"
    );
    assert_eq!(
        server.http_bytes.load(Ordering::SeqCst),
        before,
        "the rejected TLS policy must not send even partial HTTP bytes"
    );
    assert!(
        server.heard.try_recv().is_err(),
        "the rejected TLS policy must fail before any HTTP reaches the real server"
    );
}

async fn served(rig: &Rig) {
    let (status, bytes) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
    assert_eq!(status, StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("a tool answer");
    assert_eq!(body["id"], 30);
    assert_eq!(body["result"]["content"][0]["text"], "from the server");
    assert!(rig.all_ended());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn member_ca_does_not_allow_missing_wrong_roots_or_a_wrong_spki() {
    let _one = crate::root::PUBLISHING.lock().await;
    let mut server = TlsToolServer::member_ca_fixture("127.0.0.1", false, false).await;
    let other = TlsToolServer::member_ca_fixture("127.0.0.1", false, false).await;

    let mut missing = server.section();
    missing["fs"]["allow_private"] = Value::Bool(true);
    let rig = root_rig("member-ca-missing-root", server.port, missing).unwrap();
    refused_before_http(&rig, &mut server, "fs_read_file").await;

    let mut wrong_root = member(&server);
    wrong_root["fs"]["tls"]["ca_cert_pem"] = Value::String(other.ca_pem.clone());
    let rig = root_rig("member-ca-wrong-root", server.port, wrong_root).unwrap();
    refused_before_http(&rig, &mut server, "fs_read_file").await;

    let mut wrong_pin = member(&server);
    wrong_pin["fs"]["pin"]["key"] = Value::String(other.pin.clone());
    let rig = root_rig("member-ca-wrong-spki", server.port, wrong_pin).unwrap();
    refused_before_http(&rig, &mut server, "fs_read_file").await;
    server.close().await;
    other.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn member_ca_keeps_certificate_name_and_time_validation() {
    let _one = crate::root::PUBLISHING.lock().await;
    let mut wrong_name = TlsToolServer::member_ca_fixture("wrong.invalid", false, false).await;
    let rig = root_rig("member-ca-wrong-name", wrong_name.port, member(&wrong_name)).unwrap();
    refused_before_http(&rig, &mut wrong_name, "fs_read_file").await;
    wrong_name.close().await;

    let mut expired = TlsToolServer::member_ca_fixture("127.0.0.1", true, false).await;
    let rig = root_rig("member-ca-expired-cert", expired.port, member(&expired)).unwrap();
    refused_before_http(&rig, &mut expired, "fs_read_file").await;
    expired.close().await;
}

struct IdentityEnv {
    certificate: String,
    key: String,
}

impl IdentityEnv {
    fn new(server: &TlsToolServer) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let certificate = format!(
            "BUSBAR_MEMBER_TLS_NEGATIVE_CERT_{}_{}",
            std::process::id(),
            id
        );
        let key = format!(
            "BUSBAR_MEMBER_TLS_NEGATIVE_KEY_{}_{}",
            std::process::id(),
            id
        );
        std::env::set_var(&certificate, &server.client_cert_pem);
        std::env::set_var(&key, &server.client_key_pem);
        Self { certificate, key }
    }

    fn configure(&self, tools: &mut Value) {
        tools["fs"]["client_identity"] = serde_yaml::to_value(serde_json::json!({
            "cert": SecretRef::env(self.certificate.clone()),
            "key": SecretRef::env(self.key.clone()),
        }))
        .expect("ordinary identity secret references");
    }
}

impl Drop for IdentityEnv {
    fn drop(&mut self) {
        std::env::remove_var(&self.certificate);
        std::env::remove_var(&self.key);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn member_ca_preserves_mutual_tls_and_rejects_missing_or_untrusted_identity() {
    let _one = crate::root::PUBLISHING.lock().await;
    let mut server = TlsToolServer::member_ca_fixture("127.0.0.1", false, true).await;
    let rig = root_rig(
        "member-ca-mtls-missing-identity",
        server.port,
        member(&server),
    )
    .unwrap();
    refused_before_http(&rig, &mut server, "fs_read_file").await;
    assert!(!server.client_presented.load(Ordering::SeqCst));

    let other = TlsToolServer::member_ca_fixture("127.0.0.1", false, true).await;
    let wrong = IdentityEnv::new(&other);
    let mut tools = member(&server);
    wrong.configure(&mut tools);
    let rig = root_rig("member-ca-mtls-wrong-identity", server.port, tools).unwrap();
    refused_before_http(&rig, &mut server, "fs_read_file").await;
    assert!(!server.client_presented.load(Ordering::SeqCst));

    let right = IdentityEnv::new(&server);
    let mut tools = member(&server);
    right.configure(&mut tools);
    let rig = root_rig("member-ca-mtls-valid-companion", server.port, tools).unwrap();
    served(&rig).await;
    assert!(server.client_presented.load(Ordering::SeqCst));
    assert!(
        server.heard.try_recv().is_ok(),
        "the live TLS peer observed actual HTTP"
    );
    server.close().await;
    other.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn member_ca_is_scoped_to_members_and_separately_built_root_owners() {
    let _one = crate::root::PUBLISHING.lock().await;
    let mut server = TlsToolServer::member_ca_fixture("127.0.0.1", false, false).await;
    let mut tools = member(&server);
    tools["other"] = server.section()["fs"].clone();
    tools["other"]["allow_private"] = Value::Bool(true);
    let first = root_rig("member-ca-isolation-first", server.port, tools).unwrap();
    served(&first).await;
    assert!(server.heard.try_recv().is_ok());
    while server.heard.try_recv().is_ok() {}

    // The same endpoint and SPKI do not grant the sibling the successful member's TLS roots.
    // Footing::own uses the production connector without pooling; pooled-policy isolation is
    // exercised separately by the connector tests, rather than claimed by this fixture.
    refused_before_http(&first, &mut server, "other_read_file").await;

    let mut untrusted = server.section();
    untrusted["fs"]["allow_private"] = Value::Bool(true);
    // This independently composed Root has its own production connector and owner.
    let other = root_rig("member-ca-isolation-other-owner", server.port, untrusted).unwrap();
    refused_before_http(&other, &mut server, "fs_read_file").await;
    served(&first).await;
    assert!(
        server.heard.try_recv().is_ok(),
        "the original owner remains usable"
    );
    server.close().await;
}
