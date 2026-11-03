// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Actual MCP plane calls using member TLS settings through the ordinary Root connector.
//! The fixture deliberately never uses TlsToolServer::rig/footing, which preload a CA.

use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::root::door_steps::tests::{door_boundary, tool_door};
use crate::root::serve::planes_tests::PUBLISHING;
use tool_door::{send, try_rig_tools, Rig, TlsToolServer, CALL};

fn tools(server: &TlsToolServer) -> serde_yaml::Value {
    let mut tools = server.section();
    tools["fs"]["allow_private"] = true.into();
    tools["fs"]["tls"] =
        serde_yaml::to_value(serde_json::json!({"ca_cert_pem":server.ca_pem})).unwrap();
    tools
}

fn assert_actual_member_selector(rig: &Rig) {
    assert!(
        rig.live.served_facts.need_trust.contains(&"settings.*.tls"),
        "the actual loaded MCP descriptor must select the member TLS bundle"
    );
}

async fn succeeds(rig: &Rig) {
    let (status, body) = tokio::time::timeout(
        Duration::from_secs(15),
        send(&rig.router, Some(&rig.bound_token()), CALL),
    )
    .await
    .expect("bounded actual MCP call");
    assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&body));
    let body: serde_json::Value = serde_json::from_slice(&body).expect("MCP JSON response");
    assert!(body.get("error").is_none(), "{body}");
    assert_ne!(body["result"]["isError"], true, "{body}");
    assert!(
        body.to_string().contains("from the server"),
        "actual remote tool response: {body}"
    );
}

fn applied(rig: &Rig, tools: serde_yaml::Value) -> std::sync::Arc<busbar_kernel::state::App> {
    let row = door_boundary::row();
    let slot = door_boundary::slot_over(row, tools);
    std::sync::Arc::new(door_boundary::dispatched((*rig.app).clone(), row, &slot))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_mcp_member_ca_and_spki_reach_private_tls_without_base_ca_injection() {
    let _one = PUBLISHING.lock().await;
    let mut server = TlsToolServer::member_ca_fixture("127.0.0.1", false, false).await;
    let rig = try_rig_tools("member-tls-private-ca", server.port, tools(&server))
        .expect("normal Root composition");
    assert_actual_member_selector(&rig);
    succeeds(&rig).await;
    assert!(
        server.heard.try_recv().is_ok(),
        "the real TLS peer received HTTP request bytes"
    );
    assert!(
        !server.client_presented.load(Ordering::SeqCst),
        "this server did not request mTLS"
    );
    server.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_mcp_member_ca_and_sibling_client_identity_complete_mutual_tls() {
    let _one = PUBLISHING.lock().await;
    let mut server = TlsToolServer::member_ca_fixture("127.0.0.1", false, true).await;
    let cert_var = format!("BUSBAR_MEMBER_TLS_CLIENT_CERT_{}", std::process::id());
    let key_var = format!("BUSBAR_MEMBER_TLS_CLIENT_KEY_{}", std::process::id());
    std::env::set_var(&cert_var, &server.client_cert_pem);
    std::env::set_var(&key_var, &server.client_key_pem);
    let mut tools = tools(&server);
    tools["fs"]["client_identity"] = serde_yaml::to_value(serde_json::json!({
        "cert": busbar_contract::secret_ref::SecretRef::env(cert_var.clone()),
        "key": busbar_contract::secret_ref::SecretRef::env(key_var.clone()),
    }))
    .unwrap();
    let rig = try_rig_tools("member-tls-mutual", server.port, tools)
        .expect("normal member identity composition");
    assert_actual_member_selector(&rig);
    succeeds(&rig).await;
    assert!(
        server.heard.try_recv().is_ok(),
        "HTTP followed the verified handshake"
    );
    assert!(
        server.client_presented.load(Ordering::SeqCst),
        "the real server verified a client certificate"
    );
    std::env::remove_var(cert_var);
    std::env::remove_var(key_var);
    server.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_mcp_member_ca_rotation_and_rejected_apply_preserve_serving_generation() {
    let _one = PUBLISHING.lock().await;
    let mut first = TlsToolServer::member_ca_fixture("127.0.0.1", false, false).await;
    let mut second = TlsToolServer::member_ca_fixture("127.0.0.1", false, false).await;
    let rig = try_rig_tools("member-tls-rotation", first.port, tools(&first))
        .expect("initial member CA composition");
    assert_actual_member_selector(&rig);
    succeeds(&rig).await;
    assert!(first.heard.try_recv().is_ok());
    while first.heard.try_recv().is_ok() {}
    let first_bytes = first.http_bytes.load(Ordering::SeqCst);
    let before = rig.live.current().generation;
    let rotated = tools(&second);
    rig.live.apply(&applied(&rig, rotated.clone()));
    assert_eq!(
        rig.live.current().generation,
        before + 1,
        "the new TLS settings published"
    );
    succeeds(&rig).await;
    assert!(
        second.heard.try_recv().is_ok(),
        "the rotated member reached its new private CA peer"
    );
    while second.heard.try_recv().is_ok() {}
    let second_bytes = second.http_bytes.load(Ordering::SeqCst);
    let mut obsolete = rotated.clone();
    obsolete["fs"]["tls"]["ca_cert_pem"] = first.ca_pem.clone().into();
    rig.live.apply(&applied(&rig, obsolete));
    let (status, body) = tokio::time::timeout(
        Duration::from_secs(15),
        send(&rig.router, Some(&rig.bound_token()), CALL),
    )
    .await
    .expect("bounded old CA refusal");
    let rendered = String::from_utf8_lossy(&body);
    let refusal: serde_json::Value = serde_json::from_slice(&body).expect("structured MCP refusal");
    assert!(
        status.is_client_error()
            || status.is_server_error()
            || refusal.get("error").is_some()
            || refusal["result"]["isError"] == true,
        "a real refusal is required: {status} {refusal}"
    );
    assert!(
        !rendered.contains("from the server"),
        "the old CA cannot verify the rotated endpoint: {status} {rendered}"
    );
    assert_eq!(
        second.http_bytes.load(Ordering::SeqCst),
        second_bytes,
        "obsolete CA cannot send any HTTP bytes to the new peer"
    );
    rig.live.apply(&applied(&rig, rotated.clone()));
    succeeds(&rig).await;
    while second.heard.try_recv().is_ok() {}
    let good = rig.live.current().generation;
    let mut malformed = rotated;
    malformed["fs"]["tls"]["ca_cert_pem"] = "not a certificate".into();
    rig.live.apply(&applied(&rig, malformed));
    assert_eq!(
        rig.live.current().generation,
        good,
        "malformed CA was rejected before actual plugin refresh"
    );
    succeeds(&rig).await;
    assert!(
        second.heard.try_recv().is_ok(),
        "the retained approved generation still reaches its actual TLS peer"
    );
    assert_eq!(
        first.http_bytes.load(Ordering::SeqCst),
        first_bytes,
        "rotation did not send any further HTTP bytes to the prior TLS endpoint"
    );
    assert!(
        first.heard.try_recv().is_err(),
        "rotation did not fall back to the prior TLS endpoint"
    );
    first.close().await;
    second.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_mcp_inflight_request_retains_old_tls_generation_across_ca_rotation() {
    let _one = PUBLISHING.lock().await;
    let (release, held) = tokio::sync::watch::channel(false);
    let mut first = TlsToolServer::member_ca_gated(held).await;
    let mut second = TlsToolServer::member_ca_fixture("127.0.0.1", false, false).await;
    let rig = try_rig_tools("member-tls-retained-request", first.port, tools(&first))
        .expect("initial private CA member");
    assert_actual_member_selector(&rig);
    let router = rig.router.clone();
    let token = rig.bound_token();
    let pending = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(40), send(&router, Some(&token), CALL))
            .await
            .expect("bounded old generation request")
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let request = first
                .heard
                .recv()
                .await
                .expect("old TLS peer remains alive");
            if request.contains("\"tools/call\"") {
                break;
            }
        }
    })
    .await
    .expect("old actual tool request reaches its TLS peer before apply");
    assert!(
        !pending.is_finished(),
        "the real old peer has not released its response"
    );
    let first_bytes = first.http_bytes.load(Ordering::SeqCst);
    let generation = rig.live.current().generation;
    rig.live.apply(&applied(&rig, tools(&second)));
    assert_eq!(rig.live.current().generation, generation + 1);
    succeeds(&rig).await;
    assert!(
        second.heard.try_recv().is_ok(),
        "new requests reach the new CA peer while the old request is pending"
    );
    assert_eq!(
        first.http_bytes.load(Ordering::SeqCst),
        first_bytes,
        "the new request did not reuse the old TLS endpoint"
    );
    release.send(true).expect("release the old peer response");
    let (status, body) = tokio::time::timeout(Duration::from_secs(10), pending)
        .await
        .expect("old request finishes after release")
        .expect("old caller task finishes");
    assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&body));
    let body: serde_json::Value = serde_json::from_slice(&body).expect("old response JSON");
    assert!(body.get("error").is_none(), "{body}");
    assert_ne!(body["result"]["isError"], true, "{body}");
    assert_eq!(
        body["result"]["content"][0]["text"], "from the server",
        "the actual old TLS response survived successful rotation"
    );
    first.close().await;
    second.close().await;
}
