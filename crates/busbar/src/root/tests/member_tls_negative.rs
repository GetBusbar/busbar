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

async fn read_host_http_response(
    conns: &dyn busbar_contract::conn::PollConns,
    owner: busbar_contract::conn::InstanceId,
    connection: busbar_contract::conn::ConnId,
) -> Result<(u32, Vec<u8>), busbar_contract::conn::ConnError> {
    use busbar_contract::conn::PieceKind;

    tokio::time::timeout(Duration::from_secs(5), async {
        let mut bytes = vec![0; 16 * 1024];
        let mut body = Vec::new();
        let mut status = None;
        loop {
            let piece =
                std::future::poll_fn(|cx| conns.poll_read(owner, connection, cx, &mut bytes))
                    .await?;
            match piece.kind {
                PieceKind::Fields => status = piece.status_code,
                PieceKind::Body => {
                    body.extend_from_slice(&bytes[..piece.len]);
                    if piece.end {
                        return Ok((status.expect("the HTTP head precedes its body"), body));
                    }
                }
            }
        }
    })
    .await
    .expect("the real host-boundary HTTP exchange settles")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn member_ca_is_not_inherited_by_another_declared_need_on_the_same_connector() {
    use busbar_contract::abi::host::conn::connector::CAUSE_SECURITY;
    use busbar_contract::conn::{ConnError, NeedId, OpenDesc};
    use busbar_contract::transport::trust::Anchors;

    let _one = crate::root::PUBLISHING.lock().await;
    let mut server = TlsToolServer::member_ca_fixture("127.0.0.1", false, false).await;
    let tools = member(&server);
    let target = tools["fs"]["url"].as_str().unwrap().to_string();
    let rig = root_rig("member-ca-need-boundary", server.port, tools).unwrap();
    served(&rig).await;

    let row = crate::root::loader::dispatch::LinkedRow::of(
        crate::root::door_steps::tests::tool_door::line_door(),
    )
    .expect("the actual loaded MCP declaration");
    let statement = busbar_contract::abi::mechanism::rendering::read(&row.statement)
        .expect("the real MCP declaration reads");
    let (index, spec) = statement
        .needs
        .iter()
        .enumerate()
        .find(|(_, need)| {
            need.transport == "http"
                && need.target_from == "settings.*.url"
                && need.trust_from == "settings.*.tls"
        })
        .expect("the actual MCP HTTP member Need selects the structured TLS bundle");
    let actual_need = NeedId(u32::try_from(index).unwrap());
    let foreign_need = NeedId(u32::try_from(statement.needs.len()).unwrap());
    assert_ne!(actual_need, foreign_need);

    let binding = rig.plane.connection_binding();
    let owner = binding.owner();
    let declarations = rig
        .plane
        .conn_table()
        .expect("the actual Root connection table");
    let conns = &rig
        .live
        .reach
        .as_ref()
        .expect("the actual member reach")
        .conns;
    assert_eq!(
        std::sync::Arc::as_ptr(&declarations) as *const (),
        std::sync::Arc::as_ptr(conns) as *const (),
        "declarations and host reads use the SAME production Connector"
    );
    assert_eq!(declarations.declared(owner, actual_need), Some(Ok(())));
    assert_eq!(declarations.declared(owner, foreign_need), None);

    let fields: &[(&str, &[u8])] = &[("content-type", b"application/json")];
    let request = OpenDesc {
        target: &target,
        member: "fs",
        method: b"POST",
        head_target: b"/rpc",
        fields,
        body: busbar_contract::conn::Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
        ),
        timeout_ms: 5_000,
        ..Default::default()
    };
    let actual = declarations
        .open_request(owner, actual_need, &request, true, 5_000)
        .expect("the same valid request opens on the actual configured Need");
    let (status, body) = read_host_http_response(conns.as_ref(), owner, actual)
        .await
        .expect("the member CA verifies the real peer on the actual Need");
    assert_eq!(status, 200);
    let answer: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(answer["result"]["tools"].is_array());
    declarations
        .close(owner, actual)
        .expect("close the positive host exchange");
    assert!(server.heard.try_recv().is_ok());
    while server.heard.try_recv().is_ok() {}

    // This is an adversarial HOST declaration-boundary control, not a claim that the MCP product
    // naturally opens a foreign Need. Copy its actual ReadNeed to a fresh declared slot so that
    // transport, member, target, private reach and SPKI remain equal; omit only the member CA.
    declarations
        .declare(owner, foreign_need, spec, None, None)
        .expect("the copied actual carrier Need is explicitly declared");
    conns
        .seal_reach(owner, foreign_need, "fs", &target, true)
        .expect("the control is independently authorized to reach loopback");
    conns
        .anchor(
            owner,
            foreign_need,
            "fs",
            &target,
            &Anchors {
                key_pin: Some(server.pin.clone()),
                private_reach: true,
                ..Default::default()
            },
        )
        .expect("the control has the same real peer SPKI but no member CA");
    assert_eq!(declarations.declared(owner, foreign_need), Some(Ok(())));
    let before = server.http_bytes.load(Ordering::SeqCst);
    let foreign = declarations
        .open_request(owner, foreign_need, &request, true, 5_000)
        .expect("the declared, reach-authorized control starts a real TLS exchange");
    assert_eq!(
        read_host_http_response(conns.as_ref(), owner, foreign).await,
        Err(ConnError::Refused),
        "a different Need cannot inherit the configured member's CA"
    );
    let cause = declarations
        .cause(owner, foreign)
        .expect("the real transport refusal");
    assert_eq!(
        cause.stage, CAUSE_SECURITY,
        "the failure is TLS, not undeclared reach"
    );
    assert_eq!(server.http_bytes.load(Ordering::SeqCst), before);
    assert!(server.heard.try_recv().is_err());
    declarations
        .close(owner, foreign)
        .expect("close the refused control");

    // Keep the actual generation guard and owner alive throughout both exchanges. Do not forget
    // the real owner to clean up a control Need: normal Rig retirement owns that lifecycle.
    served(&rig).await;
    assert_eq!(binding.owner(), owner);
    server.close().await;
}
