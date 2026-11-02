// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(feature = "auth-sigv4")]

use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD, POINT_HEAD_BODY};
use busbar_contract::abi::host::service::{
    UnitRef, FLOW_CONTINUE, FLOW_STOP, REFUSE_OVER_GATE, REFUSE_STOPPED,
};
use busbar_contract::abi::transport::route::{METHOD_POST, PATH_EXACT};
use busbar_contract::auth_calls::Strip;
use busbar_kernel::governance::NewKeySpec;
use busbar_kernel::guest::{Claimant, GuestList, Line, LineAuth, Route};
use busbar_kernel::inbound::{Call, HandIn, Head, Listener, Refuse};
use std::sync::Arc;
use std::time::{Duration, Instant};
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[tokio::test]
async fn actual_signed_reader_preserves_credential_body_gate_and_revocation_custody() {
    const CHILD: &str = "BUSBAR_CENTRAL2_INBOUND_SIGNED_CHILD";
    const WITNESS: &str = "actual root inbound signed reader completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("inbound-signed-custody");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([9u8; 32]))
        .expect("write the actual configured signing key");
    let at_rest = directory.join("at-rest-key");
    std::fs::write(&at_rest, hex::encode([17u8; 32])).expect("write actual at-rest key");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": ["keys"], "admin_auth": [], "signing_key": { "file": signing } },
        "store": { "module": module, "settings": settings },
        "credentials": { "at_rest": { "key": { "file": at_rest } } },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        None,
        true,
    )
    .expect("the actual product builds the session deployment");
    limits.stage_boot();
    let book = crate::root::boot::book(&app, &module).expect("the actual Store boots rate history");
    limits.keep().expect("the product limits commit");
    let _book = book;
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let gov = app
        .governance
        .as_ref()
        .expect("the real store supplies governance");

    let (kind, shape) = app
        .auth
        .issued_credential()
        .expect("actual linked credential reader states its issued shape");
    assert_eq!(kind, "sigv4");
    let now = busbar_kernel::store::now();
    let (key, bearer, public_id, secret) = gov
        .mint_signed_with_credential(
            NewKeySpec {
                name: "actual inbound signed reader".into(),
                ..Default::default()
            },
            now + 3600,
            now,
            &kind,
            &shape,
        )
        .expect("actual signed Store issues an encrypted recoverable credential");
    let secret = secret.expose(&busbar_kernel::seal::lend()).clone();
    let inbound = Arc::clone(crate::root::inbound::host());
    inbound
        .install(
            71,
            3,
            Listener {
                guests: GuestList::seal(vec![Line {
                    route: Route {
                        methods: METHOD_POST,
                        path_form: PATH_EXACT,
                        path: "/v1/messages".into(),
                        fields: Vec::new(),
                        rung: 0,
                    },
                    claimant: Claimant::Plane("inbound-signed-custody".into()),
                    dialect: 0,
                    auth: LineAuth::Chain(vec!["keys".into()], AuthPoints::HEAD_BODY),
                    upgrade: None,
                    offered: AuthPoints::HEAD_BODY,
                }])
                .expect("actual host declaration seals"),
                auths: Default::default(),
                body_limit: 16,
                app: Arc::clone(&app),
                door_refusals: Vec::new(),
                ids: vec![7100],
                signed_ingress: Arc::new(|_, _| true),
                scope: None,
            },
        )
        .expect("actual signed reader listener installs");
    let handle = inbound.specs(71, 3).unwrap()[0].auth;
    let body = b"hello".to_vec();
    // Sign with the product's public signing implementation, not a fabricated
    // AuthCalls verdict. The actual plugin reads the encrypted Store credential.
    let timestamp = std::process::Command::new("date")
        .args(["-u", "+%Y%m%dT%H%M%SZ"])
        .output()
        .expect("UTC date is available");
    assert!(timestamp.status.success());
    let timestamp = String::from_utf8(timestamp.stdout)
        .unwrap()
        .trim()
        .to_string();
    use sha2::Digest as _;
    let hash = hex::encode(sha2::Sha256::digest(&body));
    let headers = vec![
        ("host".to_string(), "inbound.busbar.test".to_string()),
        ("x-amz-date".to_string(), timestamp.clone()),
        ("x-amz-content-sha256".to_string(), hash.clone()),
    ];
    let (signature, signed_headers) = busbar_auth_sigv4::inbound::sign_v4(
        &secret,
        "us-east-1",
        "busbar",
        "POST",
        "/v1/messages",
        "",
        &headers,
        &hash,
        &timestamp,
        &timestamp[..8],
    );
    let mut fields: Vec<(String, Vec<u8>)> = headers
        .into_iter()
        .map(|(name, value)| (name, value.into_bytes()))
        .collect();
    fields.push(("authorization".into(), format!(
        "AWS4-HMAC-SHA256 Credential={public_id}/{}/us-east-1/busbar/aws4_request, SignedHeaders={signed_headers}, Signature={signature}",
        &timestamp[..8]).into_bytes()));
    let head = Head {
        method: "POST".into(),
        target: "/v1/messages".into(),
        fields,
        ..Head::default()
    };
    let call = |head: Head, body: Option<Vec<u8>>, point, unit, stream| {
        let inbound = Arc::clone(&inbound);
        async move {
            let (send, receive) = tokio::sync::oneshot::channel();
            match inbound.auth_call(
                Call {
                    owner: 71,
                    generation: 3,
                    auth: handle,
                    unit,
                    point,
                    conn: 1,
                    stream,
                    framing: 1,
                    head,
                    body,
                    deadline: None,
                },
                Box::new(move |result| {
                    let _ = send.send(result);
                }),
            ) {
                Some(answer) => answer,
                None => receive
                    .await
                    .expect("actual reader Store completion arrives"),
            }
            .expect("actual signed auth call answers")
        }
    };
    let waiting = call(head.clone(), None, POINT_HEAD, UnitRef::NONE, 1).await;
    assert_eq!(waiting.flow, FLOW_CONTINUE);
    assert!(
        inbound.admitted(waiting.unit.id).is_none(),
        "a signed head cannot admit an identity before the body arrives"
    );
    let verified = call(
        head.clone(),
        Some(body.clone()),
        POINT_HEAD_BODY,
        waiting.unit,
        1,
    )
    .await;
    assert_eq!(verified.flow, FLOW_CONTINUE);
    let admission = inbound
        .admitted(verified.unit.id)
        .expect("actual signed identity admitted");
    assert_eq!(
        admission.resolved.as_ref().map(|key| key.id.as_str()),
        Some(key.id.as_str())
    );
    assert!(verified.strips.contains(&Strip::field("authorization")));
    assert!(
        !format!("{verified:?}").contains(&secret),
        "transport answer contains no credential"
    );
    let mut stripped = head.clone();
    stripped
        .fields
        .retain(|(name, _)| !verified.strips.contains(&Strip::field(name)));
    let (flow, admitted) = inbound
        .hand_in(HandIn {
            owner: 71,
            generation: 3,
            auth: handle,
            unit: verified.unit,
            line: 0,
            conn: 1,
            stream: 1,
            framing: Some(1),
            head: stripped,
        })
        .expect("actual signed hand-in answers");
    assert_eq!(flow, FLOW_CONTINUE);
    assert_eq!(
        admitted, verified.unit,
        "successful signed hand-in retains the unit"
    );

    let tampered = call(
        head.clone(),
        Some(b"wrong".to_vec()),
        POINT_HEAD_BODY,
        UnitRef::NONE,
        2,
    )
    .await;
    assert_eq!(
        tampered.flow, FLOW_STOP,
        "body integrity is verified by the actual reader"
    );
    let over = inbound.auth_call(
        Call {
            owner: 71,
            generation: 3,
            auth: handle,
            unit: UnitRef::NONE,
            point: POINT_HEAD_BODY,
            conn: 1,
            stream: 3,
            framing: 1,
            head: head.clone(),
            body: Some(vec![b'x'; 64]),
            deadline: None,
        },
        Box::new(|_| {}),
    );
    assert_eq!(over, Some(Err(busbar_kernel::inbound::OVER_GATE)));
    let refusal = inbound
        .refuse(Refuse {
            owner: 71,
            generation: 3,
            unit: UnitRef::NONE,
            cause: REFUSE_OVER_GATE,
            line: 0,
            conn: 1,
            stream: 3,
            framing: Some(1),
            request: Some(head.clone()),
        })
        .expect("the kernel renders body-gate refusal");
    assert_eq!(refusal.status, 413);
    let token = bearer.expose(&busbar_kernel::seal::lend());
    let bearer_head = Head {
        method: "POST".into(),
        target: "/v1/messages".into(),
        fields: vec![(
            "authorization".into(),
            format!("Bearer {token}").into_bytes(),
        )],
        ..Head::default()
    };
    assert_eq!(
        call(
            bearer_head.clone(),
            Some(b"hello".to_vec()),
            POINT_HEAD_BODY,
            UnitRef::NONE,
            5
        )
        .await
        .flow,
        FLOW_CONTINUE,
        "the actual reader's Pass result falls through to the valid bearer"
    );
    gov.revoke(&key.id, "actual signed-reader revocation")
        .expect("actual Store revokes credential");
    let revoked = call(head.clone(), Some(body), POINT_HEAD_BODY, UnitRef::NONE, 4).await;
    assert_eq!(revoked.flow, FLOW_STOP);
    let refusal = inbound
        .refuse(Refuse {
            owner: 71,
            generation: 3,
            unit: revoked.unit,
            cause: REFUSE_STOPPED,
            line: 0,
            conn: 1,
            stream: 4,
            framing: Some(1),
            request: Some(head),
        })
        .expect("the kernel renders revoked credential refusal");
    assert_eq!(refusal.status, 401);
    assert_eq!(
        call(
            bearer_head,
            Some(b"hello".to_vec()),
            POINT_HEAD_BODY,
            UnitRef::NONE,
            6
        )
        .await
        .flow,
        FLOW_STOP,
        "the actual revoked bearer is refused on the token path too"
    );
    println!("{WITNESS}");
}
