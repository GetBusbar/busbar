// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(all(distribution_root, linked_every_auth))]

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

// Ordinary signed-request fixture. The pinned SigV4 cfg(test) signer delegates
// to the contract AWS4 recipe; dependency cfg(test) APIs are not exported to a
// root test. Keep the same canonical header, request and day-key/HMAC recipe here
// using the already direct contract SDK HMAC and SHA-256 dependencies. This only
// creates a request: the actual plugin still performs every verification/read.
#[allow(clippy::too_many_arguments)]
fn sign_fixture(
    secret: &str,
    region: &str,
    service: &str,
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    headers: &[(String, String)],
    payload_hash: &str,
    amzdate: &str,
    datestamp: &str,
) -> (String, String) {
    use busbar_contract::abi::sdk::hmac::hmac_sha256;
    use sha2::Digest as _;
    let canonical_value = |value: &str| {
        let mut out = String::with_capacity(value.len());
        let mut pending_space = false;
        for character in value.chars() {
            if character == ' ' {
                pending_space = true;
            } else {
                if pending_space && !out.is_empty() {
                    out.push(' ');
                }
                pending_space = false;
                out.push(character);
            }
        }
        out
    };
    let mut headers: Vec<_> = headers
        .iter()
        .map(|(name, value)| (name.to_lowercase(), canonical_value(value)))
        .collect();
    headers.sort_by(|left, right| left.0.cmp(&right.0));
    let mut canonical_headers = String::new();
    let mut signed_headers = String::new();
    let mut previous = None;
    for (name, value) in &headers {
        if previous == Some(name) {
            canonical_headers.pop();
            canonical_headers.push(',');
        } else {
            canonical_headers.push_str(name);
            canonical_headers.push(':');
            if !signed_headers.is_empty() {
                signed_headers.push(';');
            }
            signed_headers.push_str(name);
        }
        canonical_headers.push_str(value);
        canonical_headers.push('\n');
        previous = Some(name);
    }
    let canonical_request = [
        method,
        canonical_uri,
        canonical_query,
        &canonical_headers,
        &signed_headers,
        payload_hash,
    ]
    .join("\n");
    let request_hash = hex::encode(sha2::Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amzdate}\n{datestamp}/{region}/{service}/aws4_request\n{request_hash}"
    );
    let date_key = hmac_sha256(format!("AWS4{secret}").as_bytes(), datestamp.as_bytes());
    let region_key = hmac_sha256(date_key.as_ref(), region.as_bytes());
    let service_key = hmac_sha256(region_key.as_ref(), service.as_bytes());
    let signing_key = hmac_sha256(service_key.as_ref(), b"aws4_request");
    let signature = hmac_sha256(signing_key.as_ref(), string_to_sign.as_bytes());
    (hex::encode(&signature[..]), signed_headers)
}

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
    // Sign a real request with the pinned recipe, never a fabricated AuthCalls
    // verdict. The actual plugin reads the encrypted Store credential.
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
    let (signature, signed_headers) = sign_fixture(
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
    let mut head = Head::default();
    head.method = "POST".into();
    head.target = "/v1/messages".into();
    head.fields = fields;
    let call_result = |head: Head, body: Option<Vec<u8>>, point, unit, stream| {
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
        }
    };
    let call = |head, body, point, unit, stream| {
        let result = call_result(head, body, point, unit, stream);
        async move { result.await.expect("actual signed auth call answers") }
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
    let mut bearer_head = Head::default();
    bearer_head.method = "POST".into();
    bearer_head.target = "/v1/messages".into();
    bearer_head.fields = vec![(
        "authorization".into(),
        format!("Bearer {token}").into_bytes(),
    )];
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
    // A pending signed unit belongs to its exact original request, before any
    // real reader verdict exists. A substitution must not consume that unit.
    for (index, mutation) in [
        "method",
        "path",
        "authority",
        "field",
        "query",
        "credential",
        "added",
    ]
    .into_iter()
    .enumerate()
    {
        let stream = 10 + index as u64;
        let first = call(head.clone(), None, POINT_HEAD, UnitRef::NONE, stream).await;
        assert_eq!(first.flow, FLOW_CONTINUE);
        let mut changed = head.clone();
        match mutation {
            "method" => changed.method = "PUT".into(),
            "path" => changed.target = "/other/messages".into(),
            "authority" => changed.authority = "other.example".into(),
            "field" => {
                changed
                    .fields
                    .iter_mut()
                    .find(|(name, _)| name == "host")
                    .unwrap()
                    .1 = b"other.example".to_vec()
            }
            "query" => changed.query = Some("scope=changed".into()),
            "credential" => {
                changed
                    .fields
                    .iter_mut()
                    .find(|(name, _)| name == "authorization")
                    .unwrap()
                    .1 = b"changed signature".to_vec()
            }
            "added" => changed.fields.push(("x-added".into(), b"changed".to_vec())),
            _ => unreachable!(),
        }
        assert_eq!(
            call_result(
                changed,
                Some(body.clone()),
                POINT_HEAD_BODY,
                first.unit,
                stream
            )
            .await,
            Err(busbar_kernel::inbound::UNIT_FOREIGN),
            "{mutation}"
        );
        assert!(
            inbound.admitted(first.unit.id).is_none(),
            "{mutation} must not admit before a genuine body verdict"
        );
        let premature = inbound
            .hand_in(HandIn {
                owner: 71,
                generation: 3,
                auth: handle,
                unit: first.unit,
                line: 0,
                conn: 1,
                stream,
                framing: Some(1),
                head: head.clone(),
            })
            .expect("pending hand-in answers without consuming the original unit");
        assert_eq!(
            premature.0, FLOW_STOP,
            "{mutation}: a pending reader cannot be handed in"
        );
        let recovered = call(
            head.clone(),
            Some(body.clone()),
            POINT_HEAD_BODY,
            first.unit,
            stream,
        )
        .await;
        assert_eq!(
            recovered.flow, FLOW_CONTINUE,
            "{mutation}: original request remains recoverable"
        );
        let mut stripped = head.clone();
        stripped
            .fields
            .retain(|(name, _)| !recovered.strips.contains(&Strip::field(name)));
        assert_eq!(
            inbound
                .hand_in(HandIn {
                    owner: 71,
                    generation: 3,
                    auth: handle,
                    unit: first.unit,
                    line: 0,
                    conn: 1,
                    stream,
                    framing: Some(1),
                    head: stripped,
                })
                .unwrap()
                .0,
            FLOW_CONTINUE,
            "{mutation}"
        );
        inbound.exit(first.unit.id);
    }
    // SigV4 declares a credential FIELD strip, not query-key stripping. Test
    // only its real declaration; no synthetic query-strip capability is added.
    for (index, form) in ["original", "field", "case"].into_iter().enumerate() {
        let stream = 30 + index as u64;
        let first = call(head.clone(), None, POINT_HEAD, UnitRef::NONE, stream).await;
        let verified = call(
            head.clone(),
            Some(body.clone()),
            POINT_HEAD_BODY,
            first.unit,
            stream,
        )
        .await;
        assert_eq!(verified.flow, FLOW_CONTINUE);
        assert!(verified.strips.contains(&Strip::field("authorization")));
        let mut continuation = head.clone();
        match form {
            "original" => {}
            "field" => continuation
                .fields
                .retain(|(name, _)| !name.eq_ignore_ascii_case("authorization")),
            "case" => {
                for (name, _) in &mut continuation.fields {
                    *name = name.to_ascii_uppercase();
                }
            }
            _ => unreachable!(),
        }
        assert_eq!(
            call(
                continuation,
                Some(body.clone()),
                POINT_HEAD_BODY,
                first.unit,
                stream
            )
            .await
            .flow,
            FLOW_CONTINUE,
            "{form}: original bytes or genuinely declared field removal is accepted"
        );
        let mut changed_query = head.clone();
        changed_query.query = Some("scope=unannounced".into());
        assert_eq!(
            call_result(
                changed_query,
                Some(body.clone()),
                POINT_HEAD_BODY,
                first.unit,
                stream
            )
            .await,
            Err(busbar_kernel::inbound::UNIT_FOREIGN),
            "query stripping was never declared by this reader"
        );
        let mut stripped = head.clone();
        stripped
            .fields
            .retain(|(name, _)| !verified.strips.contains(&Strip::field(name)));
        assert_eq!(
            inbound
                .hand_in(HandIn {
                    owner: 71,
                    generation: 3,
                    auth: handle,
                    unit: first.unit,
                    line: 0,
                    conn: 1,
                    stream,
                    framing: Some(1),
                    head: stripped,
                })
                .unwrap()
                .0,
            FLOW_CONTINUE
        );
        inbound.exit(first.unit.id);
    }
    let cancelled = call(head.clone(), None, POINT_HEAD, UnitRef::NONE, 40).await;
    inbound.exit(cancelled.unit.id);
    assert_eq!(
        call_result(
            head.clone(),
            Some(body.clone()),
            POINT_HEAD_BODY,
            cancelled.unit,
            40
        )
        .await,
        Err(busbar_kernel::inbound::UNIT_FOREIGN),
        "cancellation never revives the old unit"
    );
    assert!(inbound.admitted(cancelled.unit.id).is_none());
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
