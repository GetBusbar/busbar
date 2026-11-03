// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD};
use busbar_contract::abi::host::service::{UnitRef, FLOW_CONTINUE, FLOW_STOP, REFUSE_STOPPED};
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
async fn actual_inbound_keys_preserve_resolution_revocation_rotation_and_carrier_custody() {
    const CHILD: &str = "BUSBAR_CENTRAL2_INBOUND_KEYS_CHILD";
    const WITNESS: &str = "actual root inbound key custody completed";
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
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest("store", &module, "third-party");
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("inbound-keys-custody");
    let archive = plugins::signed(&plugins::key(0x33), manifest, &library);
    let archive_sha256 = plugins::sha256(&archive);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([9u8; 32]))
        .expect("write the actual configured signing key");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": ["keys"], "admin_auth": [], "signing_key": { "file": signing } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let mut plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        fetch: vec![busbar_kernel::config::PluginFetch::Url(
            busbar_kernel::config::UrlFetch {
                url: "https://plugins.invalid/store.tar.gz".into(),
                sha256: Some(archive_sha256),
            },
        )],
        ..Default::default()
    };
    plugin_config
        .trust
        .publishers
        .push(busbar_kernel::config::PluginPublisher {
            name: "third-party".into(),
            public_key: hex::encode(plugins::key(0x33).verifying_key().as_bytes()),
        });
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

    let inbound = Arc::clone(crate::root::inbound::host());
    // A typed listener declaration exercises the actual public host API over the
    // normally built application; no auth verifier or Store result is fabricated.
    inbound
        .install(
            7,
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
                    claimant: Claimant::Plane("inbound-keys-custody".into()),
                    dialect: 0,
                    auth: LineAuth::Chain(vec!["keys".into()], AuthPoints::HEAD),
                    upgrade: None,
                    offered: AuthPoints::HEAD,
                }])
                .expect("the normal host declaration seals"),
                auths: Default::default(),
                body_limit: 16,
                app: Arc::clone(&app),
                door_refusals: Vec::new(),
                ids: vec![7000],
                signed_ingress: Arc::new(|_, _| false),
                scope: None,
            },
        )
        .expect("the host listener installs");
    let handle = inbound.specs(7, 3).unwrap()[0].auth;
    let head = |fields: Vec<(String, Vec<u8>)>| {
        let mut head = Head::default();
        head.method = "POST".into();
        head.target = "/v1/messages".into();
        head.fields = fields;
        head
    };
    let bearer = |token: &str| {
        head(vec![(
            "authorization".into(),
            format!("Bearer {token}").into_bytes(),
        )])
    };
    let call = |head: Head| {
        let inbound = Arc::clone(&inbound);
        async move {
            let (send, receive) = tokio::sync::oneshot::channel();
            let answer = inbound.auth_call(
                Call {
                    owner: 7,
                    generation: 3,
                    auth: handle,
                    unit: UnitRef::NONE,
                    point: POINT_HEAD,
                    conn: 1,
                    stream: 1,
                    framing: 1,
                    head,
                    body: None,
                    deadline: None,
                },
                Box::new(move |result| {
                    let _ = send.send(result);
                }),
            );
            match answer {
                Some(answer) => answer,
                None => receive
                    .await
                    .expect("the real asynchronous Store completes"),
            }
            .expect("the actual inbound call answers")
        }
    };
    let now = busbar_kernel::store::now();
    let (key, token) = gov
        .mint_signed(
            NewKeySpec {
                name: "inbound-custody".into(),
                ..Default::default()
            },
            now + 3600,
            now,
        )
        .expect("the actual Store mints the key");
    let token = token.expose(&busbar_kernel::seal::lend()).clone();
    let admitted = call(bearer(&token)).await;
    assert_eq!(admitted.flow, FLOW_CONTINUE);
    let resolved = inbound
        .admitted(admitted.unit.id)
        .expect("the host retains admission");
    assert_eq!(resolved.provider, "keys");
    assert_eq!(
        resolved.resolved.as_ref().map(|key| key.id.as_str()),
        Some(key.id.as_str())
    );
    assert!(admitted.strips.contains(&Strip::field("authorization")));
    assert!(
        !format!("{admitted:?}").contains(&token),
        "transport answers contain no credential"
    );
    gov.revoke(&key.id, "actual inbound revoke")
        .expect("the actual Store revokes");
    let revoked = call(bearer(&token)).await;
    assert_eq!(revoked.flow, FLOW_STOP);
    let refusal = inbound
        .refuse(Refuse {
            owner: 7,
            generation: 3,
            unit: revoked.unit,
            cause: REFUSE_STOPPED,
            line: 0,
            conn: 1,
            stream: 1,
            framing: Some(1),
            request: Some(bearer(&token)),
        })
        .expect("the kernel renders its refusal");
    assert_eq!(refusal.status, 401);

    let (key, old) = gov
        .mint_signed(
            NewKeySpec {
                name: "inbound-rotate".into(),
                ..Default::default()
            },
            now + 3600,
            now,
        )
        .unwrap();
    let old = old.expose(&busbar_kernel::seal::lend()).clone();
    assert_eq!(call(bearer(&old)).await.flow, FLOW_CONTINUE);
    let new = gov.rotate_key(&key.id, now + 3600).unwrap().unwrap();
    let new = new.token.expose(&busbar_kernel::seal::lend()).clone();
    assert_eq!(
        call(bearer(&old)).await.flow,
        FLOW_STOP,
        "rotation retires the actual old credential"
    );
    assert_eq!(
        call(bearer(&new)).await.flow,
        FLOW_CONTINUE,
        "rotation admits its actual replacement"
    );
    let (_, expired) = gov
        .mint_signed(
            NewKeySpec {
                name: "inbound-expired".into(),
                ..Default::default()
            },
            now - 60,
            now - 3600,
        )
        .unwrap();
    assert_eq!(
        call(bearer(expired.expose(&busbar_kernel::seal::lend())))
            .await
            .flow,
        FLOW_STOP
    );
    let invalid = call(head(vec![("x-api-key".into(), b"not-a-key".to_vec())])).await;
    assert_eq!(invalid.flow, FLOW_STOP);
    let invalid_refusal = inbound
        .refuse(Refuse {
            owner: 7,
            generation: 3,
            unit: invalid.unit,
            cause: REFUSE_STOPPED,
            line: 0,
            conn: 1,
            stream: 1,
            framing: Some(1),
            request: Some(head(Vec::new())),
        })
        .expect("the kernel refuses the invalid carrier");
    assert_eq!(invalid_refusal.status, 401);
    assert_eq!(call(head(Vec::new())).await.flow, FLOW_STOP);
    let dual = call(head(vec![
        ("authorization".into(), format!("Bearer {new}").into_bytes()),
        ("x-api-key".into(), b"stray".to_vec()),
    ]))
    .await;
    assert_eq!(dual.flow, FLOW_CONTINUE);
    assert!(dual.strips.contains(&Strip::field("authorization")));
    assert!(dual.strips.contains(&Strip::field("x-api-key")));
    let hand_in = |head| {
        inbound
            .hand_in(HandIn {
                owner: 7,
                generation: 3,
                auth: handle,
                unit: dual.unit,
                line: 0,
                conn: 1,
                stream: 1,
                framing: Some(1),
                head,
            })
            .expect("the actual host checks hand-in")
            .0
    };
    assert_eq!(
        hand_in(head(vec![("x-api-key".into(), b"stray".to_vec())])),
        FLOW_STOP,
        "the transport must strip every named credential carrier"
    );
    assert_eq!(
        hand_in(head(Vec::new())),
        FLOW_CONTINUE,
        "the fully stripped authenticated request proceeds"
    );
    println!("{WITNESS}");
}
