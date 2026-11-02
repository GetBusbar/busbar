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
async fn actual_ticket_preflight_preserves_unspent_custody_and_invalid_prefix_refusal() {
    const CHILD: &str = "BUSBAR_CENTRAL2_INBOUND_TICKETS_CHILD";
    const WITNESS: &str = "actual root inbound ticket custody completed";
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
    let directory = plugins::scratch("inbound-keys-custody");
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
                door_refusals: vec![busbar_kernel::plane_routes::PlaneRefusalSpec {
                    route: busbar_kernel::plane_routes::DoorRouteId {
                        path: "/v1/messages".into(),
                        method: busbar_contract::abi::mechanism::route::RouteMethod::Post,
                    },
                    refuse: Arc::new(|_, _| {
                        axum::http::Response::builder()
                            .status(401)
                            .body(axum::body::Body::empty())
                            .unwrap()
                    }),
                    ticket_prefix: Some("tk_".into()),
                    signed_ingress: Arc::from([]),
                }],
                ids: vec![7000],
                signed_ingress: Arc::new(|_, _| false),
                scope: None,
            },
        )
        .expect("the host listener installs");
    let handle = inbound.specs(7, 3).unwrap()[0].auth;
    let head = |fields: Vec<(String, Vec<u8>)>| Head {
        method: "POST".into(),
        target: "/v1/messages".into(),
        fields,
        ..Head::default()
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
    let (key, ordinary) = gov
        .mint_signed(
            NewKeySpec {
                name: "ticket-preflight".into(),
                ..Default::default()
            },
            now + 3600,
            now,
        )
        .unwrap();
    let ordinary = ordinary.expose(&busbar_kernel::seal::lend()).clone();
    let (ticket, _) = gov
        .mint_ticket(&key.id, "tk_", 600, None, b"ticket-record", now)
        .unwrap();
    // Repeated preflight and rejected/abandoned hand-ins must not consume a ticket.
    for _ in 0..2 {
        let original = bearer(&ticket);
        let answer = call(original.clone()).await;
        assert_eq!(answer.flow, FLOW_CONTINUE);
        assert_eq!(
            inbound
                .admitted(answer.unit.id)
                .unwrap()
                .resolved
                .unwrap()
                .id,
            key.id
        );
        let mut changed = original.stripped(&answer.strips).unwrap();
        changed.target = "/different".into();
        assert_eq!(
            inbound
                .hand_in(HandIn {
                    owner: 7,
                    generation: 3,
                    auth: handle,
                    unit: answer.unit,
                    line: 0,
                    conn: 1,
                    stream: 1,
                    framing: Some(1),
                    head: changed
                })
                .unwrap()
                .0,
            FLOW_STOP
        );
        inbound.exit(answer.unit.id);
    }
    assert_eq!(call(bearer(&ticket)).await.flow, FLOW_CONTINUE);
    assert_eq!(
        gov.admit_ticket("tk_", &ticket, now).map(|(_, body)| body),
        Some(b"ticket-record".to_vec()),
        "only this explicit final admission consumes the still-live ticket"
    );
    assert_eq!(call(bearer(&ticket)).await.flow, FLOW_STOP);
    let (expired, _) = gov
        .mint_ticket(&key.id, "tk_", 1, None, b"expired", now - 5)
        .unwrap();
    let relabeled = format!("tk_{}", ordinary.strip_prefix("bbk_").unwrap());
    for invalid in ["tk_malformed", expired.as_str(), relabeled.as_str()] {
        assert_eq!(call(bearer(invalid)).await.flow, FLOW_STOP);
    }
    assert_eq!(
        call(bearer(&ordinary)).await.flow,
        FLOW_CONTINUE,
        "ordinary keys remain usable on the ticket route"
    );
    let (wrong_prefix, _) = gov
        .mint_ticket(&key.id, "other_", 600, None, b"wrong-prefix", now)
        .unwrap();
    assert_eq!(call(bearer(&wrong_prefix)).await.flow, FLOW_STOP);
    assert_eq!(
        gov.admit_ticket("other_", &wrong_prefix, now)
            .map(|(_, body)| body),
        Some(b"wrong-prefix".to_vec())
    );
    let (revoked, _) = gov
        .mint_ticket(&key.id, "tk_", 600, None, b"revoked", now)
        .unwrap();
    gov.revoke(&key.id, "ticket owner revoked").unwrap();
    assert_eq!(call(bearer(&revoked)).await.flow, FLOW_STOP);
    println!("{WITNESS}");
}
