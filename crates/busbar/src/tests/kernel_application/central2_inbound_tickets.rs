// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::test_plugins as plugins;
use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD};
use busbar_contract::abi::host::service::{UnitRef, FLOW_CONTINUE, FLOW_STOP};
use busbar_contract::abi::transport::route::{METHOD_POST, PATH_EXACT};
use busbar_contract::json::JsonValueTrait as _;
use busbar_kernel::governance::NewKeySpec;
use busbar_kernel::guest::{Claimant, GuestList, Line, LineAuth, Route};
use busbar_kernel::inbound::{Call, HandIn, Head, Listener};
use std::sync::Arc;

#[tokio::test]
async fn actual_ticket_preflight_preserves_unspent_custody_and_invalid_prefix_refusal() {
    const CHILD: &str = "BUSBAR_CENTRAL2_INBOUND_TICKETS_CHILD";
    const WITNESS: &str = "actual root inbound ticket custody completed";
    isolated!(CHILD, WITNESS, witness = "usage");
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let module = crate::root::test_plugins::native_image(&library_path).name;
    let manifest =
        crate::root::test_plugins::native_manifest("store", &library_path, "third-party");
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("inbound-keys-custody");
    let archive = plugins::signed(&plugins::key(0x33), manifest, &library);
    let archive_sha256 = busbar_plugin_loader::sign::sha256_hex(&archive);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings = crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([9u8; 32]))
        .expect("write the actual configured signing key");
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        serde_json::json!({
            "providers": {},
            "models": {},
            "auth": { "chain": ["keys"], "signing_key": { "file": signing } },
            "store": { "module": module, "settings": settings },
            "advanced": {  },
        }),
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let mut plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        fetch: vec![busbar_kernel::config::PluginFetch::Url(
            busbar_kernel::config::UrlFetch {
                url: "http://127.0.0.1:9/store.tar.gz".into(),
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
            plugins: vec![module.clone()],
            keys: vec![busbar_kernel::config::PluginPublisherKey {
                public_key: hex::encode(plugins::key(0x33).verifying_key().as_bytes()),
                revoked: false,
            }],
        });
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let native_config = config;
    let native_plugins = plugin_config;
    let crate::root::min3_boot::fixture::Fixture {
        backend: native_core,
        rules,
    } = crate::root::min3_boot::fixture::open(&native_config, &native_plugins, rules.clone())
        .await
        .expect("actual Store opens for native startup");
    let native_core = crate::root::real_store::core_over(native_core).await;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        native_config,
        native_plugins,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(native_core),
        true,
    )
    .await
    .expect("the actual product builds the session deployment");
    limits.stage_boot();
    let book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store boots rate history");
    limits.keep().await.expect("the product limits commit");
    let _book = book;
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let app = Arc::new(app);
    let gov = app
        .governance
        .as_ref()
        .expect("the real store supplies governance");

    let inbound = Arc::clone(crate::root::inbound::host());

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
    let (key, ordinary) = gov
        .mint_signed_async(
            NewKeySpec {
                name: "ticket-preflight".into(),
                ..Default::default()
            },
            now + 3600,
            now,
        )
        .await
        .unwrap();
    let ordinary = ordinary.expose(&busbar_kernel::seal::lend()).clone();
    let (ticket, _) = gov
        .mint_ticket(&key.id, "tk_", 600, None, b"ticket-record", now)
        .await
        .unwrap();

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
        let mut changed = original.clone();
        assert!(
            changed.query.is_none(),
            "this actual ticket request carries no query fields"
        );
        changed.fields.retain(|(name, _)| {
            !answer.strips.iter().any(|strip| {
                strip.place == busbar_contract::auth_calls::StripPlace::Field
                    && strip.name.eq_ignore_ascii_case(name)
            })
        });
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
        gov.redeem_verified_ticket_async(
            gov.prepare_ticket_redemption_async("tk_", &ticket, now)
                .await
                .unwrap(),
            now
        )
        .await
        .map(|(_, body)| body),
        Some(b"ticket-record".to_vec()),
        "only this explicit final admission consumes the still-live ticket"
    );
    assert_eq!(call(bearer(&ticket)).await.flow, FLOW_STOP);
    let (expired, expiry) = gov
        .mint_ticket(
            &key.id,
            "tk_",
            1,
            None,
            b"expired",
            busbar_kernel::store::now(),
        )
        .await
        .unwrap();
    while busbar_kernel::store::now() <= expiry {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
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
        .await
        .unwrap();
    assert_eq!(call(bearer(&wrong_prefix)).await.flow, FLOW_STOP);
    assert_eq!(
        gov.redeem_verified_ticket_async(
            gov.prepare_ticket_redemption_async("other_", &wrong_prefix, now)
                .await
                .unwrap(),
            now
        )
        .await
        .map(|(_, body)| body),
        Some(b"wrong-prefix".to_vec())
    );
    let (revoked, _) = gov
        .mint_ticket(&key.id, "tk_", 600, None, b"revoked", now)
        .await
        .unwrap();
    gov.revoke_async(&key.id, "ticket owner revoked")
        .await
        .unwrap();
    assert_eq!(call(bearer(&revoked)).await.flow, FLOW_STOP);
    println!("{WITNESS}");
}
