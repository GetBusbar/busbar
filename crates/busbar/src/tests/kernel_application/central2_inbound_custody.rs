// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD};
use busbar_contract::abi::host::service::REFUSE_STOPPED;
use busbar_contract::abi::host::service::{UnitRef, FLOW_CONTINUE};
use busbar_contract::abi::transport::route::{METHOD_POST, PATH_EXACT};
use busbar_kernel::governance::NewKeySpec;
use busbar_kernel::guest::{Claimant, GuestList, Line, LineAuth, Route};
use busbar_kernel::inbound::{Call, HandIn, Head, Listener, Refuse, UNIT_FOREIGN};
use std::sync::Arc;
use std::time::{Duration, Instant};
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[tokio::test]
async fn actual_inbound_foreign_binding_and_session_custody() {
    const CHILD: &str = "BUSBAR_CENTRAL2_INBOUND_CUSTODY_CHILD";
    const WITNESS: &str = "actual root inbound binding custody completed";
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
    let directory = plugins::scratch("inbound-generation-custody");
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
    let gov = Arc::clone(
        app.governance
            .as_ref()
            .expect("the actual Store supplies governance"),
    );

    let inbound = Arc::clone(crate::root::inbound::host());
    let listener = |app| Listener {
        guests: GuestList::seal(vec![Line {
            route: Route {
                methods: METHOD_POST,
                path_form: PATH_EXACT,
                path: "/v1/messages".into(),
                fields: Vec::new(),
                rung: 0,
            },
            claimant: Claimant::Plane("inbound-generation-custody".into()),
            dialect: 0,
            auth: LineAuth::Chain(vec!["keys".into()], AuthPoints::HEAD),
            upgrade: None,
            offered: AuthPoints::HEAD,
        }])
        .unwrap(),
        auths: Default::default(),
        body_limit: 16,
        app,
        door_refusals: Vec::new(),
        ids: vec![7000],
        signed_ingress: Arc::new(|_, _| false),
        scope: None,
    };
    inbound.install(7, 3, listener(Arc::clone(&app))).unwrap();
    inbound
        .install_at(7, 71, 3, listener(Arc::clone(&app)))
        .unwrap();
    let auth = inbound.specs(7, 3).unwrap()[0].auth;
    let now = busbar_kernel::store::now();
    let (_, token) = gov
        .mint_signed(
            NewKeySpec {
                name: "generation-original".into(),
                ..Default::default()
            },
            now + 3600,
            now,
        )
        .unwrap();
    let token = token.expose(&busbar_kernel::seal::lend()).clone();
    let mut original = Head::default();
    original.method = "POST".into();
    original.target = "/v1/messages".into();
    original.fields = vec![(
        "authorization".into(),
        format!("Bearer {token}").into_bytes(),
    )];
    let request = |unit, conn, stream, framing| Call {
        owner: 7,
        generation: 3,
        auth,
        unit,
        point: POINT_HEAD,
        conn,
        stream,
        framing,
        head: original.clone(),
        body: None,
        deadline: None,
    };
    // Every refusal must leave the original request's authority intact. Unlike
    // the former scripted verifier, these units are admitted by the real key path.
    let mut sanitized = original.clone();
    sanitized.fields.clear();
    for (conn, stream, framing) in [
        (2, 1, Some(1)),
        (1, 2, Some(1)),
        (1, 1, Some(2)),
        (1, 1, None),
    ] {
        for operation in ["auth", "hand-in", "refuse"] {
            if operation == "auth" && framing.is_none() {
                continue;
            }
            let (send, receive) = tokio::sync::oneshot::channel();
            let result = inbound.auth_call(
                request(UnitRef::NONE, 1, 1, 1),
                Box::new(move |r| {
                    let _ = send.send(r);
                }),
            );
            let admitted = match result {
                Some(r) => r,
                None => receive.await.unwrap(),
            }
            .unwrap();
            assert_eq!(admitted.flow, FLOW_CONTINUE);
            let unit = admitted.unit;
            let result = match operation {
                "auth" => inbound
                    .auth_call(
                        request(unit, conn, stream, framing.unwrap()),
                        Box::new(|_| panic!("foreign binding cannot start verification")),
                    )
                    .expect("foreign binding answers now")
                    .map(|_| ()),
                "hand-in" => inbound
                    .hand_in(HandIn {
                        owner: 7,
                        generation: 3,
                        auth,
                        unit,
                        line: 0,
                        conn,
                        stream,
                        framing,
                        head: sanitized.clone(),
                    })
                    .map(|_| ()),
                "refuse" => inbound
                    .refuse(Refuse {
                        owner: 7,
                        generation: 3,
                        unit,
                        cause: REFUSE_STOPPED,
                        line: 0,
                        conn,
                        stream,
                        framing,
                        request: Some(sanitized.clone()),
                    })
                    .map(|_| ()),
                _ => unreachable!(),
            };
            assert_eq!(
                result,
                Err(UNIT_FOREIGN),
                "{operation}: {conn}/{stream}/{framing:?}"
            );
            assert_eq!(
                inbound.hand_in(HandIn {
                    owner: 7,
                    generation: 3,
                    auth,
                    unit,
                    line: 0,
                    conn: 1,
                    stream: 1,
                    framing: Some(1),
                    head: sanitized.clone()
                }),
                Ok((FLOW_CONTINUE, unit)),
                "foreign reuse leaves original intact"
            );
            inbound.exit(unit.id);
        }
    }
    // A claimed admission is the only authority transferable to a detached
    // destination. The public host API enforces the same private verified check.
    inbound.framing_started(7, 71, 1, 3).unwrap();
    inbound.grant_stream(7, 1, 1, 3).unwrap();
    let (send, receive) = tokio::sync::oneshot::channel();
    let result = inbound.auth_call(
        request(UnitRef::NONE, 1, 1, 1),
        Box::new(move |r| {
            let _ = send.send(r);
        }),
    );
    let admitted = match result {
        Some(r) => r,
        None => receive.await.unwrap(),
    }
    .unwrap();
    let unit = admitted.unit;
    assert_eq!(
        inbound.hand_in(HandIn {
            owner: 7,
            generation: 3,
            auth,
            unit,
            line: 0,
            conn: 1,
            stream: 1,
            framing: Some(1),
            head: sanitized.clone()
        }),
        Ok((FLOW_CONTINUE, unit))
    );
    let admission = inbound.claim_request(7, 1, 1, &sanitized).unwrap();

    let source = busbar_contract::framing_scope::AdoptionSource {
        owner: 7,
        listener: 71,
        leg: 1,
        conn: 1,
    };
    assert!(
        inbound.framing_adopting(source, 97, 19).is_err(),
        "live source has not detached"
    );
    let secret = inbound.unit_secret(7, unit.id).unwrap().0;
    inbound.framing_detached(7, 1).unwrap();
    for wrong in [
        busbar_contract::framing_scope::AdoptionSource { owner: 8, ..source },
        busbar_contract::framing_scope::AdoptionSource {
            listener: 72,
            ..source
        },
        busbar_contract::framing_scope::AdoptionSource { leg: 2, ..source },
        busbar_contract::framing_scope::AdoptionSource { conn: 2, ..source },
    ] {
        assert!(inbound.framing_adopting(wrong, 97, 19).is_err());
    }
    let staged = inbound.framing_adopting(source, 97, 19).unwrap();
    assert_eq!(staged.session.unit.id, unit.id);
    assert_eq!(staged.session.stream, 1);
    assert_eq!(staged.generation, 3);
    assert!(inbound.unit_secret(7, unit.id).is_none());
    assert!(
        inbound.unit_secret(97, unit.id).is_none(),
        "staging grants no service authority"
    );
    assert!(inbound.grant_stream(97, 19, 2, 3).is_err());
    inbound.framing_adopted(97, 19, 803).unwrap();
    assert_ne!(inbound.unit_secret(97, unit.id).unwrap().0, secret);
    let continued = |unit, conn, stream, framing| {
        inbound
            .auth_call(
                Call {
                    owner: 97,
                    generation: 3,
                    auth,
                    unit,
                    point: POINT_HEAD,
                    conn,
                    stream,
                    framing,
                    head: sanitized.clone(),
                    body: None,
                    deadline: None,
                },
                Box::new(|_| panic!("retained admission must not verify again")),
            )
            .expect("retained or foreign answers now")
    };
    assert!(
        matches!(continued(unit, 803, 1, 19), Err(UNIT_FOREIGN)),
        "old MAC loses authority"
    );
    for (conn, stream, framing) in [(1, 1, 19), (803, 2, 19), (803, 1, 1)] {
        assert!(matches!(
            continued(staged.session.unit, conn, stream, framing),
            Err(UNIT_FOREIGN)
        ));
    }
    let current = continued(staged.session.unit, 803, 1, 19).unwrap();
    assert_eq!(current.unit, staged.session.unit);
    assert_eq!(current.flow, FLOW_CONTINUE);

    inbound.stream_ended(7, 1, 1);
    inbound.framing_ended(1);
    assert_eq!(
        continued(staged.session.unit, 803, 1, 19).unwrap().flow,
        FLOW_CONTINUE
    );
    inbound.framing_ended(19);
    assert!(inbound.unit_secret(97, unit.id).is_none());
    assert!(inbound.with_credential(unit.id, |_| ()).is_none());
    drop(admission);
    // Two independently claimed requests on one detached connection cannot be
    // guessed into a session. Each actual Store-backed key admission remains held.
    inbound.framing_started(7, 71, 21, 3).unwrap();
    let mut held = Vec::new();
    for stream in [1, 2] {
        inbound.grant_stream(7, 21, stream, 3).unwrap();
        let (send, receive) = tokio::sync::oneshot::channel();
        let result = inbound.auth_call(
            request(UnitRef::NONE, 11, stream, 21),
            Box::new(move |r| {
                let _ = send.send(r);
            }),
        );
        let unit = match result {
            Some(r) => r,
            None => receive.await.unwrap(),
        }
        .unwrap()
        .unit;
        assert_eq!(
            inbound.hand_in(HandIn {
                owner: 7,
                generation: 3,
                auth,
                unit,
                line: 0,
                conn: 11,
                stream,
                framing: Some(21),
                head: sanitized.clone()
            }),
            Ok((FLOW_CONTINUE, unit))
        );
        let receipt = inbound.claim_request(7, 11, stream, &sanitized).unwrap();
        held.push((unit, receipt));
    }
    inbound.framing_detached(7, 21).unwrap();
    assert!(inbound
        .framing_adopting(
            busbar_contract::framing_scope::AdoptionSource {
                owner: 7,
                listener: 71,
                leg: 21,
                conn: 11
            },
            97,
            29
        )
        .is_err());
    for (unit, _) in &held {
        assert!(inbound.unit_secret(7, unit.id).is_some());
    }
    inbound.framing_ended(21);
    for (unit, _) in &held {
        assert!(inbound.unit_secret(7, unit.id).is_none());
    }
    drop(held);

    // Ending either side of a staged transfer retires its credential and prevents
    // a late commit; repeat with distinct genuine framing/connection identities.
    for (source_leg, destination_leg, conn, ended) in [(31, 39, 21, 31), (41, 49, 31, 49)] {
        inbound.framing_started(7, 71, source_leg, 3).unwrap();
        inbound.grant_stream(7, source_leg, 1, 3).unwrap();
        let (send, receive) = tokio::sync::oneshot::channel();
        let result = inbound.auth_call(
            request(UnitRef::NONE, conn, 1, source_leg),
            Box::new(move |r| {
                let _ = send.send(r);
            }),
        );
        let unit = match result {
            Some(r) => r,
            None => receive.await.unwrap(),
        }
        .unwrap()
        .unit;
        assert_eq!(
            inbound.hand_in(HandIn {
                owner: 7,
                generation: 3,
                auth,
                unit,
                line: 0,
                conn,
                stream: 1,
                framing: Some(source_leg),
                head: sanitized.clone()
            }),
            Ok((FLOW_CONTINUE, unit))
        );
        let receipt = inbound.claim_request(7, conn, 1, &sanitized).unwrap();
        inbound.framing_detached(7, source_leg).unwrap();
        let moved = inbound
            .framing_adopting(
                busbar_contract::framing_scope::AdoptionSource {
                    owner: 7,
                    listener: 71,
                    leg: source_leg,
                    conn,
                },
                97,
                destination_leg,
            )
            .unwrap();
        inbound.framing_ended(ended);
        assert!(inbound.framing_adopted(97, destination_leg, 803).is_err());
        assert!(inbound.unit_secret(7, unit.id).is_none());
        assert!(inbound.unit_secret(97, moved.session.unit.id).is_none());
        assert!(inbound.with_credential(unit.id, |_| ()).is_none());
        inbound.framing_ended(source_leg);
        inbound.framing_ended(destination_leg);
        drop(receipt);
    }
    // Actual credential stripping never authorizes deletion of framing fields,
    // including duplicate fields named by Connection. The original opaque signed
    // verifier claim is narrower here: key authentication is real, no fake signer.
    inbound.framing_started(7, 71, 61, 3).unwrap();
    inbound.grant_stream(7, 61, 1, 3).unwrap();
    let mut framed = original.clone();
    framed.fields.extend([
        ("connection".into(), b"close, x-signed".to_vec()),
        ("content-length".into(), b"3".to_vec()),
        ("x-signed".into(), b"first".to_vec()),
        ("x-signed".into(), b"second".to_vec()),
    ]);
    framed.query = Some("x=1".into());
    let (send, receive) = tokio::sync::oneshot::channel();
    let result = inbound.auth_call(
        Call {
            owner: 7,
            generation: 3,
            auth,
            unit: UnitRef::NONE,
            point: POINT_HEAD,
            conn: 61,
            stream: 1,
            framing: 61,
            head: framed.clone(),
            body: None,
            deadline: None,
        },
        Box::new(move |r| {
            let _ = send.send(r);
        }),
    );
    let answer = match result {
        Some(r) => r,
        None => receive.await.unwrap(),
    }
    .unwrap();
    assert_eq!(answer.flow, FLOW_CONTINUE);
    assert!(answer
        .strips
        .contains(&busbar_contract::auth_calls::Strip::field("authorization")));
    let mut framed_admitted = framed.clone();
    framed_admitted
        .fields
        .retain(|(name, _)| name != "authorization");
    for removed in ["connection", "content-length", "x-signed"] {
        let mut changed = framed_admitted.clone();
        changed.fields.retain(|(name, _)| name != removed);
        assert_eq!(
            inbound
                .hand_in(HandIn {
                    owner: 7,
                    generation: 3,
                    auth,
                    unit: answer.unit,
                    line: 0,
                    conn: 61,
                    stream: 1,
                    framing: Some(61),
                    head: changed
                })
                .unwrap()
                .0,
            busbar_contract::abi::host::service::FLOW_STOP,
            "auth permits only its credential strip: {removed}"
        );
    }
    assert_eq!(
        inbound.hand_in(HandIn {
            owner: 7,
            generation: 3,
            auth,
            unit: answer.unit,
            line: 0,
            conn: 61,
            stream: 1,
            framing: Some(61),
            head: framed_admitted.clone()
        }),
        Ok((FLOW_CONTINUE, answer.unit))
    );
    for removed in ["connection", "content-length", "x-signed"] {
        let mut changed = framed_admitted.clone();
        changed.fields.retain(|(name, _)| name != removed);
        assert!(
            inbound.claim_request(7, 61, 1, &changed).is_err(),
            "emission cannot delete an admitted field: {removed}"
        );
    }
    let receipt = inbound.claim_request(7, 61, 1, &framed_admitted).unwrap();
    assert!(
        inbound.claim_request(7, 61, 1, &framed_admitted).is_err(),
        "claim remains single-use"
    );
    drop(receipt);
    inbound.framing_ended(61);
    println!("{WITNESS}");
}
