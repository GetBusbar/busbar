// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD};
use busbar_contract::abi::host::service::{UnitRef, FLOW_CONTINUE};
use busbar_contract::abi::transport::route::{METHOD_POST, PATH_EXACT};
use busbar_kernel::governance::NewKeySpec;
use busbar_kernel::guest::{Claimant, GuestList, Line, LineAuth, Route};
use busbar_kernel::inbound::{Call, HandIn, Head, Listener, NO_LIST};
use std::sync::Arc;
use std::time::{Duration, Instant};
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[tokio::test]
async fn actual_inbound_generation_keeps_only_original_request_authority() {
    const CHILD: &str = "BUSBAR_CENTRAL2_INBOUND_GENERATION_CHILD";
    const WITNESS: &str = "actual root inbound generation custody completed";
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
        config.clone(),
        plugin_config.clone(),
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
    let original = Head {
        method: "POST".into(),
        target: "/v1/messages".into(),
        fields: vec![(
            "authorization".into(),
            format!("Bearer {token}").into_bytes(),
        )],
        ..Head::default()
    };
    let call = |unit| Call {
        owner: 7,
        generation: 3,
        auth,
        unit,
        point: POINT_HEAD,
        conn: 1,
        stream: 1,
        framing: 1,
        head: original.clone(),
        body: None,
        deadline: None,
    };
    let (send, receive) = tokio::sync::oneshot::channel();
    let first = inbound.auth_call(
        call(UnitRef::NONE),
        Box::new(move |result| {
            let _ = send.send(result);
        }),
    );
    let first = match first {
        Some(answer) => answer,
        None => receive.await.unwrap(),
    }
    .unwrap();
    assert_eq!(first.flow, FLOW_CONTINUE);
    let old_app = Arc::downgrade(&app);
    let (replacement, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        Some(&app),
        &rules,
        None,
        false,
    )
    .expect("a normal reload builds against the original Store lineage");
    limits.keep().expect("the actual replacement limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let replacement = Arc::new(replacement);
    for generation in 4..=6 {
        for owner in [7, 8] {
            inbound
                .install(owner, generation, listener(Arc::clone(&replacement)))
                .unwrap();
        }
    }
    drop(gov);
    drop(app);
    assert!(
        old_app.upgrade().is_some(),
        "the active request retains its actual original App"
    );
    let answer = |request| {
        inbound.auth_call(
            request,
            Box::new(|_| {
                panic!("a retained settled request cannot restart asynchronous verification")
            }),
        )
    };
    let continuation = answer(call(first.unit))
        .expect("the retained request answers now")
        .unwrap();
    assert_eq!(continuation.unit, first.unit);
    assert_eq!(continuation.flow, FLOW_CONTINUE);
    let mut sanitized = original.clone();
    sanitized.fields.clear();
    assert_eq!(
        inbound.hand_in(HandIn {
            owner: 7,
            generation: 3,
            auth,
            unit: first.unit,
            line: 0,
            conn: 1,
            stream: 1,
            framing: Some(1),
            head: sanitized,
        }),
        Ok((FLOW_CONTINUE, first.unit))
    );
    assert!(
        matches!(answer(call(UnitRef::NONE)), Some(Err(NO_LIST))),
        "no new request may reopen the expired listener generation"
    );
    let mut foreign = call(first.unit);
    foreign.stream = 2;
    assert!(
        matches!(answer(foreign), Some(Err(_))),
        "the retained request grants no other stream authority"
    );
    assert!(
        matches!(
            answer(call(UnitRef {
                mac: first.unit.mac ^ 1,
                ..first.unit
            })),
            Some(Err(_))
        ),
        "the retained table does not admit a forged unit"
    );
    inbound.exit(first.unit.id);
    assert!(
        old_app.upgrade().is_none(),
        "unit exit releases the last old application reference"
    );
    // Admission snapshots the product listener's body policy; publishing a replacement
    // cannot impose a different bound on bytes already admitted, including zero.
    for (owner, limit) in [(9, 0), (10, 7)] {
        let mut policy = listener(Arc::clone(&replacement));
        policy.body_limit = limit;
        inbound.install_at(owner, 71, 7, policy.clone()).unwrap();
        inbound.framing_started(owner, 71, 1, 7).unwrap();
        inbound.grant_stream(owner, 1, 1, 7).unwrap();
        let auth = inbound.specs_at(owner, 71, 7).unwrap()[0].auth;
        let (send, receive) = tokio::sync::oneshot::channel();
        let admitted = inbound.auth_call(
            Call {
                owner,
                generation: 7,
                auth,
                unit: UnitRef::NONE,
                point: POINT_HEAD,
                conn: 1,
                stream: 1,
                framing: 1,
                head: original.clone(),
                body: None,
                deadline: None,
            },
            Box::new(move |result| {
                let _ = send.send(result);
            }),
        );
        let admitted = match admitted {
            Some(answer) => answer,
            None => receive.await.unwrap(),
        }
        .unwrap();
        assert_eq!(admitted.flow, FLOW_CONTINUE);
        let mut sanitized = original.clone();
        sanitized.fields.clear();
        assert_eq!(
            inbound.hand_in(HandIn {
                owner,
                generation: 7,
                auth,
                unit: admitted.unit,
                line: 0,
                conn: 1,
                stream: 1,
                framing: Some(1),
                head: sanitized.clone(),
            }),
            Ok((FLOW_CONTINUE, admitted.unit))
        );
        let receipt = inbound.claim_request(owner, 1, 1, &sanitized).unwrap();
        policy.body_limit = 19;
        inbound.install_at(owner, 71, 8, policy).unwrap();
        assert_eq!(
            receipt.body_limit(),
            limit,
            "live replacement cannot change the admitted body's original bound"
        );
    }
    println!("{WITNESS}");
}
