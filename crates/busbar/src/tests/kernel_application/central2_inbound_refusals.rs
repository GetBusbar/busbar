// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::auth::{AuthPoints, POINT_HEAD};
use busbar_contract::abi::host::service::{UnitRef, FLOW_STOP, REFUSE_STOPPED};
use busbar_contract::abi::transport::route::{METHOD_POST, PATH_EXACT};
use busbar_kernel::guest::{Claimant, GuestList, Line, LineAuth, Route};
use busbar_kernel::inbound::{Call, Head, Listener, Refusal, Refuse};
use std::sync::Arc;
use std::time::{Duration, Instant};
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[tokio::test]
async fn actual_inbound_refusals_preserve_builder_bytes_unit_retirement_and_real_sink_events() {
    const CHILD: &str = "BUSBAR_CENTRAL2_INBOUND_REFUSALS_CHILD";
    const WITNESS: &str = "actual root inbound refusal custody completed";
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
    let mut manifest = plugins::manifest("store", &module, "third-party");
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("inbound-keys-custody");
    let archive = plugins::signed(&plugins::key(0x33), manifest, &library);
    let archive_sha256 = busbar_plugin_loader::sign::sha256_hex(&archive);
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
    assert!(
        app.governance.is_some(),
        "the real Store supplies governance"
    );

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
    use axum::http::StatusCode;
    use busbar_contract::abi::host::service::{
        LINE_NONE, REFUSE_METHOD_MISS, REFUSE_NO_ROUTE, REFUSE_OVER_GATE,
    };
    use tracing_subscriber::layer::SubscriberExt as _;
    let captured = RefusalEvents::default();
    let subscriber = tracing_subscriber::registry().with(captured.clone());
    let _capture = tracing::subscriber::set_default(subscriber);
    let refuse = |cause, line, unit, path: &str| {
        let mut request = Head::default();
        request.method = "POST".into();
        request.target = path.into();
        inbound.refuse(Refuse {
            owner: 7,
            generation: 3,
            unit,
            cause,
            line,
            conn: 1,
            stream: 1,
            framing: Some(1),
            request: Some(request),
        })
    };
    for (cause, line, status, kind, message) in [
        (
            REFUSE_NO_ROUTE,
            LINE_NONE,
            StatusCode::NOT_FOUND,
            busbar_contract::protocol::ERR_TYPE_NOT_FOUND,
            "the requested resource was not found",
        ),
        (
            REFUSE_METHOD_MISS,
            0,
            StatusCode::METHOD_NOT_ALLOWED,
            busbar_contract::protocol::ERR_TYPE_INVALID_REQUEST,
            "method not allowed for this resource",
        ),
        (
            REFUSE_OVER_GATE,
            0,
            StatusCode::PAYLOAD_TOO_LARGE,
            busbar_contract::protocol::KIND_REQUEST_TOO_LARGE,
            "request body exceeds the maximum allowed size",
        ),
    ] {
        for path in ["/v1/messages", "/api/v1/admin/keys", "/definitely/unknown"] {
            let before = captured.0.lock().unwrap().len();
            let got = refuse(cause, line, UnitRef::NONE, path).unwrap();
            let want = Refusal::of(busbar_kernel::router::fallback_error_response(
                &app.planes,
                path,
                status,
                kind,
                message,
            ));
            assert_eq!(
                got, want,
                "exact production bytes cause {cause} path {path}"
            );
            assert_eq!(got.status, status.as_u16());
            let events = captured.0.lock().unwrap();
            assert_eq!(
                events.len(),
                before + 1,
                "the real root refusal sink is called once"
            );
            let event = events.last().unwrap();
            assert_eq!(event.get("unit").map(String::as_str), Some("None"));
            assert_eq!(event.get("owner").map(String::as_str), Some("7"));
            assert_eq!(event.get("cause").unwrap(), &cause.to_string());
            assert_eq!(event.get("status").unwrap(), &status.as_u16().to_string());
        }
    }
    let stopped = call(bearer("not-a-valid-signed-key")).await;
    assert_eq!(stopped.flow, FLOW_STOP);
    assert!(inbound.unit_secret(7, stopped.unit.id).is_some());
    let before = captured.0.lock().unwrap().len();
    let got = refuse(REFUSE_STOPPED, 0, stopped.unit, "/v1/messages").unwrap();
    let (status, kind) = busbar_kernel::auth::auth_failure_status_and_kind("");
    let want = Refusal::of(busbar_kernel::router::fallback_error_response(
        &app.planes,
        "/v1/messages",
        status,
        kind,
        busbar_kernel::ingress::protocols::vendor_auth_failure_message(""),
    ));
    assert_eq!(
        got, want,
        "the real stopped identity uses exactly the native unauthorized rendering"
    );
    assert_eq!(got.status, 401);
    assert!(
        inbound.unit_secret(7, stopped.unit.id).is_none(),
        "the refused unit is retired"
    );
    {
        let events = captured.0.lock().unwrap();
        assert_eq!(events.len(), before + 1);
        assert_eq!(
            events.last().unwrap().get("unit").unwrap(),
            &format!("Some({})", stopped.unit.id)
        );
        assert_eq!(
            events.last().unwrap().get("status").map(String::as_str),
            Some("401")
        );
    }
    assert_eq!(
        refuse(REFUSE_STOPPED, 0, stopped.unit, "/v1/messages"),
        Err(busbar_kernel::inbound::UNIT_FOREIGN)
    );
    assert_eq!(
        captured.0.lock().unwrap().len(),
        before + 1,
        "an already-retired unit emits no second refusal event"
    );
    println!("{WITNESS}");
}

#[derive(Clone, Default)]
struct RefusalEvents(Arc<std::sync::Mutex<Vec<std::collections::BTreeMap<String, String>>>>);
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for RefusalEvents {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Fields(std::collections::BTreeMap<String, String>);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.insert(field.name().into(), format!("{value:?}"));
            }
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                self.0.insert(field.name().into(), value.into());
            }
        }
        let mut fields = Fields(Default::default());
        event.record(&mut fields);
        if fields
            .0
            .get("message")
            .is_some_and(|message| message.contains("inbound refusal"))
        {
            self.0.lock().unwrap().push(fields.0);
        }
    }
}
