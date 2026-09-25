// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE REQUEST-LOG WEBHOOK SINK, BOTH WAYS** (item 141 / K9c; DECISIONS #2 rule (1)).
//!
//! The build's linked `request-log-webhook` export row — reached through the generated linked table
//! ([`crate::LINKED`]`.exports`), never by crate name — and the SAME crate's `cdylib`, signed
//! first-party under the SAME statement into a fresh `plugins/` directory, are each registered
//! through the plugin registry's one admission and opened through its one `open_export`. One script
//! runs against each: validate and check its settings, start it (the host's policy asked of its
//! target), deliver two lines (one the far end accepts, one it answers 503), shed one. Everything
//! the host sees — the answers, the requests its egress carrier was asked to make, and every
//! metric and diagnostic it folded — must be byte-identical between the doors.
//!
//! RED ARMS: a tarball packed WITHOUT the declaration the linked row states (the pack tool's
//! `--declares-file` left off) is not the same plugin — its shed counter is not granted and the
//! transcript diverges; and without the linked row the module is not on the axis at all.

use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_loader::{ExportStream, HostResult, HttpRequest, HttpResponse, PluginRegistry};
use serde_json::{json, Value};
use std::sync::Mutex;

const ALIAS: &str = "request-log-webhook";

/// What the host was handed during one script: carried requests and folded observations.
static CARRIED: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static FOLDED: Mutex<Vec<Value>> = Mutex::new(Vec::new());
/// One script at a time (the carrier and the observer are process-global).
static SERIAL: Mutex<()> = Mutex::new(());

/// The egress this test installs: its policy refuses `*.internal.example`; the far end answers 503
/// on a path ending `/fail` and 204 otherwise. It records every request it carries.
struct Carrier;

impl busbar_plugin_loader::EgressCarrier for Carrier {
    fn carry(&self, request: &HttpRequest) -> HostResult {
        CARRIED
            .lock()
            .unwrap()
            .push(serde_json::to_value(request).unwrap());
        let status = if request.url.ends_with("/fail") {
            503
        } else {
            204
        };
        HostResult::Http(HttpResponse {
            status,
            body: String::new(),
        })
    }

    fn admit(&self, url: &str) -> Result<(), String> {
        match url.contains(".internal.example") {
            true => Err(format!("refused target '{url}'")),
            false => Ok(()),
        }
    }
}

struct Observer;

impl busbar_plugin_loader::observe::PluginObserver for Observer {
    fn observe(&self, plugin: &str, kind: &str, metrics: &[Value], diagnostics: &[Value]) {
        FOLDED.lock().unwrap().push(json!({
            "plugin": plugin, "kind": kind, "metrics": metrics, "diagnostics": diagnostics,
            "first_party": busbar_plugin_loader::observe::first_party(plugin),
        }));
    }
}

fn installed() -> std::sync::MutexGuard<'static, ()> {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        busbar_plugin_loader::install_egress_carrier(&Carrier);
        busbar_plugin_loader::observe::install_plugin_observer(&Observer);
    });
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// THE LINKED DOOR: the build's linked export rows, as the composition root registers them.
fn linked_door() -> PluginRegistry {
    let rows = super::linked_exports(crate::LINKED.exports).expect("the linked rows state");
    PluginRegistry::empty()
        .link(rows)
        .expect("the linked door admits them")
}

/// The statement the linked row makes for `ALIAS` — what the tarball must state too.
fn statement(registry: &PluginRegistry) -> Manifest {
    registry
        .resolve(ALIAS)
        .expect("the webhook row")
        .manifest
        .clone()
}

/// The webhook crate's cdylib in this target dir (under CI a missing artifact fails, never skips).
fn cdylib() -> Option<Vec<u8>> {
    let exe = std::env::current_exe().ok()?;
    let profile = exe.parent()?.parent()?;
    let name = busbar_plugin_loader::plugin_library_filename("busbar_export_webhook");
    let found = [profile.join(&name), profile.join("deps").join(&name)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p);
    assert!(
        found.is_some() || std::env::var_os("CI").is_none(),
        "the webhook sink's cdylib is not built under CI; the both-ways proof must not skip"
    );
    std::fs::read(found?).ok()
}

/// THE DROPPED-IN DOOR: `lib` signed by the release key under `manifest` into a fresh `plugins/`.
fn dropped_door(tag: &str, mut manifest: Manifest, lib: &[u8]) -> PluginRegistry {
    let dir = std::env::temp_dir().join(format!("busbar-k9c-webhook-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let release = SigningKey::from_bytes(&[9u8; 32]);
    manifest.sha256 = busbar_plugin_loader::sign::sha256_hex(lib);
    let signed = sign(&release, manifest, lib);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "libwebhook.so", lib).unwrap();
    std::fs::write(dir.join("webhook.tar.gz"), tarball).unwrap();
    let policy = TrustPolicy {
        first_party_key: Some(release.verifying_key()),
        binary_version: "1.6.0".into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
    };
    let registry = busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the scan");
    let _ = std::fs::remove_dir_all(&dir);
    registry
}

/// One script against the `request-log-webhook` row of `registry`: everything the host saw.
fn transcript(registry: &PluginRegistry) -> Value {
    CARRIED.lock().unwrap().clear();
    FOLDED.lock().unwrap().clear();
    let good = json!({
        "url": "https://user:pw@siem.example/in",
        "auth_header": {"name": "Authorization", "value": "Bearer x"},
        "delivery_timeout_secs": 3,
        "max_inflight_deliveries": 7
    });
    let refused = json!({"url": "https://hooks.internal.example/in"});
    let failing = json!({"url": "https://siem.example/fail"});
    let validated = (
        registry.validate_export(ALIAS, "w", &json!({"url": "https://a/", "x": 1})),
        registry.check_export(
            ALIAS,
            &[(
                "w".into(),
                json!({"url": "https://a/", "delivery_timeout_secs": 0}),
            )],
        ),
    );
    let open = |settings: &Value| {
        registry
            .open_export(ALIAS, &settings.to_string())
            .expect("opens")
    };
    let live = open(&good);
    let started = (live.start(), open(&refused).start());
    live.deliver(
        ExportStream::Logs,
        &json!({"ts": 1, "pool": "p", "outcome": "ok"}),
    )
    .unwrap();
    let failing = open(&failing);
    let _ = failing.start();
    failing
        .deliver(ExportStream::Logs, &json!({"ts": 2}))
        .unwrap();
    live.shed();
    json!({
        "validated": format!("{validated:?}"),
        "started": format!("{started:?}"),
        "streams": format!("{:?}", live.streams()),
        "carried": *CARRIED.lock().unwrap(),
        "folded": *FOLDED.lock().unwrap(),
    })
}

/// **K9c EXIT TEST.** The linked and the dropped-in webhook sink register one statement and hand
/// the host byte-identical transcripts; the RED arms diverge.
#[test]
fn the_linked_and_the_dropped_in_webhook_sink_are_one_plugin() {
    let _guard = installed();
    let linked = linked_door();
    let Some(lib) = cdylib() else {
        return;
    };
    let dropped = dropped_door("both", statement(&linked), &lib);
    let (a, b) = (statement(&linked), statement(&dropped));
    let same = |m: &Manifest| {
        (
            m.name.clone(),
            m.alias.clone(),
            m.kind.clone(),
            m.declares.clone(),
        )
    };
    assert_eq!(same(&a), same(&b), "both doors state the same plugin");

    let linked_run = transcript(&linked);
    let dropped_run = transcript(&dropped);
    // What the host sees, spelled out once so the equality below is about the right thing.
    let text = linked_run.to_string();
    for want in [
        r#""url":"https://user:pw@siem.example/in""#,
        r#"["content-type","application/json"],["Authorization","Bearer x"]"#,
        r#""timeout_ms":3000"#,
        "BUSBAR-7070",
        "refused target 'https://hooks.internal.example/in'; disabling this webhook exporter",
        "BUSBAR-7071",
        r#""status":"503""#,
        r#""webhook_url":"\"https://siem.example/fail\"""#,
        r#""name":"busbar_webhook_logs_dropped_total""#,
        "Some((true, 7, \\\"webhook\\\"))",
        "Some((false, 0, \\\"webhook\\\"))",
        "unknown field `x`",
        "(#0) sets settings.delivery_timeout_secs: 0",
    ] {
        assert!(
            text.contains(want),
            "linked transcript lacks {want}: {text}"
        );
    }
    assert_eq!(linked_run, dropped_run, "the two doors are one plugin");

    // RED ARM 1: a tarball without the declaration the linked row states is a different plugin —
    // its shed counter is not granted, so the host's fold of a shed delivery differs.
    let mut undeclared = statement(&linked);
    undeclared.name = "busbar-export-webhook-undeclared".into();
    undeclared.alias = "request-log-webhook-undeclared".into();
    undeclared.declares = Default::default();
    let bare = dropped_door("undeclared", undeclared, &lib);
    let sink = bare
        .open_export(
            "request-log-webhook-undeclared",
            r#"{"url":"https://a.example/"}"#,
        )
        .expect("opens");
    FOLDED.lock().unwrap().clear();
    sink.shed();
    assert!(
        FOLDED
            .lock()
            .unwrap()
            .iter()
            .all(|f| f["metrics"].as_array().is_none_or(Vec::is_empty)),
        "an undeclared shed counter must not be granted: {:?}",
        FOLDED.lock().unwrap()
    );

    // RED ARM 2: without the linked row the module is not on the axis.
    assert!(PluginRegistry::empty().resolve(ALIAS).is_none());
    assert!(PluginRegistry::empty()
        .validate_export(ALIAS, "w", &json!({}))
        .is_none());
}
