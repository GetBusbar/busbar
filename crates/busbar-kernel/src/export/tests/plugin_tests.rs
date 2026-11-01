// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the export axis (`export/plugin.rs`). The kernel names no export plugin, so the axis
//! here is a plugin registry scanned out of a temp `plugins/` directory holding NEUTRAL `kind:
//! export` rows whose library bytes are not a library — enough for every question the kernel asks
//! of the axis (does this module resolve, is it an export) and for the open to fail the way a
//! broken plugin fails. The dropped-in plugin that actually SERVES is driven end to end by the
//! composition root (`crates/busbar/tests/export_plugin_dropped_in_serves.rs`).

use super::*;
use crate::config::{resolve_export, ExportDefCfg, ExportDefs};

use crate::export::scrape::tests::installed_axis;

fn def(module: &str) -> ExportDefCfg {
    serde_json::from_value(serde_json::json!({ "module": module })).expect("a minimal definition")
}

struct ListenerPolicySink {
    routes: Vec<Route>,
    public: Vec<String>,
    persistent: Vec<String>,
}

struct ListenerSentinel {
    policy: ListenerPolicySink,
    label: &'static str,
    called: Arc<std::sync::Mutex<Vec<(&'static str, bool)>>>,
}

impl ExportCalls for ListenerSentinel {
    fn streams(&self) -> &[u8] {
        &[]
    }
    fn routes(&self) -> &[Route] {
        self.policy.routes()
    }
    fn public_routes(&self) -> &[String] {
        self.policy.public_routes()
    }
    fn persistent_routes(&self) -> &[String] {
        self.policy.persistent_routes()
    }
    fn deliver(&self, _: u8, _: Vec<u8>, _: Box<dyn Send>) -> Delivered {
        Delivered::Shed
    }
    fn scrape(&self, _: &[busbar_contract::export_calls::Family]) -> Result<Vec<u8>, String> {
        Err("unused".into())
    }
    fn status(&self) -> Option<Vec<u8>> {
        None
    }
    fn serve(&self, _: &ServeRequest<'_>) -> Result<busbar_contract::export_calls::Served, String> {
        let granted = !matches!(
            crate::export::scrape::read(busbar_contract::abi::host::service::SNAPSHOT_SCOPE_HOOKS),
            busbar_contract::services::Snapshot::Refused(_)
        );
        self.called.lock().unwrap().push((self.label, granted));
        Ok(busbar_contract::export_calls::Served {
            status: 200,
            headers: Vec::new(),
            body: self.label.as_bytes().to_vec(),
        })
    }
}

#[test]
fn replacement_export_cannot_lend_its_grant_to_the_old_named_instance() {
    use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
    for old_module in ["third-party", "trusted-observer"] {
        let called = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = |name: &str, module: &str, scrape, label| PluginSink {
            name: name.into(),
            module: module.into(),
            sink: Arc::new(ListenerSentinel {
                policy: ListenerPolicySink {
                    routes: vec![Route {
                        path: "/observations".into(),
                        method: RouteMethod::Get,
                        auth: RouteAuth::Key,
                    }],
                    public: vec!["/observations".into()],
                    persistent: Vec::new(),
                },
                label,
                called: Arc::clone(&called),
            }),
            scrape,
            projection: Projection::for_test(&[ExportStream::Metrics], &[]),
            span_record: false,
            admission: OnceLock::new(),
            reads: OnceLock::new(),
        };
        let cfg = ExportCfg {
            plugins: vec![crate::config::PluginExportSettings {
                name: "reused-name".into(),
                def: def("trusted-observer"),
                projection: Projection::for_test(&[ExportStream::Metrics], &[]),
                scrape: true,
            }],
            ..ExportCfg::default()
        };
        let boot = [
            sink("reused-name", old_module, false, "old"),
            sink("other-name", "trusted-observer", true, "trusted"),
        ];
        let routes = route_decls_from(&cfg, &boot);
        let route = routes
            .iter()
            .find(|r| r.route.path == "/observations")
            .unwrap();
        let reply = route.dispatch.handle_http(&EndpointRequest {
            method: "GET".into(),
            path: "/observations".into(),
            query: String::new(),
            headers: Vec::new(),
            body: Vec::new(),
        });
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, b"trusted");
        assert_eq!(
            *called.lock().unwrap(),
            [("trusted", true)],
            "the old display name never confers the new module's grant"
        );

        called.lock().unwrap().clear();
        let routes = route_decls_from(&cfg, &boot[..1]);
        for route in routes {
            let _ = route.dispatch.handle_http(&EndpointRequest {
                method: "GET".into(),
                path: route.route.path.clone(),
                query: String::new(),
                headers: Vec::new(),
                body: Vec::new(),
            });
        }
        assert!(
            called.lock().unwrap().is_empty(),
            "an unopened replacement never falls back to the old module"
        );
    }
}

impl ExportCalls for ListenerPolicySink {
    fn streams(&self) -> &[u8] {
        &[]
    }
    fn routes(&self) -> &[Route] {
        &self.routes
    }
    fn public_routes(&self) -> &[String] {
        &self.public
    }
    fn persistent_routes(&self) -> &[String] {
        &self.persistent
    }
    fn deliver(&self, _: u8, _: Vec<u8>, _: Box<dyn Send>) -> Delivered {
        Delivered::Shed
    }
    fn scrape(&self, _: &[busbar_contract::export_calls::Family]) -> Result<Vec<u8>, String> {
        Err("unused".into())
    }
    fn status(&self) -> Option<Vec<u8>> {
        None
    }
    fn serve(&self, _: &ServeRequest<'_>) -> Result<busbar_contract::export_calls::Served, String> {
        Err("unused".into())
    }
}

#[test]
fn declared_listener_policy_preserves_boot_routes_but_removes_config_routes() {
    use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
    for paths in [
        ["/metrics", "/metrics/hooks"],
        ["/observations", "/observations/process"],
    ] {
        let sink = PluginSink {
            name: "observer".into(),
            module: "neutral-observer".into(),
            sink: Arc::new(ListenerPolicySink {
                routes: paths
                    .iter()
                    .map(|path| Route {
                        path: (*path).into(),
                        method: RouteMethod::Get,
                        auth: RouteAuth::Key,
                    })
                    .collect(),
                public: paths.iter().map(|path| (*path).into()).collect(),
                persistent: vec![paths[1].into()],
            }),
            scrape: true,
            projection: Projection::for_test(&[ExportStream::Metrics], &[]),
            span_record: false,
            admission: OnceLock::new(),
            reads: OnceLock::new(),
        };
        let mut cfg = ExportCfg {
            plugins: vec![crate::config::PluginExportSettings {
                name: "observer".into(),
                def: def("neutral-observer"),
                projection: Projection::for_test(&[ExportStream::Metrics], &[]),
                scrape: true,
            }],
            ..ExportCfg::default()
        };
        let boot = [sink];
        let table = crate::plugin_routes::build_route_table(route_decls_from(&cfg, &boot)).unwrap();
        for path in paths {
            assert_eq!(
                table.declared_auth(path, &http::Method::GET),
                Some(RouteAuth::Key)
            );
        }
        let removed =
            crate::plugin_routes::build_route_table(route_decls_from(&ExportCfg::default(), &boot))
                .unwrap();
        assert_eq!(removed.declared_auth(paths[0], &http::Method::GET), None);
        assert_eq!(
            removed.declared_auth(paths[1], &http::Method::GET),
            Some(RouteAuth::Key)
        );
        cfg.plugins[0].scrape = false;
        let ungranted =
            crate::plugin_routes::build_route_table(route_decls_from(&cfg, &[])).unwrap();
        assert!(ungranted.paths().is_empty());
        let ungranted_boot = [PluginSink {
            scrape: false,
            ..boot.into_iter().next().unwrap()
        }];
        let ungranted =
            crate::plugin_routes::build_route_table(route_decls_from(&cfg, &ungranted_boot))
                .unwrap();
        assert!(
            ungranted.paths().is_empty(),
            "metadata cannot grant a snapshot consumer's privileges"
        );
    }
}

/// THE CONTROL OF ITEM 141 at the config layer: a `module:` naming a `kind: export` row on the axis
/// — by its name or its alias — RESOLVES to an instance the boot will open, and one naming nothing
/// on the axis is refused in exactly 1.5.5's words, so a config without plugins reads as it always did.
#[test]
fn a_module_on_the_axis_resolves_and_an_unregistered_one_is_refused_as_before() {
    installed_axis();
    for module in ["k9-axis-sink", "k9-tail"] {
        let mut defs = ExportDefs::new();
        defs.insert("audit-tail".to_string(), def(module));
        let mut errors = Vec::new();
        let cfg = resolve_export(&defs, &mut errors);
        assert!(errors.is_empty(), "{module}: {errors:?}");
        assert_eq!(cfg.plugins.len(), 1, "{module}");
        assert_eq!(cfg.plugins[0].name, "audit-tail");
        // The sink's streams are not known until it is opened, so the compute gate provisionally
        // wants what this release produces — `logs` among them — rather than nothing.
        assert!(cfg.projection_union().wants_stream(ExportStream::Logs));
    }

    let mut defs = ExportDefs::new();
    defs.insert("audit-tail".to_string(), def("k9-never-registered"));
    let mut errors = Vec::new();
    let cfg = resolve_export(&defs, &mut errors);
    assert!(cfg.plugins.is_empty());
    assert_eq!(
        errors,
        vec![
            // The modules this axis serves: it LINKS the scrape double (and nothing else). A default
            // binary links every sink, and its line is 1.5.5's byte for byte
            // (`crates/busbar/tests/export_unknown_module_lists_what_links.rs`).
            "export.audit-tail.module: unknown exporter 'k9-never-registered'; the built-in export \
             modules are prometheus"
                .to_string()
        ]
    );
}

/// A sink that will not open refuses the boot, naming the instance and carrying the loader's reason
/// — a configured sink is never silently absent.
#[test]
fn a_sink_that_will_not_open_refuses_naming_the_instance() {
    installed_axis();
    let mut defs = ExportDefs::new();
    defs.insert("tail".to_string(), def("k9-axis-sink"));
    let mut errors = Vec::new();
    let cfg = resolve_export(&defs, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
    let refusal = open(&cfg).expect_err("bytes that are not a library do not open");
    assert!(refusal.starts_with("export.tail: "), "{refusal}");
}

/// THE SHED CAP (PB-12): a plugin sink that states no admission is held to the host's
/// [`MAX_INFLIGHT_PLUGIN_DELIVERIES`] — the 65th delivery in flight is SHED, never queued, and a
/// released slot admits again; a sink that states its bound is held to exactly that. RED arm, in
/// the same test: a stated bound of 0 is the host's cap, never a gate that admits nothing (or
/// everything).
#[test]
fn a_plugin_sink_sheds_deliveries_beyond_its_inflight_cap() {
    assert_eq!(MAX_INFLIGHT_PLUGIN_DELIVERIES, 64);
    let fill = |a: &Admission, n: usize| -> Vec<_> {
        (0..n)
            .map(|i| {
                a.gate
                    .try_enter()
                    .unwrap_or_else(|| panic!("slot {i} is within the cap"))
            })
            .collect()
    };
    let host = Admission::of("k9-tail", None);
    assert!(host.live);
    let held = fill(&host, MAX_INFLIGHT_PLUGIN_DELIVERIES);
    assert!(
        host.gate.try_enter().is_none(),
        "the delivery past the cap is shed"
    );
    drop(held);
    assert!(
        host.gate.try_enter().is_some(),
        "a released slot admits again"
    );

    let stated = Admission::of("k9-tail", Some((true, 3, "webhook".into())));
    let held = fill(&stated, 3);
    assert!(
        stated.gate.try_enter().is_none(),
        "a stated bound is the cap"
    );
    drop(held);

    // RED ARM: `inflight: 0` states no bound — the host's cap, not zero.
    let zero = Admission::of("k9-tail", Some((true, 0, String::new())));
    let _held = fill(&zero, MAX_INFLIGHT_PLUGIN_DELIVERIES);
    assert!(zero.gate.try_enter().is_none());
    // A sink that is not live keeps its gate but takes nothing.
    assert!(!Admission::of("k9-tail", Some((false, 0, String::new()))).live);
}

/// Each configured instance holds its OWN admission gate: one saturated instance never consumes a
/// sibling's budget (the per-instance posture the request-log webhook always had).
#[test]
fn each_plugin_sink_instance_gets_its_own_admission_gate() {
    let a = Admission::of("request-log-webhook", Some((true, 1, "webhook".into())));
    let b = Admission::of("request-log-webhook", Some((true, 1, "webhook".into())));
    let _held = a.gate.try_enter().expect("a admits one");
    assert!(a.gate.try_enter().is_none(), "a is saturated");
    assert!(
        b.gate.try_enter().is_some(),
        "b is untouched by a's saturation"
    );
}

// ── Q128 arch u31 #36/#37: what a sink is fed, and what is audited as read ─────────────────────

/// A sink double answering every delivery with `answer`, stating `stated` at start, and counting
/// the deliveries it shed.
struct AnsweringSink {
    answer: Delivered,
    stated: Option<(bool, u64, String)>,
    sheds: std::sync::atomic::AtomicU64,
}

impl ExportCalls for AnsweringSink {
    fn streams(&self) -> &[u8] {
        &[]
    }
    fn routes(&self) -> &[busbar_contract::abi::mechanism::route::Route] {
        &[]
    }
    fn deliver(&self, _: u8, _: Vec<u8>, _: Box<dyn Send>) -> Delivered {
        self.answer
    }
    fn scrape(&self, _: &[busbar_contract::export_calls::Family]) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }
    fn status(&self) -> Option<Vec<u8>> {
        None
    }
    fn serve(
        &self,
        _: &busbar_contract::export_calls::ServeRequest<'_>,
    ) -> Result<busbar_contract::export_calls::Served, String> {
        Err("the double serves nothing".to_string())
    }
    fn admission(&self) -> Option<(bool, u64, String)> {
        self.stated.clone()
    }
    fn shed(&self) {
        self.sheds
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// An opened (not yet started) sink over `double`, recording its reads on a journal of its own.
fn opened(module: &str, double: Arc<AnsweringSink>) -> PluginSink {
    PluginSink {
        name: module.to_string(),
        module: module.to_string(),
        sink: double,
        scrape: false,
        projection: Projection::for_test(&[ExportStream::Logs], &[]),
        span_record: false,
        admission: OnceLock::new(),
        reads: OnceLock::from(Arc::new(crate::audit::amend::NodeAmendments::new())),
    }
}

fn double(answer: Delivered, stated: Option<(bool, u64, String)>) -> Arc<AnsweringSink> {
    Arc::new(AnsweringSink {
        answer,
        stated,
        sheds: std::sync::atomic::AtomicU64::new(0),
    })
}

/// The export access amendments `s` sealed on its journal under `op` (each test uses its own label).
fn reads_under(s: &PluginSink, op: &str) -> usize {
    s.reads
        .get()
        .map(|journal| journal.recent())
        .unwrap_or_default()
        .into_iter()
        .filter(|a| {
            matches!(&a.body, crate::audit::amend::AmendBody::Access(x) if x.op_class.as_str() == op)
        })
        .count()
}

fn payload(_: Projection, _: bool) -> Arc<Value> {
    Arc::new(serde_json::json!({ "path": "/v1/x" }))
}

/// A line the sink's queue SHED never reached it, so it is not audited as read; a line it QUEUED is
/// audited once. RED before the fix: the amendment was written before the hand-off, so a shed line
/// was recorded as an export read of fields that never left the node.
#[test]
fn a_shed_line_is_not_audited_as_read_and_a_queued_one_is() {
    let shedding = double(Delivered::Shed, None);
    let s = opened("q128b-u31-36-shed", Arc::clone(&shedding));
    start_one(&s);
    deliver_one(&s, ExportStream::Logs, "q128b-u31-36-shed", &mut payload);
    assert_eq!(
        reads_under(&s, "q128b-u31-36-shed"),
        0,
        "a shed line is no read"
    );
    assert_eq!(shedding.sheds.load(std::sync::atomic::Ordering::Relaxed), 1);

    let queueing = double(Delivered::Queued, None);
    let s = opened("q128b-u31-36-queued", Arc::clone(&queueing));
    start_one(&s);
    deliver_one(&s, ExportStream::Logs, "q128b-u31-36-queued", &mut payload);
    assert_eq!(
        reads_under(&s, "q128b-u31-36-queued"),
        1,
        "a queued line is one read"
    );
    assert_eq!(queueing.sheds.load(std::sync::atomic::Ordering::Relaxed), 0);
}

/// A sink is fed under the admission IT stated at start, even when a delivery reached it first: a
/// delivery before start is shed, and the sink's own `live: false` then holds. RED before the fix:
/// the first delivery filled the admission with the host's default (live), start's `set` was a
/// no-op, and the sink's stated admission was ignored for the life of the process.
#[test]
fn a_delivery_before_start_never_overrides_the_sinks_stated_admission() {
    let paused = double(Delivered::Queued, Some((false, 1, String::new())));
    let s = opened("q128b-u31-37", Arc::clone(&paused));
    deliver_one(&s, ExportStream::Logs, "q128b-u31-37-early", &mut payload);
    assert_eq!(
        reads_under(&s, "q128b-u31-37-early"),
        0,
        "nothing is fed before start"
    );
    assert_eq!(paused.sheds.load(std::sync::atomic::Ordering::Relaxed), 1);
    start_one(&s);
    deliver_one(&s, ExportStream::Logs, "q128b-u31-37-late", &mut payload);
    assert_eq!(
        reads_under(&s, "q128b-u31-37-late"),
        0,
        "the sink stated live: false, and that holds"
    );
}

/// An axis whose one module declares `auth_header.value` secret (its Statement's `secret_refs`)
/// and `url` reference-capable (its Statement's reference-capable list), answering nothing else:
/// what [`sink_settings`] asks of a real axis.
struct DeclaringAxis;

impl ExportAxis for DeclaringAxis {
    fn probe(&self, _: &str, _: &str, _: &Value) -> Option<busbar_contract::export_calls::Probed> {
        None
    }
    fn check(&self, _: &str, _: u32, _: &[(String, &Value)]) -> Option<Vec<String>> {
        None
    }
    fn open(&self, module: &str, _: &str, _: &Value) -> Result<Arc<dyn ExportCalls>, String> {
        Err(format!("{module} opens nothing here"))
    }
    fn linked(&self, _: &str) -> bool {
        true
    }
    fn first_party(&self, _: &str) -> bool {
        true
    }
    fn secret_refs(&self, module: &str) -> Vec<String> {
        match module {
            "declaring-sink" => vec!["auth_header.value".into()],
            _ => Vec::new(),
        }
    }
    fn reference_fields(&self, module: &str) -> Vec<String> {
        match module {
            "declaring-sink" => vec!["url".into()],
            _ => Vec::new(),
        }
    }
}

fn settings_of(v: Value) -> serde_json::Map<String, Value> {
    match v {
        Value::Object(map) => map,
        other => panic!("not settings: {other}"),
    }
}

/// THE EXPORT HOST, REFERENCE-CAPABLE `url` (lead ruling item 7a; 1.5.5's own otlp and
/// request-log-webhook docs write `url: {env: VAR}`): a reference at the sink's reference-capable
/// `url` and at its secret `auth_header.value` reaches the sink RESOLVED to its string (the export
/// host lends nothing; references resolve in place); a literal url is handed as written; the
/// configuration keeps the reference. RED before: the sink was handed the `{env: …}` map.
#[test]
fn a_reference_at_a_reference_capable_url_reaches_the_sink_resolved() {
    let (url, token) = (
        format!("BUSBAR_T_REFCAP_EXPORT_URL_{}", std::process::id()),
        format!("BUSBAR_T_REFCAP_EXPORT_TOKEN_{}", std::process::id()),
    );
    std::env::set_var(&url, "https://siem.example/in");
    std::env::set_var(&token, "Bearer t0k");
    let written = settings_of(serde_json::json!({
        "url": { "env": url },
        "auth_header": { "name": "Authorization", "value": { "env": token } },
        "batch": 10,
    }));
    let handed = sink_settings(&DeclaringAxis, "declaring-sink", &written).expect("resolves");
    let diagnostic = format!("{handed:?}");
    assert!(
        !diagnostic.contains("Bearer t0k"),
        "the settings owner must not expose a resolved credential through Debug"
    );
    assert_eq!(
        handed.as_value(),
        &serde_json::json!({
            "url": "https://siem.example/in",
            "auth_header": { "name": "Authorization", "value": "Bearer t0k" },
            "batch": 10,
        })
    );
    assert_eq!(written["url"], serde_json::json!({ "env": url }));

    let literal = settings_of(serde_json::json!({ "url": "https://collector.example/v1/traces" }));
    assert_eq!(
        sink_settings(&DeclaringAxis, "declaring-sink", &literal)
            .expect("as written")
            .as_value(),
        &Value::Object(literal.clone())
    );

    // Fail-closed: an unset variable at the url is the error, naming the field.
    std::env::remove_var(&url);
    let err = sink_settings(&DeclaringAxis, "declaring-sink", &written).unwrap_err();
    assert!(err.contains("url"), "{err}");
    assert!(!err.contains("Bearer t0k"), "{err}");
    std::env::remove_var(&token);

    // A module declaring nothing is handed its settings as written: the undeclared reference is
    // the undeclared-reference refusal's to word (`config_validate`), not this resolution's.
    let undeclared = settings_of(serde_json::json!({ "url": { "env": "NEVER_READ" } }));
    assert_eq!(
        sink_settings(&DeclaringAxis, "silent-sink", &undeclared)
            .expect("as written")
            .as_value(),
        &Value::Object(undeclared.clone())
    );
}

#[test]
fn export_reference_diagnostics_keep_secret_and_plain_fields_distinct() {
    use crate::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let url_var = format!("BUSBAR_T_EXPORT_CLASS_URL_{}", std::process::id());
    let token_var = format!("BUSBAR_T_EXPORT_CLASS_TOKEN_{}", std::process::id());
    let url = "https://classification.example/collector";
    let token = "Bearer export-classification-fixture";
    std::env::set_var(&url_var, url);
    std::env::set_var(&token_var, token);
    let written = settings_of(serde_json::json!({
        "url": { "env": url_var },
        "auth_header": { "name": "Authorization", "value": { "env": token_var } },
    }));
    let cap = WarnCapture::capturing_debug();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let handed = tracing::subscriber::with_default(subscriber, || {
        sink_settings(&DeclaringAxis, "declaring-sink", &written)
    });
    std::env::remove_var(&url_var);
    std::env::remove_var(&token_var);
    let handed = handed.expect("the two references resolve");
    assert_eq!(handed.as_value()["url"], url);
    assert_eq!(handed.as_value()["auth_header"]["value"], token);
    assert_eq!(written["url"], serde_json::json!({ "env": url_var }));
    assert_eq!(
        written["auth_header"]["value"],
        serde_json::json!({ "env": token_var })
    );
    let literal = settings_of(serde_json::json!({
        "url": "https://literal.example/collector",
        "auth_header": { "name": "Authorization", "value": "Bearer literal-fixture" },
    }));
    assert_eq!(
        sink_settings(&DeclaringAxis, "declaring-sink", &literal)
            .expect("existing literal settings still pass through")
            .as_value(),
        &Value::Object(literal.clone())
    );
    let events = cap.messages();
    assert!(
        events
            .iter()
            .all(|line| !line.contains(url) && !line.contains(token)),
        "reference diagnostics must never include resolved values"
    );
    assert!(
        events
            .iter()
            .any(|line| line.contains("setting=url ")
                && line.contains("reference-capable (not secret)")),
        "the URL reference must retain its plain-setting classification"
    );
    assert!(
        events
            .iter()
            .any(|line| line.contains("setting=auth_header.value ")
                && line.contains("SECRET REFERENCE")),
        "the declared credential must be identified as a secret reference"
    );
}

/// RED (export ABI defect 8): the HOST words the refusal of every instance of a `one_instance`
/// module after the first, naming the first, around the reason the module's check gives — and
/// in its own reason when the check gives none. Before, the plugin worded the whole line, and a
/// module whose check found nothing let a second instance through unrefused and unresolved.
#[test]
fn the_host_words_the_one_instance_refusal() {
    let names = ["a".to_string(), "b".to_string(), "c".to_string()];
    let why = "The sink holds one port, so a second instance could only be ignored.";
    assert_eq!(
        word_one_instance("probe", &names, vec![why.to_string()]),
        [
            format!("export.b: a second `module: probe` instance (already defined as 'a'). {why}"),
            format!("export.c: a second `module: probe` instance (already defined as 'a'). {why}"),
        ]
    );
    let unworded = word_one_instance("probe", &names[..2], Vec::new());
    assert_eq!(unworded.len(), 1, "{unworded:?}");
    assert!(
        unworded[0]
            .starts_with("export.b: a second `module: probe` instance (already defined as 'a'). "),
        "{unworded:?}"
    );
    // A plugin built on an SDK that worded the whole line keeps its line, verbatim.
    let whole = vec![
        "export.b: a second `module: probe` instance (already defined as 'a'). Old.".to_string(),
    ];
    assert_eq!(
        word_one_instance("probe", &names[..2], whole.clone()),
        whole
    );
}
