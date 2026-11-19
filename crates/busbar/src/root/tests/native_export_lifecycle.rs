// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Installed native Export images through the real S9 registry, Needs, pump and observation owner.
//! No ExportPort double: the webhook makes actual HTTP requests; metrics routes come from the image.
use super::*;
use crate::root::export_observer::{ExportGeneration, ExportObservers};
use busbar_contract::export_calls::{Delivered, ExportCalls, ExportDropReason, ExportLossKind};
use busbar_contract::export_stream::ExportStream;
use busbar_plugin_loader::export_pump::{PortDoor, StopReport};
use std::path::{Path, PathBuf};
use tokio::sync::{mpsc, oneshot, Notify};

const WAIT: Duration = Duration::from_secs(5);

struct NativeExport {
    door: Arc<PortDoor>,
    witness: Arc<NativeWitness>,
    returned: mpsc::UnboundedReceiver<(u64, u32, Option<u64>)>,
    pumps: Option<crate::root::exports::ports::Exports>,
    observers: Arc<ExportObservers>,
    _generation: ExportGeneration,
    serving: ServingFixture,
    startup: Option<busbar_kernel::persistence::startup::Startup>,
    rules: Arc<dyn RootRules>,
    plugins: PluginsCfg,
    document: serde_json::Value,
    name: String,
    directory: PathBuf,
}

fn stage_image(directory: &Path, kind: &str, path: &Path) -> String {
    // A MIN-3 image is named by its stamp; the root admits no other image.
    let manifest = crate::root::test_plugins::native_manifest(
        kind,
        path,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    let module = manifest.name.clone();
    let bytes = std::fs::read(path).expect("read the separately built actual image");
    let archive =
        crate::root::test_plugins::signed(&crate::root::test_plugins::key(0x5a), manifest, &bytes);
    std::fs::write(directory.join(format!("{module}.tar.gz")), archive).unwrap();
    module
}

impl NativeExport {
    async fn open(image: &str, settings: serde_json::Value) -> Self {
        crate::dist_root_install::install();
        let name = format!("native-export-{}", busbar_kernel::door::op_id().counter());
        let directory = crate::root::test_plugins::scratch(&name);
        let store_module = stage_image(
            &directory,
            "store",
            &crate::root::test_plugins::application_store_library(),
        );
        let path = crate::root::test_plugins::cdylib_path(image).unwrap_or_else(|| {
            crate::root::test_plugins::missing(image, crate::root::test_plugins::BUILD_PINNED)
        });
        let export_module = stage_image(&directory, "export", &path);
        let plugins = crate::root::test_plugins::trusted_config(&directory);
        let mut document = serde_json::json!({
            "providers": {}, "models": {},
            "auth": {"chain": []},
            "store": {"module": store_module, "settings": crate::root::test_plugins::application_store_settings(&directory)},
            "advanced": {"block_private_addresses": false},
            "export": {},
        });
        document["export"][&name] =
            serde_json::json!({"module": export_module, "settings": settings});
        let cfg = Self::config(&document, &plugins);
        let policy: Arc<dyn RootRules> = Arc::new(crate::root::door_steps::Rules::default());
        let fixture = super::open(&cfg, &plugins, policy)
            .await
            .expect("native S5/Store fixture opens");
        // Keep the actual admission owner for root finish, rather than dropping Startup after
        // extracting its CoreStore as the serving-only fixture helper does.
        let mut startup = busbar_kernel::persistence::startup::Startup::new(
            fixture.backend,
            busbar_kernel::persistence::facade::Limits {
                pending_operations: 1024,
                conflict_retries: 8,
                scan_items: 128,
                scan_bytes: 1024 * 1024,
            },
            true,
        )
        .unwrap();
        loop {
            use busbar_kernel::persistence::startup::Progress;
            match startup
                .advance()
                .await
                .expect("actual native Store admission")
            {
                Progress::Advanced => {}
                Progress::Admitted => break,
                other => panic!("native Export fixture did not admit: {other:?}"),
            }
        }
        let serving = ServingFixture {
            owners: fixture.owners,
            core: startup.store().unwrap(),
        };
        let observers = ExportObservers::new();
        let reservation = observers.reserve([name.clone()]).unwrap();
        let built = &serving.owners.built;
        let instances = configured(&cfg, &[]).unwrap();
        let specs = specifications(&instances, cfg.public_url.as_deref(), false);
        let (_, spec) = specs
            .iter()
            .find(|(kind, spec)| *kind == KindCode::Export && spec.name == name)
            .expect("the configured native exporter participates in the ordinary plan");
        let prepared = built
            .registry
            .reserve(spec)
            .expect("the real instance reserves before open");
        let instance_id = prepared.id();
        let provisioned = crate::root::provisioning::prepare(
            Arc::clone(&serving.core),
            Arc::new(LogEvents),
            Vec::new(),
        )
        .await
        .unwrap();
        let needs = built.needs_for(
            Arc::clone(&serving.owners.prefix),
            Arc::new(StoreRecords::new(Arc::clone(&serving.core))),
            provisioned.directory,
        );
        let port = built
            .registry
            .open_export_reserved(prepared, &needs, &serving.owners.prefix.refs())
            .await
            .expect("the installed native Export opens through production Needs");
        let disk = Arc::new(crate::root::exports::ports::BoundDisk::new(
            instance_id,
            Arc::clone(&built.binder),
            crate::root::linked::disk_lane(),
        ));
        let (returned, answers) = mpsc::unbounded_channel();
        let witness = Arc::new(NativeWitness {
            port,
            attempts: AtomicU64::new(0),
            returned,
        });
        let door = PortDoor::prepare(
            &name,
            witness.clone(),
            disk,
            &spec.limits,
            reservation.observer(&name).unwrap(),
        );
        let pumps =
            crate::root::exports::ports::Exports::new(vec![(name.clone(), door.clone())]).unwrap();
        let generation = reservation.commit();
        pumps.start().expect("the published native pump starts");
        Self {
            door,
            witness,
            returned: answers,
            pumps: Some(pumps),
            observers,
            _generation: generation,
            serving,
            startup: Some(startup),
            rules: fixture.rules,
            plugins,
            document,
            name,
            directory,
        }
    }

    fn config(document: &serde_json::Value, plugins: &PluginsCfg) -> RootCfg {
        let grammar = super::grammar(plugins).expect("actual installed-image grammar");
        let deploy = busbar_kernel::config::deploy_from_deserializer(document, &grammar).unwrap();
        busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap()
    }

    fn send(&self, line: &[u8], hold: Box<dyn Send>) {
        assert_eq!(
            self.door
                .deliver(ExportStream::Logs as u8, line.to_vec(), hold),
            Delivered::Queued
        );
    }

    async fn stop(&mut self, deadline: Instant) -> StopReport {
        let pumps = self.pumps.take().expect("one actual root pump owner");
        let reports = tokio::task::spawn_blocking(move || pumps.stop_until(deadline))
            .await
            .unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].0, self.name);
        reports[0].1
    }

    async fn quiesced(&self) -> StopReport {
        tokio::time::timeout(WAIT, async {
            loop {
                let report = self.door.stop_until(Instant::now());
                if report.worker_stopped {
                    return report;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("native cancellation finishes within the proof bound")
    }

    async fn settle_loss(&self) {
        let first = self.observers.unresolved();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].instance, self.name);
        self.observers.step();
        self.observers.step();
        let still_pending = self.observers.unresolved();
        if !still_pending.is_empty() {
            assert_eq!(
                still_pending, first,
                "ownership transfer cannot replace first-loss facts"
            );
        }
        self.observers.stop_intake();
        let (app, _limits) = self.application(&self.document, None).await;
        busbar_kernel::audit::auditlog::register_test_audit_stream(&Arc::new(app)).await;
        tokio::time::timeout(WAIT, async {
            loop {
                self.observers.step();
                busbar_kernel::audit::auditlog::flush_pending()
                    .await
                    .unwrap();
                self.observers.step();
                if self.observers.is_settled() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the exact original gets a native confirmation");
        let rows =
            busbar_kernel::audit::auditlog::AUDIT_LOG.list_filtered(0, usize::MAX, None, None);
        let recorded: Vec<_> = rows
            .iter()
            .filter(|row| {
                row.action == "export.loss" && row.instance.as_deref() == Some(self.name.as_str())
            })
            .collect();
        assert_eq!(
            recorded.len(),
            1,
            "repeated transfer passes retain exactly one native original"
        );
        assert_eq!(
            recorded[0].resource,
            format!("dropped.stopped.count_{}", first[0].count)
        );
        assert_eq!(self.observers.late_callbacks(), 0);
    }
}

struct Receiver {
    url: String,
    requests: mpsc::UnboundedReceiver<Vec<u8>>,
    release: Arc<Notify>,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl Receiver {
    async fn start(retry: bool) -> Self {
        use axum::routing::post;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/receive", listener.local_addr().unwrap());
        let (send, requests) = mpsc::unbounded_channel();
        let release = Arc::new(Notify::new());
        let held = release.clone();
        let router = axum::Router::new().route(
            "/receive",
            post(move |body: axum::body::Bytes| {
                let send = send.clone();
                let held = held.clone();
                async move {
                    let released = held.notified();
                    tokio::pin!(released);
                    released.as_mut().enable();
                    send.send(body.to_vec()).unwrap();
                    if retry {
                        (
                            axum::http::StatusCode::SERVICE_UNAVAILABLE,
                            [("retry-after", "300")],
                        )
                    } else {
                        released.await;
                        (axum::http::StatusCode::OK, [("retry-after", "0")])
                    }
                }
            }),
        );
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        Self {
            url,
            requests,
            release,
            stop: Some(stop),
            task,
        }
    }

    async fn next(&mut self) -> Vec<u8> {
        tokio::time::timeout(WAIT, self.requests.recv())
            .await
            .unwrap()
            .expect("actual native HTTP attempt")
    }

    async fn finish(mut self) {
        self.release.notify_waiters();
        let _ = self.stop.take().unwrap().send(());
        tokio::time::timeout(WAIT, &mut self.task)
            .await
            .expect("receiver stops")
            .unwrap();
        assert!(
            self.requests.try_recv().is_err(),
            "stopping must not dispatch another delivery"
        );
    }
}

#[tokio::test]
async fn installed_webhook_retry_after_cannot_extend_stop_or_start_another_attempt() {
    let mut receiver = Receiver::start(true).await;
    let mut fixture = NativeExport::open(
        "busbar_export_webhook_plugin",
        serde_json::json!({"url": receiver.url}),
    )
    .await;
    fixture.send(br#"{"case":"retry"}"#, Box::new(()));
    assert_eq!(receiver.next().await, br#"{"case":"retry"}"#);
    let (delivery, attempt, retry_after) = tokio::time::timeout(WAIT, fixture.returned.recv())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(delivery, 0);
    assert_eq!(
        (attempt, retry_after),
        (1, Some(300)),
        "the actual installed image returned Retry-After before stopping"
    );
    let began = Instant::now();
    let report = fixture.stop(began + Duration::from_millis(50)).await;
    assert!(
        began.elapsed() < WAIT,
        "Retry-After300 must not extend the root stop deadline"
    );
    assert!(
        !report.clean(),
        "the retrying original was never acknowledged"
    );
    // The first call may have returned immediately before or during cancellation. Its worker
    // owns the final loss callback in either ordering; observe actual custody release below.
    let door = fixture.door.clone();
    tokio::time::timeout(WAIT, async {
        while door.dropped() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(fixture.door.delivered(), 0);
    let stopped = fixture.quiesced().await;
    assert_eq!(
        (stopped.queued, stopped.in_flight, stopped.dropped),
        (0, 0, 1)
    );
    assert_eq!(fixture.witness.attempts.load(Ordering::Acquire), 1);
    fixture.settle_loss().await;
    receiver.finish().await;
}

#[tokio::test]
async fn installed_webhook_cancellation_counts_queued_and_inflight_and_retains_native_loss_receipt()
{
    struct Released(mpsc::UnboundedSender<()>);
    impl Drop for Released {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }
    let mut receiver = Receiver::start(false).await;
    let mut fixture = NativeExport::open(
        "busbar_export_webhook_plugin",
        serde_json::json!({"url": receiver.url}),
    )
    .await;
    let (released, mut custody) = mpsc::unbounded_channel();
    fixture.send(b"first", Box::new(Released(released.clone())));
    assert_eq!(receiver.next().await, b"first");
    fixture.send(b"queued", Box::new(Released(released)));
    let report = fixture
        .stop(Instant::now() + Duration::from_millis(50))
        .await;
    assert!(
        !report.clean(),
        "unacknowledged in-flight and queued bytes cannot make exit0"
    );
    for _ in 0..2 {
        tokio::time::timeout(WAIT, custody.recv())
            .await
            .unwrap()
            .unwrap();
    }
    assert_eq!(fixture.door.delivered(), 0);
    assert_eq!(fixture.door.dropped(), 2);
    let loss = fixture.observers.unresolved();
    assert_eq!(loss.len(), 1, "first event owns the retained original");
    assert_eq!(
        loss[0].kind,
        ExportLossKind::Dropped(ExportDropReason::Stopped)
    );
    assert!(loss[0].count > 0 && loss[0].count <= 2);
    let stopped = fixture.quiesced().await;
    assert_eq!(
        (stopped.queued, stopped.in_flight, stopped.dropped),
        (0, 0, 2)
    );
    assert_eq!(
        fixture.witness.attempts.load(Ordering::Acquire),
        1,
        "queued work was never reoffered after cancellation"
    );
    fixture.settle_loss().await;
    receiver.finish().await;
}

#[tokio::test]
async fn acknowledged_native_webhook_finishes_root_shutdown_and_retires_actual_writer() {
    let mut receiver = Receiver::start(false).await;
    let mut fixture = NativeExport::open(
        "busbar_export_webhook_plugin",
        serde_json::json!({"url": receiver.url}),
    )
    .await;
    fixture.send(b"acknowledged", Box::new(()));
    assert_eq!(receiver.next().await, b"acknowledged");
    receiver.release.notify_waiters();
    tokio::time::timeout(WAIT, async {
        while fixture.door.delivered() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(fixture.finish_native(WAIT).await, 0);
    assert!(fixture.observers.is_settled());
    assert_eq!(fixture.door.dropped(), 0);
    assert!(
        fixture.write_probe().await.is_err(),
        "finish retired this exact native writer"
    );
    receiver.finish().await;
}

#[tokio::test]
async fn cancelled_native_webhook_root_finish_retains_writer_and_original_loss() {
    let mut receiver = Receiver::start(false).await;
    let mut fixture = NativeExport::open(
        "busbar_export_webhook_plugin",
        serde_json::json!({"url": receiver.url}),
    )
    .await;
    fixture.send(b"in-flight", Box::new(()));
    assert_eq!(receiver.next().await, b"in-flight");
    fixture.send(b"queued", Box::new(()));
    assert_eq!(fixture.finish_native(Duration::from_millis(100)).await, 75);
    fixture
        .write_probe()
        .await
        .expect("incomplete finish cannot retire the admitted native writer");
    let stopped = fixture.quiesced().await;
    assert_eq!(
        (stopped.queued, stopped.in_flight, stopped.dropped),
        (0, 0, 2)
    );
    assert_eq!(fixture.door.delivered(), 0);
    assert_eq!(fixture.witness.attempts.load(Ordering::Acquire), 1);
    // A deadline may leave the original at the observer or already in native custody. Resume
    // the same owner, never manufacture another loss record or replace its receipt.
    fixture.observers.stop_intake();
    tokio::time::timeout(WAIT, async {
        loop {
            fixture.observers.step();
            busbar_kernel::audit::auditlog::flush_pending()
                .await
                .unwrap();
            fixture.observers.step();
            if fixture.observers.is_settled() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let rows = busbar_kernel::audit::auditlog::AUDIT_LOG.list_filtered(
        0,
        usize::MAX,
        Some("export.loss"),
        None,
    );
    let originals: Vec<_> = rows
        .iter()
        .filter(|row| row.instance.as_deref() == Some(fixture.name.as_str()))
        .collect();
    assert_eq!(
        originals.len(),
        1,
        "root finish and resumed settlement confirm one original"
    );
    assert!(matches!(
        originals[0].resource.as_str(),
        "dropped.stopped.count_1" | "dropped.stopped.count_2"
    ));
    assert_eq!(fixture.observers.late_callbacks(), 0);
    receiver.finish().await;
}

/// Observation-only forwarding boundary: every answer and cancellation is the installed image's.
struct NativeWitness {
    port: Arc<dyn busbar_ports::export::ExportPort>,
    attempts: AtomicU64,
    returned: mpsc::UnboundedSender<(u64, u32, Option<u64>)>,
}
impl busbar_ports::export::ExportPort for NativeWitness {
    fn streams(&self) -> u32 {
        self.port.streams()
    }
    fn scopes(&self) -> &[busbar_ports::export::ScopeInfo] {
        self.port.scopes()
    }
    fn recorder(&self) -> Option<busbar_ports::export::RecorderNeeds> {
        self.port.recorder()
    }
    fn span_records(&self) -> bool {
        self.port.span_records()
    }
    fn custody_ceiling(&self) -> Option<u32> {
        self.port.custody_ceiling()
    }
    fn pending_capacity(&self) -> Option<u64> {
        self.port.pending_capacity()
    }
    fn confirm(
        &self,
        cx: busbar_ports::CallCx,
        delivery: u64,
    ) -> BoxFut<'_, Result<busbar_ports::export::Custody, busbar_ports::PortError>> {
        self.port.confirm(cx, delivery)
    }
    fn render(
        &self,
        scope: u32,
        snapshot: &[busbar_ports::export::FamilyIn<'_>],
        sink: &mut dyn FnMut(&str, &[u8]),
    ) -> Result<(), busbar_ports::PortError> {
        self.port.render(scope, snapshot, sink)
    }
    fn deliver<'a>(
        &'a self,
        cx: busbar_ports::CallCx,
        stream: u32,
        delivery: u64,
        attempt: u32,
        lines: &'a [&'a [u8]],
    ) -> BoxFut<'a, Result<busbar_ports::export::Delivered, busbar_ports::PortError>> {
        self.attempts.fetch_add(1, Ordering::AcqRel);
        Box::pin(async move {
            let answer = self
                .port
                .deliver(cx, stream, delivery, attempt, lines)
                .await;
            let retry = match &answer {
                Err(busbar_ports::PortError::Failed { retry_after_s, .. }) => *retry_after_s,
                _ => None,
            };
            let _ = self.returned.send((delivery, attempt, retry));
            answer
        })
    }
}

impl NativeExport {
    async fn write_probe(&self) -> Result<(), String> {
        self.serving
            .core
            .identity()
            .put_key(&busbar_contract::records::VirtualKey {
                id: format!(
                    "native-export-writer-probe-{}",
                    busbar_kernel::door::op_id().counter()
                ),
                enabled: true,
                ..Default::default()
            })
            .await
            .map(|_| ())
            .map_err(|error| format!("{error:?}"))
    }

    async fn finish_native(&mut self, budget: Duration) -> i32 {
        use crate::root::shutdown::{
            DrainClock, ExportRetry, PostServe, ShutdownDrain, ShutdownSignals,
        };
        self.persist(&self.document).unwrap();
        let (app, limits) = self.application(&self.document, None).await;
        limits.stage_boot();
        crate::root::door_steps::tests::boot_fixture_prices(&app).await;
        limits.keep().await.unwrap();
        let cfg = Self::config(&self.document, &self.plugins);
        let exports = busbar_kernel::export::plugin::open_prepared(
            &cfg.export,
            &self.pumps.as_ref().unwrap().calls(),
            app.amendments.clone(),
        )
        .unwrap();
        let app = Arc::new(
            busbar_kernel::export::plugin::assemble_routes(app, &cfg.export, Vec::new(), exports)
                .unwrap(),
        );
        busbar_kernel::audit::auditlog::register_test_audit_stream(&app).await;
        let observers = self.observers.clone();
        let post = PostServe {
            admin: None,
            lines: None,
            threads: Vec::new(),
            work_recovery: tokio::spawn(async {}),
            generation_workers: crate::root::min3_candidate::Workers::idle(),
            exports: self.pumps.take().expect("one root pump owner"),
            export_captures: app.exports.clone(),
            export_observer_retry: ExportRetry::start(observers.clone()),
            export_observers: observers,
            control_drain: Box::pin(async {}),
            node_lease: None,
            flusher: None,
            governance: app.governance.clone(),
            late: crate::root::serve::Services::idle(),
            book: None,
            startup: self
                .startup
                .take()
                .expect("the exact admitted native writer"),
            predecessor: None,
        };
        let drain = ShutdownDrain::new(DrainClock::new(budget));
        let (workers, safety) = tokio::sync::watch::channel(false);
        let (listeners, _) = tokio::sync::broadcast::channel(1);
        drain.start_deregister(
            Duration::ZERO,
            Arc::new(busbar_kernel::endpoints::ProbeState::new(None)),
            ShutdownSignals {
                safety,
                support: workers.clone(),
                workers,
                listeners,
            },
        );
        tokio::time::timeout(WAIT, crate::root::shutdown::finish(post, &drain))
            .await
            .expect("actual root finish respects its one shutdown budget")
    }

    async fn application(
        &self,
        document: &serde_json::Value,
        prior: Option<&busbar_kernel::state::App>,
    ) -> (busbar_kernel::state::App, busbar_kernel::InstalledLimits) {
        let cfg = Self::config(document, &self.plugins);
        let (app, rotation, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            crate::root::test_plugins::plaintext_listeners(cfg),
            self.plugins.clone(),
            None,
            Default::default(),
            Default::default(),
            (Some(self.directory.join("config.yaml")), None),
            prior,
            &self.rules,
            Some(self.serving.core.clone()),
            false,
        )
        .await
        .expect("build the candidate over its actual admitted native owners");
        assert!(rotation.is_none(), "the fixture has no credential rotation");
        (app, limits)
    }

    fn persist(&self, document: &serde_json::Value) -> Result<(), String> {
        let yaml = busbar_contract::yaml::to_string(document).map_err(|error| error.to_string())?;
        std::fs::write(self.directory.join("config.yaml"), yaml).map_err(|error| error.to_string())
    }
}

#[tokio::test]
async fn installed_export_routes_and_restart_pending_follow_add_remove_and_reversion() {
    let mut fixture = NativeExport::open(
        "busbar_export_prometheus_plugin",
        serde_json::json!({"buffer_seconds": 60}),
    )
    .await;
    fixture.persist(&fixture.document).unwrap();
    let (app, limits) = fixture.application(&fixture.document, None).await;
    limits.stage_boot();
    crate::root::door_steps::tests::boot_fixture_prices(&app).await;
    limits.keep().await.unwrap();
    let cfg = NativeExport::config(&fixture.document, &fixture.plugins);
    let exports = busbar_kernel::export::plugin::open_prepared(
        &cfg.export,
        &fixture.pumps.as_ref().unwrap().calls(),
        app.amendments.clone(),
    )
    .unwrap();
    let boot = Arc::new(
        busbar_kernel::export::plugin::assemble_routes(app, &cfg.export, Vec::new(), exports)
            .unwrap(),
    );
    let boot_paths = boot.boot_route_paths.clone();
    assert!(boot_paths.contains("/metrics"));
    assert!(boot_paths.contains("/metrics/hooks"));
    assert_eq!(
        fixture
            .door
            .render_scope(busbar_plugin_abi::export::SCOPE_METRICS, &[])
            .unwrap()
            .status,
        200,
        "the installed native image actually renders its declared route"
    );
    let handle = busbar_kernel::state::AppHandle::new(boot.clone());
    let replacement = "replacement-metrics";
    let mut changed = fixture.document.clone();
    let definition = changed["export"]
        .as_object_mut()
        .unwrap()
        .remove(&fixture.name)
        .unwrap();
    changed["export"][replacement] = definition;
    changed["listen"] = serde_json::json!("127.0.0.1:19099");
    let mut removed = changed.clone();
    removed["export"] = serde_json::json!({});
    let mut reverted = fixture.document.clone();
    reverted["listen"] = changed["listen"].clone();
    let mut cases = vec![
        (
            changed.clone(),
            vec![
                format!("export.{}", fixture.name),
                format!("export.{replacement}"),
            ],
        ),
        (
            changed,
            vec![
                format!("export.{}", fixture.name),
                format!("export.{replacement}"),
            ],
        ),
        (removed.clone(), vec![format!("export.{}", fixture.name)]),
        (removed, vec![format!("export.{}", fixture.name)]),
        (reverted, Vec::new()),
    ];
    for (document, expected) in &mut cases {
        expected.sort();
        let prior = handle.load();
        let prior_version = prior.config_version;
        let prior_generation = prior.config_generation.load(Ordering::Acquire);
        let (next, limits) = fixture.application(document, Some(&prior)).await;
        assert!(
            Arc::ptr_eq(&handle.load(), &prior),
            "candidate preparation cannot replace serving ownership"
        );
        assert!(
            Arc::ptr_eq(&next.exports, &boot.exports),
            "export membership remains bound to its boot native owner"
        );
        assert_eq!(next.boot_route_paths.as_ref(), boot_paths.as_ref());
        let export_pending: Vec<_> = next
            .config_pending_restart
            .iter()
            .filter(|path| path.starts_with("export."))
            .cloned()
            .collect();
        assert_eq!(
            &export_pending, expected,
            "pending membership is always recomputed against boot, including exact reversion"
        );
        assert!(
            next.config_pending_restart
                .iter()
                .any(|path| path == "/listen"),
            "unrelated unapplied listener state remains visible"
        );
        let next = Arc::new(next);
        handle
            .reload_rates_and_swap(
                next.clone(),
                || fixture.persist(document),
                limits,
                "native-export-reload-proof",
            )
            .await
            .unwrap();
        let live = handle.load();
        assert!(Arc::ptr_eq(&live, &next));
        assert_eq!(live.config_version, prior_version + 1);
        assert!(live.config_generation.load(Ordering::Acquire) > prior_generation);
        assert!(Arc::ptr_eq(&live.exports, &boot.exports));
        assert_eq!(
            boot.config_version, 0,
            "retained boot requests keep their exact old generation"
        );
        assert_eq!(
            fixture
                .door
                .render_scope(busbar_plugin_abi::export::SCOPE_METRICS, &[])
                .unwrap()
                .status,
            200
        );
    }
    let live = handle.load();
    assert_eq!(
        live.plugin_routes.paths(),
        boot.plugin_routes.paths(),
        "reversion restores the actual declared routing table"
    );
    assert!(live
        .config_pending_restart
        .iter()
        .all(|path| !path.starts_with("export.")));
    let (candidate, limits) = fixture.application(&fixture.document, Some(&live)).await;
    assert!(handle
        .reload_rates_and_swap(
            Arc::new(candidate),
            || Err("fixture source write refused".into()),
            limits,
            "native-export-rejected-proof"
        )
        .await
        .is_err());
    assert!(
        Arc::ptr_eq(&handle.load(), &live),
        "failed candidate publication leaves the serving generation and routes intact"
    );
    assert_eq!(
        fixture.witness.attempts.load(Ordering::Acquire),
        0,
        "pull-only metrics never invents a delivery attempt"
    );
    assert!(fixture.stop(Instant::now() + WAIT).await.clean());
}
