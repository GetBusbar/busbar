// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::test_plugins as plugins;
use busbar_contract::records::{MeteringDelta, VirtualKey};
use busbar_kernel::config::groups::{GroupCfg, LimitCfg, LimitMetric, LimitWindow};
use busbar_kernel::cost::CostModel;
use busbar_kernel::governance::recovery::{
    RecoveryError, RecoveryEvent, RecoveryKind, RecoveryResolution, RecoverySink, RecoveryState,
    RecoveryVerdict,
};
use busbar_kernel::governance::GovState;
use busbar_kernel::persistence::facade::CoreStore;
use std::collections::BTreeMap;
use std::sync::Arc;
const MODEL: &str = "m";

#[derive(Clone, Default)]
struct RecoveryDiagnostics(Arc<std::sync::Mutex<Vec<String>>>);
impl tracing::Subscriber for RecoveryDiagnostics {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        *metadata.level() <= tracing::Level::WARN
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                use std::fmt::Write;
                let _ = write!(self.0, "{}={value:?}; ", field.name());
            }
        }
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        let mut events = self.0.lock().unwrap();
        if events.len() < 64 {
            events.push(fields.0);
        }
    }
}

async fn input(store: &CoreStore, bucket: &str, window: u64) -> i128 {
    let usage = store.ledger().get_usage(bucket, window).await.unwrap();
    let count =
        busbar_contract::Count::total(usage.models.iter().filter(|row| row.model == MODEL).map(
            |row| {
                busbar_contract::Count::from_stored(
                    row.usage_units
                        .get(busbar_contract::records::UNIT_INPUT)
                        .copied()
                        .unwrap_or(0),
                    row.scale,
                )
                .expect("a valid stored count scale")
            },
        ))
        .expect("the exact signed input count fits");
    let unit = busbar_contract::Count::ONE.micros();
    assert_eq!(
        count.micros() % unit,
        0,
        "this witness expects whole counts"
    );
    count.micros() / unit
}

type Pause = (
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
    Arc<std::sync::atomic::AtomicBool>,
);
struct Journal {
    inner: Arc<dyn RecoverySink>,
    selected: std::sync::Mutex<Vec<RecoveryEvent>>,
    fail_after_write: std::sync::atomic::AtomicBool,
    before_write: std::sync::Mutex<Option<Pause>>,
}

impl Journal {
    fn current(&self, id: [u8; 16]) -> RecoveryEvent {
        self.selected
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|event| event.operation_id == id)
            .unwrap()
            .clone()
    }
}
#[async_trait::async_trait]
impl RecoverySink for Journal {
    async fn replay(&self) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        self.inner.replay().await
    }
    async fn replay_selections(
        &self,
    ) -> Result<Vec<busbar_kernel::governance::recovery::RecoverySelection>, RecoveryError> {
        self.inner.replay_selections().await
    }
    async fn verify_checkpoint(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        self.inner.verify_checkpoint(event).await
    }
    async fn confirm_owned_checkpoint(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        self.inner.confirm_owned_checkpoint(event).await
    }
    async fn verify_origin(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        self.inner.verify_origin(event).await
    }
    async fn persist(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        let pause = self.before_write.lock().unwrap().take();
        if let Some((entered, release, blocked)) = pause {
            blocked.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = entered.send(());
            let _ = release.await;
            blocked.store(false, std::sync::atomic::Ordering::SeqCst);
        }
        self.inner.persist(event).await?;
        let mut selected = self.selected.lock().unwrap();
        if !selected.contains(event) {
            selected.push(event.clone());
        }
        if self
            .fail_after_write
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            Err(RecoveryError::Unavailable(
                "reply lost after selection".into(),
            ))
        } else {
            Ok(())
        }
    }
}
fn model(groups: &[(&str, GroupCfg)]) -> CostModel {
    CostModel::resolve_parts(
        None,
        0,
        &groups
            .iter()
            .map(|(name, cfg)| (name.to_string(), cfg.clone()))
            .collect(),
    )
}
fn group_cfg(parent: Option<&str>, enabled: bool, limits: Vec<LimitCfg>) -> GroupCfg {
    GroupCfg {
        parent: parent.map(str::to_string),
        enabled,
        limits,
        ..Default::default()
    }
}
fn limit(metric: LimitMetric, amount: u64, per: Option<LimitWindow>) -> LimitCfg {
    LimitCfg {
        metric,
        amount,
        per,
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    }
}
fn virtual_key(id: &str, group: Option<&str>) -> VirtualKey {
    VirtualKey {
        id: id.into(),
        generation_hash: format!("h:{id}"),
        name: id.into(),
        allowed_scopes: None,
        enabled: true,
        created_at: 0,
        group: group.map(str::to_string),
        labels: BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
        ..Default::default()
    }
}
fn toks(input: u64, output: u64) -> BTreeMap<String, u64> {
    BTreeMap::from([("input".into(), input), ("output".into(), output)])
}
fn era_now() -> u64 {
    busbar_kernel::rate_apply::effective_from_at(busbar_kernel::store::now_ms())
}
async fn metered(store: &CoreStore, key_id: &str, model: &str, n: u64, now: u64) {
    let era = busbar_kernel::rate_apply::era_at(busbar_kernel::store::now_ms());
    store
        .ledger()
        .add_metering(&MeteringDelta {
            scale: 0,
            key_id: key_id.into(),
            bucket: busbar_kernel::governance::metering_bucket(now),
            model: model.into(),
            provider: String::new(),
            tokens_input: i128::from(n),
            tokens_output: 0,
            tokens_cache_read: 0,
            tokens_cache_write: 0,
            requests: 1,
            billable_requests: 1,
            key_group_at_use: String::new(),
            pricing_version: era
                .entry_id
                .map(|id| id.metering_version())
                .unwrap_or_default(),
            priced_from_ms: era.effective_from,
            usage_units: Default::default(),
        })
        .await
        .unwrap();
}
#[tokio::test]
async fn actual_root_flusher_resumes_not_landed_using_the_current_cost_without_blocking_reactor() {
    const CHILD: &str = "BUSBAR_ACTUAL_RECOVERY_FLUSHER_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let name = std::thread::current().name().unwrap().to_string();
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("actual recovery flusher completed")
        );
        return;
    }
    let diagnostics = RecoveryDiagnostics::default();
    tracing::subscriber::set_global_default(diagnostics.clone())
        .expect("the isolated flusher child owns its diagnostic subscriber");
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
    let directory = plugins::scratch("actual-recovery-flusher");
    let archive = plugins::signed(&plugins::key(0x33), manifest, &library);
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
    let operator_token = directory.join("operator-token");
    std::fs::write(&operator_token, "actual-route-operator").unwrap();
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing } },
        "identity-providers": {},
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": {"file": operator_token},
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let mut plugin_config = plugins::trusted_config_with_key(&directory, &plugins::key(0x33));
    plugin_config.trust.publishers[0].name = "third-party".into();
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let native_config = config;
    let native_plugins = plugin_config;
    let native_core = crate::root::real_store::core_over(
        busbar_kernel::appbuild::bootstrap_config_store(&native_config, &native_plugins)
            .await
            .expect("actual Store opens for native startup"),
    )
    .await;
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
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
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }

    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = app
        .governance
        .as_ref()
        .unwrap()
        .core_store_handle()
        .unwrap();
    let journal = Arc::new(Journal {
        inner: crate::root::durability::usage_recovery_sink(_book.runtime_journal.clone()).unwrap(),
        selected: Default::default(),
        fail_after_write: Default::default(),
        before_write: Default::default(),
    });
    let old_cost = model(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(
                LimitMetric::Budget,
                1_000_000,
                Some(LimitWindow::Month),
            )],
        ),
    )]);
    let current_cost = model(&[(
        "g",
        group_cfg(
            None,
            true,
            vec![limit(
                LimitMetric::Budget,
                1_000_000,
                Some(LimitWindow::Day),
            )],
        ),
    )]);
    let key = virtual_key("vk_live_cost_verdict", Some("g"));
    store.identity().put_key(&key).await.unwrap();

    let card_epoch_ms = busbar_kernel::store::now_ms();
    let now = card_epoch_ms / 1_000;
    let first = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    first.attach_recovery_sink(journal.clone()).await.unwrap();
    first.try_admit(&old_cost, &key, "", now).unwrap();
    first.record_usage(&old_cost, &key, "", MODEL, &toks(100, 0), now);
    metered(store.as_ref(), &key.id, MODEL, 100, now).await;
    journal
        .fail_after_write
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let correction_delta = BTreeMap::from([(busbar_contract::records::UNIT_INPUT.into(), -60)]);
    let adjustment = busbar_kernel::governance::Adjustment {
        key_id: &key.id,
        pool: "",
        model: MODEL,
        entry_era: era_now(),
        entry_id: None,
        card_epoch_ms,
        delta: &correction_delta,
        now,
    };
    let adjusted = first.adjust_usage_async(&old_cost, &adjustment).await;
    assert!(
        adjusted.is_err(),
        "the journal's lost selection reply must fail the adjustment: {adjusted:?}"
    );
    let original = journal
        .selected
        .lock()
        .unwrap()
        .iter()
        .find(|event| event.kind == RecoveryKind::Correction)
        .unwrap()
        .clone();
    assert_eq!(input(store.as_ref(), &key.id, 0).await, 0);
    drop(first);
    journal
        .fail_after_write
        .store(false, std::sync::atomic::Ordering::SeqCst);

    let day_bucket = "group:g@day";
    let day_window =
        busbar_kernel::governance::budget_window(busbar_kernel::governance::WINDOW_DAY, now);

    let foreign_key = virtual_key("vk_foreign_day_usage", Some("g"));
    store.identity().put_key(&foreign_key).await.unwrap();
    let foreign = GovState::new_with_core(store.clone(), None, None)
        .await
        .unwrap();
    foreign
        .try_admit(&current_cost, &foreign_key, "", now)
        .unwrap();
    foreign.record_usage(&current_cost, &foreign_key, "", MODEL, &toks(100, 0), now);
    metered(store.as_ref(), &foreign_key.id, MODEL, 100, now).await;
    foreign.flush_budgets().await;
    assert_eq!(input(store.as_ref(), day_bucket, day_window).await, 100);
    drop(foreign);
    let gov = Arc::new(
        GovState::new_with_core(store.clone(), None, None)
            .await
            .unwrap(),
    );
    gov.attach_recovery_sink(journal.clone()).await.unwrap();
    gov.hydrate_budgets_async(&old_cost, now).await.unwrap();
    gov.flush_budgets().await;
    let unknown = journal.current(original.operation_id);
    assert_eq!(unknown.state, RecoveryState::LandedUnknown);
    journal
        .fail_after_write
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(gov
        .recovery()
        .resolve(
            &old_cost,
            RecoveryResolution {
                operation_id: unknown.operation_id,
                body_fingerprint: unknown.body_fingerprint,
                expected_revision: unknown.revision,
                verdict: RecoveryVerdict::NotLanded,
                sender_quiesced: true,
                backend_quiesced: true,
                actor: "operator".into(),
                reason: "old sender retired; backend confirms no original mutation".into(),
            }
        )
        .await
        .is_err());
    assert_eq!(
        journal.current(original.operation_id).state,
        RecoveryState::VerdictNotLanded
    );

    journal
        .fail_after_write
        .store(false, std::sync::atomic::Ordering::SeqCst);
    app.governance = Some(gov.clone());
    app.amendments = Arc::clone(gov.amendments());
    app.cost = Arc::new(old_cost);
    let app = Arc::new(app);
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(app.clone()));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let blocked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let in_worker = blocked.clone();
    *journal.before_write.lock().unwrap() = Some((entered_tx, release_rx, in_worker));
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let flusher = busbar_kernel::governance::spawn_budget_flusher(
        gov.clone(),
        shutdown_rx,
        Some(handle.clone()),
    );

    let mut next = (*app).clone();
    next.cost = Arc::new(current_cost);
    next.config_version += 1;
    handle.swap(Arc::new(next)).await;

    tokio::time::timeout(std::time::Duration::from_secs(5), entered_rx)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert!(blocked.load(std::sync::atomic::Ordering::SeqCst));
    })
    .await
    .expect(
        "the single Tokio reactor continues while the native recovery acknowledgment is suspended",
    );
    let mut checkpoint = journal.current(original.operation_id);
    assert_eq!(checkpoint.revision, unknown.revision + 1);
    assert_eq!(checkpoint.state, RecoveryState::VerdictNotLanded);
    let mut checkpoint_waits = Vec::with_capacity(3);
    release_tx.send(()).unwrap();
    // The native journal must select the raw cut, the successor authorization, and settlement.
    // Bound each of these three advances, rather than charging every native Store round trip
    // in all three stages to one five-second timer. A stalled stage still fails in five seconds.
    for expected_state in [
        RecoveryState::VerdictNotLanded,
        RecoveryState::VerdictNotLanded,
        RecoveryState::Settled,
    ] {
        let revision = checkpoint.revision + 1;
        let started = std::time::Instant::now();
        checkpoint = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let next = journal
                    .selected
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|event| {
                        event.operation_id == original.operation_id && event.revision == revision
                    })
                    .cloned();
                if let Some(next) = next {
                    break next;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|elapsed| {
            let states: Vec<_> = journal.selected.lock().unwrap().iter()
                .map(|event| (hex::encode(event.operation_id), event.kind, event.revision, event.state))
                .collect();
            panic!("the actual periodic flusher resumes the durable verdict without another resolve or restart: {elapsed}; native checkpoints={states:?}; recovery diagnostics={:?}", diagnostics.0.lock().unwrap());
        });
        assert_eq!(checkpoint.kind, RecoveryKind::Correction);
        assert_eq!(checkpoint.revision, revision);
        assert_eq!(checkpoint.state, expected_state);
        checkpoint_waits.push((revision, started.elapsed()));
    }
    assert_eq!(
        checkpoint.state,
        RecoveryState::Settled,
        "the three native parent checkpoints settle the correction without another resolve or restart"
    );
    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), flusher)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(input(store.as_ref(), &key.id, 0).await, 40);
    assert_eq!(
        input(store.as_ref(), day_bucket, day_window).await,
        40,
        "fresh conditional revalidation uses the swapped current day-window cost model"
    );
    let month_window =
        busbar_kernel::governance::budget_window(busbar_kernel::governance::WINDOW_MONTH, now);
    assert_eq!(
        input(store.as_ref(), "group:g@month", month_window).await,
        100,
        "the previous model's raw month-window debt is recorded, not corrected under stale configuration"
    );
    println!("actual recovery flusher completed; native checkpoint waits={checkpoint_waits:?}");
}
