// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::test_plugins as plugins;
use busbar_contract::abi::store::OpId;
use busbar_contract::records::{
    MeteringDelta, MeteringRow, RecordStore, RecordStoreError, RecordStoreResult, UsageDelta,
    UsageLedger, VirtualKey,
};
use busbar_kernel::config::groups::{GroupCfg, LimitCfg, LimitMetric, LimitWindow};
use busbar_kernel::cost::CostModel;
use busbar_kernel::governance::recovery::{
    RecoveryError, RecoveryEvent, RecoveryKind, RecoveryResolution, RecoverySink, RecoveryState,
    RecoveryVerdict,
};
use busbar_kernel::governance::GovState;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
const MODEL: &str = "m";
#[derive(Clone, Copy)]
enum Reply {
    Confirm,
    FailBefore,
}
struct ChunkStore {
    inner: Arc<dyn RecordStore>,
    replies: std::sync::Mutex<VecDeque<Reply>>,
    before_batch: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
impl RecordStore for ChunkStore {
    fn supports_usage_batch_deduped(&self) -> bool {
        true
    }
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(&self, id: &str, window: u64) -> RecordStoreResult<UsageLedger> {
        self.inner.get_usage(id, window)
    }
    fn put_usage(&self, id: &str, window: u64, row: &UsageLedger) -> RecordStoreResult<()> {
        self.inner.put_usage(id, window, row)
    }
    fn add_usage(&self, id: &str, window: u64, delta: &UsageDelta) -> RecordStoreResult<()> {
        self.add_usage_batch_deduped(busbar_kernel::door::op_id(), &[(id, window, delta.clone())])
    }
    fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(&self, day: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(day)
    }
    fn supports_usage_correction(&self) -> bool {
        true
    }
    fn apply_usage_correction(
        &self,
        request: &busbar_contract::records::correction::Request,
    ) -> RecordStoreResult<busbar_contract::records::correction::Decision> {
        self.inner.apply_usage_correction(request)
    }
    fn add_usage_batch_deduped(
        &self,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> RecordStoreResult<()> {
        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Reply::Confirm);
        let hook = self.before_batch.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
        if matches!(reply, Reply::FailBefore) {
            return Err(RecordStoreError("planted pre-commit chunk failure".into()));
        }
        self.inner.add_usage_batch_deduped(op, cells)?;
        Ok(())
    }
}
fn input(store: &dyn RecordStore, bucket: &str, window: u64) -> u64 {
    store
        .get_usage(bucket, window)
        .unwrap()
        .models
        .iter()
        .filter(|row| row.model == MODEL)
        .map(|row| {
            row.usage_units
                .get(busbar_contract::records::UNIT_INPUT)
                .copied()
                .unwrap_or(0)
        })
        .sum()
}

struct Journal {
    inner: Arc<dyn RecoverySink>,
    selected: std::sync::Mutex<Vec<RecoveryEvent>>,
    fail_after_write: std::sync::atomic::AtomicBool,
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
impl RecoverySink for Journal {
    fn replay(&self) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        self.inner.replay()
    }
    fn replay_selections(
        &self,
    ) -> Result<Vec<busbar_kernel::governance::recovery::RecoverySelection>, RecoveryError> {
        self.inner.replay_selections()
    }
    fn verify_checkpoint(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        self.inner.verify_checkpoint(event)
    }
    fn confirm_owned_checkpoint(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        self.inner.confirm_owned_checkpoint(event)
    }
    fn verify_origin(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        self.inner.verify_origin(event)
    }
    fn persist(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        // The real Store selects and verifies custody; this wrapper only loses
        // the reply after durable success and observes the selected test events.
        self.inner.persist(event)?;
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
fn metered(store: &dyn RecordStore, key_id: &str, model: &str, n: u64, now: u64) {
    let era = busbar_kernel::rate_apply::era_at(busbar_kernel::store::now_ms());
    store
        .add_metering(&MeteringDelta {
            key_id: key_id.into(),
            bucket: busbar_kernel::governance::metering_bucket(now),
            model: model.into(),
            provider: String::new(),
            tokens_input: n,
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
    let mut plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
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
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
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
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }

    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let store = Arc::new(ChunkStore {
        inner: app.governance.as_ref().unwrap().store(),
        replies: Default::default(),
        before_batch: Default::default(),
    });
    let journal = Arc::new(Journal {
        inner: crate::root::durability::usage_recovery_sink(&_book.durability),
        selected: Default::default(),
        fail_after_write: Default::default(),
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
    store.put_key(&key).unwrap();
    // The real boot's opening card can begin within this wall-clock second.
    // Keep the corrected unit's millisecond arrival, rather than truncating it
    // to an instant before that card existed.
    let card_epoch_ms = busbar_kernel::store::now_ms();
    let now = card_epoch_ms / 1_000;
    let first = GovState::new(store.clone(), None).unwrap();
    first.attach_recovery_sink(journal.clone()).unwrap();
    first.try_admit(&old_cost, &key, "", now).unwrap();
    first.record_usage(&old_cost, &key, "", MODEL, &toks(100, 0), now);
    metered(store.as_ref(), &key.id, MODEL, 100, now);
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
    let adjusted = first.adjust_usage(&old_cost, &adjustment);
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
    assert_eq!(input(store.as_ref(), &key.id, 0), 0);
    drop(first);
    journal
        .fail_after_write
        .store(false, std::sync::atomic::Ordering::SeqCst);

    let day_bucket = "group:g@day";
    let day_window =
        busbar_kernel::governance::budget_window(busbar_kernel::governance::WINDOW_DAY, now);
    // Build both raw and dated day-window debt through the actual usage path,
    // rather than reproduce the kernel's private era encoding in this root test.
    let foreign_key = virtual_key("vk_foreign_day_usage", Some("g"));
    store.put_key(&foreign_key).unwrap();
    let foreign = GovState::new(store.clone(), None).unwrap();
    foreign
        .try_admit(&current_cost, &foreign_key, "", now)
        .unwrap();
    foreign.record_usage(&current_cost, &foreign_key, "", MODEL, &toks(100, 0), now);
    metered(store.as_ref(), &foreign_key.id, MODEL, 100, now);
    foreign.flush_budgets();
    assert_eq!(input(store.as_ref(), day_bucket, day_window), 100);
    drop(foreign);
    let gov = Arc::new(GovState::new(store.clone(), None).unwrap());
    gov.attach_recovery_sink(journal.clone()).unwrap();
    gov.hydrate_budgets(&old_cost, now).unwrap();
    gov.flush_budgets();
    let unknown = journal.current(original.operation_id);
    assert_eq!(unknown.state, RecoveryState::LandedUnknown);
    store.replies.lock().unwrap().push_back(Reply::FailBefore);
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
        .is_err());
    assert_eq!(
        journal.current(original.operation_id).state,
        RecoveryState::VerdictNotLanded
    );

    app.governance = Some(gov.clone());
    app.amendments = Arc::clone(gov.amendments());
    app.cost = Arc::new(old_cost);
    let app = Arc::new(app);
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(app.clone()));
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let blocked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let in_worker = blocked.clone();
    *store.before_batch.lock().unwrap() = Some(Box::new(move || {
        in_worker.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = entered_tx.send(());
        let _ = release_rx.recv();
        in_worker.store(false, std::sync::atomic::Ordering::SeqCst);
    }));
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    let flusher = busbar_kernel::governance::spawn_budget_flusher(
        gov.clone(),
        shutdown_rx,
        Some(handle.clone()),
    );
    // No await precedes this swap: a cost cached by the spawning function would be stale.
    let mut next = (*app).clone();
    next.cost = Arc::new(current_cost);
    next.config_version += 1;
    handle.swap(Arc::new(next));

    tokio::time::timeout(std::time::Duration::from_secs(5), entered_rx)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert!(blocked.load(std::sync::atomic::Ordering::SeqCst));
    })
    .await
    .expect("the single Tokio reactor continues while the Store worker is blocked");
    release_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if journal.current(original.operation_id).state == RecoveryState::Settled { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("the actual periodic flusher resumes the durable verdict without another resolve or restart");
    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), flusher)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(input(store.as_ref(), &key.id, 0), 40);
    assert_eq!(
        input(store.as_ref(), day_bucket, day_window),
        40,
        "fresh conditional revalidation uses the swapped current day-window cost model"
    );
    let month_window =
        busbar_kernel::governance::budget_window(busbar_kernel::governance::WINDOW_MONTH, now);
    assert_eq!(input(store.as_ref(), "group:g@month", month_window), 100,
        "the previous model's raw month-window debt is recorded, not corrected under stale configuration");
    println!("actual recovery flusher completed");
}
