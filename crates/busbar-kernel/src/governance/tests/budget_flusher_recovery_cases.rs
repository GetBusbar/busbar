// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::governance::recovery::{
    tests::Journal, RecoveryKind, RecoveryResolution, RecoveryState, RecoveryVerdict,
};

#[tokio::test]
async fn live_flusher_resumes_not_landed_with_current_cost_without_blocking_reactor() {
    crate::snapshot::init();
    let store = Arc::new(ChunkStore::default());
    let journal = Arc::new(Journal::default());
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
    let key = key("vk_live_cost_verdict", Some("g"));
    store.put_key(&key).unwrap();
    let now = crate::store::now();
    let first = GovState::new(store.clone(), None).unwrap();
    first.attach_recovery_sink(journal.clone()).unwrap();
    first.try_admit(&old_cost, &key, "", now).unwrap();
    first.record_usage(&old_cost, &key, "", MODEL, &toks(100, 0), now);
    metered(&first, &key.id, MODEL, 100, now);
    journal
        .fail_after_write
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let correction_delta = BTreeMap::from([(busbar_contract::records::UNIT_INPUT.into(), -60)]);
    let adjustment = crate::governance::Adjustment {
        key_id: &key.id,
        pool: "",
        model: MODEL,
        entry_era: era_now(),
        entry_id: None,
        card_epoch_ms: now * 1_000,
        delta: &correction_delta,
        now,
    };
    assert!(first.adjust_usage(&old_cost, &adjustment).is_err());
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
    let day_window = crate::governance::budget_window(crate::governance::WINDOW_DAY, now);
    let foreign = UsageDelta {
        models: vec![busbar_contract::records::ModelTokensDelta {
            model: MODEL.into(),
            usage_units: BTreeMap::from([("input".into(), 100)]),
        }],
        ..Default::default()
    };
    store
        .inner
        .add_usage(day_bucket, day_window, &foreign)
        .unwrap();
    if era_now() != 0 {
        store
            .inner
            .add_usage(
                &crate::governance::era_bucket(day_bucket),
                day_window,
                &crate::governance::dated_delta(&foreign, RawRateEra::legacy(era_now())),
            )
            .unwrap();
    }
    let gov = Arc::new(GovState::new(store.clone(), None).unwrap());
    gov.attach_recovery_sink(journal.clone()).unwrap();
    gov.hydrate_budgets(&old_cost, now).unwrap();
    gov.flush_budgets();
    let unknown = gov.recovery_event(original.operation_id).unwrap();
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
        gov.recovery_event(original.operation_id).unwrap().state,
        RecoveryState::VerdictNotLanded
    );

    let registry: Arc<dyn busbar_contract::plugin_rows::PluginRows> =
        Arc::new(busbar_plugin_loader::registry::PluginRegistry::empty());
    let secret_resolver = Arc::new(crate::config::secret::SecretResolver::builtins_only());
    let app = Arc::new(crate::state::App::from_test_parts(crate::state::AppParts {
        fallback_runtime_key: "",
        serve_tables: Default::default(),
        root_rules: Arc::new(crate::appbuild::AcceptAll),
        config_projection: Default::default(),
        config_tables: Default::default(),
        store: Arc::new(crate::store::HealthState::new(Vec::new())),
        limits: Default::default(),
        session_store: Arc::new(crate::session::SessionStore::new(1024, None)),
        incremental_scan: Default::default(),
        plane_pools: Default::default(),
        auth: Arc::new(
            crate::auth::AuthMiddleware::new(
                &crate::config::AuthCfg::default_none(),
                &registry,
                &secret_resolver,
            )
            .unwrap(),
        ),
        rewrite_hooks: Default::default(),
        tap_hooks: Default::default(),
        tap_hooks_candidate: Default::default(),
        tap_hooks_routing: Default::default(),
        tap_hooks_response: Default::default(),
        global_gates: Default::default(),
        pool_orderings: Default::default(),
        pool_decision_gates: Default::default(),
        pool_rewrite_chains: Default::default(),
        plane_gates: Default::default(),
        plane_rewrites: Default::default(),
        hook_env: crate::hooks::HookEnv::new(registry, secret_resolver.clone()).unwrap(),
        hook_registry: Default::default(),
        requested_signals: Default::default(),
        any_content_hook: Default::default(),
        global_hooks: Default::default(),
        base_hook_names: Default::default(),
        groups_registry: Default::default(),
        base_group_names: Default::default(),
        identity_providers: Default::default(),
        export_defs: Default::default(),
        admin: Default::default(),
        admin_chain: Default::default(),
        admin_modules: Arc::new(crate::auth::AdminAuthChain::empty()),
        public_url: Default::default(),
        oauth_as: Default::default(),
        demotion_record: Default::default(),
        amendments: Arc::clone(gov.amendments()),
        planes: Default::default(),
        plane_slots: Default::default(),
        plane_sections: Default::default(),
        auth_scope_caps: Default::default(),
        role_bindings: Default::default(),
        config_path: Default::default(),
        providers_path: Default::default(),
        overlay_path: Default::default(),
        config_version: Default::default(),
        max_keys_per_principal: Default::default(),
        max_auto_provisioned_groups: Default::default(),
        governance: Some(gov.clone()),
        secret_resolver: secret_resolver,
        cost: Arc::new(old_cost),
        plugins_dir: Default::default(),
        plugins_cfg: Default::default(),
        plugin_admission: Default::default(),
        self_key_ttl_secs: crate::governance::mint_policy::DEFAULT_KEY_TTL_SECS,
        mint_policy: Default::default(),
        request_id_counter: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        plugin_routes: Arc::new(crate::plugin_routes::PluginRouteTable::empty()),
        boot_route_paths: Default::default(),
        planes_awaiting_restart: Default::default(),
    }));
    let handle = Arc::new(crate::state::AppHandle::new(app.clone()));
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
    let flusher =
        crate::governance::spawn_budget_flusher(gov.clone(), shutdown_rx, Some(handle.clone()));
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
            if gov.recovery_event(original.operation_id).is_some_and(|event| event.state == RecoveryState::Settled) { break; }
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
    let month_window = crate::governance::budget_window(crate::governance::WINDOW_MONTH, now);
    assert_eq!(input(store.as_ref(), "group:g@month", month_window), 100,
        "the previous model's raw month-window debt is recorded, not corrected under stale configuration");
}
