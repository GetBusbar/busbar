// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A real retained usage operation, observed and resolved through the mounted operator surface.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::count::Count;
use busbar_contract::persistence::*;
use busbar_contract::records::VirtualKey;
use busbar_kernel::governance::recovery::RecoveryState;
use serde_json::{json, Value};

const MODEL: &str = "oracle-recovery-observed-model";
const INPUT: u64 = 7;

struct LoseOneCommittedReply {
    inner: Arc<dyn PersistenceBackend>,
    lose: AtomicBool,
    in_flight: AtomicUsize,
    usage_calls: AtomicUsize,
    committed: Mutex<Vec<[u8; 32]>>,
}

impl PersistenceBackend for LoseOneCommittedReply {
    fn info(&self) -> BackendInfo {
        self.inner.info()
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.inner.clock(dataset)
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        self.inner.read(request)
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        self.inner.scan(request)
    }
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move {
            let usage = candidate.candidate().mutations.iter().any(|mutation| {
                matches!(mutation, Mutation::Put { address, .. } if address.key.first() == Some(&b'U'))
            });
            if usage {
                self.usage_calls.fetch_add(1, Ordering::SeqCst);
            }
            self.in_flight.fetch_add(1, Ordering::SeqCst);
            let fingerprint = candidate.fingerprint();
            let result = self.inner.commit(candidate).await;
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            if usage && matches!(result, Ok(Decision::Applied(_))) {
                let mut commits = self.committed.lock().unwrap();
                if !commits.contains(&fingerprint) {
                    commits.push(fingerprint);
                }
                if self.lose.load(Ordering::SeqCst) {
                    return Err(Failure::Unknown);
                }
            }
            result
        })
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").unwrap();
    }
    out
}

const ADMIN_TOKEN: &str = "isolated-ledger-recovery-operator-token";

async fn post_with_credential(
    router: &axum::Router,
    path: &str,
    body: &Value,
    credential: Option<&str>,
) -> (u16, Value) {
    use tower::ServiceExt;
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = credential {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let request = request
        .body(axum::body::Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

async fn post(router: &axum::Router, path: &str, body: &Value) -> (u16, Value) {
    post_with_credential(router, path, body, Some(ADMIN_TOKEN)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_actual_retained_usage_operation_is_listed_and_resolved_through_the_admin_route() {
    actual_retained_usage_resolution(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_store_compatibility_replay_preserves_the_resolved_verdict() {
    actual_retained_usage_resolution(true).await;
}

async fn actual_retained_usage_resolution(compatibility_history: bool) {
    crate::dist_root_install::install();
    busbar_core_admin::install();
    let backend = crate::root::real_store::native_backend().await;
    let module = crate::LINKED
        .stores
        .iter()
        .find(|row| row.1)
        .unwrap()
        .0
        .to_owned();
    let boundary = Arc::new(LoseOneCommittedReply {
        inner: backend,
        lose: AtomicBool::new(false),
        in_flight: AtomicUsize::new(0),
        usage_calls: AtomicUsize::new(0),
        committed: Mutex::new(Vec::new()),
    });
    let inner = crate::root::real_store::core_over(boundary.clone()).await;
    let config = busbar_kernel::config::deploy_from_deserializer(json!({
        "providers": {}, "models": {}, "auth": {"chain": [], "admin_auth": [busbar_kernel::config::operator_provider()]},
        "store": {"module": module, "settings": {}}
    }))
    .unwrap();
    let mut config = busbar_kernel::config::resolve(&config, &Default::default()).unwrap();
    let token_directory = crate::root::test_plugins::scratch("ledger-recovery-operator");
    let token_file = token_directory.join("operator-token");
    std::fs::write(&token_file, ADMIN_TOKEN).unwrap();
    config.auth.as_mut().unwrap().admin_auth[0].token = Some(
        busbar_kernel::config::secret::SecretRef::file(token_file.to_string_lossy()),
    );
    let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
        Arc::new(crate::root::door_steps::Rules::default());
    let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(inner.clone()),
        false,
    )
    .await
    .expect("the normal product builder owns the supplied actual Store");
    std::fs::remove_file(token_file).unwrap();
    std::fs::remove_dir(token_directory).unwrap();
    limits.stage_boot();
    let book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store owns the durable recovery journal");
    limits.keep().await.unwrap();
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let first = app.governance.as_ref().unwrap().clone();
    let key = VirtualKey {
        id: "oracle-retained-usage-key".into(),
        generation_hash: "oracle-ledger-generation".into(),
        name: "isolated recovery proof account".into(),
        enabled: true,
        created_at: busbar_kernel::store::now(),
        ..Default::default()
    };
    inner.identity().put_key(&key).await.unwrap();
    boundary.lose.store(true, Ordering::SeqCst);
    let now = busbar_kernel::store::now();
    first.try_admit(&app.cost, &key, "", now).unwrap();
    first.record_usage(
        &app.cost,
        &key,
        "",
        MODEL,
        &BTreeMap::from([("input".into(), INPUT)]),
        now,
    );
    first.flush_budgets().await;
    let observed_backend_operations = boundary.committed.lock().unwrap().clone();
    let original_usage_calls = boundary.usage_calls.load(Ordering::SeqCst);
    assert!(original_usage_calls > 0);
    assert_eq!(
        observed_backend_operations.len(),
        1,
        "the real backend committed once before the reply was lost"
    );

    assert_eq!(
        inner
            .ledger()
            .get_usage(&key.id, 0)
            .await
            .unwrap()
            .tokens_for(MODEL),
        Some(
            Count::from_integer(i128::from(INPUT))
                .expect("fixture input fits Count")
                .micros()
        )
    );
    let initial = first
        .recovery()
        .list(None, 100)
        .await
        .unwrap()
        .into_iter()
        .find(|i| i.state == RecoveryState::Intent)
        .unwrap();
    let operation_id = initial.operation_id;
    assert_eq!(initial.state, RecoveryState::Intent);
    assert_eq!(boundary.in_flight.load(Ordering::SeqCst), 0);
    app.governance = None;
    match Arc::try_unwrap(first) {
        Ok(sender) => drop(sender),
        Err(_) => {
            panic!("the original sender must be retired before an operator attests quiescence")
        }
    }

    let restarted = Arc::new(
        busbar_kernel::governance::GovState::new_with_core(inner.clone(), None, None)
            .await
            .unwrap(),
    );
    let sink = crate::root::durability::usage_recovery_sink(book.runtime_journal.clone()).unwrap();
    restarted.attach_recovery_sink(sink.clone()).await.unwrap();
    restarted
        .hydrate_budgets_async(&app.cost, now)
        .await
        .unwrap();
    restarted.flush_budgets().await;
    assert_eq!(
        boundary.committed.lock().unwrap().len(),
        1,
        "unknown-age replay must not resend the original operation"
    );
    assert_eq!(
        boundary.usage_calls.load(Ordering::SeqCst),
        original_usage_calls,
        "unknown-age replay does not submit the original candidate again"
    );
    app.amendments = Arc::clone(restarted.amendments());
    app.governance = Some(restarted.clone());
    let app = Arc::new(app);
    let (_data, bare_admin, handle) =
        busbar_kernel::build_split_routers_with_limits(app, 1 << 20, 0, false);
    let live_handle = handle.clone();
    let router = super::mount(
        bare_admin,
        crate::root::kernel::new_kernel(),
        1 << 20,
        |dispatch| {
            crate::root::kernel::ProductionUnits::admin_over_book(
                dispatch,
                super::live_admin_door(live_handle),
                &book,
            )
            .with_auth_bindings(crate::root::auth_bindings::AuthBindings::new(
                Arc::new(crate::root::auth_bindings::GovernanceDirectory::new(
                    restarted.clone(),
                )),
            ))
        },
    );
    let (unauthenticated_status, _) = post_with_credential(
        &router,
        "/api/v1/admin/ledger/recovery/list",
        &json!({}),
        None,
    )
    .await;
    assert_eq!(unauthenticated_status, 401);
    let (listed_status, listed) =
        post(&router, "/api/v1/admin/ledger/recovery/list", &json!({})).await;
    assert_eq!(listed_status, 200, "{listed}");
    let item = listed["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["operation_id"] == lower_hex(&operation_id))
        .unwrap()
        .clone();
    assert_eq!(item["state"], "landed_unknown");
    assert_eq!(item["can_resolve"], true);
    assert_eq!(
        item["body_fingerprint"],
        lower_hex(&initial.body_fingerprint)
    );
    let reason = format!(
        "Actual backend acknowledged operation {}; its observed input count is {INPUT}; original sender was retired and no usage call remains in flight.",
        lower_hex(&operation_id)
    );
    let resolution = json!({
        "operation_id": item["operation_id"], "body_fingerprint": item["body_fingerprint"],
        "recovery_version": item["recovery_version"], "verdict": "landed", "reason": reason,
        "sender_quiesced": true, "backend_quiesced": boundary.in_flight.load(Ordering::SeqCst) == 0,
    });
    let (unauthenticated_resolve_status, _) = post_with_credential(
        &router,
        "/api/v1/admin/ledger/recovery/resolve",
        &resolution,
        None,
    )
    .await;
    assert_eq!(unauthenticated_resolve_status, 401);
    let mut not_quiesced = resolution.clone();
    not_quiesced["sender_quiesced"] = json!(false);
    let (quiescence_status, _) = post(
        &router,
        "/api/v1/admin/ledger/recovery/resolve",
        &not_quiesced,
    )
    .await;
    assert_eq!(
        quiescence_status, 400,
        "a retained operation does not infer sender quiescence"
    );
    let mut wrong_fingerprint = resolution.clone();
    let fingerprint = item["body_fingerprint"].as_str().unwrap();
    wrong_fingerprint["body_fingerprint"] = json!(format!(
        "{}{}",
        if fingerprint.starts_with('0') {
            "1"
        } else {
            "0"
        },
        &fingerprint[1..]
    ));
    let (fingerprint_status, _) = post(
        &router,
        "/api/v1/admin/ledger/recovery/resolve",
        &wrong_fingerprint,
    )
    .await;
    assert_eq!(
        fingerprint_status, 409,
        "a different immutable body cannot borrow this operation's authority"
    );
    let mut stale = resolution.clone();
    stale["recovery_version"] = json!(item["recovery_version"].as_u64().unwrap() + 1);
    let (stale_status, _) = post(&router, "/api/v1/admin/ledger/recovery/resolve", &stale).await;
    assert_eq!(
        stale_status, 409,
        "only the observed retained version authorizes resolution"
    );
    let (status, resolved) = post(
        &router,
        "/api/v1/admin/ledger/recovery/resolve",
        &resolution,
    )
    .await;
    assert_eq!(status, 200, "{resolved}");
    assert_eq!(resolved["operation_id"], item["operation_id"]);
    assert_eq!(resolved["body_fingerprint"], item["body_fingerprint"]);
    assert_eq!(resolved["state"], "settled");
    assert_eq!(resolved["can_resolve"], false);
    let (repeat_status, repeat) = post(
        &router,
        "/api/v1/admin/ledger/recovery/resolve",
        &resolution,
    )
    .await;
    assert_eq!(repeat_status, 200, "{repeat}");
    assert_eq!(
        repeat, resolved,
        "the same evidence cannot apply the effect twice"
    );
    assert_eq!(boundary.committed.lock().unwrap().len(), 1);
    assert_eq!(
        boundary.usage_calls.load(Ordering::SeqCst),
        original_usage_calls
    );
    assert_eq!(
        inner
            .ledger()
            .get_usage(&key.id, 0)
            .await
            .unwrap()
            .tokens_for(MODEL),
        Some(
            Count::from_integer(i128::from(INPUT))
                .expect("fixture input fits Count")
                .micros()
        )
    );

    let durable = if compatibility_history {
        sink.replay()
            .await
            .expect("actual Store compatibility replay must read the retained journal")
            .into_iter()
            .find(|event| {
                event.operation_id == operation_id && event.state == RecoveryState::VerdictLanded
            })
            .expect("the actual selected history retains its durable verdict")
    } else {
        let selections = sink.replay_selections().await.unwrap();
        let selected = selections
            .into_iter()
            .find(|selection| selection.selected.operation_id == operation_id)
            .unwrap()
            .selected;
        assert_eq!(selected.state, RecoveryState::Settled);
        selected
    };
    assert_eq!(durable.operation_id, operation_id);
    assert_eq!(durable.body_fingerprint, initial.body_fingerprint);
    let custody: Value = serde_json::from_slice(&durable.payload).unwrap();
    assert_eq!(
        custody["verdict"]["actor"],
        busbar_kernel::config::operator_principal_id(),
        "the real configured operator credential supplies durable resolution attribution"
    );
    assert_eq!(custody["verdict"]["reason"], resolution["reason"]);
    assert_eq!(custody["verdict"]["landed"], true);
    assert_eq!(custody["verdict"]["sender_quiesced"], true);
    assert_eq!(custody["verdict"]["backend_quiesced"], true);
    if let Some(path) = std::env::var_os("BUSBAR_LEDGER_RECOVERY_PROOF_PATH") {
        let proof = json!({
            "fixture": "actual-retained-usage-admin-route-v1", "store_module": module,
            "boundary": "lost reply after actual commit; original sender then retired",
            "cell": "admin.ops|PostLedgerRecoveryResolve|ok",
            "admin_posture": "configured production operator chain with bearer credential",
            "unauthenticated_list_status": unauthenticated_status,
            "unauthenticated_resolve_status": unauthenticated_resolve_status,
            "listed_status": listed_status,
            "listed_item": item, "resolve_request": resolution, "resolve_status": status,
            "resolve_response": resolved, "stale_version_status": stale_status,
            "wrong_fingerprint_status": fingerprint_status, "missing_quiescence_status": quiescence_status,
            "backend_acknowledged_operation": lower_hex(&operation_id),
            "outstanding_original_usage_calls": boundary.in_flight.load(Ordering::SeqCst),
            "repeat_status": repeat_status, "repeat_response": repeat,
            "actual_backend_commits": boundary.committed.lock().unwrap().len(),
            "actual_backend_input": inner.ledger().get_usage(&key.id, 0).await.unwrap().tokens_for(MODEL),
            "verdict_actor": custody["verdict"]["actor"],
        });
        std::fs::write(path, serde_json::to_vec_pretty(&proof).unwrap()).unwrap();
    }
}
