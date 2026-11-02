// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use busbar_kernel::auth::AuthPrincipal;
use busbar_kernel::config::overlay::{persist_root, OverlayStore, RootSettings};
use busbar_kernel::rate_apply::{PreparedRates, RateApply, RateCommit, RawRates};
use busbar_kernel::state::{App, AppHandle};
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

const BASE_FEE: i64 = 0;
const REFUSED_CANDIDATE_FEE: i64 = 71_001;
const UNKNOWN_CANDIDATE_FEE: i64 = 71_002;
const REFUSED_ACTIVATION_FEE: i64 = 71_003;
const UNKNOWN_ACTIVATION_FEE: i64 = 71_004;
const PENDING_ACTIVATION_FEE: i64 = 71_005;
const PRE_PUBLICATION_PANIC_FEE: i64 = 71_006;
const POST_PUBLICATION_PANIC_FEE: i64 = 71_007;
const REFUSED_CONFIG_FEE: i64 = 71_008;
const UNKNOWN_CONFIG_FEE: i64 = 71_009;
const CANDIDATE_BODY_CAP: usize = 5_000_123;
const NONPRICE_BODY_CAP: usize = CANDIDATE_BODY_CAP + 1;
const COMPLETION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const PRE_PUBLICATION_PLANE: &str = "price-publication-test";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LivePrice {
    fee: i64,
    epoch: u64,
}

struct Scenario {
    candidate: TestOverlayStore,
    activation: TestOverlayStore,
    live: Mutex<LivePrice>,
    origins: Mutex<Vec<String>>,
    recoveries: std::sync::atomic::AtomicUsize,
}

impl Scenario {
    fn install(fee: i64) -> Arc<Self> {
        let _fixture = crate::new_test_app();
        let holder = holder();
        busbar_kernel_testkit::test_support::rate_holders::install_rate_apply(holder);
        let scenario = Arc::new(Self {
            candidate: TestOverlayStore::new(),
            activation: TestOverlayStore::new(),
            live: Mutex::new(LivePrice {
                fee: BASE_FEE,
                epoch: 0,
            }),
            origins: Mutex::new(Vec::new()),
            recoveries: std::sync::atomic::AtomicUsize::new(0),
        });
        assert!(holder
            .scenarios
            .lock()
            .unwrap()
            .insert(fee, scenario.clone())
            .is_none());
        scenario
    }

    fn live(&self) -> LivePrice {
        *self.live.lock().unwrap()
    }

    fn publish(&self, fee: i64) {
        let mut live = self.live.lock().unwrap();
        if live.fee != fee {
            live.fee = fee;
            live.epoch += 1;
        }
    }
}

struct Holder {
    scenarios: Mutex<BTreeMap<i64, Arc<Scenario>>>,
}

fn holder() -> &'static Holder {
    static HOLDER: OnceLock<Holder> = OnceLock::new();
    HOLDER.get_or_init(|| Holder {
        scenarios: Mutex::new(BTreeMap::new()),
    })
}

struct Prepared {
    scenario: Option<Arc<Scenario>>,
    fee: i64,
}

struct Confirmed(Prepared);

fn confirm(store: &TestOverlayStore, fee: i64) -> Result<(), String> {
    let (_recovered, doc) = store.backend().reopen_for_reload()?;
    if doc
        .and_then(|doc| doc.root)
        .and_then(|root| root.per_request_fee)
        != Some(fee)
    {
        persist_root(
            Some(&store.backend()),
            &RootSettings {
                per_request_fee: Some(fee),
                ..Default::default()
            },
        )?;
    }
    Ok(())
}

impl RateApply for Holder {
    fn prepare_recovery(
        &self,
        card: &busbar_kernel::config::card::CardFields,
        rates: &RawRates<'_>,
        origin: &str,
    ) -> Result<Box<dyn PreparedRates>, String> {
        let scenario = self
            .scenarios
            .lock()
            .unwrap()
            .get(&rates.flat_minor)
            .cloned();
        if let Some(scenario) = scenario {
            scenario
                .recoveries
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        self.prepare(card, rates, origin)
    }

    fn prepare(
        &self,
        _card: &busbar_kernel::config::card::CardFields,
        rates: &RawRates<'_>,
        origin: &str,
    ) -> Result<Box<dyn PreparedRates>, String> {
        let scenario = self
            .scenarios
            .lock()
            .unwrap()
            .get(&rates.flat_minor)
            .cloned();
        if let Some(scenario) = &scenario {
            scenario.origins.lock().unwrap().push(origin.to_string());
            if scenario.live().fee == rates.flat_minor {
                return Ok(Box::new(Prepared {
                    scenario: None,
                    fee: rates.flat_minor,
                }));
            }
            confirm(&scenario.candidate, rates.flat_minor)?;
        }
        Ok(Box::new(Prepared {
            scenario,
            fee: rates.flat_minor,
        }))
    }

    fn rates_applied(&self, rates: &RawRates<'_>) {
        let scenario = self
            .scenarios
            .lock()
            .unwrap()
            .get(&rates.flat_minor)
            .cloned();
        if let Some(scenario) = scenario {
            scenario.publish(rates.flat_minor);
        }
    }
}

impl PreparedRates for Prepared {
    fn confirm_activation(self: Box<Self>) -> Result<Box<dyn RateCommit>, String> {
        if let Some(scenario) = &self.scenario {
            confirm(&scenario.activation, self.fee)?;
        }
        Ok(Box::new(Confirmed(*self)))
    }
}

impl RateCommit for Confirmed {
    fn commit(self: Box<Self>) {
        if let Some(scenario) = &self.0.scenario {
            scenario.publish(self.0.fee);
        }
    }
}

struct Inputs(std::path::PathBuf);

impl Drop for Inputs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn settings_handle(tag: &str) -> (Inputs, TestOverlayStore, Arc<AppHandle>) {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (dir, config_path, providers_path) = write_reset_fixture(tag);
    let overlay = TestOverlayStore::new();
    let mut app = crate::new_test_app()
        .overlay_backend(overlay.backend())
        .build();
    let inner = Arc::get_mut(&mut app).unwrap();
    inner.config_path = Some(config_path);
    inner.providers_path = Some(providers_path);
    (Inputs(dir), overlay, Arc::new(AppHandle::new(app)))
}

async fn put(handle: &Arc<AppHandle>, fee: i64) -> axum::response::Response {
    crate::v1::json::put_config_settings(
        State(handle.clone()),
        axum::Extension(AuthPrincipal(None)),
        HeaderMap::new(),
        serde_json::json!({"per_request_fee": fee, "limits": {"request_body_max_bytes": CANDIDATE_BODY_CAP}})
            .to_string().into(),
    ).await
}

async fn reload(handle: &Arc<AppHandle>) -> axum::response::Response {
    crate::v1::json::reload_config(State(handle.clone()), axum::Extension(AuthPrincipal(None)))
        .await
}

fn stored_fee(backend: &OverlayStore) -> Option<i64> {
    backend
        .read_required()
        .unwrap()
        .and_then(|doc| doc.root)
        .and_then(|root| root.per_request_fee)
}

#[tokio::test]
async fn settings_refuses_unconfirmed_prices_then_reload_confirms_the_exact_candidate_once() {
    let _limits = busbar_kernel_testkit::limits::LIMITS_TEST_LOCK.lock().await;
    for (fee, activation, unknown) in [
        (REFUSED_CANDIDATE_FEE, false, false),
        (UNKNOWN_CANDIDATE_FEE, false, true),
        (REFUSED_ACTIVATION_FEE, true, false),
        (UNKNOWN_ACTIVATION_FEE, true, true),
    ] {
        let scenario = Scenario::install(fee);
        let (inputs, overlay, handle) = settings_handle(&format!("unconfirmed-price-{fee}"));
        let before = handle.load();
        let before_limits = busbar_kernel::config::limits::installed();
        let before_price = scenario.live();
        let failing = if activation {
            &scenario.activation
        } else {
            &scenario.candidate
        };
        if unknown {
            failing.lose_next_commit_reply();
        } else {
            failing.fail_transactions(true);
        }

        assert_eq!(put(&handle, fee).await.status(), StatusCode::BAD_REQUEST);
        assert!(Arc::ptr_eq(&handle.load(), &before));
        assert_eq!(handle.load().config_version, before.config_version);
        assert_eq!(scenario.live(), before_price);
        assert_eq!(
            busbar_kernel::config::limits::installed().map(|limits| limits.request_body_max_bytes),
            before_limits
                .as_ref()
                .map(|limits| limits.request_body_max_bytes)
        );
        assert_eq!(
            stored_fee(&overlay.backend()),
            Some(fee),
            "config and prices can use different Stores"
        );
        let submitted = failing.candidates();
        assert_eq!(submitted.len(), 1);

        assert!(persist_root(Some(&overlay.backend()), &RootSettings::default()).is_err());
        assert_eq!(put(&handle, fee).await.status(), StatusCode::BAD_REQUEST);
        let applied = crate::v1::json::apply_config(
            State(handle.clone()), axum::Extension(AuthPrincipal(None)), HeaderMap::new(),
            serde_json::json!({"config": {"providers": {}, "models": {}, "store": {"module": migrated_store_module()}}})
                .to_string().into(),
        ).await;
        assert_eq!(applied.status(), StatusCode::BAD_REQUEST);
        assert!(Arc::ptr_eq(&handle.load(), &before));
        assert_eq!(failing.candidates().len(), submitted.len());

        let config_path = inputs.0.join("config.yaml");
        let original = std::fs::read(&config_path).unwrap();
        std::fs::write(&config_path,
            "store: {module: memory}\nproviders: {}\nmodels: {}\ngroups:\n  broken:\n    parent: missing\n",
        ).unwrap();
        assert_eq!(reload(&handle).await.status(), StatusCode::BAD_REQUEST);
        assert!(Arc::ptr_eq(&handle.load(), &before));
        assert_eq!(scenario.live(), before_price);
        assert_eq!(put(&handle, fee).await.status(), StatusCode::BAD_REQUEST);
        std::fs::write(&config_path, original).unwrap();

        failing.fail_transactions(false);
        assert_eq!(reload(&handle).await.status(), StatusCode::OK);
        assert_eq!(
            scenario
                .recoveries
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert!(!Arc::ptr_eq(&handle.load(), &before));
        assert_eq!(
            scenario.live(),
            LivePrice {
                fee,
                epoch: before_price.epoch + 1
            }
        );
        assert_eq!(
            busbar_kernel::config::limits::installed().map(|limits| limits.request_body_max_bytes),
            Some(CANDIDATE_BODY_CAP)
        );
        let confirmed = failing.candidates();
        assert_eq!(confirmed.len(), 2);
        assert_eq!(confirmed[0].op_id, confirmed[1].op_id);
        assert_eq!(confirmed[0].fingerprint(), confirmed[1].fingerprint());
        assert_eq!(
            scenario.origins.lock().unwrap()[0],
            format!("config/settings by {}", AuthPrincipal(None).actor_id())
        );
        assert!(persist_root(Some(&overlay.backend()), &RootSettings::default()).is_err());

        scenario.candidate.fail_writes(true);
        scenario.activation.fail_writes(true);
        assert_eq!(reload(&handle).await.status(), StatusCode::OK);
        let nonprice = crate::v1::json::put_config_settings(
            State(handle.clone()),
            axum::Extension(AuthPrincipal(None)),
            HeaderMap::new(),
            serde_json::json!({"limits": {"request_body_max_bytes": NONPRICE_BODY_CAP}})
                .to_string()
                .into(),
        )
        .await;
        assert_eq!(nonprice.status(), StatusCode::OK);
        assert_eq!(
            busbar_kernel::config::limits::installed().map(|limits| limits.request_body_max_bytes),
            Some(NONPRICE_BODY_CAP)
        );
        assert_eq!(scenario.live().epoch, before_price.epoch + 1);
        assert_eq!(failing.candidates().len(), confirmed.len());
    }
}

#[tokio::test]
async fn an_absent_card_and_unchanged_prices_allow_a_successful_settings_handler() {
    let _limits = busbar_kernel_testkit::limits::LIMITS_TEST_LOCK.lock().await;
    let (_inputs, overlay, handle) = settings_handle("no-configured-price-card");
    let before = handle.load();
    assert_eq!(put(&handle, BASE_FEE).await.status(), StatusCode::OK);
    assert!(!Arc::ptr_eq(&handle.load(), &before));
    assert_eq!(stored_fee(&overlay.backend()), Some(BASE_FEE));
    assert_eq!(
        busbar_kernel::config::limits::installed().map(|limits| limits.request_body_max_bytes),
        Some(CANDIDATE_BODY_CAP)
    );
    let next = handle.load();
    assert_eq!(reload(&handle).await.status(), StatusCode::OK);
    assert!(!Arc::ptr_eq(&handle.load(), &next));
}

#[tokio::test]
async fn config_refusal_or_unknown_reply_never_attempts_price_activation() {
    let _limits = busbar_kernel_testkit::limits::LIMITS_TEST_LOCK.lock().await;
    for (fee, unknown) in [(REFUSED_CONFIG_FEE, false), (UNKNOWN_CONFIG_FEE, true)] {
        let scenario = Scenario::install(fee);
        let (_inputs, overlay, handle) = settings_handle(&format!("unconfirmed-config-{fee}"));
        let before = handle.load();
        if unknown {
            overlay.lose_next_commit_reply();
        } else {
            overlay.fail_writes(true);
        }
        assert_eq!(put(&handle, fee).await.status(), StatusCode::BAD_REQUEST);
        assert!(Arc::ptr_eq(&handle.load(), &before));
        assert_eq!(
            scenario.live(),
            LivePrice {
                fee: BASE_FEE,
                epoch: 0
            }
        );
        assert!(scenario.candidate.candidates().is_empty());
        assert!(scenario.activation.candidates().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_activation_and_canceled_handler_keep_the_old_generation_until_confirmation() {
    let _limits = busbar_kernel_testkit::limits::LIMITS_TEST_LOCK.lock().await;
    let scenario = Scenario::install(PENDING_ACTIVATION_FEE);
    let (_inputs, _overlay, handle) = settings_handle("pending-price-activation");
    let before = handle.load();
    let before_limits = busbar_kernel::config::limits::installed();
    let pause = scenario.activation.pause_next_commit_reply();
    let request = {
        let handle = handle.clone();
        tokio::spawn(async move { put(&handle, PENDING_ACTIVATION_FEE).await })
    };
    tokio::time::timeout(COMPLETION_TIMEOUT, async {
        while !pause.entered() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("activation reached an actual Pending Store reply");
    assert!(Arc::ptr_eq(&handle.load(), &before));
    assert_eq!(
        scenario.live(),
        LivePrice {
            fee: BASE_FEE,
            epoch: 0
        }
    );
    assert_eq!(
        busbar_kernel::config::limits::installed().map(|limits| limits.request_body_max_bytes),
        before_limits
            .as_ref()
            .map(|limits| limits.request_body_max_bytes)
    );
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    assert!(Arc::ptr_eq(&handle.load(), &before));
    let queued = {
        let handle = handle.clone();
        tokio::spawn(async move {
            busbar_kernel::config::transaction::config_transaction::<
                _,
                _,
                crate::v1::contract::AdminError,
            >(&handle, |txn| Ok(txn.done(txn.app().config_version)))
            .await
        })
    };
    tokio::task::yield_now().await;
    assert!(
        !queued.is_finished(),
        "the canceled caller does not release its blocking task's guard"
    );
    pause.release();
    let version = tokio::time::timeout(COMPLETION_TIMEOUT, queued)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(version > before.config_version);
    assert!(!Arc::ptr_eq(&handle.load(), &before));
    assert_eq!(
        scenario.live(),
        LivePrice {
            fee: PENDING_ACTIVATION_FEE,
            epoch: 1
        }
    );
    assert_eq!(scenario.activation.candidates().len(), 1);
}

static PRE_PANIC_PATH: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

fn before_publication(
    _prior: &dyn busbar_kernel::plane_driver::slots::PlaneSlots,
    next: &dyn busbar_kernel::plane_driver::slots::PlaneSlots,
) {
    let next = next.as_any().downcast_ref::<App>().unwrap();
    let panic = {
        let target = PRE_PANIC_PATH.lock().unwrap();
        target
            .as_ref()
            .is_some_and(|path| next.config_path.as_ref() == Some(path))
    };
    assert!(!panic, "injected pre-publication plane callback panic");
}

static PANIC_PLANE: busbar_kernel::plane_driver::registry::PlaneDecl =
    busbar_kernel::plane_driver::registry::PlaneDecl {
        declaration: busbar_kernel::plane_driver::registry::PlaneDeclaration {
            key: PRE_PUBLICATION_PLANE,
            fallback: false,
            config_section: PRE_PUBLICATION_PLANE,
            scope_kinds: &[],
            ..busbar_kernel_testkit::test_support::NEUTRAL_FALLBACK.declaration
        },
        on_swap: Some(before_publication),
        ..busbar_kernel_testkit::test_support::NEUTRAL_FALLBACK
    };

struct ClearPanicPath;
impl Drop for ClearPanicPath {
    fn drop(&mut self) {
        *PRE_PANIC_PATH.lock().unwrap() = None;
    }
}

#[tokio::test]
async fn callback_panics_preserve_one_coherent_published_price_generation() {
    let _limits = busbar_kernel_testkit::limits::LIMITS_TEST_LOCK.lock().await;
    let scenario = Scenario::install(PRE_PUBLICATION_PANIC_FEE);
    let (_inputs, overlay, handle) = settings_handle("before-price-publication");
    busbar_kernel_testkit::test_support::planes::register_test_plane(&PANIC_PLANE);
    let before = handle.load();
    let before_limits = busbar_kernel::config::limits::installed();
    *PRE_PANIC_PATH.lock().unwrap() = before.config_path.clone();
    let clear = ClearPanicPath;
    assert_eq!(
        put(&handle, PRE_PUBLICATION_PANIC_FEE).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(Arc::ptr_eq(&handle.load(), &before));
    assert_eq!(
        scenario.live(),
        LivePrice {
            fee: BASE_FEE,
            epoch: 0
        }
    );
    assert_eq!(
        busbar_kernel::config::limits::installed().map(|limits| limits.request_body_max_bytes),
        before_limits
            .as_ref()
            .map(|limits| limits.request_body_max_bytes)
    );
    assert!(scenario.candidate.candidates().is_empty());
    assert!(persist_root(Some(&overlay.backend()), &RootSettings::default()).is_err());
    drop(clear);
    assert_eq!(reload(&handle).await.status(), StatusCode::OK);
    assert_eq!(
        scenario.live(),
        LivePrice {
            fee: PRE_PUBLICATION_PANIC_FEE,
            epoch: 1
        }
    );

    let scenario = Scenario::install(POST_PUBLICATION_PANIC_FEE);
    let (_inputs, overlay, handle) = settings_handle("after-price-publication");
    let before = handle.load();
    let first = Arc::new(std::sync::atomic::AtomicBool::new(true));
    handle.on_apply(Box::new({
        let first = first.clone();
        let scenario = scenario.clone();
        let weak = Arc::downgrade(&handle);
        move |next| {
            assert!(Arc::ptr_eq(&weak.upgrade().unwrap().load(), next));
            assert_eq!(scenario.live().fee, POST_PUBLICATION_PANIC_FEE);
            if first.swap(false, std::sync::atomic::Ordering::SeqCst) {
                weak.upgrade().unwrap().on_apply(Box::new(|_| {}));
                panic!("injected post-publication applier panic");
            }
        }
    }));
    assert_eq!(
        put(&handle, POST_PUBLICATION_PANIC_FEE).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(!Arc::ptr_eq(&handle.load(), &before));
    assert_eq!(
        scenario.live(),
        LivePrice {
            fee: POST_PUBLICATION_PANIC_FEE,
            epoch: 1
        }
    );
    assert_eq!(
        stored_fee(&overlay.backend()),
        Some(POST_PUBLICATION_PANIC_FEE)
    );
    assert_eq!(
        put(&handle, POST_PUBLICATION_PANIC_FEE).await.status(),
        StatusCode::OK
    );
    assert_eq!(scenario.live().epoch, 1);
}
