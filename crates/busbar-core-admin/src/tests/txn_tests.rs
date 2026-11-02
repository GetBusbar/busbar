use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use serde_json::json;

use crate::v1::contract::AdminError;
use crate::v1::json::{delete_group, install_plugin};
use busbar_kernel::config::transaction::{config_transaction, Outcome};
use busbar_kernel::governance::GovState;
use busbar_kernel::state::AppHandle;
use busbar_kernel_testkit::test_support::store_double::MemoryStore;

struct SlowStore {
    inner: MemoryStore,
    delay: Duration,

    reads: AtomicU64,
}

impl SlowStore {
    fn new(delay: Duration) -> Self {
        Self {
            inner: MemoryStore::new(),
            delay,
            reads: AtomicU64::new(0),
        }
    }
}

impl busbar_contract::records::RecordStore for SlowStore {
    fn put_key(
        &self,
        key: &busbar_contract::records::VirtualKey,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(
        &self,
        id: &str,
    ) -> busbar_contract::records::RecordStoreResult<Option<busbar_contract::records::VirtualKey>>
    {
        self.inner.get_key(id)
    }
    fn list_keys(
        &self,
    ) -> busbar_contract::records::RecordStoreResult<Vec<busbar_contract::records::VirtualKey>>
    {
        self.reads.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_contract::records::RecordStoreResult<busbar_contract::records::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_contract::records::UsageLedger,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &busbar_contract::records::MeteringDelta,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> busbar_contract::records::RecordStoreResult<Vec<busbar_contract::records::MeteringRow>>
    {
        self.inner.list_metering(bucket)
    }
    fn put_key_with_credential(
        &self,
        key: &busbar_contract::records::VirtualKey,
        secret: &busbar_contract::records::CredentialSecret,
    ) -> busbar_contract::records::RecordStoreResult<()> {
        self.inner.put_key_with_credential(key, secret)
    }
    fn list_credentials(
        &self,
        key_id: &str,
    ) -> busbar_contract::records::RecordStoreResult<Vec<busbar_contract::records::CredentialMeta>>
    {
        self.inner.list_credentials(key_id)
    }
}

fn gov(store: Arc<dyn busbar_kernel::governance::RecordStore>) -> Arc<GovState> {
    Arc::new(
        GovState::new_with_signer(
            store,
            None,
            Some(
                busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
                    &[7u8; 32],
                    busbar_kernel::governance::signing::DEFAULT_KID,
                ),
            ),
        )
        .expect("gov"),
    )
}

fn tree(names: &[&str]) -> std::collections::BTreeMap<String, busbar_kernel::config::GroupCfg> {
    names
        .iter()
        .map(|n| (n.to_string(), busbar_kernel::config::GroupCfg::default()))
        .collect()
}

fn handle_for(app: Arc<busbar_kernel::state::App>) -> Arc<AppHandle> {
    Arc::new(AppHandle::new(app))
}

fn anon() -> axum::Extension<busbar_kernel::auth::AuthPrincipal> {
    axum::Extension(busbar_kernel::auth::AuthPrincipal(None))
}

async fn mint(handle: &Arc<AppHandle>, name: &str, group: Option<&str>) -> StatusCode {
    let body = match group {
        Some(g) => json!({ "name": name, "group": g }),
        None => json!({ "name": name }),
    };
    crate::keys::create_key(
        State(handle.clone()),
        anon(),
        HeaderMap::new(),
        axum::Extension(std::sync::Arc::new(crate::keys::KeyReplayCache::new())),
        axum::body::Bytes::from(body.to_string()),
    )
    .await
    .status()
}

async fn delete_team(handle: Arc<AppHandle>) -> StatusCode {
    delete_group(
        State(handle),
        anon(),
        Path("team".to_string()),
        HeaderMap::new(),
    )
    .await
    .status()
}

fn spawn_liveness_probe() -> (
    Arc<AtomicBool>,
    Arc<AtomicU64>,
    tokio::task::JoinHandle<u64>,
) {
    let stop = Arc::new(AtomicBool::new(false));
    let worst = Arc::new(AtomicU64::new(0));
    let probe = {
        let (stop, worst) = (stop.clone(), worst.clone());
        tokio::spawn(async move {
            let mut last = Instant::now();
            let mut ticks = 0u64;
            while !stop.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
                let now = Instant::now();
                worst.fetch_max(
                    now.duration_since(last).as_millis() as u64,
                    Ordering::SeqCst,
                );
                last = now;
                ticks += 1;
            }
            ticks
        })
    };
    (stop, worst, probe)
}

fn parking_secret_hook_env(delay: Duration) -> busbar_kernel::hooks::HookEnv {
    busbar_kernel::hooks::HookEnv::with_axis(
        busbar_kernel_testkit::test_support::rows::Rows::new()
            .with_dropped_secret_slots(
                busbar_kernel_testkit::test_support::rows::row("some-hook-plugin", "", "hook"),
                &["licenseKey"],
            )
            .into_rows(),
        busbar_kernel_testkit::test_support::hook_double::HookAxisDouble::new(&[
            "some-hook-plugin",
        ]),
        Arc::new(busbar_kernel::config::secret::SecretResolver::with_plugin(
            Box::new(move |_module: &str, _settings: &str| {
                std::thread::sleep(delay);
                Ok(busbar_contract::redacted::Secret::new(b"resolved".to_vec()))
            }),
        )),
    )
}

async fn register_secret_hook(handle: Arc<AppHandle>) -> (StatusCode, String) {
    let body = json!({
        "name": "compliance-gate",
        "config": {
            "module": "some-hook-plugin",
            "kind": "gate",
            "global": true,
            "settings": { "licenseKey": { "module": "acme-vault", "settings": { "path": "kv/busbar" } } }
        }
    });
    let response = crate::v1::json::register_hook(
        State(handle),
        anon(),
        HeaderMap::new(),
        axum::body::Bytes::from(body.to_string()),
    )
    .await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 65_536)
        .await
        .expect("the hook response body is bounded");
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn slow_secret_plugin_does_not_stall_the_executor() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let delay = Duration::from_millis(400);
    let app = crate::new_test_app()
        .hook_env(parking_secret_hook_env(delay))
        .build();
    let handle = handle_for(app);

    let (stop, worst, probe) = spawn_liveness_probe();
    tokio::time::sleep(Duration::from_millis(20)).await;
    worst.store(0, Ordering::SeqCst);

    let (status, body) = tokio::spawn(register_secret_hook(handle.clone()))
        .await
        .expect("register joins");
    stop.store(true, Ordering::SeqCst);
    let ticks = probe.await.expect("probe joins");

    assert_eq!(
        status,
        StatusCode::CREATED,
        "the hook registers: {status}: {body}"
    );
    assert!(ticks > 0, "the probe must have run");
    let worst_gap = worst.load(Ordering::SeqCst);
    assert!(
        worst_gap < delay.as_millis() as u64 / 2,
        "EXECUTOR STALLED: the liveness probe's worst tick gap was {worst_gap}ms while a {}ms \
         `kind: secret` PLUGIN resolve ran under the config-mutation lock. Blocking plugin FFI \
         reached the async thread — the snapshot build must be deferred through `Txn::read_store` \
         onto spawn_blocking.",
        delay.as_millis()
    );
}
