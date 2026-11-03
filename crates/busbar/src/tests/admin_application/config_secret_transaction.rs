// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use axum::http::StatusCode;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn slow_secret_plugin_does_not_stall_the_executor() {
    const CHILD: &str = "BUSBAR_ADMIN_SECRET_TRANSACTION_CHILD";
    const WITNESS: &str = "actual root overlay refusal assertions completed";
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
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("admin-store-overlay");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let hook_path =
        std::path::PathBuf::from(std::env::var_os("BUSBAR_TEST_WEBREQUEST_CDYLIB").expect(
            "BUSBAR_TEST_WEBREQUEST_CDYLIB names the actual reference-aware webrequest product",
        ));
    let hook_statement = busbar_plugin_loader::dispatch::rendering_of_library(&hook_path)
        .expect("the actual webrequest statement reads")
        .expect("the actual webrequest exports its statement");
    let hook_module = busbar_contract::abi::mechanism::rendering::read(&hook_statement)
        .expect("the actual webrequest statement is valid")
        .name;
    let mut hook_manifest = plugins::manifest(
        "hook",
        &hook_module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    hook_manifest.statement = Some(hex::encode(hook_statement));
    hook_manifest.needs.prompt = busbar_contract::plugin_rows::NeedLevel::Rw;
    hook_manifest.needs.user = busbar_contract::plugin_rows::NeedLevel::Ro;
    let hook_archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        hook_manifest,
        &std::fs::read(hook_path).expect("the actual hook library reads"),
    );
    std::fs::write(directory.join("actual-webrequest.tar.gz"), hook_archive)
        .expect("stage actual signed webrequest");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(document.clone())
        .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let boot_calls = app
        .governance
        .as_ref()
        .expect("actual governance")
        .store_calls()
        .expect("actual boot Store calls");
    crate::root::kernel::ROOT_CARD.keep_in_store(boot_calls, 101);
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .expect("the actual rate history boots before rates are committed");
    limits
        .keep()
        .expect("the booted actual rates and limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let delay = Duration::from_millis(400);
    assert!(
        app.hook_env
            .registry
            .reference_slots(&hook_module)
            .iter()
            .any(|p| p == "url"),
        "the actual webrequest product must declare its reference-aware url"
    );
    let reference = directory.join("hook-url.txt");
    std::fs::write(&reference, "http://127.0.0.1:9/hook\n").unwrap();
    let delayed = Arc::new(DelayedActualResolver {
        inner: app.hook_env.secret_resolver.clone(),
        path: reference.clone(),
        delay,
        delay_once: AtomicBool::new(true),
        calls: AtomicU64::new(0),
    });
    app.hook_env.secret_resolver = delayed.clone();
    let calls = app
        .governance
        .as_ref()
        .unwrap()
        .store_calls()
        .expect("actual Store calls");
    app.overlay_path = Some(
        busbar_kernel::config::overlay::OverlayStore::new(calls).expect("actual Store overlay"),
    );
    let (_data, admin, _handle) =
        busbar_kernel::build_split_routers_with_limits(Arc::new(app), 1 << 20, 0, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, admin).await });
    let (stop, worst, probe) = spawn_liveness_probe();
    tokio::time::sleep(Duration::from_millis(20)).await;
    worst.store(0, Ordering::SeqCst);

    let (status, body) =
        tokio::spawn(async move {
            let response = reqwest::Client::new().post(format!("http://{addr}/api/v1/admin/hooks"))
            .json(&serde_json::json!({"name": "compliance-gate", "config": {
                "module": hook_module, "kind": "gate", "global": true, "prompt": "rw", "user": "ro",
                "settings": {"url": {"file": reference}},
            }})).send().await.unwrap();
            let status = response.status();
            let body = String::from_utf8(response.bytes().await.unwrap().to_vec()).unwrap();
            (status, body)
        })
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
    assert_eq!(
        delayed.calls.load(Ordering::SeqCst),
        1,
        "the measured request actually resolved the declared file reference"
    );
    server.abort();
    println!("{WITNESS}");
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
// One causal delay on the actual file reference; every result/error is exactly delegated.
struct DelayedActualResolver {
    inner: Arc<dyn busbar_contract::secret::SecretResolve>,
    path: std::path::PathBuf,
    delay: Duration,
    delay_once: AtomicBool,
    calls: AtomicU64,
}
impl DelayedActualResolver {
    fn delay_target(&self, secret: &busbar_contract::secret_ref::SecretRef) {
        if secret
            .file_path()
            .is_some_and(|p| std::path::Path::new(p) == self.path)
            && self.delay_once.swap(false, Ordering::SeqCst)
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.delay);
        }
    }
}
impl busbar_contract::secret::SecretResolve for DelayedActualResolver {
    fn resolve(
        &self,
        secret: &busbar_contract::secret_ref::SecretRef,
    ) -> Result<busbar_contract::redacted::Secret<Vec<u8>>, String> {
        self.delay_target(secret);
        self.inner.resolve(secret)
    }
    fn resolve_string(
        &self,
        secret: &busbar_contract::secret_ref::SecretRef,
    ) -> Result<busbar_contract::redacted::Secret<String>, String> {
        self.delay_target(secret);
        self.inner.resolve_string(secret)
    }
    fn resolve_at_config(
        &self,
        secret: &busbar_contract::secret_ref::SecretRef,
        scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<busbar_contract::redacted::Secret<Vec<u8>>, String> {
        self.delay_target(secret);
        self.inner.resolve_at_config(secret, scope)
    }
    fn resolve_string_at_config(
        &self,
        secret: &busbar_contract::secret_ref::SecretRef,
        scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<busbar_contract::redacted::Secret<String>, String> {
        self.delay_target(secret);
        self.inner.resolve_string_at_config(secret, scope)
    }
    fn resolve_refusing(
        &self,
        secret: &busbar_contract::secret_ref::SecretRef,
        scope: Option<&busbar_contract::config_time::ConfigScope>,
    ) -> Result<busbar_contract::redacted::Secret<Vec<u8>>, busbar_contract::secret::SecretRefused>
    {
        self.delay_target(secret);
        self.inner.resolve_refusing(secret, scope)
    }
}
