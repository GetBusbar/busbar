// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use crate::root::test_plugins as plugins;
use axum::http::StatusCode;
use busbar_contract::persistence::*;
use busbar_contract::records::*;
use busbar_kernel::governance::at_rest::{self, AtRestKeys};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
#[tokio::test]
async fn unchanged_admin_reload_retries_at_rest_maintenance_after_store_recovery() {
    const CHILD: &str = "BUSBAR_ADMIN_REWRAP_CHILD";
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
        for failure in ["listing", "rewrap"] {
            let mut child = Child(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", &name, "--nocapture"])
                    .env(CHILD, failure)
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
                        status.success()
                            && output.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
                        "the actual-root usage witness failed: {status}: {output}"
                    );
                    assert!(
                        output.contains(&format!("{WITNESS} {failure}")),
                        "the exact child did not complete its assertions: {output}"
                    );
                    break;
                }
                assert!(
                    Instant::now() < until,
                    "the actual-root usage witness timed out"
                );
                std::thread::park_timeout(Duration::from_millis(5));
            }
        }
        return;
    }
    let selected = std::env::var(CHILD).expect("exact maintenance scenario");
    assert!(matches!(selected.as_str(), "listing" | "rewrap"));
    for failure in ["listing", "rewrap"]
        .into_iter()
        .filter(|failure| *failure == selected)
    {
        crate::dist_root_install::install();
        let library_path = crate::root::test_plugins::application_store_library();
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
        let settings: serde_json::Value =
            crate::root::test_plugins::application_store_settings(&directory);
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
        let native = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
            .await
            .expect("the actual native Store bootstraps");
        let store = RewrapStore::new(native);
        let core = crate::root::real_store::core_over(store.clone()).await;
        let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            config,
            plugin_config,
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(core.clone()),
            false,
        )
        .await
        .expect("the actual product builds the swap deployment");
        limits.stage_boot();
        let boot_calls = app
            .governance
            .as_ref()
            .expect("actual governance")
            .core_store_handle()
            .expect("actual boot Store calls");
        crate::root::kernel::ROOT_CARD
            .keep_in_store(boot_calls, 101)
            .expect("native rate history binding");
        crate::root::kernel::ROOT_CARD
            .boot_in_store(None)
            .await
            .expect("the actual rate history boots before rates are committed");
        limits
            .keep()
            .await
            .expect("the booted actual rates and limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
        }
        let dir = directory.clone();
        let config_path = dir.join("config.yaml");
        let providers_path = dir.join("providers.yaml");
        let old_path = dir.join("old-at-rest.key");
        let new_path = dir.join("new-at-rest.key");
        std::fs::write(&old_path, [3_u8; 32]).unwrap();
        std::fs::write(&new_path, [4_u8; 32]).unwrap();
        let mut disk = document.clone();
        disk["plugins"] = plugins::config_document(&app.plugins_cfg);
        disk["credentials"] = serde_json::json!({"at_rest": {"key": {"file": new_path}, "previous": {"file": old_path}}});
        std::fs::write(&config_path, serde_yaml::to_string(&disk).unwrap()).unwrap();
        std::fs::write(&providers_path, "{}\n").unwrap();
        core.identity()
            .put_key(&VirtualKey {
                id: "rewrap-owner".into(),
                generation_hash: "binding:rewrap-owner:0".into(),
                enabled: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let meta = CredentialMeta {
            id: "rewrap-credential".into(),
            key_id: "rewrap-owner".into(),
            kind: app
                .auth
                .issued_credential()
                .expect("the actual linked credential reader declares the recoverable kind")
                .0,
            slot: 0,
            public_id: "rewrap-public".into(),
            secret_form: SecretForm::Recoverable,
            created_at: 0,
            updated_at: 0,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        };
        let old_keys = AtRestKeys::new(&[3_u8; 32], None);
        core.identity()
            .put_credential(&CredentialSecret {
                secret: old_keys
                    .seal(&meta, b"recoverable-test-secret")
                    .unwrap()
                    .into(),
                meta,
            })
            .await
            .unwrap();
        let actual_plugins = app.plugins_cfg.clone();
        drop(app);
        let cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual config resolves");
        let (mut app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
            cfg,
            actual_plugins,
            None,
            Default::default(),
            Default::default(),
            (None, None),
            None,
            &rules,
            Some(core.clone()),
            false,
        )
        .await
        .expect("normal composition uses the precise actual-Store primitive fault wrapper");
        limits.stage_boot();
        let boot_calls = app
            .governance
            .as_ref()
            .expect("actual governance")
            .core_store_handle()
            .expect("actual boot Store calls");
        assert!(
            Arc::ptr_eq(&boot_calls, &core),
            "the rebuilt App retains its original CoreStore"
        );
        assert!(
            crate::root::kernel::ROOT_CARD
                .card_store()
                .expect("the original native price owner remains loaded")
                .is_bound_to(&boot_calls),
            "reload retains the same native price owner"
        );
        limits
            .keep()
            .await
            .expect("the booted actual rates and limits commit");
        if let Some(rotate) = rotate {
            rotate.await;
        }
        app.config_path = Some(config_path);
        app.providers_path = Some(providers_path);
        let gov = app.governance.as_ref().unwrap().clone();
        assert!(crate::root::kernel::ROOT_CARD
            .card_store()
            .expect("the actual native price history remains loaded")
            .is_bound_to(&core));
        let overlay_faults = store.clone();
        let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(core.clone())
            .expect("actual Store overlay");
        app.overlay_path = Some(overlay.clone());
        let (_data, admin, handle) = busbar_kernel::build_split_routers_with_limits(
            crate::root::real_store::hydrated(Arc::new(app)).await,
            1 << 20,
            0,
            false,
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, admin).await });
        let client = reqwest::Client::new();
        store
            .fail_listing
            .store(failure == "listing", Ordering::SeqCst);
        store
            .deny_rewrap
            .store(failure == "rewrap", Ordering::SeqCst);
        let first = client
            .post(format!("http://{addr}/api/v1/admin/config/reload"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            first.status(),
            StatusCode::OK,
            "{failure}: first reload commits even with maintenance debt"
        );
        // The reply has completed its failed maintenance pass. Allow an independent
        // identity read to inspect the retained ciphertext before retrying reload.
        store.fail_listing.store(false, Ordering::SeqCst);
        let pending = core
            .identity()
            .list_credentials_since(0)
            .await
            .unwrap()
            .remove(0);
        assert_eq!(at_rest::sealed_kid(&pending.secret), Some(old_keys.kid()));
        let current_keys = AtRestKeys::new(&[4_u8; 32], Some(&[3_u8; 32]));
        assert_eq!(
            at_rest::open(Some(&current_keys), &pending.meta, &pending.secret)
                .as_deref()
                .map(String::as_str),
            Some("recoverable-test-secret")
        );
        let calls = store.listings.load(Ordering::SeqCst);
        store.fail_listing.store(false, Ordering::SeqCst);
        store.deny_rewrap.store(false, Ordering::SeqCst);
        let second = client
            .post(format!("http://{addr}/api/v1/admin/config/reload"))
            .send()
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::OK, "{failure}: retry reload");
        assert!(
            store.listings.load(Ordering::SeqCst) > calls,
            "{failure}: unchanged kids must still retry the Store"
        );
        let sealed = core
            .identity()
            .list_credentials_since(0)
            .await
            .unwrap()
            .remove(0);
        assert_eq!(
            at_rest::sealed_kid(&sealed.secret),
            Some(current_keys.kid())
        );
        assert_eq!(
            at_rest::open(Some(&current_keys), &sealed.meta, &sealed.secret)
                .as_deref()
                .map(String::as_str),
            Some("recoverable-test-secret")
        );

        std::fs::write(&new_path, [5_u8; 32]).unwrap();
        overlay_faults.fail_writes.store(true, Ordering::SeqCst);
        let before = handle.load();
        let calls = store.listings.load(Ordering::SeqCst);
        let rejected = client
            .put(format!("http://{addr}/api/v1/admin/config/settings"))
            .json(&serde_json::json!({"limits": {"request_body_max_bytes": 5000123}}))
            .send()
            .await
            .unwrap();
        assert!(!rejected.status().is_success());
        let rejected_body = rejected.bytes().await.unwrap();
        let rejected_text = std::str::from_utf8(&rejected_body).unwrap();
        assert!(
            rejected_text.contains("persistence to the overlay was not confirmed"),
            "{rejected_text}"
        );
        assert!(Arc::ptr_eq(&before, &handle.load()));

        assert!(!gov.set_at_rest_keys(Some(AtRestKeys::new(&[4_u8; 32], Some(&[3_u8; 32])))));
        assert_eq!(
            store.listings.load(Ordering::SeqCst),
            calls,
            "rejected commit does not run credential maintenance"
        );
        server.abort();
        let _ = std::fs::remove_dir_all(dir);
    }
    println!("{WITNESS} {selected}");
}
// Faults affect only native operations owned by the selected maintenance path.
// Core continues to own credential interpretation, CAS and ciphertext custody.
struct RewrapStore {
    actual: Arc<dyn PersistenceBackend>,
    listings: AtomicUsize,
    fail_listing: AtomicBool,
    deny_rewrap: AtomicBool,
    fail_writes: AtomicBool,
}
impl RewrapStore {
    fn new(actual: Arc<dyn PersistenceBackend>) -> Arc<Self> {
        Arc::new(Self {
            actual,
            listings: AtomicUsize::new(0),
            fail_listing: AtomicBool::new(false),
            deny_rewrap: AtomicBool::new(false),
            fail_writes: AtomicBool::new(false),
        })
    }
}
impl PersistenceBackend for RewrapStore {
    fn info(&self) -> BackendInfo {
        self.actual.info()
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.actual.clock(dataset)
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        self.actual.read(request)
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async move {
            if request.namespace == busbar_kernel::governance::persistence::identity::NAMESPACE {
                self.listings.fetch_add(1, Ordering::SeqCst);
                if self.fail_listing.load(Ordering::SeqCst) {
                    return Err(Failure::Unavailable);
                }
            }
            self.actual.scan(request).await
        })
    }
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move {
            for mutation in &candidate.candidate().mutations {
                let address = match mutation {
                    Mutation::Put { address, .. } | Mutation::Delete(address) => address,
                    Mutation::DeleteRange { .. } => continue,
                };
                if self.deny_rewrap.load(Ordering::SeqCst)
                    && address.namespace
                        == busbar_kernel::governance::persistence::identity::CONFIDENTIAL.0
                {
                    return Err(Failure::Refused);
                }
                if self.fail_writes.load(Ordering::SeqCst)
                    && address
                        .key
                        .windows(b"busbar.config.overlay.v1".len())
                        .any(|part| part == b"busbar.config.overlay.v1")
                {
                    return Err(Failure::Refused);
                }
            }
            self.actual.commit(candidate).await
        })
    }
}
