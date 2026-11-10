// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::test_plugins as plugins;
use std::collections::HashSet;
use std::sync::Arc;
const TOKEN: &str = "admintok";

struct Scratch(std::path::PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn isolated() -> bool {
    const CHILD: &str = "BUSBAR_ARTIFACT_CAS_ROOT_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return false;
    }
    let name = std::thread::current().name().unwrap().to_owned();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &name, "--nocapture"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    true
}

async fn application() -> (Arc<busbar_kernel::state::App>, Scratch) {
    crate::dist_root_install::install();
    let store_library = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory = plugins::scratch("artifact-cas-actual-store");
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([7u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("the actual Store opens the configuration authority");
    let anchor = crate::root::real_store::core_over(anchor).await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .await
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let app = Arc::new(app);
    busbar_kernel::boot::hydrate_all(&app)
        .await
        .expect("the actual Store hydrates");
    (app, Scratch(directory))
}

async fn body(response: reqwest::Response, status: u16) -> serde_json::Value {
    let actual = response.status().as_u16();
    let bytes = response.bytes().await.unwrap();
    assert_eq!(actual, status, "{}", String::from_utf8_lossy(&bytes));
    if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    }
}

fn candidate() -> Vec<u8> {
    let manifest = plugins::manifest("store", "artifact-cas-target", plugins::FIXTURE_PUBLISHER);
    plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        b"not loaded by this admission fixture",
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plugin_archive_preconditions_fence_replacement_delete_and_rollback() {
    if isolated() {
        return;
    }
    let (app, scratch) = application().await;
    let overlay = app.overlay_path.clone().unwrap();
    let (_, router, handle) =
        busbar_core_admin::build_split_routers_with_limits(app, 1 << 20, 16, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    let base = format!("http://{addr}/api/v1/admin");
    let archive = candidate();
    let digest = busbar_contract::redacted::sha256_hex(&archive);
    use base64::Engine as _;
    let installed = body(client.post(format!("{base}/plugins")).bearer_auth(TOKEN)
        .json(&serde_json::json!({"file":"reviewed.tar.gz","tarball_b64":base64::engine::general_purpose::STANDARD.encode(&archive)}))
        .send().await.unwrap(), 201).await;
    assert_eq!(installed["file"], "reviewed.tar.gz");
    let listing = body(
        client
            .get(format!("{base}/plugins?type=store"))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap(),
        200,
    )
    .await;
    let row = listing["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| artifact_file(row) == "reviewed.tar.gz")
        .unwrap();
    assert_eq!(row["archive_sha256"], digest);
    let version = handle.load().config_version;
    let before_overlay =
        serde_json::to_value(overlay.read_required_async().await.unwrap().map(|doc| {
            serde_json::to_value(doc.authoring(&busbar_kernel::seal::acquire()))
                .expect("the overlay authoring view serializes")
        }))
        .unwrap();
    let mut replacement = archive.clone();
    // Gzip mtime belongs to the archive, outside the signed member. Same library, different archive.
    replacement[4..8].copy_from_slice(&42_u32.to_le_bytes());
    let next_digest = busbar_contract::redacted::sha256_hex(&replacement);
    assert_ne!(digest, next_digest);
    // Exercise the real install route: replacing archive bytes does not publish a config generation.
    body(client.post(format!("{base}/plugins")).bearer_auth(TOKEN)
        .json(&serde_json::json!({"file":"reviewed.tar.gz","tarball_b64":base64::engine::general_purpose::STANDARD.encode(&replacement)}))
        .send().await.unwrap(),201).await;
    assert_eq!(handle.load().config_version, version);
    let listed = body(
        client
            .get(format!("{base}/plugins?type=store"))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap(),
        200,
    )
    .await;
    assert_eq!(
        listed["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| artifact_file(row) == "reviewed.tar.gz")
            .unwrap()["archive_sha256"],
        next_digest
    );
    let path = scratch.0.join("reviewed.tar.gz");
    // An actual disk write deferred by the same transaction must finish before the conditional delete can inspect it.
    busbar_kernel::durable::write(&path, &archive).unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let writer_handle = handle.clone();
    let writer_path = path.clone();
    let writer_bytes = replacement.clone();
    let writer = tokio::spawn(async move {
        busbar_kernel::config::transaction::config_transaction(&writer_handle, move |txn| {
            Ok::<_, busbar_core_admin::v1::contract::AdminError>(txn.store_write(move || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                busbar_kernel::durable::write(&writer_path, &writer_bytes).unwrap();
                Ok(busbar_kernel::config::transaction::Outcome::Value(()))
            }))
        })
        .await
        .unwrap();
    });
    entered_rx.await.unwrap();
    let delete = client
        .delete(format!("{base}/plugins/reviewed.tar.gz"))
        .bearer_auth(TOKEN)
        .query(&[("expected_archive_sha256", &digest)])
        .send();
    tokio::pin!(delete);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut delete)
            .await
            .is_err(),
        "delete must wait for the mutation transaction"
    );
    release_tx.send(()).unwrap();
    writer.await.unwrap();
    body(delete.await.unwrap(), 409).await;
    let stale = body(
        client
            .post(format!("{base}/plugins/rollback"))
            .bearer_auth(TOKEN)
            .header("If-Match", format!("\"{version}\""))
            .json(&serde_json::json!({"file":"reviewed.tar.gz","expected_archive_sha256":digest}))
            .send()
            .await
            .unwrap(),
        409,
    )
    .await;
    assert_eq!(stale["error"]["code"], "conflict");
    assert_eq!(std::fs::read(&path).unwrap(), replacement);
    assert_eq!(handle.load().config_version, version);
    assert_eq!(
        serde_json::to_value(overlay.read_required_async().await.unwrap().map(|doc| {
            serde_json::to_value(doc.authoring(&busbar_kernel::seal::acquire()))
                .expect("the overlay authoring view serializes")
        }))
        .unwrap(),
        before_overlay
    );
    body(
        client
            .delete(format!(
                "{base}/plugins/reviewed.tar.gz?expected_archive_sha256=bad"
            ))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap(),
        400,
    )
    .await;
    body(
        client
            .post(format!("{base}/plugins/rollback"))
            .bearer_auth(TOKEN)
            .json(&serde_json::json!({"file":"reviewed.tar.gz","expected_archive_sha256":null}))
            .send()
            .await
            .unwrap(),
        400,
    )
    .await;
    body(
        client
            .delete(format!("{base}/plugins/reviewed.tar.gz"))
            .bearer_auth(TOKEN)
            .query(&[("expected_archive_sha256", &next_digest)])
            .send()
            .await
            .unwrap(),
        204,
    )
    .await;
    assert!(!path.exists());
    body(
        client
            .delete(format!("{base}/plugins/reviewed.tar.gz"))
            .bearer_auth(TOKEN)
            .query(&[("expected_archive_sha256", &next_digest)])
            .send()
            .await
            .unwrap(),
        409,
    )
    .await;
    body(
        client
            .delete(format!("{base}/plugins/reviewed.tar.gz"))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap(),
        404,
    )
    .await;
    body(client.post(format!("{base}/plugins/rollback")).bearer_auth(TOKEN).json(&serde_json::json!({"file":"reviewed.tar.gz","expected_archive_sha256":next_digest})).send().await.unwrap(),409).await;
    server.abort();
    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_if_match_is_checked_at_serialized_admission_without_stale_drain() {
    if isolated() {
        return;
    }
    let (app, _scratch) = application().await;
    let (_, router, handle) =
        busbar_core_admin::build_split_routers_with_limits(app, 1 << 20, 16, false);
    let (shutdown, mut receiver) = tokio::sync::broadcast::channel(4);
    busbar_core_admin::restart::publish_shutdown(shutdown);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();
    let url = format!("http://{addr}/api/v1/admin/restart");
    let version = handle.load().config_version;
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let writer_handle = handle.clone();
    let writer = tokio::spawn(async move {
        busbar_kernel::config::transaction::config_transaction(&writer_handle, move |txn| {
            let mut next = (**txn.app()).clone();
            next.config_version += 1;
            Ok::<_, busbar_core_admin::v1::contract::AdminError>(txn.commit(
                Arc::new(next),
                move || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(())
                },
                (),
            ))
        })
        .await
        .unwrap();
    });
    entered_rx.await.unwrap();
    let request = client
        .post(&url)
        .bearer_auth(TOKEN)
        .header("If-Match", format!("\"{version}\""))
        .json(&serde_json::json!({"confirm":true}))
        .send();
    tokio::pin!(request);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut request)
            .await
            .is_err()
    );
    release_tx.send(()).unwrap();
    writer.await.unwrap();
    let stale = body(request.await.unwrap(), 409).await;
    assert_eq!(stale["error"]["code"], "version_conflict");
    assert!(matches!(
        receiver.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    body(
        client
            .post(&url)
            .bearer_auth(TOKEN)
            .header("If-Match", "malformed")
            .json(&serde_json::json!({"confirm":true}))
            .send()
            .await
            .unwrap(),
        400,
    )
    .await;
    assert!(matches!(
        receiver.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    body(
        client
            .post(&url)
            .bearer_auth(TOKEN)
            .header("If-Match", format!("\"{}\"", handle.load().config_version))
            .json(&serde_json::json!({"confirm":true}))
            .send()
            .await
            .unwrap(),
        202,
    )
    .await;
    tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    body(
        client
            .post(&url)
            .bearer_auth(TOKEN)
            .json(&serde_json::json!({"confirm":true}))
            .send()
            .await
            .unwrap(),
        202,
    )
    .await;
    tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    server.abort();
    let _ = server.await;
}

// Decode the archive listing's field schema; the field name is not a provider selector.
fn artifact_file(row: &serde_json::Value) -> &str {
    #[derive(serde::Deserialize)]
    struct Artifact<'a> {
        file: &'a str,
    }
    <Artifact<'_> as serde::Deserialize>::deserialize(row)
        .expect("the archive listing supplies its file field")
        .file
}
