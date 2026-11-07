// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::root::test_plugins as plugins;

const DIRECTORY: &str = "BUSBAR_ADMIN_RESTART_DIRECTORY";
const WITNESS: &str = "actual durable admin restart phase completed";
const KEY_HANDOFF: &str = "BUSBAR_RESTART_KEY:";
const TOKEN_HANDOFF: &str = "BUSBAR_RESTART_TOKEN:";

/// Each boot owns its process globals and reopens the same actual SQLite namespace.
/// The rotate token crosses only the captured stdout/stdin pipes, never a file or env var.
fn restart_phases(child_env: &str, with_token: bool) {
    struct Directory(PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let directory = Directory(plugins::scratch(child_env));
    let name = std::thread::current()
        .name()
        .expect("the test runner names its exact test thread")
        .to_string();
    let mut handoff = Zeroizing::new(String::new());
    for phase in ["first", "restart"] {
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(child_env, phase)
                .env(DIRECTORY, &directory.0)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root restart phase"),
        );
        {
            let mut stdin = child.0.stdin.take().unwrap();
            stdin.write_all(handoff.as_bytes()).unwrap();
        }
        let until = std::time::Instant::now() + std::time::Duration::from_secs(90);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                let mut output = Zeroizing::new(Vec::new());
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_end(&mut output)
                    .unwrap();
                // Child stdout can contain the private token handoff. Its stderr already
                // carries assertion failures; never include the captured bytes in a panic.
                assert!(
                    status.success(),
                    "the {phase} restart phase failed: {status}"
                );
                let output = std::str::from_utf8(&output).unwrap();
                assert!(
                    output.contains(WITNESS),
                    "the {phase} phase did not finish its assertions"
                );
                if phase == "first" {
                    let id = output
                        .lines()
                        .find_map(|line| line.strip_prefix(KEY_HANDOFF))
                        .expect("the first phase returns its public key id");
                    let token = if with_token {
                        output
                            .lines()
                            .find_map(|line| line.strip_prefix(TOKEN_HANDOFF))
                            .expect("the first rotate returns its token through the private pipe")
                    } else {
                        ""
                    };
                    handoff = Zeroizing::new(format!("{id}\n{token}\n"));
                }
                break;
            }
            assert!(
                std::time::Instant::now() < until,
                "the {phase} restart phase timed out"
            );
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
    }
}

fn send_handoff(id: &str, token: Option<&str>) {
    assert!(!id.contains(['\n', '\r']));
    let mut pipe = std::io::stdout().lock();
    writeln!(pipe, "{KEY_HANDOFF}{id}").unwrap();
    if let Some(token) = token {
        assert!(!token.contains(['\n', '\r']));
        writeln!(pipe, "{TOKEN_HANDOFF}{token}").unwrap();
    }
    pipe.flush().unwrap();
}

fn receive_handoff() -> Zeroizing<String> {
    let mut handoff = Zeroizing::new(String::new());
    std::io::stdin().read_to_string(&mut handoff).unwrap();
    handoff
}

async fn application(
    directory: &Path,
    first: bool,
) -> (
    busbar_kernel::state::App,
    Arc<busbar_kernel::persistence::facade::CoreStore>,
    crate::root::durability::NodeBook,
) {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    if first {
        let mut manifest = plugins::manifest("store", &module, plugins::FIXTURE_PUBLISHER);
        manifest.statement = Some(hex::encode(statement));
        let archive = plugins::signed(
            &crate::dist_root_install::release_key(),
            manifest,
            &std::fs::read(store_library).expect("the actual Store artifact reads"),
        );
        std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
        std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
        std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    }
    let settings = plugins::application_store_settings(directory);
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {}, "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] }, "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the same actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the same actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = plugins::trusted_config(directory);
    let backend = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("the actual Store reopens the configuration authority");
    let store = crate::root::real_store::core_over(backend).await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(store.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotation, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(store.clone()),
        true,
    )
    .await
    .expect("the real root cold-composes the configured Store and admin application");
    assert_eq!(
        app.config_version, 0,
        "each process constructs a cold App, not a retained reload"
    );
    limits.stage_boot();
    let book = crate::root::boot::book(&app, &module)
        .await
        .expect("each cold process binds its actual Store book and rate history before serving");
    limits
        .keep()
        .await
        .expect("the actual restarted limits commit");
    if let Some(rotation) = rotation {
        rotation.await;
    }
    (app, store, book)
}

#[tokio::test]
async fn an_idempotent_mint_retried_after_a_restart_is_refused_not_minted_twice() {
    const CHILD: &str = "BUSBAR_ADMIN_RESTART_B1759167CF80";
    let Ok(phase) = std::env::var(CHILD) else {
        restart_phases(CHILD, false);
        return;
    };
    assert!(matches!(phase.as_str(), "first" | "restart"));
    let first = phase == "first";
    let directory = PathBuf::from(std::env::var_os(DIRECTORY).unwrap());
    let handoff = if first {
        Zeroizing::new(String::new())
    } else {
        receive_handoff()
    };
    let (app, store, _book) = application(&directory, first).await;
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serving = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let response = reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .header("idempotency-key", "restart-mint")
        .body(serde_json::json!({"name": "once"}).to_string())
        .send()
        .await
        .unwrap();
    if first {
        assert_eq!(response.status().as_u16(), 201);
        let minted: serde_json::Value = response.json().await.unwrap();
        send_handoff(minted["id"].as_str().expect("the mint names its key"), None);
    } else {
        assert_eq!(
            response.status().as_u16(),
            409,
            "a retry after a process restart must not mint again"
        );
        let retry: serde_json::Value = response.json().await.unwrap();
        let id = handoff
            .lines()
            .next()
            .expect("the first process returned its minted key id");
        assert!(!id.is_empty());
        assert!(
            retry.to_string().contains(id),
            "the refusal names the key the first request made: {retry}"
        );
        let minted = store
            .identity()
            .list_keys()
            .await
            .unwrap()
            .into_iter()
            .filter(|key| key.name == "once")
            .count();
        assert_eq!(minted, 1, "exactly one key exists for one Idempotency-Key");
    }
    serving.abort();
    let _ = serving.await;
    println!("{WITNESS}");
}

#[tokio::test]
async fn an_idempotent_rotate_retried_after_a_restart_is_refused_not_rotated_twice() {
    const CHILD: &str = "BUSBAR_ADMIN_RESTART_2B7BD9ED5994";
    let Ok(phase) = std::env::var(CHILD) else {
        restart_phases(CHILD, true);
        return;
    };
    assert!(matches!(phase.as_str(), "first" | "restart"));
    let first = phase == "first";
    let directory = PathBuf::from(std::env::var_os(DIRECTORY).unwrap());
    let handoff = if first {
        Zeroizing::new(String::new())
    } else {
        receive_handoff()
    };
    let (app, _store, _book) = application(&directory, first).await;
    let gov = app
        .governance
        .as_ref()
        .expect("the fresh actual governance exists")
        .clone();
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serving = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let id = if first {
        let response = client
            .post(format!("http://{addr}/api/v1/admin/keys"))
            .header("x-admin-token", "admintok")
            .json(&serde_json::json!({"name": "rotated"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 201);
        let created: serde_json::Value = response.json().await.unwrap();
        created["id"].as_str().unwrap().to_string()
    } else {
        handoff
            .lines()
            .next()
            .expect("the first process returned its key id")
            .to_string()
    };
    assert!(!id.is_empty());
    let response = client
        .post(format!("http://{addr}/api/v1/admin/keys/{id}/rotate"))
        .header("x-admin-token", "admintok")
        .header("idempotency-key", "restart-rotate")
        .send()
        .await
        .unwrap();
    if first {
        assert_eq!(response.status().as_u16(), 200);
        let rotated: serde_json::Value = response.json().await.unwrap();
        send_handoff(
            &id,
            Some(
                rotated["token"]
                    .as_str()
                    .expect("the rotate hands out a token"),
            ),
        );
    } else {
        assert_eq!(
            response.status().as_u16(),
            409,
            "a retry after a process restart must not rotate again"
        );
        let token = handoff
            .lines()
            .nth(1)
            .expect("the first rotate returned its token through the private pipe");
        assert!(!token.is_empty());
        let got = client
            .get(format!("http://{addr}/api/v1/admin/keys/{id}"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        assert_eq!(got.status().as_u16(), 200);
        assert!(
            gov.verify_token(token, busbar_kernel::store::now(), None)
                .is_some(),
            "the first rotate's token still authenticates: no second rotate ran"
        );
    }
    serving.abort();
    let _ = serving.await;
    println!("{WITNESS}");
}
