// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_core_admin::v1::json::credential_flush_response_for_test as credential_flush_response;
use busbar_kernel::audit_ring;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

static ACCEPTED: Mutex<Option<tokio::sync::mpsc::UnboundedSender<audit_ring::AuditEntry>>> =
    Mutex::new(None);

fn accepted(entry: &audit_ring::AuditEntry) {
    if entry.action == "auth.cache_flush" && entry.principal.starts_with("flush-projection:") {
        if let Some(sender) = &*ACCEPTED.lock().unwrap() {
            let _ = sender.send(entry.clone());
        }
    }
}

#[test]
fn completed_refresh_answers_project_truthful_status_body_and_audit() {
    const CHILD: &str = "BUSBAR_ACTUAL_FLUSH_RESPONSE_CHILD";
    const WITNESS: &str = "actual SQLite flush-response controls completed";
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
            .expect("the test has an exact name")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start isolated actual root"),
        );
        let until = Instant::now() + Duration::from_secs(90);
        loop {
            if let Some(status) = child.0.try_wait().expect("poll actual root") {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(status.success(), "actual root failed: {status}: {output}");
                assert!(
                    output.contains(WITNESS),
                    "exact child did not complete: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "actual SQLite acceptance control timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    busbar_kernel::snapshot::init_for_test(Duration::from_secs(3600));
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_TEST_SQLITE_CDYLIB")
            .expect("BUSBAR_TEST_SQLITE_CDYLIB names the actual built SQLite product"),
    );
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("read actual SQLite statement")
        .expect("SQLite exports a statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("valid actual SQLite statement")
        .name;
    assert_eq!(module, "busbar-store-sqlite");
    let mut manifest = plugins::manifest("store", &module, "third-party");
    manifest.statement = Some(hex::encode(statement));
    let directory = plugins::scratch(&format!(
        "actual-flush-response-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let library = std::fs::read(&library_path).expect("read actual SQLite library");
    let archive = plugins::signed(&plugins::key(0x33), manifest, &library);
    let archive_sha256 = busbar_plugin_loader::sign::sha256_hex(&archive);
    std::fs::write(directory.join("sqlite.tar.gz"), archive)
        .expect("stage signed actual SQLite product");
    let database = directory.join("flush-response.sqlite3");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {}, "auth": {"chain": [], "admin_auth": []},
        "store": {"module": module, "settings": {"db_path": database, "busy_timeout_ms": 0}}
    }))
    .expect("actual SQLite deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("actual deployment resolves");
    let mut plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        fetch: vec![busbar_kernel::config::PluginFetch::Url(
            busbar_kernel::config::UrlFetch {
                url: "https://plugins.invalid/sqlite.tar.gz".into(),
                sha256: Some(archive_sha256),
            },
        )],
        ..Default::default()
    };
    plugin_config
        .trust
        .publishers
        .push(busbar_kernel::config::PluginPublisher {
            name: "third-party".into(),
            public_key: hex::encode(plugins::key(0x33).verifying_key().as_bytes()),
        });
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .expect("actual Store config authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::new(
        anchor
            .calls
            .as_ref()
            .cloned()
            .expect("actual typed Store calls"),
    )
    .expect("actual conditional config records");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .expect("normal actual SQLite root builds");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("same SQLite Store books the root before activation");
    limits.keep().expect("actual root limits activate");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    busbar_kernel::boot::hydrate_all(&app).expect("actual root audit hydration");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("response body runtime");
    runtime.block_on(async {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        *ACCEPTED.lock().unwrap() = Some(sender);
        busbar_kernel::audit::auditlog::install_accepted_entry_test_hook(accepted);
        for (actor, result, module, status, outcome) in [
            (
                "flush-projection:admin-refused",
                Err("private-refresh-error-token".into()),
                None,
                500,
                audit_ring::OUTCOME_REJECTED,
            ),
            (
                "flush-projection:data-refused",
                Err("private-refresh-error-token".into()),
                None,
                500,
                audit_ring::OUTCOME_REJECTED,
            ),
            (
                "flush-projection:filtered",
                Ok(8),
                Some("target"),
                200,
                audit_ring::OUTCOME_APPLIED,
            ),
            (
                "flush-projection:absent",
                Ok(0),
                Some("not-configured"),
                200,
                audit_ring::OUTCOME_APPLIED,
            ),
        ] {
            let response = credential_flush_response(result, module, actor);
            assert_eq!(response.status().as_u16(), status);
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains("private-refresh-error-token"));
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            if status == 500 {
                assert_eq!(body["error"]["code"], "internal");
                assert!(
                    body.get("flushed").is_none(),
                    "partial progress is not a successful flush"
                );
            } else {
                assert_eq!(
                    body["flushed"],
                    if module == Some("target") { 8 } else { 0 }
                );
            }
            let row = tokio::time::timeout(std::time::Duration::from_secs(5), receiver.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.principal, actor);
            assert_eq!(row.resource, module.unwrap_or("*"));
            assert_eq!(row.outcome, outcome);
            let outcomes: Vec<_> = busbar_kernel::audit::auditlog::AUDIT_LOG
                .list_filtered(
                    0,
                    audit_ring::MAX_AUDIT_ENTRIES,
                    Some("auth.cache_flush"),
                    None,
                )
                .into_iter()
                .filter(|entry| entry.principal == actor)
                .map(|entry| entry.outcome)
                .collect();
            assert_eq!(
                outcomes,
                vec![outcome],
                "each flush records exactly one outcome"
            );
        }
        *ACCEPTED.lock().unwrap() = None;
    });
    println!("{WITNESS}");
}
