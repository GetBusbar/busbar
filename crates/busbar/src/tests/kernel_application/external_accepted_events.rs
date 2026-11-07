// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Actual SQLite acceptance/recovery controls. The four production exporters do

use busbar_contract::plugin::Kind;
use busbar_contract::records::PlaneSelector;
use busbar_kernel::audit::auditlog::{
    emit_admin_hostless_now, plugin_refusal_resource, record_plugin_refusal, PluginRefusal,
    AUDIT_LOG,
};
use busbar_kernel::audit_ring::OUTCOME_APPLIED;
use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::root::test_plugins as plugins;

static ACCEPTED: AtomicUsize = AtomicUsize::new(0);
fn accepted(entry: &busbar_kernel::audit_ring::AuditEntry) {
    if entry.resource.starts_with("actual-accepted:") {
        assert!(
            AUDIT_LOG
                .list_filtered(0, 10, None, Some(&entry.resource))
                .iter()
                .any(|accepted| accepted.seq == entry.seq),
            "the accepted ring is visible before the producer observer"
        );
        ACCEPTED.fetch_add(1, Ordering::SeqCst);
    }
}

struct WriterLock(std::process::Child);
impl WriterLock {
    fn acquire(database: &Path) -> Self {
        let mut child = std::process::Command::new("python3")
            .args(["-u", "-c", "import sqlite3,sys\nc=sqlite3.connect(sys.argv[1],timeout=0)\nc.execute('BEGIN IMMEDIATE')\nprint('writer-held',flush=True)\nsys.stdin.readline()\nc.rollback()\nc.close()"])
            .arg(database)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn().expect("hold the actual SQLite database writer lock");
        let mut witness = String::new();
        std::io::BufReader::new(child.stdout.take().expect("SQLite control stdout"))
            .read_line(&mut witness)
            .expect("read the SQLite lock witness");
        assert_eq!(witness.trim(), "writer-held");
        Self(child)
    }
}
impl Drop for WriterLock {
    fn drop(&mut self) {
        if let Some(mut input) = self.0.stdin.take() {
            input
                .write_all(b"release\n")
                .expect("release the actual SQLite writer lock");
        }
        assert!(self
            .0
            .wait()
            .expect("wait for SQLite lock control")
            .success());
    }
}

#[tokio::test]
async fn accepted_audit_records_recover_once_on_actual_sqlite_and_hydration_does_not_accept_them_again(
) {
    const CHILD: &str = "BUSBAR_ACTUAL_ACCEPTED_EVENTS_CHILD";
    const WITNESS: &str = "actual SQLite accepted-event controls completed";
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
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory = plugins::scratch(&format!(
        "actual-accepted-events-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let library = std::fs::read(&library_path).expect("read actual SQLite library");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("sqlite.tar.gz"), archive)
        .expect("stage signed actual SQLite product");
    let database = directory.join("accepted.sqlite3");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {}, "auth": {"chain": [], "admin_auth": []},
        "store": {"module": module, "settings": {"db_path": database, "busy_timeout_ms": 0}}
    }))
    .expect("actual SQLite deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("actual deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
        .await
        .expect("actual Store config authority");
    let anchor = crate::root::real_store::core_over(anchor).await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
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
    .await
    .expect("normal actual SQLite root builds");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("same SQLite Store books the root before activation");
    limits.keep().await.expect("actual root limits activate");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let app = Arc::new(app);
    busbar_kernel::boot::hydrate_all(&app)
        .await
        .expect("actual root audit hydration");
    busbar_kernel::audit::auditlog::install_accepted_entry_test_hook(accepted);
    let store = app
        .governance
        .as_ref()
        .expect("normal root has governance")
        .core_store_handle()
        .expect("actual native Store");
    busbar_kernel::audit::auditlog::register_test_audit_stream(&app).await;
    let emit = |resource| async move {
        emit_admin_hostless_now("config.mutate", resource, OUTCOME_APPLIED, "admin");
        let _ = busbar_kernel::audit::auditlog::flush_pending().await;
    };
    let rows = |resource| AUDIT_LOG.list_filtered(0, 10, None, Some(resource));
    emit("actual-accepted:first").await;
    assert_eq!(
        rows("actual-accepted:first").len(),
        1,
        "one mutation is accepted once"
    );
    assert_eq!(
        ACCEPTED.load(Ordering::SeqCst),
        1,
        "ring acceptance happens once"
    );
    let failure_resource = plugin_refusal_resource(
        Kind::Export.root(),
        "actual-accepted-failure",
        "delivery-failed",
    );
    {
        let _lock = WriterLock::acquire(&database);
        std::thread::spawn(|| {
            record_plugin_refusal(
                PluginRefusal::Op,
                Kind::Export.root(),
                "actual-accepted-failure",
                "delivery-failed",
            )
        })
        .join()
        .expect("asynchronous host export-refusal record completes");
        assert!(
            busbar_kernel::audit::auditlog::flush_pending()
                .await
                .is_err(),
            "the locked Store refuses the actual native append"
        );
        assert!(
            rows(&failure_resource).is_empty(),
            "failed append has not entered the accepted ring"
        );
    }
    emit("actual-accepted:failure-recovery").await;
    let failure = rows(&failure_resource);
    assert_eq!(
        failure.len(),
        1,
        "asynchronous refusal is recovered into the audit chain once"
    );
    let durable = busbar_kernel::host_records_async::AsyncHistory::authorized(
        store,
        busbar_kernel::audit::auditlog::PERSISTENCE_OWNER,
        [busbar_kernel::host_records_async::HistoryCollection {
            kind: busbar_kernel::store::plane_view::KIND_AUDIT,
            mode: busbar_kernel::host_records_async::HistoryMode::Append,
            retention: busbar_contract::records::Retention::Age,
            parent: None,
        }],
    )
    .expect("actual core audit collection")
    .list(
        busbar_kernel::store::plane_view::KIND_AUDIT,
        &PlaneSelector::All,
    )
    .await
    .expect("read actual durable audit records");
    assert!(
        durable.iter().any(|body| {
            let stored: busbar_kernel::audit::journal::NeutralBody =
                serde_json::from_slice(&body.body)
                    .expect("the actual persisted audit record decodes");
            stored.seq == failure[0].seq
                && stored.hash == failure[0].hash
                && String::from_utf8_lossy(&stored.content).contains(&failure_resource)
        }),
        "the asynchronous refusal is durably appended"
    );
    emit_admin_hostless_now(
        PluginRefusal::Op.action(),
        &failure_resource,
        OUTCOME_APPLIED,
        "admin",
    );
    busbar_kernel::audit::auditlog::flush_pending()
        .await
        .unwrap();
    assert_eq!(
        rows(&failure_resource).len(),
        2,
        "ordinary identical resource text remains a separate accepted mutation"
    );
    let auth_resource = plugin_refusal_resource(
        Kind::Auth.root(),
        "actual-accepted-failure",
        "delivery-failed",
    );
    record_plugin_refusal(
        PluginRefusal::Op,
        Kind::Auth.root(),
        "actual-accepted-failure",
        "delivery-failed",
    );
    busbar_kernel::audit::auditlog::flush_pending()
        .await
        .unwrap();
    assert_eq!(
        rows(&auth_resource).len(),
        1,
        "non-export refusal remains an accepted producer"
    );
    {
        let _lock = WriterLock::acquire(&database);
        emit("actual-accepted:queued").await;
        assert!(
            rows("actual-accepted:queued").is_empty(),
            "Store outage has not accepted the pending record"
        );
    }
    emit("actual-accepted:recovered").await;
    let queued = rows("actual-accepted:queued");
    let recovered = rows("actual-accepted:recovered");
    assert_eq!(queued.len(), 1, "recovered queued record is accepted once");
    assert_eq!(recovered.len(), 1, "recovery trigger is accepted once");
    assert_eq!(
        recovered[0].seq,
        queued[0].seq + 1,
        "recovery preserves contiguous order"
    );
    let before = ACCEPTED.load(Ordering::SeqCst);
    busbar_kernel::boot::hydrate_all(&app)
        .await
        .expect("rehydrate actual accepted records");
    assert_eq!(
        ACCEPTED.load(Ordering::SeqCst),
        before,
        "restored records are not accepted again, so hydration cannot redispatch them"
    );
    assert_eq!(
        rows("actual-accepted:queued").len(),
        1,
        "restore does not duplicate the accepted ring entry"
    );
    println!("{WITNESS}");
}
