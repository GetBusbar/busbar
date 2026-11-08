// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Explicit creation of a real durable namespace for subprocess protocol fixtures.
//! A Memory Store cannot carry a cold CLI baseline into the later stdio process.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CREATION_FILE: &str = "principal-namespace-creation.json";
const STORE_FILE: &str = "principal-fixture-store.json";
const SCHEMA: &str = "test.fixture.principal-creation";
const WITNESS_KEY: &[u8] = b"namespace";

/// Stage the qualified actual Store through the same signed, pinned archive path as boot.
/// Exclusive file creation precedes every Store open and is retained as creation provenance.
pub fn stage(directory: &Path) {
    let library = super::plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library)
        .expect("the qualified actual Store statement reads")
        .expect("the qualified actual Store states its door");
    let facts = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the qualified actual Store statement parses");
    let mut manifest =
        super::plugins::manifest("store", &facts.name, super::plugins::FIXTURE_PUBLISHER);
    manifest.version = facts.version;
    manifest.statement = Some(hex::encode(statement));
    let image = std::fs::read(&library).expect("the qualified actual Store image reads");
    let archive =
        super::plugins::signed(&super::credentials::harness_release_key(), manifest, &image);
    std::fs::write(directory.join("plugins/principal-store.tar.gz"), archive)
        .expect("stage the signed actual Store archive");
    let settings = super::plugins::application_store_settings(directory);
    let database = PathBuf::from(
        settings["db_path"]
            .as_str()
            .expect("the actual SQLite settings select a database path"),
    );
    assert_eq!(
        database,
        directory.join("application.sqlite"),
        "exclusive creation and the actual application Store settings name the same database"
    );
    for suffix in ["application.sqlite-wal", "application.sqlite-shm"] {
        assert!(
            !directory.join(suffix).exists(),
            "no retained Store sidecar"
        );
    }
    drop(
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&database)
            .expect("the fixture exclusively creates its new database before any Store open"),
    );
    let creation = serde_json::json!({
        "database": database,
        "creation": "exclusive create_new before first Store open",
        "fixture": directory,
        "library": library,
        "library_sha256": super::plugins::sha256(&image),
        "sender_quiesced": true,
        "backend_quiesced": true,
    });
    std::fs::write(
        directory.join(CREATION_FILE),
        serde_json::to_vec(&creation).expect("creation provenance serializes"),
    )
    .expect("retain genuine namespace creation provenance");
    std::fs::write(
        directory.join(STORE_FILE),
        serde_json::to_vec(&serde_json::json!({
            "module": facts.name,
            "settings": settings,
        }))
        .expect("actual Store selection serializes"),
    )
    .expect("retain the actual fixture Store selection");
}

pub fn selection(directory: &Path) -> Option<serde_json::Value> {
    let path = directory.join(STORE_FILE);
    path.exists().then(|| {
        serde_json::from_slice(&std::fs::read(path).expect("fixture Store selection reads"))
            .expect("fixture Store selection parses")
    })
}

fn clone_command(command: &Command) -> Command {
    let mut cloned = Command::new(command.get_program());
    cloned.args(command.get_args());
    for (name, value) in command.get_envs() {
        match value {
            Some(value) => cloned.env(name, value),
            None => cloned.env_remove(name),
        };
    }
    if let Some(directory) = command.get_current_dir() {
        cloned.current_dir(directory);
    }
    cloned
}

fn command_output(mut command: Command) -> Output {
    use std::io::Read as _;
    let mut child = super::boot::Reap(
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run the actual product principal lifecycle CLI"),
    );
    let mut stdout = child.stdout.take().expect("CLI stdout is captured");
    let mut stderr = child.stderr.take().expect("CLI stderr is captured");
    let out = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let err = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).unwrap();
        bytes
    });
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().expect("inspect CLI completion") {
            break status;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            child.kill().expect("stop the bounded CLI");
            break child.wait().expect("reap the bounded CLI");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = out.join().expect("CLI stdout reader completes");
    let stderr = err.join().expect("CLI stderr reader completes");
    assert!(
        !timed_out,
        "actual principal CLI exceeded its bound: stdout={} stderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    Output {
        status,
        stdout,
        stderr,
    }
}

fn run(command: &Command, input: &Path, action: &str, directory: &Path) -> serde_json::Value {
    let mut child = clone_command(command);
    child
        .args([
            "--principal-transition",
            input.to_str().expect("fixture path is UTF-8"),
        ])
        .args(["--transition-action", action]);
    let output = command_output(child);
    let evidence = directory.join("principal-setup");
    std::fs::create_dir_all(&evidence).expect("principal setup evidence directory");
    static OBSERVATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let ordinal = OBSERVATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::fs::write(
        evidence.join(format!("{ordinal}-{action}.stdout")),
        &output.stdout,
    )
    .unwrap();
    std::fs::write(
        evidence.join(format!("{ordinal}-{action}.stderr")),
        &output.stderr,
    )
    .unwrap();
    assert!(
        output.status.success(),
        "actual principal {action} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    serde_json::from_slice(&output.stdout).expect("actual principal CLI report is JSON")
}

/// Initialize only the namespace this fixture just created, then prove the actual durable head.
/// No provider identity, grants or baseline bytes are fabricated by the fixture.
pub fn initialize(directory: &Path, command: &Command) -> Result<serde_json::Value, String> {
    use busbar_contract::persistence::axis::{PersistenceAxis as _, StoreDoor};
    let before = run(command, Path::new("-"), "inspect", directory);
    if !before["principal_receipt_head_sha256"].is_null() {
        return Err("a retained namespace cannot be presented as freshly created".into());
    }
    assert_eq!(
        before["store_ephemeral"], false,
        "the actual Store must retain a cold baseline"
    );
    let required = before["requirements"]
        .as_array()
        .expect("actual principal inventory is an array");
    assert!(
        !required.is_empty(),
        "the actual auth providers declare their principal formats"
    );
    let creation = std::fs::read(directory.join(CREATION_FILE)).expect("creation provenance reads");
    let provenance: serde_json::Value = serde_json::from_slice(&creation).unwrap();
    let library = PathBuf::from(
        provenance["library"]
            .as_str()
            .expect("actual Store image path"),
    );
    let image = std::fs::read(&library).expect("the same actual Store image reads");
    assert_eq!(provenance["library_sha256"], super::plugins::sha256(&image));
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library)
        .expect("actual Store statement reads")
        .expect("actual Store states its door");
    let dispatcher = Arc::new(busbar_plugin_loader::dispatch::Dispatcher::new(
        busbar_plugin_loader::dispatch::DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    let axis = busbar_plugin_loader::store_v4::DoorPersistenceAxis {
        dispatcher,
        logs: busbar_plugin_loader::dispatch::PluginLogConfig::from_words(
            None,
            None,
            &Default::default(),
            None,
            None,
        )
        .expect("ordinary Store log defaults"),
        conns: busbar_plugin_loader::dispatch::ConnTable::NoNeeds,
        limits: busbar_plugin_loader::store_v4::Limits {
            descriptor_bytes: 32 * 1024 * 1024,
            output_items: 4096,
            output_bytes: 32 * 1024 * 1024,
            decode_bytes: 32 * 1024 * 1024,
        },
    };
    let witness = super::plugins::sha256(&creation).into_bytes();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("the isolated witness writer runtime")
        .block_on(async {
            let backend = axis
                .open(
                    StoreDoor::Dropped {
                        file: library.display().to_string(),
                        bytes: Arc::new(image),
                        stated: statement,
                    },
                    "stdio-fixture-creation-witness",
                    &serde_json::to_vec(&super::plugins::application_store_settings(directory))
                        .unwrap(),
                )
                .await
                .expect("the actual durable Store opens through its native door");
            assert_ne!(
                backend.info().durability,
                busbar_contract::persistence::Durability::Ephemeral
            );
            let mut startup = busbar_kernel::persistence::startup::Startup::new(
                backend,
                busbar_kernel::persistence::facade::Limits {
                    pending_operations: 1024,
                    conflict_retries: 8,
                    scan_items: 128,
                    scan_bytes: 1024 * 1024,
                },
                true,
            )
            .expect("native witness storage authority");
            loop {
                use busbar_kernel::persistence::startup::Progress;
                match startup
                    .advance()
                    .await
                    .expect("admit native witness writer")
                {
                    Progress::Advanced => {}
                    Progress::Admitted => break,
                    other => panic!("witness writer not admitted: {other:?}"),
                }
            }
            let owner = busbar_kernel::persistence::scoped::ScopedStore::host_private(
                startup.store().expect("admitted witness Store"),
                "busbar.fixture.principal-creation",
                [SCHEMA.into()],
            )
            .expect("private creation-witness owner");
            assert_eq!(
                owner
                    .put(
                        SCHEMA,
                        WITNESS_KEY,
                        busbar_contract::Secret::new(witness.clone())
                    )
                    .await
                    .expect("native creation-witness commit"),
                busbar_kernel::persistence::scoped::Outcome::Applied
            );
        });
    drop(axis);
    let receipt = serde_json::json!({
        "version": 2,
        "witness_binding": {"instance": "busbar.fixture.principal-creation", "private": true,
                            "source_scope": "unscoped"},
        "store_config_sha256": before["store_config_sha256"],
        "requirements": before["requirements"],
        "witness": {"schema": SCHEMA, "key_hex": hex::encode(WITNESS_KEY),
                    "value_hex": hex::encode(witness)},
        "ephemeral_instance": false,
        "exclusive_instance": false,
        "creation_evidence_sha256": super::plugins::sha256(&creation),
        "newly_created_namespace": true,
        "sender_quiesced": true,
        "backend_quiesced": true,
        "actor": "isolated stdio fixture namespace provisioner",
        "reason": "exclusive new database file; no application senders started; actual creation witness committed before real cold initialization",
    });
    let receipt_path = directory.join("principal-fresh.json");
    std::fs::write(&receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();
    run(command, &receipt_path, "initialize-fresh", directory);
    let after = run(command, Path::new("-"), "inspect", directory);
    assert!(
        after["principal_receipt_head_sha256"].is_string(),
        "real initialized head survives a separate CLI process"
    );
    assert_eq!(after["store_config_sha256"], before["store_config_sha256"]);
    assert_eq!(after["requirements"], before["requirements"]);
    Ok(after)
}
