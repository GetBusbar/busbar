// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W2-SW-STORE (ABI-MIN3-WBS switch-over 5 of 7, IF §11.3, §12.10, WBS rule 12): the store kind boots through
//! the MIN-3 path, the store adapter (`PersistenceBackend` over the proxy, `StoreLane` for a blocking-file store)
//! opened by `Registry::open_store`, and nothing of the old store ABI remains.
//!
//! The real binary over a dropped-in store-sqlite:
//! 1. A stamped config whose store bag still has the 1.5.5 shape (store-sqlite's obsolete `license_key`) boots:
//!    the store converts the bag in its own `open` (no `migrate` call), the seam writes the settled bag back
//!    (step 5W), and a second boot reads one marker and writes nothing.
//! 2. A reload whose new store bag the store's `open` refuses fails that instance only: the old instance keeps
//!    serving and config.yaml is not rewritten.
//! 3. store-postgres boots through the same path (needs a reachable server: `BUSBAR_TEST_POSTGRES_URL`).
//!
//! And the source of every crate carries no reference to the old store ABI (the switch-over's done rule).

#![cfg(unix)]

mod common;

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

const ADMIN_TOKEN: &str = "store-min3-switch-admin";
const OBSOLETE_ENV: &str = "SQLITE_OBSOLETE_LICENSE_SENTINEL";
const BOOT: Duration = Duration::from_secs(30);

fn fixture_dir(tag: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-store-min3-{tag}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("plugins")).unwrap();
    std::fs::write(dir.join("providers.yaml"), "{}\n").unwrap();
    dir
}

/// A stamped (`config_version: 1`) config over `store`, with the admin token the reload uses.
fn write_config(dir: &Path, data: u16, admin: u16, store: &serde_json::Value) {
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            "config_version: 1\nlisten: \"127.0.0.1:{data}\"\nadmin_listen: \"127.0.0.1:{admin}\"\n\
             admin_require_mtls: false\nplugins: {plugins}\nstore: {store}\n\
             identity-providers:\n  admin-tokens:\n    module: admin-tokens\n    settings:\n      \
             token: {{ env: BUSBAR_ADMIN_TOKEN }}\n\
             auth:\n  chain: []\n  admin_auth: [admin-tokens]\nproviders: {{}}\nmodels: {{}}\n",
            plugins = common::plugins::trusted_config_document(&dir.join("plugins")),
        ),
    )
    .unwrap();
}

/// The staged store-sqlite selection with its bag in the 1.5.5 shape: the obsolete `license_key` beside the
/// current settings, as a 1.5.5 operator left it.
fn sqlite_store_1_5_5(dir: &Path) -> serde_json::Value {
    common::fresh_namespace::stage(dir);
    let mut store = common::fresh_namespace::selection(dir).expect("the staged Store selection");
    store["settings"]["license_key"] = serde_json::json!({ "env": OBSOLETE_ENV });
    store
}

fn read(path: &Path) -> String {
    let mut text = String::new();
    if let Ok(mut file) = std::fs::File::open(path) {
        let _ = file.read_to_string(&mut text);
    }
    text
}

struct Node {
    child: common::boot::Reap,
    log: PathBuf,
}

impl Node {
    fn boot(dir: &Path, name: &str) -> Self {
        let log = dir.join(format!("{name}.log"));
        let out = std::fs::File::create(&log).unwrap();
        let child = Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
            .env(OBSOLETE_ENV, "unused-by-sqlite")
            .env("RUST_LOG", "info")
            .env(
                common::credentials::HARNESS_FIRST_PARTY_KEY_ENV,
                common::credentials::harness_release_key_hex(),
            )
            .stdin(Stdio::null())
            .stdout(out.try_clone().unwrap())
            .stderr(out)
            .spawn()
            .expect("spawn busbar");
        let mut node = Self {
            child: common::boot::Reap(child),
            log,
        };
        let deadline = Instant::now() + BOOT;
        while !common::boot::log_shows_data_and_admin_listening(&node.text()) {
            if let Some(status) = node.child.try_wait().expect("try_wait") {
                panic!("busbar exited ({status}):\n{}", node.text());
            }
            assert!(
                Instant::now() < deadline,
                "busbar did not listen:\n{}",
                node.text()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        node
    }

    fn text(&self) -> String {
        read(&self.log)
    }

    fn stop(mut self) -> String {
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(self.child.id().to_string())
            .status();
        let deadline = Instant::now() + BOOT;
        while self.child.try_wait().expect("try_wait").is_none() {
            assert!(
                Instant::now() < deadline,
                "busbar did not stop:\n{}",
                self.text()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        self.text()
    }
}

fn store_settings(config: &Path) -> serde_json::Value {
    let doc: serde_json::Value =
        busbar_contract::yaml::from_str(&std::fs::read_to_string(config).unwrap())
            .expect("config.yaml parses");
    doc["store"]["settings"].clone()
}

fn written(config: &Path) -> (Vec<u8>, SystemTime) {
    (
        std::fs::read(config).unwrap(),
        std::fs::metadata(config).unwrap().modified().unwrap(),
    )
}

fn reload(admin: u16) -> (u16, String) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let answer = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("client")
            .post(format!(
                "http://127.0.0.1:{admin}/api/v1/admin/config/reload"
            ))
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {ADMIN_TOKEN}"),
            )
            .send()
            .await
            .expect("reload request");
        let status = answer.status().as_u16();
        (status, answer.text().await.unwrap_or_default())
    })
}

#[test]
fn a_1_5_5_store_bag_converts_in_open_and_the_second_boot_writes_nothing() {
    let dir = fixture_dir("convert");
    let (data, admin) = (common::boot::free_port(), common::boot::free_port());
    let store = sqlite_store_1_5_5(&dir);
    write_config(&dir, data, admin, &store);
    let config = dir.join("config.yaml");

    let first = Node::boot(&dir, "first");
    assert!(common::boot::healthz_answers(data), "{}", first.text());
    let log = first.stop();
    let settled = store_settings(&config);
    assert!(
        settled.get("license_key").is_none(),
        "the store's open settled its bag without the obsolete field and the boot wrote it back: \
         {settled}\n{log}"
    );
    let mut expected = store["settings"].clone();
    expected.as_object_mut().unwrap().remove("license_key");
    assert_eq!(
        settled, expected,
        "only the obsolete field left the bag; every other setting is as the operator wrote it"
    );

    let before = written(&config);
    let second = Node::boot(&dir, "second");
    assert!(common::boot::healthz_answers(data), "{}", second.text());
    let log = second.stop();
    assert_eq!(
        written(&config),
        before,
        "a current bag is one marker read: the second boot writes nothing\n{log}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_refused_reload_open_leaves_the_old_store_instance_serving() {
    let dir = fixture_dir("reload");
    let (data, admin) = (common::boot::free_port(), common::boot::free_port());
    let mut store = sqlite_store_1_5_5(&dir);
    store["settings"]
        .as_object_mut()
        .unwrap()
        .remove("license_key");
    write_config(&dir, data, admin, &store);
    let config = dir.join("config.yaml");
    let node = Node::boot(&dir, "serving");

    // The new bag names a database under a directory that is a regular file: store-sqlite's open refuses it.
    let blocker = dir.join("not-a-directory");
    std::fs::write(&blocker, b"").unwrap();
    let mut refused = store.clone();
    refused["settings"]["db_path"] = serde_json::json!(blocker.join("refused.sqlite"));
    write_config(&dir, data, admin, &refused);
    let before = written(&config);

    let (status, body) = reload(admin);
    assert!(
        !(200..300).contains(&status),
        "the refused store open fails the reload: {status} {body}\n{}",
        node.text()
    );
    assert!(
        common::boot::healthz_answers(data),
        "the old store instance keeps serving after the refused reload\n{}",
        node.text()
    );
    assert_eq!(
        written(&config),
        before,
        "a refused open writes no settled bag back"
    );
    assert!(
        !blocker.with_file_name("refused.sqlite").exists(),
        "the refused open created no database"
    );
    let _ = node.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "needs a reachable PostgreSQL server: set BUSBAR_TEST_POSTGRES_URL"]
fn store_postgres_boots_through_the_min3_path() {
    let url = std::env::var("BUSBAR_TEST_POSTGRES_URL").expect("BUSBAR_TEST_POSTGRES_URL");
    let dir = fixture_dir("postgres");
    let (data, admin) = (common::boot::free_port(), common::boot::free_port());
    let store = serde_json::json!({ "module": "postgres", "settings": { "url": url } });
    write_config(&dir, data, admin, &store);
    let config = dir.join("config.yaml");
    let node = Node::boot(&dir, "postgres");
    assert!(common::boot::healthz_answers(data), "{}", node.text());
    let before = written(&config);
    let log = node.stop();
    let again = Node::boot(&dir, "postgres-again");
    let _ = again.stop();
    assert_eq!(
        written(&config),
        before,
        "a current bag is never rewritten\n{log}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Every old store ABI name the switch-over deletes (WBS W2-SW-STORE "no old store ABI reference").
const OLD_STORE_ABI: &[&str] = &[
    "abi::store::",
    "abi::sdk::store",
    "sdk::store::",
    "store_v4",
    "StoreV4",
    "admit_recoverable",
    "DoorPersistenceAxis",
    "LoadedPersistence",
];

fn scan(dir: &Path, hits: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if name == "target" || name == ".git" {
            continue;
        }
        if path.is_dir() {
            scan(&path, hits);
        } else if path.extension().is_some_and(|ext| ext == "rs")
            && name != "store_boots_through_min3.rs"
        {
            let text = read(&path);
            for word in OLD_STORE_ABI {
                if let Some(line) = text.lines().position(|line| line.contains(word)) {
                    hits.push(format!("{}:{}: {word}", path.display(), line + 1));
                }
            }
        }
    }
}

#[test]
fn no_old_store_abi_reference_remains() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut hits = Vec::new();
    for top in ["crates", "tools", "dist"] {
        scan(&root.join(top), &mut hits);
    }
    assert!(
        hits.is_empty(),
        "the old store ABI is still referenced:\n{}",
        hits.join("\n")
    );
}
