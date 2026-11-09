// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Normal-command upgrade of the exact published-writer SQLite fixture. The
//! recorder runs the pinned native release and supplies its own provenance and rows.
//! No migration command, source export, fence helper or preinitialized App runs.
#![cfg(unix)]

use std::{
    io,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command},
    time::{Duration, Instant},
};

use busbar_plugin_loader::sign::{Manifest, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const ADMIN: &str = "released-sqlite-startup-admin";
// Native CI records new keys and timestamps on each invocation. Pin the writer
// and recorder, then verify the actual transcript's files rather than one old DB.
const RECORDER: &str = "83acfa89d93afda0e3c319a1d17c246d5e933e7a";

fn released_source(fixture: &Path) -> io::Result<(Vec<u8>, Value)> {
    let manifest = std::fs::read_to_string(fixture.join("MANIFEST.tsv"))?;
    let mut rows = std::collections::BTreeMap::new();
    let mut files = std::collections::BTreeSet::new();
    for line in manifest.lines().filter(|line| !line.starts_with('#')) {
        let (kind, value) = line.split_once('\t').expect("manifest TSV row");
        if kind == "file" {
            let (name, digest) = value.split_once(' ').expect("manifest file digest");
            assert!(Path::new(name)
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_))));
            assert!(files.insert(name), "duplicate fixture file");
            assert_eq!(
                hex::encode(Sha256::digest(std::fs::read(fixture.join(name))?)),
                digest,
                "released fixture file changed: {name}"
            );
        } else {
            assert!(
                rows.insert(kind, value).is_none(),
                "duplicate provenance row"
            );
        }
    }
    assert_eq!(rows["backend"], "sqlite");
    assert_eq!(rows["recorder"], RECORDER);
    assert_eq!(rows["requests"], "200 200 200 503 200 200 ");
    let writer: Vec<_> = rows["busbar"].split_whitespace().collect();
    assert_eq!(writer.len(), 3);
    assert_eq!(writer[0], "v1.5.5");
    let triple = writer[1]
        .strip_prefix("busbar-")
        .expect("published busbar asset");
    assert!(
        include_str!("../../../testing/shadow-oracle/golden-digests.tsv")
            .lines()
            .any(|line| line == format!("1.5.5\t{}\t{}", writer[1], writer[2]))
    );
    let plugin = rows["plugin"];
    assert!(
        include_str!("../../../testing/shadow-oracle/plugin-digests.tsv")
            .lines()
            .any(|line| line == format!("store-sqlite\t{}", plugin.replace(' ', "\t")))
    );
    assert!(plugin.starts_with(&format!(
        "v1.0.6 busbar-store-sqlite-1.0.6-{triple}.tar.gz "
    )));
    for name in [
        "governance.db",
        "rows.json",
        "readback/usage.json",
        "readback/key-fixture-grouped.json",
        "readback/key-fixture-ungrouped.json",
    ] {
        assert!(
            files.contains(name),
            "missing released recorder output: {name}"
        );
    }
    let original = std::fs::read(fixture.join("governance.db"))?;
    let output = Command::new(std::env::var_os("BUSBAR_TEST_PYTHON").unwrap_or_else(|| "python3".into()))
        .args(["-I", "-c", r#"
import json,pathlib,sqlite3,sys
p=pathlib.Path(sys.argv[1]).resolve()
c=sqlite3.connect(p.as_uri()+'?mode=ro',uri=True)
assert c.execute('pragma user_version').fetchone()[0]==6
assert c.execute("select count(*) from sqlite_master where name='__busbar_upgrade'").fetchone()[0]==0
keys=c.execute('select id,name,key_group from keys order by name').fetchall()
assert len(keys)==2 and [(k[1],k[2]) for k in keys]==[('fixture-grouped','fixture'),('fixture-ungrouped',None)],keys
buckets=c.execute('select distinct bucket from usage_metering').fetchall()
assert len(buckets)==1,buckets
source=c.execute('select sum(requests),sum(billable_requests),sum(tokens_input),sum(tokens_output),sum(tokens_cache_read) from usage_metering').fetchone()
assert source==(5,5,47,35,8),source
assert set(k[0] for k in keys)==set(r[0] for r in c.execute('select distinct key_id from usage_metering'))
print(json.dumps({'keys':keys,'bucket':int(buckets[0][0])}))
"#]).arg(fixture.join("governance.db")).output()?;
    assert!(
        output.status.success(),
        "released SQLite observation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok((original, serde_json::from_slice(&output.stdout)?))
}

struct Workspace(PathBuf);
impl Drop for Workspace {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            std::fs::remove_dir_all(&self.0).expect("remove the successful startup fixture");
        }
    }
}
struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Server {
    async fn stop(&mut self) {
        assert!(Command::new("kill")
            .args(["-TERM", &self.0.id().to_string()])
            .status()
            .unwrap()
            .success());
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "normal graceful shutdown failed: {status}"
                );
                return;
            }
            assert!(
                Instant::now() < deadline,
                "normal graceful shutdown exceeded 30 seconds"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn snapshot(database: &Path) -> Value {
    // Read-only native observation, independent of the serving API. Legacy
    // user_version remains 6; the inactive/current primitive format is meta=1.
    let output = Command::new(std::env::var_os("BUSBAR_TEST_PYTHON").unwrap_or_else(|| "python3".into()))
        .args(["-I", "-c", r#"
import json,pathlib,sqlite3,sys
p=pathlib.Path(sys.argv[1]).resolve()
c=sqlite3.connect(p.as_uri()+'?mode=ro',uri=True)
u=c.execute('select version,source_physical,target_format,phase,hex(upgrade),hex(target),hex(activation),hex(completion) from __busbar_upgrade where id=1').fetchone()
assert u is not None and u[:4]==(1,6,1,2),u
assert u[6] and u[7],u
physical=c.execute("select hex(value) from meta where key='physical_format'").fetchone()[0]
assert physical=='01000000',physical
checkpoints=c.execute('select hex(key),hex(value) from records where namespace=? and key=?',(b'busbar.migrate1\0',bytes.fromhex(u[4]))).fetchall()
assert len(checkpoints)==1,len(checkpoints)
source=c.execute('select sum(requests),sum(billable_requests),sum(tokens_input),sum(tokens_output),sum(tokens_cache_read) from usage_metering').fetchone()
assert source==(5,5,47,35,8),source
print(json.dumps({'native':u,'physical':physical,'checkpoints':checkpoints,'source':source,'legacy_user_version':c.execute('pragma user_version').fetchone()[0]}))
"#])
        .arg(database)
        .output().expect("observe SQLite using the native read-only client");
    assert!(
        output.status.success(),
        "native migration observation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn stage_plugin(work: &Path) -> Value {
    let library = PathBuf::from(
        std::env::var_os("BUSBAR_TEST_SQLITE_CDYLIB")
            .expect("BUSBAR_TEST_SQLITE_CDYLIB is the current native SQLite Store image"),
    );
    assert!(library.is_absolute() && library.is_file());
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library)
        .unwrap()
        .expect("the actual SQLite image declares its door");
    let facts = busbar_contract::abi::mechanism::rendering::read(&statement).unwrap();
    assert_eq!(
        facts.kind,
        busbar_contract::abi::mechanism::KindCode::Store as u32
    );
    let image = std::fs::read(library).unwrap();
    let key = SigningKey::from_bytes(&[0x5a; 32]);
    let manifest = Manifest {
        name: facts.name.clone(),
        // The actual SQLite package's documented shipping alias (its
        // plugin/src/lib.rs and Cargo.toml), retained by the 1.5.5 recorder.
        alias: "sqlite".into(),
        kind: "store".into(),
        version: facts.version,
        publisher: "startup-fixture".into(),
        abi_version: facts.kind_abi,
        statement: Some(hex::encode(statement)),
        ..Default::default()
    };
    let archive = busbar_plugin_loader::tarball::package(
        &busbar_plugin_loader::sign::sign(&key, manifest, &image),
        "lib.so",
        &image,
    )
    .unwrap();
    std::fs::write(work.join("plugins/sqlite.tar.gz"), &archive).unwrap();
    json!({
        "enabled": true, "dir": work.join("plugins"),
        "fetch": [{"url":"https://startup-fixtures.invalid/sqlite.tar.gz", "sha256":hex::encode(Sha256::digest(&archive))}],
        "trust": {"allow_unsigned":false, "allow_third_party":true, "publishers":[{"name":"startup-fixture", "public_key":hex::encode(key.verifying_key().as_bytes())}]}
    })
}

fn boot(work: &Path, ordinal: u8) -> Server {
    let log = std::fs::File::create(work.join(format!("boot-{ordinal}.log"))).unwrap();
    Server(
        Command::new(env!("CARGO_BIN_EXE_busbar"))
            .current_dir(work)
            .env("BUSBAR_CONFIG", work.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", work.join("providers.yaml"))
            .env("BUSBAR_ADMIN_TOKEN", ADMIN)
            .env("FIXTURE_UPSTREAM_KEY", "unused-startup-fixture")
            .env(
                "BUSBAR_SIGNING_KEY",
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .env("RUST_LOG", "warn")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("run the actual assembled Busbar normally, without migration flags"),
    )
}

async fn ready(
    server: &mut Server,
    work: &Path,
    ordinal: u8,
    listen: u16,
    admin: u16,
    source: &Value,
) -> Value {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let status = server.0.try_wait().unwrap();
        assert!(
            status.is_none(),
            "normal startup exited {status:?}: {}",
            std::fs::read_to_string(work.join(format!("boot-{ordinal}.log"))).unwrap()
        );
        if let Ok(response) = client
            .get(format!("http://127.0.0.1:{listen}/healthz"))
            .send()
            .await
        {
            if response.status().is_success() {
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "normal startup did not become healthy: {}",
            std::fs::read_to_string(work.join(format!("boot-{ordinal}.log"))).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let usage = client
        .get(format!(
            "http://127.0.0.1:{admin}/api/v1/admin/usage?window={}",
            source["bucket"].as_i64().unwrap()
        ))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    let status = usage.status();
    let usage = usage.text().await.unwrap();
    assert!(
        status.is_success(),
        "healthy server's admin usage refused {status}: {usage}"
    );
    let usage: Value = serde_json::from_str(&usage).unwrap();
    assert_eq!(usage["total"]["requests"], 5);
    assert_eq!(usage["total"]["tokens_input"].as_f64(), Some(47.0));
    assert_eq!(usage["total"]["tokens_output"].as_f64(), Some(35.0));
    assert_eq!(usage["total"]["tokens_cache_read"].as_f64(), Some(8.0));
    let keys = client
        .get(format!("http://127.0.0.1:{admin}/api/v1/admin/keys"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    let status = keys.status();
    let keys = keys.text().await.unwrap();
    assert!(
        status.is_success(),
        "healthy server's admin keys refused {status}: {keys}"
    );
    for key in source["keys"].as_array().unwrap() {
        assert!(
            keys.contains(key[0].as_str().unwrap()),
            "released key missing: {keys}"
        );
    }
    usage["total"].clone()
}

#[tokio::test]
async fn ordinary_startup_upgrades_released_sqlite_and_restart_does_not_reapply() -> io::Result<()>
{
    let fixture = PathBuf::from(std::env::var_os("BUSBAR_TEST_SQLITE_155_FIXTURE").expect(
        "BUSBAR_TEST_SQLITE_155_FIXTURE supplies the actual published-writer fixture directory",
    ));
    let (original, source) = released_source(&fixture)?;
    let source_sha256 = hex::encode(Sha256::digest(&original));
    let root = PathBuf::from(
        std::env::var_os("BUSBAR_TEST_TMP_ROOT")
            .expect("BUSBAR_TEST_TMP_ROOT explicitly selects disposable native-test output"),
    );
    assert!(
        root.is_absolute(),
        "native-test output must use an absolute task directory"
    );
    let work = Workspace(root.join(format!(
            "startup-upgrade-sqlite-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )));
    std::fs::create_dir_all(work.0.join("plugins"))?;
    std::fs::write(work.0.join("governance.db"), original)?;
    let plugins = stage_plugin(&work.0);
    let (listen, admin) = (port(), port());
    // Historical deployment shape from scripts/store-migration-fixture.sh's
    // actual 1.5.5 recorder, with isolated paths/ports and current signed plugin
    // installation inputs. Old rate-card fields and Store alias stay authored.
    let config = format!(
        r#"listen: "127.0.0.1:{listen}"
admin_listen: "127.0.0.1:{admin}"
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: {{ env: BUSBAR_ADMIN_TOKEN }}
auth:
  chain: [keys]
  signing_key: {{ env: BUSBAR_SIGNING_KEY }}
  admin_auth: [admin-tokens]
plugins: {plugins}
store:
  module: sqlite
  settings: {{ db_path: {database} }}
groups:
  fixture:
    limits: [{{ budget: 1000000, per: day }}]
providers:
  fixture-openai:
    api_key: {{ env: FIXTURE_UPSTREAM_KEY }}
models:
  m-chat: {{ provider: fixture-openai }}
  m-cache: {{ provider: fixture-openai }}
  m-chat-down: {{ provider: fixture-openai }}
per_request_fee: 3
rate_card:
  m-chat: {{ input_utok: 100000, output_utok: 200000 }}
  m-cache: {{ input_utok: 100000, output_utok: 200000, cache_read_utok: 10000 }}
  m-chat-down: {{ input_utok: 100000, output_utok: 200000 }}
advanced:
  usage_flush_interval_ms: 3600000
"#,
        database = serde_json::to_string(&work.0.join("governance.db")).unwrap()
    );
    std::fs::write(work.0.join("config.yaml"), &config)?;
    std::fs::write(
        work.0.join("providers.yaml"),
        "fixture-openai:\n  protocol: openai\n  base_url: http://127.0.0.1:9\n",
    )?;
    let mut first = boot(&work.0, 1);
    let first_usage = ready(&mut first, &work.0, 1, listen, admin, &source).await;
    first.stop().await;
    let checkpoint = snapshot(&work.0.join("governance.db"));
    assert_eq!(checkpoint["legacy_user_version"], 6);
    let converted = std::fs::read(work.0.join("config.yaml"))?;
    assert_ne!(
        converted,
        config.as_bytes(),
        "ordinary startup must publish its mechanical old-config conversion"
    );
    let migrated: serde_yaml::Value = serde_yaml::from_slice(&converted).unwrap();
    assert_eq!(
        migrated["advanced"]["allow_destinations"],
        serde_yaml::to_value(["127.0.0.1"]).unwrap(),
        "preserve only the recorder's exact loopback destination grant"
    );
    let mut second = boot(&work.0, 2);
    assert_eq!(
        ready(&mut second, &work.0, 2, listen, admin, &source).await,
        first_usage
    );
    second.stop().await;
    assert_eq!(
        snapshot(&work.0.join("governance.db")),
        checkpoint,
        "cold restart changed native upgrade, final checkpoint, or original source totals"
    );
    assert_eq!(std::fs::read(work.0.join("config.yaml"))?, converted);
    assert_eq!(
        hex::encode(Sha256::digest(std::fs::read(
            fixture.join("governance.db")
        )?)),
        source_sha256,
        "the immutable published fixture was mutated"
    );
    Ok(())
}
