// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(unix)]
#![cfg(linked_section_pools)]

mod common;

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-neutrality-fixture-{}-{}",
        std::process::id(),
        {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos()),
                line!(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn free_port() -> u16 {
    common::boot::free_port()
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();
    let signing_key = Command::new(common::boot::exe())
        .arg("--generate-signing-key")
        .output()
        .expect("generate a signing key");
    assert!(signing_key.status.success(), "--generate-signing-key");
    std::fs::write(dir.join("signing.key"), &signing_key.stdout).unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
advanced:
  allow_destinations: ["127.0.0.1"]
store: {{module: memory}}
admin_require_mtls: false
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: {{ env: BUSBAR_ADMIN_TOKEN }}
auth:
  chain:
    - keys
  signing_key: {{ file: "{signing}" }}
  admin_auth:
    - admin-tokens
export:
  metrics: {{ module: prometheus, settings: {{ buffer_seconds: 60 }} }}
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
"#,
            signing = dir.join("signing.key").display()
        ),
    )
    .unwrap();
}

const ADMIN_TOKEN: &str = "neutrality-fixture-admin";

const LEDGER_SERIES: &[&str] = &[
    "busbar_ledger_",
    "busbar_journal_",
    "busbar_hold_",
    "busbar_wal_",
];

const LEDGER_BOOT_WORDS: &[&str] = &[
    "keyset",
    "data_dir",
    "data-dir",
    "data dir",
    "wal ",
    "wal_",
    "journal",
    "record rate",
    "record_rate",
];

#[test]
fn no_ledger_series_and_no_keyset_lines_without_data_dir() {
    let dir = fixture_dir();
    let data_port = free_port();
    let admin_port = free_port();
    write_configs(&dir, data_port, admin_port);

    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();

    let before = snapshot(&dir);
    assert!(
        before.len() >= 3,
        "the fixture directory snapshotted to {} paths. A snapshot that sees nothing compares \
         nothing, and this assertion would then pass on a node that wrote a whole ledger tree.",
        before.len()
    );
    let mut child = Command::new(common::boot::exe())
        .current_dir(&dir)
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env("BUSBAR_ADMIN_TOKEN", ADMIN_TOKEN)
        .env("RUST_LOG", "info")
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .expect("spawn busbar");

    let _dump = common::boot::DumpOnPanic(&log_path);

    let booted = wait_for(Duration::from_secs(30), || {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!(
                "busbar exited before listening (status {status:?}); log:\n{}",
                read_to_string(&log_path)
            );
        }
        common::boot::healthz_answers(data_port)
    });
    assert!(
        booted,
        "busbar did not reach 'listening' (data and admin) within 30s; log:\n{}",
        read_to_string(&log_path)
    );

    let (_, minted) = http_request(
        &format!("127.0.0.1:{admin_port}"),
        "POST",
        "/api/v1/admin/keys",
        Some(r#"{"name":"neutrality"}"#),
        Some(ADMIN_TOKEN),
    );
    let token = minted
        .split("\"token\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_else(|| panic!("the admin API must mint a key: {minted}"))
        .to_string();

    let chat = http_request(
        &format!("127.0.0.1:{data_port}"),
        "POST",
        "/v1/messages",
        Some(
            r#"{"model":"test-model","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#,
        ),
        Some(&token),
    );

    let data_addr = format!("127.0.0.1:{data_port}");
    let mut status = 0u16;
    let mut body = String::new();
    let ready = wait_for(Duration::from_secs(10), || {
        let (s, b) = http_request(&data_addr, "GET", "/metrics", None, Some(&token));
        status = s;
        body = b;
        s == 200
    });
    assert!(
        ready,
        "GET /metrics never answered 200 within 10s (last status {status}); chat answered {chat:?}; \
         mint answered {minted}; last exposition:\n{body}"
    );
    assert!(
        !body.is_empty() && body.contains("# HELP"),
        "a 200 /metrics response must never be empty or partial — a cold-worker scrape must be \
         REFUSED (non-200), not answered 200 with nothing to show; got an empty/HELP-less body \
         instead: {body:?}"
    );
    let body = body.as_str();
    assert!(
        body.contains("busbar_"),
        "the exposition must carry busbar's own series (a bare 200 proves nothing); chat answered \
         {chat:?}; mint answered {minted}; exposition:\n{body}"
    );
    let leaked: Vec<&str> = body
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter(|l| LEDGER_SERIES.iter().any(|p| l.starts_with(p)))
        .collect();
    assert!(
        leaked.is_empty(),
        "no ledger/journal/hold/WAL series may appear on a config without data_dir; found:\n{}",
        leaked.join("\n")
    );

    let pid = child.id().to_string();
    let _ = Command::new("kill").arg("-TERM").arg(&pid).status();
    let exited = wait_for(Duration::from_secs(15), || {
        child.try_wait().expect("try_wait").is_some()
    });
    if !exited {
        let _ = child.kill();
    }
    let log_text = read_to_string(&log_path);
    let leaked_lines: Vec<&str> = log_text
        .lines()
        .filter(|l| {
            let lower = l.to_ascii_lowercase();
            LEDGER_BOOT_WORDS.iter().any(|w| lower.contains(w))
        })
        .collect();
    assert!(
        leaked_lines.is_empty(),
        "no keyset / data-dir / WAL / journal / record-rate line may be logged on a config \
         without data_dir; found:\n{}",
        leaked_lines.join("\n")
    );

    let after = snapshot(&dir);
    let appeared: Vec<&String> = after.difference(&before).collect();
    let vanished: Vec<&String> = before.difference(&after).collect();
    assert!(
        appeared.is_empty(),
        "a config WITHOUT a data dir persisted something. These paths did not exist before boot \
         and exist after boot + one request + one scrape + a clean shutdown:\n{}\n\
         Durability is a data-dir property; without one the node holds its books in memory and \
         leaves the filesystem exactly as it found it.",
        appeared
            .iter()
            .map(|p| format!("  + {p}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        vanished.is_empty(),
        "the node REMOVED files from the config's own directory:\n{}",
        vanished
            .iter()
            .map(|p| format!("  - {p}"))
            .collect::<Vec<_>>()
            .join("\n")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

fn snapshot(dir: &Path) -> BTreeSet<String> {
    fn walk(base: &Path, at: &Path, out: &mut BTreeSet<String>) {
        let Ok(entries) = std::fs::read_dir(at) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let rel = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let is_dir = path.is_dir();
            out.insert(if is_dir { format!("{rel}/") } else { rel });
            if is_dir {
                walk(base, &path, out);
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(dir, dir, &mut out);
    out
}

fn http_request(
    addr: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    token: Option<&str>,
) -> (u16, String) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("client");
        let mut req = match method {
            "POST" => client.post(format!("http://{addr}{path}")),
            _ => client.get(format!("http://{addr}{path}")),
        };
        if let Some(t) = token {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {t}"));
        }
        if let Some(b) = body {
            req = req
                .header("content-type", "application/json")
                .body(b.to_string());
        }
        let resp = req.send().await.expect("request");
        let status = resp.status().as_u16();
        (status, resp.text().await.unwrap_or_default())
    })
}

fn wait_for(budget: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    cond()
}

fn read_to_string(path: &Path) -> String {
    let mut s = String::new();
    if let Ok(mut f) = std::fs::File::open(path) {
        let _ = f.read_to_string(&mut s);
    }
    s
}
