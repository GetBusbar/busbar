// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A 1.5.5-shaped config (no `data_dir`, no `peers`, no `keyset_ref`) boots a busbar that is
//! indistinguishable from 1.5.5 on the two surfaces a local ledger would first show up on:
//!
//! * the `/metrics` exposition carries no `busbar_ledger_*`, `busbar_journal_*`, `busbar_hold_*`
//!   or `busbar_wal_*` series;
//! * the boot log carries no keyset / data-dir / WAL line (no probe, no "keyset missing", no
//!   "data dir not writable", no record-rate warning).
//!
//! Nothing of the kind exists in the tree today, so this is the tripwire: the first ledger series
//! or boot line that leaks onto a plain 1.5.5 deployment turns it red.
#![cfg(unix)]
// The fixture boots a REAL busbar with an LLM provider; a `--no-default-features` build has no
// wire codec compiled in and fail-closes at boot, which is correct product behaviour, not a
// regression. Full-feature builds run it.
#![cfg(feature = "proto-llm")]

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// A fresh, isolated fixture directory (pid + nanos, like the sibling harnesses). Deliberately does
/// NOT spell "data-dir"/"data_dir" (or any other `LEDGER_BOOT_WORDS` entry): the boot log prints this
/// path (e.g. the overlay file location), and a fixture name containing the tripwire vocabulary would
/// make the test flag its own path as a leak.
fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-neutrality-fixture-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A port the OS just handed out and released: the listener must be a fixed address so the test
/// can scrape it (the boot line prints the CONFIGURED address, not the bound one).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The 1.5.5 shape (the shadow oracle's own config, cut down): one provider, one model, keys on
/// the data plane, an admin token, prometheus export, memory store (the default). No
/// 1.6.0-additive key anywhere.
fn write_configs(dir: &Path, data_port: u16, admin_port: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    let signing_key = Command::new(env!("CARGO_BIN_EXE_busbar"))
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
admin_require_mtls: false
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: {{ env: BUSBAR_ADMIN_TOKEN }}
auth:
  chain:
    - keys
  signing_key: {{ file: "{signing}" }}
  admin_auth: [admin-tokens]
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

// Deliberately does not spell "data-dir"/"data_dir": see `fixture_dir`'s comment on why the tripwire
// vocabulary must not appear anywhere this fixture's own material could echo into the boot log.
const ADMIN_TOKEN: &str = "neutrality-fixture-admin";

/// The series prefixes a local ledger would introduce; none may appear on a 1.5.5 config.
const LEDGER_SERIES: &[&str] = &[
    "busbar_ledger_",
    "busbar_journal_",
    "busbar_hold_",
    "busbar_wal_",
];

/// The boot-line vocabulary a local ledger would introduce; none may appear on a 1.5.5 config.
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

    // The BEFORE picture, taken with every file the TEST creates already on disk — the configs, the
    // signing key and the log the child will write into. Everything that appears between here and
    // the AFTER picture below was put there by the node.
    let before = snapshot(&dir);
    assert!(
        before.len() >= 3,
        "the fixture directory snapshotted to {} paths. A snapshot that sees nothing compares \
         nothing, and this assertion would then pass on a node that wrote a whole ledger tree.",
        before.len()
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_busbar"))
        // The directory the assertion below reads is only the directory a stray file lands in if
        // it is also the directory the node was started in: a journal opened at a RELATIVE path
        // follows the process, not the config. Every path the node is given here is absolute, so
        // moving the process into the fixture changes nothing except where a mistake would show.
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

    let booted = wait_for(Duration::from_secs(30), || {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!(
                "busbar exited before listening (status {status:?}); log:\n{}",
                read_to_string(&log_path)
            );
        }
        read_to_string(&log_path).contains("busbar listening")
    });
    assert!(
        booted,
        "busbar did not reach 'listening' within 30s; log:\n{}",
        read_to_string(&log_path)
    );
    // The boot log line lands the instant ANY of the per-core SO_REUSEPORT workers starts listening,
    // not when every worker (and the process-wide metrics recorder behind them) is warm: the kernel
    // can hand an early connection to a worker whose accept loop is live before the recorder install
    // (a background thread's one-time clock calibration, started at config load) has completed.
    // `crate::export::prometheus`'s contract is that such a scrape is REFUSED (non-`200`, retriable),
    // never a `200` with an empty body — so unlike the pre-fix version of this test, we do not need
    // to retry PAST an untrustworthy early response to reach a trustworthy one: any `200` this test
    // sees is required to already be the full exposition, and a scrape that lands on a cold worker
    // answers non-`200` instead, which the retry below simply waits out.

    // Mint one virtual key through the admin API, exactly as an operator would.
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
    // One request through the whole request path first (the provider is unreachable, so it ends
    // as an upstream failure): the exposition then carries the request-path series, which is
    // exactly where a ledger series would first register.
    let chat = http_request(
        &format!("127.0.0.1:{data_port}"),
        "POST",
        "/v1/messages",
        Some(
            r#"{"model":"test-model","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}"#,
        ),
        Some(&token),
    );
    // The scrape (key-authenticated on the data listener in 1.5.5). A scrape landing on a cold
    // worker (see the boot-window note above) is REFUSED, not answered empty, so we retry only to
    // wait out that refusal — every `200` collected along the way is checked below, never trusted
    // blindly just because the status line said 200.
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

    // Stop, then read the WHOLE log (boot + drain) for ledger vocabulary.
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
    // THE DIRECTORY IS THE SAME DIRECTORY.
    //
    // This used to be a three-word denylist — `keyset`, `wal`, `journal` — over the fixture dir's
    // TOP LEVEL. Two things are wrong with that, and both are the same thing: it asks whether a
    // file matching three names appeared, when the question is whether ANY file appeared. A node
    // that persisted to `state/`, `db/`, `.busbar/`, `ledger.sqlite` or a bare `0000000001.log`
    // left the denylist untouched, and a subdirectory left it untouched by construction because
    // the scan did not descend. So the test now compares the WHOLE TREE, before and after: a
    // config without a data dir persists NOTHING, which means the set of paths under the fixture
    // is identical on both sides.
    //
    // `config.yaml` is the one exception, and it is not really one: the node rewrites it in place
    // when it normalises the 1.5.5 overlay, so its CONTENT changes while its path does not. Paths
    // are what is compared, so it needs no carve-out — it is named here so a reader knows the
    // comparison was made with that behaviour in view rather than in ignorance of it.
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

/// EVERY PATH UNDER `dir`, RECURSIVELY, relative to `dir` and with a trailing `/` on directories.
///
/// Recursion is the point. A node that persists does not necessarily persist beside the config: it
/// makes a directory and persists inside it, and a scan that reads only the top level sees one new
/// name it does not recognise, or — if the name is not on a denylist — nothing at all.
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

/// One HTTP request against the booted process: (status, body text).
fn http_request(
    addr: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    bearer: Option<&str>,
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
        if let Some(t) = bearer {
            req = req.bearer_auth(t);
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

/// Poll `cond` until it returns true or `budget` elapses; returns whether it became true.
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

/// Read a file to a String, tolerating a not-yet-flushed/partial log (returns what's there).
fn read_to_string(path: &Path) -> String {
    let mut s = String::new();
    if let Ok(mut f) = std::fs::File::open(path) {
        let _ = f.read_to_string(&mut s);
    }
    s
}
