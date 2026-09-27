// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **A THIRD-PARTY PLUGIN'S OWN METRICS REACH THE SCRAPE, ATTRIBUTED BY THE HOST** — proven over a
//! REAL plugin through its dropped-in door, end to end over the shipped binary.
//!
//! The plugin is GetBusbar/headroom-hook: a real `kind: hook` compression gate whose `status` reply
//! carries its own operational series under its own names (`headroom_requests_total`,
//! `headroom_tokens_input_total`, `dollars_saved`, … — none in the reserved `busbar_` namespace). CI's
//! `plugin-proofs` job builds its `cdylib` at a pinned rev into `BUSBAR_PLUGIN_PROOF_DIR`; this test
//! packs it as an UNSIGNED third-party tarball (publisher `acme`, the config opting into unsigned
//! plugins), drops it into `plugins.dir`, defines a hook instance naming it and attaches the instance
//! to every pool. One request through a configured model runs the gate, the gate counts it, and the
//! host's hook scrape (`GET /metrics/hooks`) renders what the plugin REPORTED: its names verbatim,
//! its own labels (`pool`), and the one label the HOST adds for provenance, `hook="<instance>"`.
//!
//! RED ARM, in the same test: a second boot of the same plugin, dropped in and DEFINED but attached
//! to no pool, is never handed a request — so the plugin has counted nothing and the scrape carries
//! none of its request series. What reaches the scrape is what the plugin observed, never a series
//! the host invents for a loaded plugin.
//!
//! `#[ignore]`d: the plugin is built outside this workspace (its own repo, its own pinned
//! dependencies). ci.yml's `plugin-proofs` job is its only execution and floors the match count.

#![cfg(unix)]
#![cfg(linked_axis_body_ingress)]

mod common;

use busbar_plugin_loader::{plugin_library_filename, sign, supported_abi, tarball};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// The dropped-in plugin's manifest name — what the hook instance's `module:` names.
const PLUGIN: &str = "dropped-gate";

/// The hook INSTANCE the config defines over it — the provenance label the host attaches.
const INSTANCE: &str = "compress";

/// The pool every request is addressed to — the plugin's own `pool` label on what it counts.
const POOL: &str = "p";

/// The real plugin's library, snake-cased, as its own build names it.
const CDYLIB: &str = "headroom_hook";

/// The plugin's `cdylib` from `BUSBAR_PLUGIN_PROOF_DIR`. Unset is a skip only outside CI; a set
/// directory without the library is always a failure (the proof job built it there).
fn proof_cdylib() -> Option<Vec<u8>> {
    let Some(dir) = std::env::var_os("BUSBAR_PLUGIN_PROOF_DIR") else {
        assert!(
            std::env::var_os("CI").is_none(),
            "BUSBAR_PLUGIN_PROOF_DIR is unset under CI; the plugin-proofs job sets it"
        );
        return None;
    };
    let path = PathBuf::from(dir).join(plugin_library_filename(CDYLIB));
    Some(std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display())))
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-hook-metrics-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(d.join("plugins")).unwrap();
    d
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The plugin packed as an UNSIGNED third-party `kind: hook` tarball, stating the prompt need its
/// own release tarball states.
fn write_tarball(dir: &Path, lib: &[u8]) {
    let m = sign::Manifest {
        name: PLUGIN.into(),
        alias: PLUGIN.into(),
        kind: "hook".into(),
        version: "2.0.22".into(),
        publisher: "acme".into(),
        abi_version: *supported_abi("hook").iter().max().expect("hook abi"),
        sha256: sign::sha256_hex(lib),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        // What the plugin's own packing states (`--needs-prompt rw`): it reads and rewrites prompts.
        needs: sign::HookNeeds {
            prompt: sign::NeedLevel::Rw,
            ..Default::default()
        },
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
    };
    let bytes = tarball::package(&m, "lib.so", lib).unwrap();
    std::fs::write(dir.join("plugins").join("dropped-gate.tar.gz"), bytes).unwrap();
}

/// The config: the plugin dropped in, one hook instance over it, attached to every pool (the
/// reserved all-pools `pools.hooks` list) when `attached`, one pool, the scrape served
/// (`module: prometheus`), and one model whose upstream refuses the connection (the pool's gates
/// run before the hop).
fn write_configs(dir: &Path, data_port: u16, admin_port: u16, attached: bool) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    let attach = if attached {
        format!("  hooks: [{INSTANCE}]\n")
    } else {
        String::new()
    };
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
admin_require_mtls: false
auth:
  chain: []
plugins:
  enabled: true
  dir: '{plugins}'
  trust:
    allow_unsigned: true
export:
  metrics: {{ module: prometheus, settings: {{ buffer_seconds: 60 }} }}
hooks:
  {INSTANCE}: {{ module: {PLUGIN}, kind: gate, prompt: rw, timeout_ms: 2000 }}
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
pools:
{attach}  {POOL}:
    members:
      - {{ model: test-model, weight: 1 }}
"#,
            plugins = dir.join("plugins").display()
        ),
    )
    .unwrap();
}

/// Kill the child when the test ends, however it ends.
struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One raw HTTP/1.1 exchange over a fresh connection: `(status, body)`.
fn exchange(port: u16, request: &str) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    stream.write_all(request.as_bytes()).ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n")?;
    let status = head
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some((status, body.to_string()))
}

fn get(port: u16, path: &str) -> Option<(u16, String)> {
    exchange(
        port,
        &format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"),
    )
}

fn log_of(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("out.log")).unwrap_or_default()
}

/// Boot the binary over `dir`'s config and wait for `/metrics` to answer.
fn boot(dir: &Path, data_port: u16) -> Reap {
    let log = std::fs::File::create(dir.join("out.log")).unwrap();
    let mut child = Reap(
        Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
            .env("MOCK_KEY", "x")
            .env("RUST_LOG", "warn")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn busbar"),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            panic!(
                "busbar refused to boot with a dropped-in hook (status {status:?}); log:\n{}",
                log_of(dir)
            );
        }
        if matches!(get(data_port, "/metrics"), Some((200, _))) {
            return child;
        }
        assert!(
            Instant::now() < deadline,
            "/metrics never answered 200; log:\n{}",
            log_of(dir)
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// One chat request addressed to the pool: it passes the pool's hooks before the upstream hop. A
/// conversation, not a single turn: the plugin only works on history before the ask (a lone turn
/// has nothing to compress, and the plugin abstains without counting it).
fn one_request(data_port: u16) {
    let history =
        "The quarterly report covers revenue, costs and hiring across every region. ".repeat(40);
    let body = format!(
        r#"{{"model":"{POOL}","max_tokens":1,"messages":[{{"role":"user","content":"{history}"}},{{"role":"assistant","content":"Noted."}},{{"role":"user","content":"What were the costs?"}}]}}"#
    );
    let request = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    exchange(data_port, &request).expect("the request is answered");
}

/// The lines of the hook scrape that carry `series`.
fn series_lines(exposition: &str, series: &str) -> Vec<String> {
    exposition
        .lines()
        .filter(|l| l.starts_with(&format!("{series}{{")))
        .map(str::to_string)
        .collect()
}

#[test]
#[ignore = "needs the real plugin built into BUSBAR_PLUGIN_PROOF_DIR (ci.yml plugin-proofs)"]
fn a_dropped_in_third_party_plugins_own_metrics_reach_the_hook_scrape_attributed_by_the_host() {
    let Some(lib) = proof_cdylib() else {
        eprintln!("skip: BUSBAR_PLUGIN_PROOF_DIR is unset");
        return;
    };

    // GREEN: attached to every pool, handed one request, its own series on the scrape.
    let dir = scratch("attached");
    write_tarball(&dir, &lib);
    let (data_port, admin_port) = (free_port(), free_port());
    write_configs(&dir, data_port, admin_port, true);
    let child = boot(&dir, data_port);
    one_request(data_port);
    // The scrape serves a cache and refreshes it off the request path: poll.
    let deadline = Instant::now() + Duration::from_secs(30);
    let exposition = loop {
        let (status, body) = get(data_port, "/metrics/hooks").unwrap_or_default();
        if status == 200 && !series_lines(&body, "headroom_requests_total").is_empty() {
            break body;
        }
        assert!(
            Instant::now() < deadline,
            "the plugin's own series never reached /metrics/hooks; last scrape ({status}):\n{body}\nlog:\n{}",
            log_of(&dir)
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    let requests = series_lines(&exposition, "headroom_requests_total");
    let provenance = format!("hook=\"{INSTANCE}\"");
    assert!(
        requests
            .iter()
            .all(|l| l.contains(&provenance) && l.contains(&format!("pool=\"{POOL}\""))),
        "every sample carries the plugin's own `pool` label and the host's `{provenance}`:\n{exposition}"
    );
    assert!(
        requests.iter().any(|l| l.ends_with(" 1")),
        "the one request the gate saw is counted once:\n{exposition}"
    );
    for series in ["headroom_tokens_input_total", "dollars_saved"] {
        assert!(
            !series_lines(&exposition, series).is_empty(),
            "`{series}` is rendered under the plugin's own name:\n{exposition}"
        );
    }
    assert!(
        exposition.contains("# TYPE headroom_requests_total counter"),
        "the plugin's declared type is rendered:\n{exposition}"
    );
    assert!(
        !exposition.lines().any(|l| l.starts_with("busbar_")),
        "the hook scrape carries no first-party series:\n{exposition}"
    );
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);

    // RED ARM: the same plugin, defined but attached to no pool, is handed no request — and none of
    // its request series appears.
    let dir = scratch("unattached");
    write_tarball(&dir, &lib);
    let (data_port, admin_port) = (free_port(), free_port());
    write_configs(&dir, data_port, admin_port, false);
    let child = boot(&dir, data_port);
    one_request(data_port);
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let (_, body) = get(data_port, "/metrics/hooks").unwrap_or_default();
        assert!(
            series_lines(&body, "headroom_requests_total").is_empty(),
            "a plugin handed no request reported a request:\n{body}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
}
