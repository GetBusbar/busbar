// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **A 1.5.5 CONFIG THAT READS AN EXPORT'S URL OR AUTH HEADER FROM THE ENVIRONMENT STILL BOOTS.**
//!
//! 1.5.5 resolved `{env: …}` (and `{file: …}`) in the exporters' settings, and its docs configure
//! them that way: the OTLP sink's `url`, the request-log webhook's `url` and its
//! `auth_header: { name, value }`. 1.6.0 resolves a reference only at a field the plugin declares,
//! and refuses one anywhere else ("did not declare it as a secret"). A `url` is not a secret: the
//! sinks declare it REFERENCE-CAPABLE (the Statement's extensions' `reference_fields`; a literal url
//! passes as written, a reference resolves in place). The webhook's `auth_header.value` IS the
//! credential: it is declared SECRET (`secret_refs`). A sink pinned before it declared those fields
//! turns a working 1.5.5 deployment into one that will not start.
//!
//! Two proofs. The linked sinks' own Statements declare exactly that: `url` reference-capable and
//! not secret on both, `auth_header.value` secret on the webhook. And the real binary, given a
//! 1.5.5-shaped config whose `otlp` instance takes its `url` from the environment and whose
//! `request-log-webhook` instance takes both its `url` and its auth header's `value` from the
//! environment, accepts it under `--validate` with no undeclared refusal, boots and serves, and the
//! OTLP collector at the address the environment named receives the request path's spans: the
//! reference was resolved and the sink is served. (The webhook refuses loopback targets by policy,
//! as 1.5.5 did, so its delivery is not observed here; its instance booting without a refusal is
//! the part this guards.)
//!
//! RED at the export pins dev c892641d61 carries (otlp 3e1726f336 declares `url` SECRET, webhook
//! b5240b33d1 declares nothing): the Statements are not the ones above, and `--validate` refuses the
//! webhook's `auth_header.value` reference as undeclared.

#![cfg(unix)]
// The config serves `providers:`/`models:`, so the build must link the plane door that declares
// `pools:` (`linked_section_pools`): the linked table's answer, never a feature name.
#![cfg(linked_section_pools)]
// The sinks are linked export doors: the test is that axis's.
#![cfg(linked_axis_export_doors)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

include!(concat!(env!("OUT_DIR"), "/linked_transports.rs"));

/// The key of the wire the data door rides.
const WIRE: &str = "tcp";

/// The refusal answered for a reference at a field the plugin did not declare.
const UNDECLARED: &str = "did not declare it as a secret";

/// The environment the config's references name, as a 1.5.5 operator would set it.
const OTLP_URL: &str = "BUSBAR_T_OTLP_URL";
const HOOK_URL: &str = "BUSBAR_T_HOOK_URL";
const HOOK_TOKEN: &str = "BUSBAR_T_HOOK_TOKEN";

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-env-secret-fields-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(d.join("plugins")).unwrap();
    d
}

/// The 1.5.5 shape: each exporter's `url`, and the webhook's auth header value, an `{env: …}`
/// reference.
fn write_configs(dir: &Path, data_port: u16, admin_port: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        include_str!("fixtures/mock_provider.yaml"),
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
store: {{module: memory}}
admin_require_mtls: false
auth:
  chain: []
plugins:
  enabled: true
  dir: '{plugins}'
  trust:
    allow_unsigned: true
  logs: {{ dir: '{logs}' }}
export:
  trace:
    module: otlp
    settings:
      url: {{ env: {OTLP_URL} }}
  hook:
    module: request-log-webhook
    settings:
      url: {{ env: {HOOK_URL} }}
      auth_header: {{ name: Authorization, value: {{ env: {HOOK_TOKEN} }} }}
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
"#,
            plugins = dir.join("plugins").display(),
            logs = dir.join("plugin-logs").display(),
        ),
    )
    .unwrap();
}

/// The binary with the config and every variable the config's references name.
fn busbar(dir: &Path, collector: u16) -> Command {
    let mut cmd = Command::new(common::boot::exe());
    cmd.env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env(OTLP_URL, format!("http://127.0.0.1:{collector}/v1/traces"))
        .env(HOOK_URL, "https://siem.example/in")
        .env(HOOK_TOKEN, "Bearer upgrade-token")
        .env("RUST_LOG", "info");
    cmd
}

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// THE WIRE UNDER THE DOOR, into `dir`'s plugins, where the build does not link it.
fn drop_in_wire(dir: &Path) {
    if !LINKED_TRANSPORTS.iter().any(|w| w.key == WIRE) {
        let (lib, _) = common::plugins::transport_cdylib_under(&[WIRE]).unwrap_or_else(|| {
            common::plugins::missing(&format!("{WIRE} transport"), common::plugins::BUILD_PINNED)
        });
        let bytes = common::plugins::pack("transport", "dropped-wire", &lib, "acme");
        std::fs::write(dir.join("plugins").join("dropped-wire.tar.gz"), bytes).unwrap();
    }
}

/// Kill the child when the test ends, however it ends.
struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One HTTP/1.1 POST over a fresh connection: the status, or `None` before the listener is up.
fn post(port: u16, path: &str, body: &str) -> Option<u16> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .ok()?;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\ncontent-type: application/json\r\n\
         content-length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    text.lines().next()?.split_whitespace().nth(1)?.parse().ok()
}

/// What `statement` declares: its SECRET paths (`secret_refs`) and its REFERENCE-CAPABLE, not
/// secret, paths (its extensions' `reference_fields`), as the host reads them off its rendering.
fn declared(
    statement: &busbar_contract::abi::mechanism::door::Statement,
) -> (Vec<String>, Vec<String>) {
    use busbar_contract::abi::mechanism::rendering;
    // SAFETY: a linked sink's `STATEMENT` names only `'static` strings and lists.
    let bytes = unsafe { rendering::render(statement) }.expect("the Statement renders");
    let stated = rendering::read(&bytes).expect("the rendering reads back");
    let reference = stated
        .reference_fields()
        .expect("the reference-capable list reads");
    (stated.secret_refs, reference)
}

/// A `url` is reference-capable, never secret (a literal url, 1.5.5's BOOT cells, passes as
/// written); the webhook's `auth_header.value` is the credential, declared secret.
#[test]
fn the_export_sinks_declare_url_reference_capable_and_the_auth_header_value_secret() {
    let (none, url) = (Vec::<String>::new(), vec!["url".to_string()]);
    assert_eq!(
        declared(&busbar_export_otlp::door::STATEMENT),
        (none, url.clone()),
        "otlp: `url` reference-capable, nothing secret"
    );
    assert_eq!(
        declared(&busbar_export_webhook::STATEMENT),
        (vec!["auth_header.value".to_string()], url),
        "request-log-webhook: `auth_header.value` secret, `url` reference-capable"
    );
}

#[test]
fn a_1_5_5_config_reading_export_secrets_from_the_environment_boots_and_serves() {
    let dir = fixture_dir();
    let (data_port, admin_port) = (common::boot::free_port(), common::boot::free_port());
    let (collector_port, seen) = common::otlp::collector();
    write_configs(&dir, data_port, admin_port);
    drop_in_wire(&dir);

    // VALIDATE: the 1.5.5 config is accepted, and no `{env: …}` is refused as undeclared.
    let out = busbar(&dir, collector_port)
        .arg("--validate")
        .output()
        .expect("run busbar --validate");
    let text = said(&out);
    assert!(
        !text.contains(UNDECLARED),
        "a 1.5.5 `{{env: …}}` export field is refused as undeclared:\n{text}"
    );
    assert!(
        out.status.success(),
        "--validate refuses the 1.5.5 config ({}):\n{text}",
        out.status
    );

    // BOOT: the binary starts and serves model requests (their upstream refuses; the request
    // path's spans open and close regardless).
    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let mut child = Reap(
        busbar(&dir, collector_port)
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn busbar"),
    );
    let read_log = || std::fs::read_to_string(&log_path).unwrap_or_default();
    let body =
        r#"{"model":"test-model","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}"#;
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut served = 0;
    while served < 3 {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            panic!(
                "busbar exited ({status}) before serving a 1.5.5 config:\n{}",
                read_log()
            );
        }
        assert!(Instant::now() < deadline, "no data door:\n{}", read_log());
        match post(data_port, "/v1/messages", body) {
            Some(_) => served += 1,
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }

    // SERVED: the OTLP sink delivers to the address its `{env: …}` url named.
    let deadline = Instant::now() + Duration::from_secs(30);
    let heard = || common::otlp::spans(&common::otlp::requests(&seen, None)).len();
    while heard() == 0 {
        assert!(
            Instant::now() < deadline,
            "the collector the environment named received no span in 30 s:\n{}",
            read_log()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        child.0.try_wait().expect("try_wait").is_none(),
        "busbar stopped:\n{}",
        read_log()
    );
    let log = read_log();
    drop(child);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !log.contains(UNDECLARED),
        "the boot refused an `{{env: …}}` export field:\n{log}"
    );
}
