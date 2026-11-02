// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![cfg(unix)]
#![cfg(linked_section_pools)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

include!(concat!(env!("OUT_DIR"), "/linked_transports.rs"));

const WORKERS: usize = 2;

const THROUGH_THE_CONNECTOR: &str = "data door listening through the connector";

const REQUEST: &str = "GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
const EXCHANGE: &str = include_str!("fixtures/transport_dropped_in_exchange.txt");

fn transport_cdylib() -> (Vec<u8>, &'static str) {
    let under: Vec<&str> = LINKED_TRANSPORTS
        .iter()
        .flat_map(|w| w.composes_over.iter().copied())
        .collect();
    common::plugins::transport_cdylib_under(&under).unwrap_or_else(|| {
        common::plugins::missing("kind: transport floor door", common::plugins::BUILD_PINNED)
    })
}

fn fixture_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-transport-dropped-in-{tag}-{}-{}",
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
    std::fs::create_dir_all(d.join("plugins")).unwrap();
    d
}

fn free_port() -> u16 {
    common::boot::free_port()
}

fn drop_in(dir: &Path, lib: &[u8]) {
    drop_in_as(dir, lib, "dropped-wire");
}

fn drop_in_as(dir: &Path, lib: &[u8], name: &str) {
    let bytes = common::plugins::pack_stated("transport", name, lib, "acme");
    std::fs::write(dir.join("plugins").join(format!("{name}.tar.gz")), bytes).unwrap();
}

fn write_configs(dir: &Path, data_port: u16, admin_port: u16) {
    std::fs::write(
        dir.join("providers.yaml"),
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            r#"listen: "127.0.0.1:{data_port}"
admin_listen: "127.0.0.1:{admin_port}"
store: {{module: memory}}
advanced:
  allow_destinations: ["127.0.0.1"]
  worker_threads: {WORKERS}
admin_require_mtls: false
auth:
  chain: []
plugins:
  enabled: true
  dir: '{plugins}'
  trust:
    allow_unsigned: true
providers:
  mock:
    api_key: {{ env: MOCK_KEY }}
models:
  test-model:
    provider: mock
"#,
            plugins = dir.join("plugins").display()
        ),
    )
    .unwrap();
}

fn busbar(dir: &Path) -> Command {
    let mut cmd = Command::new(common::boot::exe());
    cmd.env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", dir.join("providers.yaml"))
        .env("MOCK_KEY", "x")
        .env("RUST_LOG", "debug");
    cmd
}

struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn serve_once(dir: &Path, data_port: u16, expect_through: usize) -> (String, bool, usize) {
    let log = std::fs::File::create(dir.join("out.log")).unwrap();
    let mut child = Reap(
        busbar(dir)
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .expect("spawn busbar"),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            panic!(
                "busbar exited ({status:?}) before serving; log:\n{}",
                std::fs::read_to_string(dir.join("out.log")).unwrap_or_default()
            );
        }
        if let Some(raw) = exchange(data_port) {
            let kernel = kernel_socket(data_port);
            let settle = Instant::now() + Duration::from_secs(10);
            let through = loop {
                let n = std::fs::read_to_string(dir.join("out.log"))
                    .unwrap_or_default()
                    .lines()
                    .filter(|l| l.contains(THROUGH_THE_CONNECTOR))
                    .count();
                if n >= expect_through || Instant::now() > settle {
                    break n;
                }
                std::thread::sleep(Duration::from_millis(50));
            };
            return (masked(&raw), kernel, through);
        }
        assert!(Instant::now() < deadline, "the data door never answered");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn kernel_socket(port: u16) -> bool {
    use socket2::{Domain, Socket, Type};
    let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
    let Ok(probe) = Socket::new(Domain::IPV4, Type::STREAM, None) else {
        return false;
    };

    probe.set_reuse_address(true).is_ok()
        && probe.set_reuse_port(true).is_ok()
        && probe.bind(&addr.into()).is_ok()
}

fn refused(dir: &Path) -> Output {
    let (out_path, err_path) = (dir.join("refused.out"), dir.join("refused.err"));
    let mut child = Reap(
        busbar(dir)
            .stdout(std::fs::File::create(&out_path).unwrap())
            .stderr(std::fs::File::create(&err_path).unwrap())
            .spawn()
            .expect("spawn busbar"),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "busbar did not refuse to boot within 60s (it is serving); stderr:\n{}",
            std::fs::read_to_string(&err_path).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    Output {
        status,
        stdout: std::fs::read(&out_path).unwrap_or_default(),
        stderr: std::fs::read(&err_path).unwrap_or_default(),
    }
}

fn exchange(port: u16) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    stream.write_all(REQUEST.as_bytes()).ok()?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).ok()?;
    (!raw.is_empty()).then_some(raw)
}

fn masked(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .split("\r\n")
        .map(|line| match line.split_once(':') {
            Some((name, _)) if name.eq_ignore_ascii_case("date") => format!("{name}: <masked>"),
            _ => line.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

fn carriers(dir: &Path) -> Vec<String> {
    std::fs::read_to_string(dir.join("out.log"))
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains(THROUGH_THE_CONNECTOR))
        .filter_map(|l| {
            plain(l)
                .split_whitespace()
                .find_map(|w| w.strip_prefix("carrier="))
                .map(|c| c.trim_matches('"').to_owned())
        })
        .collect()
}

fn plain(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn pinned() -> String {
    EXCHANGE.trim_end_matches('\n').replace('\n', "\r\n")
}

#[test]
fn a_dropped_in_transport_registers_through_the_one_fold_and_serves() {
    let (lib, key) = transport_cdylib();
    let linked = LINKED_TRANSPORTS.iter().any(|w| w.key == key);
    let dir = fixture_dir("serve");
    let (data_port, admin_port) = (free_port(), free_port());
    write_configs(&dir, data_port, admin_port);

    if linked {
        let (served, kernel, through) = serve_once(&dir, data_port, WORKERS);
        assert_eq!(served, pinned(), "the linked build's exchange");
        assert!(
            kernel,
            "the linked build's data door is the kernel's own socket"
        );
        assert_eq!(
            through, WORKERS,
            "each of the {WORKERS} data workers listens through the connector"
        );
        assert_eq!(
            carriers(&dir),
            vec![key.to_owned(); WORKERS],
            "every data worker accepts through the linked carrier"
        );

        drop_in(&dir, &lib);
        let out = refused(&dir);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "stderr:\n{stderr}");
        assert!(
            stderr.contains(&format!("DuplicateKey {{ kind: Transport, key: {key:?} }}")),
            "stderr:\n{stderr}"
        );
    } else {
        let (served, _, _) = serve_once(&dir, data_port, WORKERS);
        assert_eq!(served, pinned(), "no layer waits on the unlinked key");

        drop_in(&dir, &lib);
        let (served, _, through) = serve_once(&dir, data_port, WORKERS);
        assert_eq!(
            served,
            pinned(),
            "the dropped-in build's exchange is the linked build's"
        );

        assert_eq!(
            through, WORKERS,
            "each of the {WORKERS} data workers listens through the connector"
        );

        assert_eq!(
            carriers(&dir),
            vec![key.to_owned(); WORKERS],
            "every data worker accepts through the dropped-in carrier"
        );
        let neutral = common::plugins::neutral_frame_door_bytes().unwrap_or_else(|| {
            common::plugins::missing("neutral_frame_door", common::plugins::BUILD_LOADER_EXAMPLES)
        });
        drop_in_as(&dir, &neutral, "a-neutral-framer");
        let (served, _, through) = serve_once(&dir, data_port, WORKERS);
        assert_eq!(
            served,
            pinned(),
            "a framer beside the carrier moves no byte"
        );
        assert_eq!(through, WORKERS);
        assert_eq!(
            carriers(&dir),
            vec![key.to_owned(); WORKERS],
            "the neutral framer, declared first, is never the address carrier"
        );
        std::fs::remove_file(dir.join("plugins").join("a-neutral-framer.tar.gz")).unwrap();

        drop_in_as(&dir, &lib, "dropped-wire-again");
        let out = refused(&dir);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "stderr:\n{stderr}");
        assert!(stderr.contains(&format!("{key:?}")), "stderr:\n{stderr}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
