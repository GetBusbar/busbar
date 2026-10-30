// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! NO TELEMETRY, AIR-GAP DEPLOYABLE (privacy page: "Busbar does not include telemetry that phones
//! home to us"; site: "Air-gap deployable"). The real binary boots the configuration the
//! getbusbar/busbar image ships (`docker/config.yaml` over the shipped `providers.yaml`), listening
//! on loopback, and sits idle with no caller. Busbar dials only when it serves a request or runs
//! something the operator configured (a probe, a sink, a store, an MCP upstream); the shipped
//! default configures none of those, so the process must hold no outbound socket at all: from spawn
//! through boot and an idle window after it, every socket it owns is a listener or a connection
//! accepted on one of its own listeners.
//!
//! The process's sockets are read from the operating system, not from busbar: `/proc/<pid>/fd` and
//! `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` on Linux, `lsof` on macOS. A dial that bypassed the
//! connector (a plugin's own client) is caught the same as one through it. The idle window is
//! bounded, so a phone-home scheduled long after boot is out of its reach.
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// How long the idle node is watched after both listeners are up.
const IDLE_WINDOW: Duration = Duration::from_secs(8);

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

fn fixture_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-default-config-no-outbound-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The shipped image default, its listeners moved to loopback test ports; nothing else changes.
fn shipped_default_on(data: u16, admin: u16) -> String {
    let shipped = std::fs::read_to_string(repo_root().join("docker/config.yaml"))
        .expect("the shipped docker/config.yaml");
    let listen = "listen: \"0.0.0.0:8080\"";
    assert!(
        shipped.contains(listen),
        "docker/config.yaml states the listener this test moves"
    );
    shipped.replace(
        listen,
        &format!("listen: \"127.0.0.1:{data}\"\nadmin_listen: \"127.0.0.1:{admin}\""),
    )
}

/// One socket the process owns that is neither a listener nor accepted on one of `own`: a dial.
fn outbound_sockets(pid: u32, own: &[u16]) -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        linux_outbound(pid, own)
    }
    #[cfg(target_os = "macos")]
    {
        macos_outbound(pid, own)
    }
}

#[cfg(target_os = "macos")]
fn macos_outbound(pid: u32, own: &[u16]) -> Vec<String> {
    let Ok(out) = Command::new("lsof")
        .args(["-nP", "-a", "-p", &pid.to_string(), "-i"])
        .output()
    else {
        panic!("lsof is part of macOS and must run");
    };
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .skip(1)
        .filter(|line| {
            // NAME is the second-to-last column for TCP ("a->b (STATE)") and the last for UDP.
            let name = line
                .split_whitespace()
                .find(|w| w.contains(':'))
                .unwrap_or("");
            if line.contains("(LISTEN)") {
                return false;
            }
            let local_port = name
                .split("->")
                .next()
                .and_then(|l| l.rsplit(':').next())
                .and_then(|p| p.parse::<u16>().ok());
            !local_port.is_some_and(|p| own.contains(&p))
        })
        .map(str::to_string)
        .collect()
}

#[cfg(target_os = "linux")]
fn linux_outbound(pid: u32, own: &[u16]) -> Vec<String> {
    let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return Vec::new();
    };
    let inodes: BTreeSet<String> = fds
        .filter_map(Result::ok)
        .filter_map(|fd| std::fs::read_link(fd.path()).ok())
        .filter_map(|link| {
            let link = link.to_string_lossy().to_string();
            link.strip_prefix("socket:[")
                .and_then(|rest| rest.strip_suffix(']'))
                .map(str::to_string)
        })
        .collect();
    let mut found = Vec::new();
    for table in ["tcp", "tcp6", "udp", "udp6"] {
        let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/net/{table}")) else {
            continue;
        };
        for row in text.lines().skip(1) {
            let cols: Vec<&str> = row.split_whitespace().collect();
            if cols.len() < 10 || !inodes.contains(cols[9]) {
                continue;
            }
            let port = |addr: &str| {
                addr.rsplit(':')
                    .next()
                    .and_then(|p| u16::from_str_radix(p, 16).ok())
            };
            let (local, remote, state) = (port(cols[1]), port(cols[2]), cols[3]);
            let tcp = table.starts_with("tcp");
            let listener = if tcp {
                state == "0A"
            } else {
                remote == Some(0)
            };
            let accepted = local.is_some_and(|p| own.contains(&p));
            if !listener && !accepted {
                found.push(format!("{table} {row}"));
            }
        }
    }
    found
}

#[test]
fn default_config_makes_no_outbound_connection() {
    let dir = fixture_dir();
    let (data, admin) = (common::boot::free_port(), common::boot::free_port());
    std::fs::write(dir.join("config.yaml"), shipped_default_on(data, admin)).unwrap();
    let log_path = dir.join("out.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let log_err = log.try_clone().unwrap();
    let mut child = Command::new(common::boot::exe())
        .env("BUSBAR_CONFIG", dir.join("config.yaml"))
        .env("BUSBAR_PROVIDERS", repo_root().join("providers.yaml"))
        .env("BUSBAR_ADMIN_TOKEN", "default-config-no-outbound-admin")
        .env("ANTHROPIC_KEY", "sk-not-a-real-key")
        .current_dir(&dir)
        .stdout(log)
        .stderr(log_err)
        .spawn()
        .expect("spawn busbar");
    let _dump = common::boot::DumpOnPanic(&log_path);
    let pid = child.id();
    let own = [data, admin];
    let read = || std::fs::read_to_string(&log_path).unwrap_or_default();

    // From spawn: every sample, through boot and the idle window after it.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut samples = 0usize;
    let boot_deadline = Instant::now() + Duration::from_secs(30);
    let mut idle_until: Option<Instant> = None;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            panic!("busbar exited ({status:?}); log:\n{}", read());
        }
        seen.extend(outbound_sockets(pid, &own));
        samples += 1;
        match idle_until {
            None if common::boot::log_shows_data_and_admin_listening(&read()) => {
                idle_until = Some(Instant::now() + IDLE_WINDOW);
            }
            None if Instant::now() > boot_deadline => {
                panic!("busbar did not reach 'listening' in 30s; log:\n{}", read());
            }
            Some(until) if Instant::now() > until => break,
            _ => {}
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status();
    if common::lines::try_wait_bounded(&mut child, Duration::from_secs(30)).is_err() {
        let _ = child.kill();
    }
    assert!(
        samples > 20,
        "the process was sampled throughout: {samples}"
    );
    assert!(
        seen.is_empty(),
        "the shipped default dialled out with no caller and nothing configured to dial:\n{}",
        seen.into_iter().collect::<Vec<_>>().join("\n")
    );
    let _ = std::fs::remove_dir_all(&dir);
}
