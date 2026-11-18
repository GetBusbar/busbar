// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The process installs its one log subscriber once: a boot never prints that the subscriber (or
//! the `log` bridge) was already installed, whether it goes on to serve or is refused after logging
//! is up.

#![cfg(unix)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const DOUBLE_INIT: &str = "tracing subscriber already initialized";

const BRIDGE_TAKEN: &str = "the `log` bridge is not installed";

struct Reap(Child);

impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn fixture_dir(tag: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "busbar-tracing-init-once-{tag}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_configs(dir: &Path, listen: &str) {
    std::fs::write(dir.join("providers.yaml"), "{}\n").unwrap();
    std::fs::write(
        dir.join("config.yaml"),
        format!(
            "listen: \"{listen}\"\nadmin_listen: \"127.0.0.1:{admin_port}\"\n\
             store: {{module: memory}}\nadmin_require_mtls: false\nauth:\n  chain: []\n\
             providers: {{}}\nmodels: {{}}\n",
            admin_port = common::boot::free_port()
        ),
    )
    .unwrap();
}

/// Boot busbar on `dir`'s configs until it exits or its stderr satisfies `done`: its stderr, and its
/// exit status if it exited.
fn boot_until(dir: &Path, done: impl Fn(&str) -> bool) -> (String, Option<i32>) {
    let log = dir.join("stderr.log");
    let mut child = Reap(
        Command::new(common::boot::exe())
            .env("BUSBAR_CONFIG", dir.join("config.yaml"))
            .env_remove("BUSBAR_PROVIDERS")
            .env("RUST_LOG", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log).unwrap())
            .spawn()
            .expect("spawn busbar"),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let exited = child.0.try_wait().expect("try_wait");
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        if let Some(status) = exited {
            return (text, status.code());
        }
        if done(&text) {
            return (text, None);
        }
        assert!(
            Instant::now() < deadline,
            "busbar neither exited nor reached the expected line in 60 s; stderr:\n{text}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_clean_boot_reports_no_second_init() {
    let dir = fixture_dir("serve");
    write_configs(&dir, &format!("127.0.0.1:{}", common::boot::free_port()));
    let (out, code) = boot_until(&dir, common::boot::log_shows_data_and_admin_listening);
    assert_eq!(code, None, "the boot stays up; stderr:\n{out}");
    assert!(
        out.contains("busbar starting"),
        "the subscriber is installed (the first INFO line is written); stderr:\n{out}"
    );
    assert!(
        !out.contains(DOUBLE_INIT) && !out.contains(BRIDGE_TAKEN),
        "the boot installed its logging twice; stderr:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_refusal_after_logging_is_up_reports_no_second_init() {
    let dir = fixture_dir("refused");
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = occupied.local_addr().unwrap().to_string();
    write_configs(&dir, &address);
    let (out, code) = boot_until(&dir, |_| false);
    assert_eq!(code, Some(1), "the boot is refused; stderr:\n{out}");
    assert!(
        out.contains("cannot bind") && out.contains(&address),
        "the refusal is the occupied listener address; stderr:\n{out}"
    );
    assert!(
        out.contains("busbar starting"),
        "the subscriber is installed (the first INFO line is written); stderr:\n{out}"
    );
    assert!(
        !out.contains(DOUBLE_INIT) && !out.contains(BRIDGE_TAKEN),
        "the boot installed its logging twice; stderr:\n{out}"
    );
    drop(occupied);
    let _ = std::fs::remove_dir_all(&dir);
}
