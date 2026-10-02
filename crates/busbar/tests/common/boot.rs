// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BINARY A BOOT CLOCK TIMES — the shipped `busbar` under test, already exec'd once.
//!
//! A boot deadline measures how long BUSBAR takes to come up: parse its config, seal its
//! composition, bind its listeners. It does not measure how long the operating system takes to
//! page in and admit a freshly linked binary on its first exec (on macOS the first exec of a new
//! ~170MB debug image was measured at 8.4s on its own, then 0.03s on every later exec), and on a
//! loaded machine that one-time cost alone pushed a 30s boot deadline over while busbar itself had
//! not yet started. So the path every boot-deadline test spawns comes from [`exe`], which runs
//! `busbar --version` to completion once per test process before handing the path out: the
//! first-exec cost is paid before any clock starts, and the deadline keeps its value.

use std::process::Command;
use std::sync::OnceLock;

/// The path of the shipped binary under test, exec'd once (`--version`) before it is returned, so
/// a boot deadline started after this call times busbar's boot and not the binary's first exec.
pub fn exe() -> &'static str {
    static WARM: OnceLock<()> = OnceLock::new();
    let path = env!("CARGO_BIN_EXE_busbar");
    WARM.get_or_init(|| {
        let out = Command::new(path)
            .arg("--version")
            .output()
            .expect("exec the busbar binary under test");
        assert!(
            out.status.success(),
            "`busbar --version` failed before any boot clock started: {:?}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    });
    path
}

/// A LOOPBACK PORT NO OTHER BUSBAR TEST IN ANY PROCESS WILL BE HANDED, for this process's lifetime.
///
/// Picking a port by binding `:0` and dropping the socket leaves a window before the child busbar
/// binds it, and the DATA door binds with `SO_REUSEPORT` (one listener per worker), so a second test
/// that was handed the same number did not fail to bind: both busbars listened on one port and
/// the kernel spread connections across the two. A scrape then reached the other test's node, which
/// is how `/metrics never settled` read after 80-120 s under a full workspace run. So each port is
/// also claimed by an exclusive lock on a per-port file shared by every test process on the machine,
/// held until this process exits (the OS releases it even on a crash); a number another process has
/// claimed is skipped. Busbar's boot output is not read and not changed: the listen line logs the
/// CONFIGURED address, so binding `:0` there would report nothing.
pub fn free_port() -> u16 {
    static HELD: std::sync::Mutex<Vec<std::fs::File>> = std::sync::Mutex::new(Vec::new());
    for _ in 0..512 {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .expect("bind an ephemeral loopback port")
            .port();
        if let Some(lock) = try_reserve(port) {
            HELD.lock().unwrap_or_else(|p| p.into_inner()).push(lock);
            return port;
        }
    }
    panic!("no loopback port could be reserved in 512 tries");
}

/// The exclusive, cross-process claim on `port`, or `None` when another holder has it.
pub fn try_reserve(port: u16) -> Option<std::fs::File> {
    let dir = std::env::temp_dir().join("busbar-test-ports");
    std::fs::create_dir_all(&dir).expect("the port-claim directory");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(format!("{port}.lock")))
        .expect("the port-claim file");
    file.try_lock().ok().map(|()| file)
}
