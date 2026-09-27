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
