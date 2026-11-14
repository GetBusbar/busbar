// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Training-only profile flush for the benchmark PGO build (design PROFILES-PGO-BOLT §2.3).
//!
//! This crate is empty unless it is built with `--cfg busbar_pgo_train`, which only the
//! instrumented benchmark build sets. Then a constructor starts one thread that polls the file
//! named by `PGO_DUMP_TRIGGER`. When that file appears, the thread calls the profiler runtime's
//! `__llvm_profile_write_file()` and writes its return code to `<trigger>.done`, so the profile
//! does not depend on a clean process exit. It is a separate crate because `crates/busbar`
//! forbids unsafe code.

#[cfg(all(busbar_pgo_train, not(target_os = "linux")))]
compile_error!("busbar_pgo_train is set only by the Linux benchmark build");

#[cfg(all(busbar_pgo_train, target_os = "linux"))]
mod train {
    use std::{path::PathBuf, thread, time::Duration};

    extern "C" {
        fn __llvm_profile_write_file() -> i32;
    }

    fn watch(trigger: PathBuf) {
        let mut done = trigger.clone().into_os_string();
        done.push(".done");
        while !trigger.exists() {
            thread::sleep(Duration::from_millis(50));
        }
        // SAFETY: the profiler runtime is linked into every `-Cprofile-generate` binary, and
        // `busbar_pgo_train` is set only together with it. The call takes no arguments.
        let code = unsafe { __llvm_profile_write_file() };
        if let Err(error) = std::fs::write(PathBuf::from(done), code.to_string()) {
            eprintln!("busbar-pgo-train: cannot write the dump acknowledgement: {error}");
        }
    }

    extern "C" fn start() {
        if let Some(trigger) = std::env::var_os("PGO_DUMP_TRIGGER") {
            let spawned = thread::Builder::new()
                .name("pgo-dump".into())
                .spawn(move || watch(PathBuf::from(trigger)));
            if let Err(error) = spawned {
                eprintln!("busbar-pgo-train: cannot start the dump watcher: {error}");
            }
        }
    }

    #[used]
    #[link_section = ".init_array"]
    static START: extern "C" fn() = start;
}
