//! cargo-xtask entry point. See `docs/design/ARCHITECTURE.md` sections 1.2/8.3/9.1,
//! `docs/design/1.6.0-contract-gaps.md` CG-59, and `docs/design/xtask-gates.md` for why this
//! exists and where it is going.
//!
//! Usage: `cargo xtask gate <name>` / `cargo xtask selftest` / `cargo xtask denylist`
//! (aliased by `.cargo/config.toml`'s `[alias]` table). All logic lives in the library half of
//! this crate so `cargo test -p xtask` can drive it directly rather than through a subprocess.

fn main() {
    // THE PROCESS-LEVEL WATCHDOG IS THE BINARY'S, and only the binary's. `gate <name>` and
    // `gate <name> --selftest` cannot hand their gate to a worker thread — they build it with
    // flags a `fn()` pointer cannot carry — so the only way those arms can refuse a hung gate is
    // to end the process. That is right for a command a human or a CI step is waiting on, and
    // wrong for `cargo test -p xtask`, which drives the very same `cli::main` in-process and must
    // report its own failures rather than be shot in the head by one of them. Arming it HERE is
    // what keeps those two facts apart. `--all` needs none of this: it runs each gate on its own
    // thread and turns a hung one into red rows either way.
    xtask::gates::enable_process_watchdog();
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(xtask::cli::main(&args));
}
