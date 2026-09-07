//! cargo-xtask entry point. See `docs/design/ARCHITECTURE.md` sections 1.2/8.3/9.1,
//! `docs/design/1.6.0-contract-gaps.md` CG-59, and `docs/design/xtask-gates.md` for why this
//! exists and where it is going.
//!
//! Usage: `cargo xtask gate <name>` / `cargo xtask selftest` / `cargo xtask denylist`
//! (aliased by `.cargo/config.toml`'s `[alias]` table). All logic lives in the library half of
//! this crate so `cargo test -p xtask` can drive it directly rather than through a subprocess.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(xtask::cli::main(&args));
}
