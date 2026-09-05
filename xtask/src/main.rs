//! cargo-xtask entry point. See `docs/design/ARCHITECTURE.md` sections 1.2/8.3/9.1 and
//! `docs/design/1.6.0-contract-gaps.md` CG-59 for why this exists.
//!
//! Usage: `cargo xtask denylist [--selftest]` (aliased by `.cargo/config.toml`'s `[alias]` table).

mod denylist;
mod selftest;
mod toml_lite;

use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    // xtask/Cargo.toml's own directory's parent is the workspace root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask/Cargo.toml has a parent directory")
        .to_path_buf()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("denylist") => {
            if args.iter().any(|a| a == "--selftest") {
                let ok = selftest::run();
                std::process::exit(i32::from(!ok));
            }
            let report = denylist::run(&workspace_root());
            let ok = if args.iter().any(|a| a == "--format=tsv") {
                denylist::print_report_tsv(&report)
            } else {
                denylist::print_report(&report)
            };
            std::process::exit(i32::from(!ok));
        }
        Some(other) => {
            eprintln!("xtask: unknown subcommand `{other}`");
            eprintln!("usage: cargo xtask denylist [--selftest]");
            std::process::exit(2);
        }
        None => {
            eprintln!("usage: cargo xtask denylist [--selftest]");
            std::process::exit(2);
        }
    }
}
