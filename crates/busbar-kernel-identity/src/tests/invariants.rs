// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The crate's source invariants: one authenticate path (the kernel's), and nothing installed into
//! a process-wide static here.

// ---------------------------------------------------------------------------------------------
// One authenticate path.
// ---------------------------------------------------------------------------------------------

/// The `.rs` files under `dir`, skipping the `tests` directory.
fn non_test_sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).expect("source dir reads") {
        let path = e.expect("dir entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n != "tests") {
                non_test_sources(&path, out);
            }
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

fn is_ident(c: Option<char>) -> bool {
    c.is_some_and(|c| c.is_alphanumeric() || c == '_')
}

/// The kernel's one chain is the only authenticate path (BUSBAR-1.6.0.md R3; l.1932-1935, "a built
/// type or verb with no production construction site is either wired or deleted").
///
/// `Auth::resolve` and its satellites — the new-unit revocation walk, the bounded challenge, the
/// admin-grant lattice, the browser exchange dispatch — had no production caller, and the root's
/// `ProductionUnits` only built an `Auth` nobody read. A second authenticate implementation that
/// never runs still ships, and drifts from the one that does.
#[test]
fn the_unreached_authenticate_unit_is_gone() {
    const GONE: &[&str] = &[
        "pub fn resolve(",
        "pub struct AuthRequest",
        "fn run_chain_for_new_unit",
        "pub mod challenge",
        "pub mod admin",
        "pub mod exchange",
        "Auth::new(",
        "with_auth_chain",
        // The crate's own chain walk, its key-verifier binding and its module/principal twins of
        // the contract's: the kernel's chain is the walk that serves, so a second one only drifts.
        "pub struct AuthChain",
        "fn run_chain_with(",
        "pub trait KeyVerifier",
        "pub struct ResolvedKey",
        "pub trait AuthModule",
        "pub enum AuthOutcome",
        "fn id_is_reserved(",
    ];
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    non_test_sources(&crate_dir.join("src"), &mut files);
    files.push(crate_dir.join("../busbar/src/root/kernel.rs"));
    files.sort();

    let mut hits = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("source reads");
        for (n, line) in text.lines().enumerate() {
            for needle in GONE {
                for (at, _) in line.match_indices(needle) {
                    // A whole token only: `InProcessAuth::new(` is not `Auth::new(`, and
                    // `pub mod admin_verbs` is not `pub mod admin`.
                    let before = line[..at].chars().next_back();
                    let after = line[at + needle.len()..].chars().next();
                    if is_ident(before)
                        || (needle.ends_with(char::is_alphanumeric) && is_ident(after))
                    {
                        continue;
                    }
                    hits.push(format!("{}:{}: {needle}", file.display(), n + 1));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "the unreached authenticate unit is still in non-test source:\n{}",
        hits.join("\n")
    );
}

/// No process-wide static in this crate (BUSBAR-1.6.0.md THE DESIGN §11.11 R6: the kernel holds
/// exactly two `OnceLock` seams, `oauth_as/seam.rs` and `admin/seam.rs`). The composition root's
/// linked auth rows each carry a plugin's door function, so a static holding them is a function
/// pointer seam installed into a kernel crate; the rows and the operator words reach the kernel on
/// the root's install record instead, and every function here takes what it reads as an argument.
#[test]
fn nothing_is_installed_into_a_static_of_this_crate() {
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    non_test_sources(&crate_dir.join("src"), &mut files);
    files.sort();
    let mut hits = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("source reads");
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or_default();
            for needle in [
                "static ",
                "OnceLock",
                "OnceCell",
                "LazyLock",
                "thread_local!",
            ] {
                for (at, _) in code.match_indices(needle) {
                    // `&'static str` is a lifetime, not an item.
                    if needle == "static " && code[..at].ends_with('\'') {
                        continue;
                    }
                    if is_ident(code[..at].chars().next_back()) {
                        continue;
                    }
                    hits.push(format!("{}:{}: {}", file.display(), n + 1, line.trim()));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "a process-wide static in busbar-kernel-identity:\n{}",
        hits.join("\n")
    );
}
