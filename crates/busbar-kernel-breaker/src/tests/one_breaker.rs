//! ONE BREAKER: the workspace ships one breaker state machine and one HTTP-status ladder, both in
//! this crate. Scanned from the source, because the defect this guards against (TODO "TWO BREAKERS
//! SHIP, AND THE BUGGY ONE IS THE LIVE ONE", and the status ladder that shipped twice with its
//! no-answer arm in only one copy) was two copies that each looked right on review.

use std::path::{Path, PathBuf};

/// The workspace's `crates/` directory.
fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate sits under crates/")
        .to_path_buf()
}

/// Every production source file under `crates/*/src`: test modules (a `tests` directory or a
/// `*_tests.rs` file) are not shipped code.
fn production_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if name == "tests" || name == "target" || name.starts_with('.') {
                continue;
            }
            production_sources(&path, out);
        } else if name.ends_with(".rs") && !name.ends_with("_tests.rs") {
            out.push(path);
        }
    }
}

/// The files (relative to `crates/`) whose source contains `needle`.
fn files_containing(needle: &str) -> Vec<String> {
    let root = crates_dir();
    let mut found = Vec::new();
    let Ok(crates) = std::fs::read_dir(&root) else {
        return found;
    };
    for krate in crates.flatten() {
        let mut files = Vec::new();
        production_sources(&krate.path().join("src"), &mut files);
        for file in files {
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            if text.contains(needle) {
                found.push(
                    file.strip_prefix(&root)
                        .unwrap_or(&file)
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }
    found.sort();
    found
}

#[test]
fn one_http_status_ladder_ships_and_it_is_the_served_one() {
    // The Auth arm of the ladder: every copy of the HTTP-status classification opens with it.
    assert_eq!(
        files_containing("http_status == 401 || http_status == 403"),
        ["busbar-kernel-breaker/src/normalize.rs"],
        "the breaker's HTTP-status ladder must live in ONE place, the served normalizer"
    );
}

#[test]
fn one_breaker_state_machine_ships() {
    // The cooldown computation is the heart of the state machine: trip, escalation, the
    // Retry-After floor.
    assert_eq!(
        files_containing("fn compute_cooldown_with_retry_after("),
        ["busbar-kernel-breaker/src/cell.rs"],
        "the breaker's state machine must live in ONE place"
    );
}
