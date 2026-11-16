// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-RETIRE (ABI-MIN3-INTERFACE §14): Retired carrier words (§8.7, round 12).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).
//!
//! The source-scan arm (no `tcp`/`stdio` literal in the migration crates, no RETIRE constant in the abi) runs
//! now. The two behavioural arms (an unstamped config with a `transport` instance refused before any write,
//! config.yaml byte-identical; a CORE_CFG section 5 from a `migrate` refused CONFIG) need the unstamped-config
//! boot path and stay ignored.

use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn sources(krate: &str) -> Vec<(PathBuf, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(krate)
        .join("src");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    assert!(
        !files.is_empty(),
        "{krate}: no sources found under {}",
        root.display()
    );
    files
        .into_iter()
        .map(|p| {
            let text = std::fs::read_to_string(&p).expect("a UTF-8 source file");
            (p, text)
        })
        .collect()
}

#[test]
fn no_retired_carrier_literal_in_the_migration_crates_and_no_retire_constant_in_the_abi() {
    // `busbar-migrations` is still on dev until S2-MOB-C3 deletes it; the scan follows it while it exists.
    for krate in ["busbar-migrate", "busbar-migrations"] {
        if !Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(krate)
            .exists()
        {
            continue;
        }
        for (path, text) in sources(krate) {
            for (n, line) in text.lines().enumerate() {
                let code = line.trim_start();
                if code.starts_with("//") {
                    continue;
                }
                for word in ["\"tcp\"", "\"stdio\""] {
                    assert!(
                        !code.contains(word),
                        "{}:{}: the retired carrier word {word} is named in code",
                        path.display(),
                        n + 1
                    );
                }
            }
        }
    }
    for (path, text) in sources("busbar-plugin-abi") {
        for (n, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            let bytes = code.as_bytes();
            let named = code.match_indices("RETIRE").any(|(at, _)| {
                let before = at.checked_sub(1).map(|i| bytes[i]);
                let after = bytes.get(at + "RETIRE".len()).copied();
                let ident =
                    |b: Option<u8>| b.is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_');
                !ident(before) && !ident(after)
            });
            assert!(
                !named,
                "{}:{}: a RETIRE constant in the abi",
                path.display(),
                n + 1
            );
        }
    }
}

#[test]
#[ignore = "owner: W1-K9 (blocked: the two behavioural arms need the unstamped-config boot path (busbar-migrate's config chain over a real config.yaml, byte-compared after the refusal) and a fixture `migrate` that answers CORE_CFG section 5; busbar-migrate is not a dev-dependency of this crate and the cells wait on S2-MOB-C3 / QM1; the source-scan arm runs as `no_retired_carrier_literal_in_the_migration_crates_and_no_retire_constant_in_the_abi`)"]
fn retired_carrier_words() {
    todo!("owner: W1-K9 (C-RETIRE)")
}
