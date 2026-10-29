// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE ORACLE RUN IN N SHARDS IS AS STRICT AS ONE RUN. `bin/oracle shard-filter K N` gives every
//! cell of cells.json to exactly one shard; `shard-cover N` refuses a split that misses or repeats a
//! cell; `shard-verify K N <report>` refuses a shard whose report did not select every cell it owns
//! (or wrote none). `bin/oracle shard-selftest` drives each refusal on a small corpus, and this test
//! holds the real corpus to an exact cover.

use std::path::Path;
use std::process::Command;

fn oracle(args: &[&str]) -> std::process::Output {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    Command::new("bash")
        .arg(root.join("bin/oracle"))
        .args(args)
        .current_dir(&root)
        .output()
        .expect("bash runs the shim")
}

#[test]
fn each_shard_guard_refuses_what_it_exists_to_refuse() {
    let out = oracle(&["shard-selftest"]);
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn four_shards_cover_the_corpus_exactly_once() {
    let out = oracle(&["shard-cover", "4"]);
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
