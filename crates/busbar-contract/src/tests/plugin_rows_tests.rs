// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-contract/src/plugin_rows.rs`.

use super::*;

/// The need ladder reads as the manifest spells it, and `no` is the default.
#[test]
fn the_need_ladder_reads_the_manifests_words() {
    for (word, level) in [
        ("\"no\"", NeedLevel::No),
        ("\"ro\"", NeedLevel::Ro),
        ("\"rw\"", NeedLevel::Rw),
    ] {
        assert_eq!(serde_json::from_str::<NeedLevel>(word).unwrap(), level);
        assert_eq!(serde_json::to_string(&level).unwrap(), word);
    }
    assert_eq!(NeedLevel::default(), NeedLevel::No);
}

/// `ro` and `rw` read; only `rw` rewrites.
#[test]
fn reading_and_rewriting_follow_the_ladder() {
    assert!(!NeedLevel::No.wants_read() && !NeedLevel::No.wants_rewrite());
    assert!(NeedLevel::Ro.wants_read() && !NeedLevel::Ro.wants_rewrite());
    assert!(NeedLevel::Rw.wants_read() && NeedLevel::Rw.wants_rewrite());
}
