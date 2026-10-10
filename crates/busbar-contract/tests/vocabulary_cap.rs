// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The vocabulary is bounded even in an image where nobody ever freezes it.
//!
//! The freeze is what a composition root does; the cap is what holds where there is no composition
//! root to do it. A dynamically loaded plugin linked against its own copy of this crate has its own
//! statics, so it has its own vocabulary and its own open window — and a test binary, a fuzz target
//! or a bench has no boot phase at all. In every one of those images the freeze never happens, and
//! the only thing standing between a per-request `key()` and an unbounded leak is this ceiling.
//!
//! Its own test binary on purpose: the vocabulary is one per process, so a test that fills it must
//! not share a process with a test that counts it.

use busbar_contract::{Registration, MAX_VOCABULARY};

#[test]
fn interning_stops_at_the_ceiling_rather_than_growing_with_traffic() {
    let mut reg = Registration::new();
    for i in 0..MAX_VOCABULARY {
        assert!(
            reg.key(&format!("key-{i}")).is_some(),
            "the ceiling is a ceiling on distinct keys, and this is the {i}th"
        );
    }
    assert_eq!(Registration::interned(), MAX_VOCABULARY);

    // The next distinct name is refused. Not a panic: the name that reaches a full vocabulary is
    // the one a misused registration took off a request, and a panic there is a way to stop a node.
    assert_eq!(reg.key("one-past-the-ceiling"), None);
    assert_eq!(reg.lane("one-past-the-ceiling"), None);
    assert_eq!(Registration::interned(), MAX_VOCABULARY);

    // A key already registered still resolves, because resolving is not interning.
    assert!(reg.key("key-0").is_some());
}
