// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/operation.rs`.

use super::*;

#[test]
fn names_are_stable_and_distinct() {
    let all = [
        Operation::Chat,
        Operation::Embeddings,
        Operation::Moderation,
        Operation::Image,
        Operation::Transcription,
        Operation::Speech,
        Operation::Rerank,
    ];
    let names: Vec<_> = all.iter().map(|o| o.name()).collect();
    // all distinct
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "operation names must be unique");
    assert_eq!(Operation::Chat.name(), "chat");
}
