// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::transport::*;

#[test]
fn names_are_stable_and_distinct() {
    let names: Vec<_> = Transport::ALL.iter().map(|t| t.name()).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "transport names must be unique");
    assert_eq!(Transport::Http.name(), "http");
}
