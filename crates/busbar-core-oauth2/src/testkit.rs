// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub(crate) fn install_test_seam() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(crate::install::<crate::NoConnections>);
}

#[path = "tests/memory_store.rs"]
mod memory;
pub(crate) use memory::{lose_next_reply, memory_store, memory_store_on, MemoryBackend};
