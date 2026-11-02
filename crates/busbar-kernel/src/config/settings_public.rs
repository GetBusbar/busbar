// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeSet;
use std::sync::OnceLock;

pub trait PublicSettings: Send + Sync {
    fn public(&self, module: &str) -> BTreeSet<String>;
}

static TABLE: OnceLock<&'static dyn PublicSettings> = OnceLock::new();

pub fn install(table: &'static dyn PublicSettings) {
    let _ = TABLE.set(table);
}

#[must_use]
pub fn public(module: &str) -> BTreeSet<String> {
    TABLE
        .get()
        .map(|t| t.public(module.trim()))
        .unwrap_or_default()
}
