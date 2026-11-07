// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub type Rows = &'static [(&'static str, &'static str)];

static ROWS: std::sync::OnceLock<Rows> = std::sync::OnceLock::new();

pub fn install(rows: Rows) {
    let _ = ROWS.set(rows);
}

pub fn rows() -> Rows {
    ROWS.get().copied().unwrap_or(&[])
}

pub fn text(key: &str) -> &'static str {
    rows()
        .iter()
        .find(|(k, _)| *k == key)
        .map_or("", |(_, v)| v)
}
