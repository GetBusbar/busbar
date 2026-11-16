// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// THE MANIFEST ROW READER, shared by `build.rs` and every generator test through
// `src/linked_gen.rs` (which `include!`s it), and mounted alone by the test-source generator
// test, which reads rows and nothing else.

pub fn metadata_map(manifest: &str, table: &str) -> Vec<(String, String)> {
    let header = format!("[{table}]");
    let (mut in_table, mut present) = (false, false);
    let mut rows = Vec::new();
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.starts_with('[') {
            in_table = code == header;
            present |= in_table;
            continue;
        }
        if !in_table {
            continue;
        }
        if let Some((key, value)) = code.split_once('=') {
            rows.push((
                key.trim().trim_matches('"').to_string(),
                value.trim().trim_matches('"').to_string(),
            ));
        }
    }

    assert!(
        !present || !rows.is_empty(),
        "Cargo.toml: `{header}` is empty"
    );
    rows
}
