// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! The `plugins.fetch` refusal text: one writer, the 1.5.5 bullet list, on boot and on reload.

/// The refusal header literal is written exactly once in appbuild.rs, inside the one formatter
/// both the boot projection and the reload use, so the two refusals cannot drift apart again.
#[test]
fn plugins_fetch_refusal_has_one_writer() {
    let source = include_str!("../appbuild.rs");
    let literal = concat!("\"", "plugins.fetch failed:");
    let writers: Vec<usize> = source.match_indices(literal).map(|(at, _)| at).collect();
    assert_eq!(
        writers.len(),
        1,
        "the plugins.fetch refusal header must have one writer in appbuild.rs, found {}",
        writers.len()
    );
    let formatter = source
        .find("fn plugins_fetch_refusal")
        .expect("appbuild.rs must define the one plugins.fetch refusal formatter");
    let body_end = source[formatter..]
        .find("\n}\n")
        .map(|end| formatter + end)
        .expect("the plugins.fetch refusal formatter must have a body");
    assert!(
        (formatter..body_end).contains(&writers[0]),
        "the one plugins.fetch refusal header must be written inside plugins_fetch_refusal"
    );
}

/// The boot and reload refusal is the 1.5.5 bullet list: a header, then one bullet per failed
/// target in the order the fetch reported them.
#[test]
fn plugins_fetch_refusal_is_the_1_5_5_bullet_list() {
    let errors: Vec<String> = vec!["a".into(), "b".into()];
    assert_eq!(
        super::plugins_fetch_refusal(&errors),
        "plugins.fetch failed:\n  - a\n  - b"
    );
    assert_eq!(
        super::plugins_fetch_refusal(&["no composition root installed the plugins fetch"]),
        "plugins.fetch failed:\n  - no composition root installed the plugins fetch"
    );
}
