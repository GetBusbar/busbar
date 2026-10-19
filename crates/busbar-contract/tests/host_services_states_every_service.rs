// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED (Q128 contract u17 LOW): `HostServices` says every service is required, with no default
//! body (Part 2 row 38(a): "a default body is a plugin quietly declining to answer"). A host that
//! forgets one must fail to compile, never inherit a refusal. The refusing defaults live in the
//! services double alone.

/// The body of `pub trait <name>` in `src`, comment lines dropped.
fn trait_body(src: &str, name: &str) -> String {
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .map(|l| format!("{l}\n"))
        .collect();
    let start = code
        .find(&format!("pub trait {name}"))
        .unwrap_or_else(|| panic!("`pub trait {name}` is in its file"));
    let open = start + code[start..].find('{').expect("the trait opens");
    let mut depth = 0usize;
    for (i, c) in code[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return code[open + 1..open + i].to_string();
                }
            }
            _ => {}
        }
    }
    panic!("`pub trait {name}` closes");
}

#[test]
fn red_every_host_service_is_stated_by_its_host() {
    let body = trait_body(include_str!("../src/services.rs"), "HostServices");
    let defaulted: Vec<&str> = body
        .split(';')
        .filter(|item| item.contains("fn ") && item.contains('{'))
        .filter_map(|item| {
            let at = item.find("fn ")?;
            item[at + 3..].split('(').next()
        })
        .collect();
    assert!(
        defaulted.is_empty(),
        "HostServices methods with a default body: {defaulted:?}"
    );
    assert!(
        body.contains("fn now("),
        "the scan reads the trait (positive control)"
    );
}
