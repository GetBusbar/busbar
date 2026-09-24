// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The implementors of the sealed [`crate::plugin::KernelSeal`] trait, read off token.rs's own
//! code, against the enumeration [`KernelSeal::acquire_for_kernel`]'s documentation gives
//! (item 329). A fourth implementor, or one the documentation leaves out, fails here.

const SOURCE: &str = include_str!("../token.rs");

/// The short name of every type token.rs implements the plugin seal trait for, from code
/// lines only.
fn implementors() -> Vec<String> {
    let needle = "crate::plugin::KernelSeal for ";
    let mut out: Vec<String> = SOURCE
        .lines()
        .map(str::trim_start)
        .filter(|l| l.starts_with("impl"))
        .filter_map(|l| l.split_once(needle).map(|(_, rest)| rest))
        .map(|rest| {
            let ty = rest.split([' ', '{']).next().unwrap_or_default();
            let ty = ty.split('<').next().unwrap_or_default();
            ty.rsplit("::").next().unwrap_or_default().to_string()
        })
        .collect();
    out.sort();
    out
}

/// The `///` block directly above `pub fn acquire_for_kernel`.
fn acquire_doc() -> String {
    let lines: Vec<&str> = SOURCE.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.trim_start().starts_with("pub fn acquire_for_kernel"))
        .expect("the minter is declared in this file");
    let mut doc = Vec::new();
    for l in lines[..at].iter().rev() {
        let t = l.trim_start();
        if t.starts_with("///") {
            doc.push(t.trim_start_matches('/').trim());
        } else if t.starts_with("#[") {
            continue;
        } else {
            break;
        }
    }
    doc.reverse();
    doc.join(" ")
}

#[test]
fn the_minter_doc_names_every_seal_implementor_and_counts_them() {
    let found = implementors();
    assert_eq!(
        found,
        vec![
            "Grant".to_string(),
            "Pass".to_string(),
            "TestKernelSeal".to_string()
        ],
        "the seal trait's implementors in this file"
    );
    let doc = acquire_doc();
    for name in &found {
        assert!(
            doc.contains(name.as_str()),
            "`acquire_for_kernel`'s documentation leaves out the implementor `{name}`: {doc}"
        );
    }
    assert!(
        doc.contains("exactly three implementors"),
        "the documentation states the implementor count: {doc}"
    );
}
