// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A PLANE REGISTERS CONTRACT DATA, NEVER A KERNEL TYPE.
//!
//! The item a plane exports to be registered — its `PLANE_DECLARATION`, found by the same column-0
//! `pub const PLANE_DECL…` grammar the plane-root resolver keys on — is a
//! `busbar_contract::plane::PlaneDeclaration`: plain data naming no `busbar_kernel` item. The
//! behaviour table (`PLANE_HOOKS`) is typed by kernel seams and the KERNEL joins the two
//! (`PlaneDecl::assemble`); it is not the registration item and is not judged here.
//!
//! Why it is a test and not a convention: when the retiring engine crates fold into their
//! `busbar-plane-*` crates, whatever a plane exports for registration moves with it. A registration
//! item typed by the kernel would hand every folded plane crate a kernel edge — the #40 violation
//! the plane crates exist to be free of (BUSBAR-1.6.0.md, "SEQUENCING TRAP"). So this reads the whole
//! `crates/` tree, not a list of today's planes: a plane added tomorrow is judged the day it lands,
//! and a plane that brings back a kernel-typed `PLANE_DECL` is refused by name.

use std::path::{Path, PathBuf};

/// The registration grammar, at column 0 of a production line (an indented `PLANE_DECL` is the hot
/// lane's ABI symbol-name constant, not a declaration).
const GRAMMAR: [&str; 2] = ["pub const PLANE_DECL", "pub static PLANE_DECL"];

/// The contract type every engine plane's registration item is written as.
const CONTRACT_TYPE: &str = "busbar_contract::plane::PlaneDeclaration";

/// One registration item: where it is, its declared type, and its full text.
struct Item {
    at: String,
    ty: String,
    text: String,
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if name != "target" && name != "fixtures" {
                rust_files(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every registration item under `crates/*/src/`, with the item's text up to its closing `};`.
fn registration_items(crates: &Path) -> Vec<Item> {
    let mut files = Vec::new();
    rust_files(crates, &mut files);
    let mut items = Vec::new();
    for file in files {
        let rel = file
            .strip_prefix(crates)
            .unwrap()
            .to_string_lossy()
            .to_string();
        if !rel.contains("/src/") {
            continue;
        }
        let src = std::fs::read_to_string(&file).unwrap();
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !GRAMMAR.iter().any(|g| line.starts_with(g)) {
                continue;
            }
            let end = (i..lines.len())
                .find(|&j| lines[j].trim_end().ends_with(';'))
                .unwrap_or(i);
            let text = lines[i..=end].join("\n");
            let ty = text
                .split_once(':')
                .and_then(|(_, rest)| rest.split_once('='))
                .map(|(ty, _)| ty.trim().to_string())
                .unwrap_or_default();
            items.push(Item {
                at: format!("crates/{rel}:{}", i + 1),
                ty,
                text,
            });
        }
    }
    items
}

/// The verdict on one item: `Some(reason)` when it names the kernel.
fn names_the_kernel(item: &Item, file_src: &str) -> Option<String> {
    if item.text.contains("busbar_kernel") {
        return Some(format!(
            "{} names a `busbar_kernel` item in its registration export:\n{}",
            item.at, item.text
        ));
    }
    // A bare type name is judged by where the file imports it from, so an import alias cannot hide
    // a kernel type behind a short name.
    if !item.ty.contains("::") {
        let imported_from_kernel = file_src.lines().any(|l| {
            let l = l.trim_start();
            l.starts_with("use busbar_kernel")
                && l.split(|c: char| !c.is_alphanumeric() && c != '_')
                    .any(|w| w == item.ty)
        });
        if imported_from_kernel {
            return Some(format!(
                "{} is typed `{}`, which its file imports from `busbar_kernel`",
                item.at, item.ty
            ));
        }
    }
    None
}

#[test]
fn every_plane_registration_item_is_contract_data_naming_no_kernel_type() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let crates = crates.canonicalize().unwrap();
    let items = registration_items(&crates);

    let offenders: Vec<String> = items
        .iter()
        .filter_map(|item| {
            let file = item.at.rsplit_once(':').unwrap().0;
            let src =
                std::fs::read_to_string(crates.join(file.trim_start_matches("crates/"))).unwrap();
            names_the_kernel(item, &src)
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "a plane's registration export must be contract data (`{CONTRACT_TYPE}`) naming no kernel \
         type; the behaviour table is the kernel's to join (`PlaneDecl::assemble`):\n{}",
        offenders.join("\n")
    );

    // NON-VACUITY: the engine planes and the composition root's decision plane register through the
    // contract type. Fewer than five read means the scan read nothing, and zero offenders over zero
    // items is not a pass.
    let contract_typed = items.iter().filter(|i| i.ty == CONTRACT_TYPE).count();
    assert!(
        contract_typed >= 5,
        "expected at least five `{CONTRACT_TYPE}` registration items under crates/, found \
         {contract_typed}: {:?}",
        items.iter().map(|i| &i.at).collect::<Vec<_>>()
    );
}
