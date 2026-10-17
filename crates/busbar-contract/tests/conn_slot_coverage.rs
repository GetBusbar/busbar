// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRAIT-TO-SLOT COVERAGE WITNESS for the connection table: the linked [`Conns`] trait
//! (`src/conn.rs`) and its lowering's declarative list (`src/abi/host/conn/mod.rs`) name exactly the same
//! operations. A method with no slot (a lowering that drops what a linked host does) is RED, and so
//! is a slot no method explains. The RED arm is kept.

use std::collections::BTreeSet;
use std::path::Path;

/// The `{ ... }` block that opens at `header` in `src`, braces balanced.
fn block<'a>(src: &'a str, header: &str) -> Result<&'a str, String> {
    let start = src
        .find(header)
        .ok_or_else(|| format!("`{header}` is not in the source"))?;
    let open = start + src[start..].find('{').ok_or("no block")?;
    let mut depth = 0_usize;
    for (i, c) in src[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(&src[open + 1..open + i]);
                }
            }
            _ => {}
        }
    }
    Err(format!("`{header}`'s block never closes"))
}

/// The methods a trait declares (`fn name`), outside comments.
fn methods(trait_block: &str) -> BTreeSet<String> {
    trait_block
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("//"))
        .filter_map(|l| l.strip_prefix("fn "))
        .map(|rest| {
            rest.split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .collect()
}

/// The slots a declarative list declares (`name: Alias = fn(...)`).
fn slots(list: &str) -> BTreeSet<String> {
    list.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("//"))
        .filter_map(|l| l.split_once(':'))
        .filter(|(name, ty)| {
            !name.contains(' ')
                && ty
                    .split_once('=')
                    .is_some_and(|(_, f)| f.trim().starts_with("fn("))
        })
        .map(|(name, _)| name.trim().to_string())
        .collect()
}

fn covered(traits: &str, abi: &str) -> Result<usize, String> {
    let methods = methods(block(traits, "pub trait Conns: ")?);
    let slots = slots(block(
        abi,
        "pub struct ConnSlots lowers Conns -> RawConnOutcome {",
    )?);
    if methods.is_empty() {
        return Err("`Conns` declares no method the witness can read".into());
    }
    let unlowered: Vec<_> = methods.difference(&slots).collect();
    let unexplained: Vec<_> = slots.difference(&methods).collect();
    if !unlowered.is_empty() || !unexplained.is_empty() {
        return Err(format!(
            "`Conns` -> `ConnSlots`: methods with no slot {unlowered:?}, slots no method explains \
             {unexplained:?}"
        ));
    }
    Ok(methods.len())
}

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn every_connection_operation_has_exactly_one_slot() {
    let (traits, abi) = (read("src/conn.rs"), read("src/abi/host/conn/mod.rs"));
    assert_eq!(covered(&traits, &abi), Ok(6));
}

/// THE RED ARM, kept: a trait that grew an operation its table did not, and a table that grew a slot
/// no operation explains, are each refused by name.
#[test]
fn an_operation_without_a_slot_and_a_slot_without_an_operation_are_red() {
    let (traits, abi) = (read("src/conn.rs"), read("src/abi/host/conn/mod.rs"));
    let grown = traits.replacen(
        "pub trait Conns: Send + Sync {",
        "pub trait Conns: Send + Sync {\n    fn peek(&self);",
        1,
    );
    assert_ne!(grown, traits, "the plant landed");
    let err = covered(&grown, &abi).unwrap_err();
    assert!(err.contains("methods with no slot [\"peek\"]"), "{err}");
    let widened = abi.replacen(
        "pub struct ConnSlots lowers Conns -> RawConnOutcome {",
        "pub struct ConnSlots lowers Conns -> RawConnOutcome {\n    peek: ConnPeekFn = fn(ctx: ConnCtx);",
        1,
    );
    assert_ne!(widened, abi, "the plant landed");
    let err = covered(&traits, &widened).unwrap_err();
    assert!(err.contains("slots no method explains [\"peek\"]"), "{err}");
}
