// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PINNED PLANES ARE READ, NEVER SKIPPED (ARCHITECT row 106 (A)).
//!
//! A plane crate that left this tree for its own repo is laid back as every gate's BASE layer
//! (`Ctx::workspace`, `kind_isolation::plane_base`): read from the checkout cargo fetched for the rev
//! `Cargo.lock` pins, at the directory it lived at, never written into the tree (spec #39). These
//! cases hold the three things that makes true:
//!
//! * THE BASE IS LAID, from the checkout, and the tree on disk has no file of it.
//! * EVERY GATE FAMILY THAT READS A PLANE'S OWN SOURCE GOES RED WITHOUT IT (condition 3): a row that
//!   passes over the tree with the base passes no longer with the base removed. A gate that reported
//!   nothing missing over a plane it could not read would be a gate that scans nothing and says so
//!   green.
//! * A PLANT STILL WINS OVER THE BASE (condition 4): `with_overlay` keeps the base beneath the plant.

use std::collections::BTreeSet;
use std::path::PathBuf;

use xtask::ctx::{Ctx, Overlay};
use xtask::gates;
use xtask::ledger::Status;

fn workspace() -> Ctx {
    Ctx::workspace().expect("the workspace opens with its pinned planes")
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask sits in the workspace")
        .to_path_buf()
}

#[test]
fn the_base_lays_each_pinned_plane_from_its_checkout_and_none_of_it_is_on_disk() {
    let cx = workspace();
    let base = cx
        .base()
        .expect("the workspace pins a plane, laid as the base layer");
    let paths: Vec<String> = base
        .paths()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    assert!(
        paths.iter().any(|p| p.ends_with("/Cargo.toml")),
        "the base lays no crate manifest: {paths:?}"
    );
    for p in &paths {
        assert!(
            p.starts_with("crates/busbar-plane-"),
            "{p} is not a plane's"
        );
        assert!(
            !root().join(p).exists(),
            "{p} is on disk: a pinned plane's source re-entered the tree"
        );
        assert!(cx.exists(p) && cx.read(p).is_ok(), "{p} does not read");
        assert!(!cx.without_base().exists(p), "{p} is read without the base");
    }
}

#[test]
fn a_plant_wins_over_the_base_and_keeps_it_beneath() {
    let cx = workspace();
    let base = cx.base().expect("the base layer");
    let mut files = base.paths().map(|p| p.to_string_lossy().into_owned());
    let planted = files.next().expect("a laid file");
    let other = files.next().expect("a second laid file");
    let mut ov = Overlay::new();
    ov.set(&planted, "planted\n");
    let pcx = cx.with_overlay(ov);
    assert_eq!(pcx.read(&planted).as_deref(), Ok("planted\n"));
    assert_eq!(
        pcx.read(&other),
        cx.read(&other),
        "the base stays beneath the plant"
    );
}

/// A row that passes with the pinned planes laid and does not pass without them, for `name`.
fn goes_red_without_the_base(name: &str) {
    let cx = workspace();
    assert!(cx.base().is_some(), "the workspace pins a plane");
    let reg = gates::find(name).unwrap_or_else(|| panic!("no gate `{name}`"));
    let gate = (reg.build)();
    let with = gates::execute(gate.as_ref(), &cx);
    let without = gates::execute(gate.as_ref(), &cx.without_base());
    let passing = |v: &xtask::ledger::Verdict| -> BTreeSet<String> {
        v.rows
            .iter()
            .filter(|r| r.status == Status::Pass)
            .map(|r| r.id.clone())
            .collect()
    };
    let (with, without) = (passing(&with), passing(&without));
    let lost: Vec<&String> = with.difference(&without).collect();
    assert!(
        !lost.is_empty(),
        "`{name}` passes the same rows with the pinned planes removed ({with:?}): it reads nothing \
         of them, and a plane it cannot read is a plane it answers for as clean"
    );
}

#[test]
fn structure_lint_goes_red_without_the_base() {
    goes_red_without_the_base("structure-lint");
}

#[test]
fn config_schema_goes_red_without_the_base() {
    goes_red_without_the_base("config-schema");
}

#[test]
fn no_float_money_goes_red_without_the_base() {
    goes_red_without_the_base("no-float-money");
}

#[test]
fn plane_purity_goes_red_without_the_base() {
    goes_red_without_the_base("plane-purity");
}

#[test]
fn reachability_goes_red_without_the_base() {
    goes_red_without_the_base("reachability");
}
