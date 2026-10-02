//! `lean-core`'s review list matches a reviewed literal by its file and its exact text
//! (ARCHITECT 2026-10-02, STANDING-REDS lean-core option 2), not by its line number.

use super::rules2::{lean_core, lean_core_key, lean_core_key_of};
use super::tree::Tree;
use super::{ConstructionGate, CEILINGS};
use crate::ctx::{Ctx, Overlay};
use crate::gates::construction::model::CRow;

const HOME: &str = "crates/busbar-kernel/src/appbuild.rs";
const REVIEWED: &str = "model '{model}' references unknown provider '{}'";

fn row(cx: &Ctx) -> Result<CRow, String> {
    let cfg = ConstructionGate::cfg(cx).expect("ceilings");
    let tree = Tree::load(
        cx,
        &cfg.scan_roots().expect("scan roots"),
        &cfg.test_path_fragments().expect("fragments"),
    )
    .expect("tree");
    lean_core(cx, &tree, &cfg).map(|mut rows| rows.remove(0))
}

fn with(cx: &Ctx, rel: &str, text: String) -> Ctx {
    let mut ov = Overlay::new();
    ov.set(rel, text);
    cx.with_overlay(ov)
}

#[test]
fn a_reviewed_literal_stays_reviewed_when_lines_move_above_it() {
    let cx = Ctx::workspace().expect("workspace");
    let text = cx.read(HOME).expect("the reviewed literal's home");
    assert!(
        text.contains(&format!("\"{REVIEWED}\"")),
        "the control needs the literal on disk"
    );
    let clean = row(&cx).expect("the rule runs");
    let moved = row(&with(&cx, HOME, format!("\n\n\n{text}"))).expect("the rule runs");
    assert_eq!(moved.current, clean.current, "{}", moved.detail);
    assert!(!moved.detail.contains(REVIEWED), "{}", moved.detail);
}

#[test]
fn a_new_literal_in_a_reviewed_file_is_not_reviewed() {
    let cx = Ctx::workspace().expect("workspace");
    let text = cx.read(HOME).expect("the reviewed literal's home");
    let clean = row(&cx).expect("the rule runs");
    let planted = format!("{text}\npub const PLANTED_LEAN: &str = \"planted model literal\";\n");
    let got = row(&with(&cx, HOME, planted)).expect("the rule runs");
    assert_eq!(got.current, clean.current + 1, "{}", got.detail);
    assert!(
        got.offenders
            .iter()
            .any(|o| o.contains("planted model literal")),
        "{:?}",
        got.offenders
    );
}

#[test]
fn an_entry_that_matches_no_literal_is_reported_stale() {
    let cx = Ctx::workspace().expect("workspace");
    let ceilings = cx.read(CEILINGS).expect("ceilings");
    let clean = row(&cx).expect("the rule runs");
    let dead = lean_core_key(HOME, "a model literal nobody wrote");
    let text = super::ceilings::add_to_list(&ceilings, "rules.lean-core", "known_sites", &[dead])
        .expect("[rules.lean-core] known_sites");
    let got = row(&with(&cx, CEILINGS, text)).expect("the rule runs");
    assert_eq!(got.current, clean.current + 1, "{}", got.detail);
    assert!(
        got.offenders
            .iter()
            .any(|o| o.starts_with("stale known_sites entry")),
        "{:?}",
        got.offenders
    );
}

#[test]
fn a_line_number_entry_is_refused() {
    let cx = Ctx::workspace().expect("workspace");
    let ceilings = cx.read(CEILINGS).expect("ceilings");
    let text = super::ceilings::add_to_list(
        &ceilings,
        "rules.lean-core",
        "known_sites",
        &[format!("{HOME}:705")],
    )
    .expect("[rules.lean-core] known_sites");
    let err = row(&with(&cx, CEILINGS, text)).expect_err("a path:line entry is refused");
    assert!(err.contains("is not `<path> :: <literal text>`"), "{err}");
}

#[test]
fn an_offender_converts_to_the_entry_that_reviews_it() {
    let o = format!("\"{REVIEWED}\" at {HOME}:705");
    assert_eq!(lean_core_key_of(&o), Some(lean_core_key(HOME, REVIEWED)));
    assert_eq!(
        lean_core_key_of("stale known_sites entry `x`: strike it"),
        None
    );
}
