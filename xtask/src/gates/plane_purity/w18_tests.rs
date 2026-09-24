//! 1.6.0 ITEMS 179 AND 218's EXIT TESTS — each plants into a NON-kernel crate of the population the
//! row claims about, over a baseline whose row is GREEN, and asserts the row moves RED on the plant.
//!
//! * 179 — the forward `path-include` rule must see a `#[path]` include reaching into ANY plane
//!   crate the kind census resolves (`busbar-plane-*`, a codec), not only the legacy four engines.
//! * 218 — `core-llm-family-freeze` must walk every neutral root `planes::neutral_src_roots()`
//!   declares, so moving a concrete IR type from the kernel into another neutral crate does not
//!   declare the freeze met.

use crate::ctx::{Ctx, Overlay};
use crate::gates::plane_purity::{PlanePurityGate, ROW_FREEZE, ROW_PATH_INCLUDE};
use crate::gates::Gate;
use crate::ledger::{Status, Verdict};

fn row<'v>(v: &'v Verdict, id: &str) -> (&'v Status, &'v str) {
    let r = v
        .rows
        .iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("no row {id}"));
    (&r.status, r.detail.as_str())
}

fn assert_green_then_red(id: &str, plant_at: &str, plant: &str, needle: &str) {
    let cx = Ctx::workspace().expect("workspace");
    let gate = PlanePurityGate;
    let clean = gate.run(&cx);
    assert_eq!(
        row(&clean, id).0,
        &Status::Pass,
        "{id} must start GREEN: {}",
        row(&clean, id).1
    );
    let mut ov = Overlay::new();
    ov.set(plant_at, plant);
    let v = gate.run(&cx.with_overlay(ov));
    let (status, detail) = row(&v, id);
    assert_eq!(
        status,
        &Status::Fail,
        "{id} did not see the plant: {detail}"
    );
    assert!(
        detail.contains(needle),
        "{id} went red but not on the plant: {detail}"
    );
}

/// Item 179: a `#[path]` into `busbar-plane-llm` — a plane crate the legacy four-name list never
/// named — is a dual-compile exactly like one into `busbar-mcp`.
#[test]
fn a_path_include_into_a_busbar_plane_crate_reds_path_include() {
    assert_green_then_red(
        ROW_PATH_INCLUDE,
        "crates/busbar-kernel/src/planted_w18_path.rs",
        "#[path = \"../../../busbar-plane-llm/src/witness.rs\"]\nmod llm_witness;\n",
        "planted_w18_path.rs:1",
    );
}

/// Item 218: a concrete LLM-family IR type named in `busbar-contract` — a neutral root that is not
/// the kernel — holds the freeze open.
#[test]
fn a_concrete_ir_type_in_a_non_kernel_neutral_crate_reds_the_freeze() {
    assert_green_then_red(
        ROW_FREEZE,
        "crates/busbar-contract/src/planted_w18_freeze.rs",
        "pub fn f(_: IrStreamEvent) {}\n",
        "count=1",
    );
}
