//! Q128 AUDIT (xtask part 5) EXIT TESTS for `plane-purity` and `plane-purity-strict`. Each one
//! plants the thing a finding says the gate could not see, and asserts the row that owns it names
//! the plant.
//!
//! * HIGH — the BACKWARDS rule and the strict test-reach rows looked for `busbar_core`, a crate
//!   `busbar-kernel` absorbed, so a plane crate's reach into the kernel read as clean (Law 8: "Run a
//!   positive control before believing a zero").
//! * MEDIUM — the neutral population was a hand list (Law 8: "a roster maintained by hand is a
//!   defect with a date on it").
//! * MEDIUM — the file-count guards refused only zero (Law 8 shape 2, "the absent floor").
//! * MEDIUM — a strict ceiling raised in the change under judgement hid the rise (Law 9: "refuses
//!   every rise from that moment").
//! * MEDIUM (part 22) — a frozen-wire claim was checked for existence at its tag, not tied to what
//!   the pragma exempts (Law 10: a premise "written as a condition the runner evaluates").
//! * MEDIUM (part 22) — the IR freeze witness read a hand-typed list holding about half the LLM IR
//!   family (Law 8: a roster "derived from the instances' own declarations").

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::construction::ceilings::BASE_PIN_KEY;
use crate::gates::plane_purity::{
    strict, strict_category_row, PlanePurityGate, PlanePurityStrictGate, ROW_BACKWARDS,
    ROW_DENOMINATOR, ROW_FREEZE, ROW_FROZEN_WIRE_CLAIM, ROW_STRICT_REACH, ROW_SYMBOL,
};
use crate::gates::Gate;
use crate::ledger::{Status, Verdict};

fn row<'v>(v: &'v Verdict, id: &str) -> (&'v Status, &'v str) {
    let r = v.rows.iter().find(|r| r.id == id).unwrap_or_else(|| {
        panic!(
            "no row {id} in {:?}",
            v.rows.iter().map(|r| &r.id).collect::<Vec<_>>()
        )
    });
    (&r.status, r.detail.as_str())
}

fn assert_red_naming(v: &Verdict, id: &str, needle: &str) {
    let (status, detail) = row(v, id);
    assert_eq!(status, &Status::Fail, "{id} did not go red: {detail}");
    assert!(
        detail.contains(needle),
        "{id} is red but does not name `{needle}`: {detail}"
    );
}

/// The committed ceilings, pinned as the base's copy too: a strict run in a test has no merge-base
/// of its own, so the base is synthetic and says exactly what the committed file says.
fn strict_base_as_committed(cx: &Ctx, ov: &mut Overlay) -> String {
    let committed = cx.read(strict::STRICT_TOML).expect("ceilings file");
    ov.set_command(BASE_PIN_KEY, "q128strictbase");
    ov.set_command("git-ref:q128strictbase", "1");
    ov.set_command(
        format!("git-show:q128strictbase:{}", strict::STRICT_TOML),
        committed.clone(),
    );
    committed
}

/// HIGH. A plane crate naming the kernel — by path, by `extern crate`, and by a `use … as` rename —
/// is a backwards reach. The plant is in `busbar-plane-llm`, the in-tree plane crate.
#[test]
fn a_plane_crate_reaching_the_kernel_reds_backwards() {
    let cx = Ctx::workspace().expect("workspace");
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-plane-llm/src/planted_q128_reach.rs",
        "use busbar_kernel::plane_host::EngineHost;\nextern crate busbar_kernel_ledger;\nuse busbar_core_admin as admin;\n",
    );
    let v = PlanePurityGate.run(&cx.with_overlay(ov));
    for line in 1..=3 {
        assert_red_naming(&v, ROW_BACKWARDS, &format!("planted_q128_reach.rs:{line}"));
    }
}

/// HIGH. The test-reach ratchet covers the plane population, not the legacy-engine roster:
/// `busbar-plane-llm`'s own test code reaching the kernel is counted under its own key, and the
/// row sees it. (The per-key row ids became one row over the derived population: the owed set is
/// static and the population is not.)
#[test]
fn a_plane_crates_test_reach_has_its_own_row_and_it_sees_the_kernel() {
    let cx = Ctx::workspace().expect("workspace");
    assert!(
        PlanePurityStrictGate
            .owed()
            .contains(&ROW_STRICT_REACH.to_string()),
        "{ROW_STRICT_REACH} is not owed: {:?}",
        PlanePurityStrictGate.owed()
    );
    let mut ov = Overlay::new();
    strict_base_as_committed(&cx, &mut ov);
    ov.set(
        "crates/busbar-plane-llm/src/tests/planted_q128_reach.rs",
        "fn r() { let _ = busbar_kernel::teller::run_unit; }\n",
    );
    let v = PlanePurityStrictGate.run(&cx.with_overlay(ov));
    assert_red_naming(&v, ROW_STRICT_REACH, " plane-llm: 1 > ceiling 0");
}

/// MEDIUM. A neutral crate the kind table derives — a new kernel workflow crate — is scanned the
/// day it lands, not the day somebody adds it to a list.
#[test]
fn a_new_kernel_crate_is_in_the_neutral_scan() {
    let cx = Ctx::workspace().expect("workspace");
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-kernel-quux/Cargo.toml",
        "[package]\nname = \"busbar-kernel-quux\"\nversion = \"0.0.0\"\n",
    );
    ov.set(
        "crates/busbar-kernel-quux/src/lib.rs",
        "use busbar_plane_llm::Thing;\n",
    );
    let v = PlanePurityGate.run(&cx.with_overlay(ov));
    assert_red_naming(&v, ROW_SYMBOL, "busbar-kernel-quux/src/lib.rs:1");
}

/// Every `.rs` under `roots` removed but the first: a scan of one file.
fn all_but_one(cx: &Ctx, roots: &[String]) -> Overlay {
    let mut ov = Overlay::new();
    let files = cx
        .walk(&WalkSpec::new(roots.to_vec()).ext("rs").allow_empty())
        .expect("walk");
    assert!(files.len() > 1, "nothing to shrink under {roots:?}");
    for f in &files[1..] {
        ov.remove(&f.rel);
    }
    ov
}

fn neutral_roots_today(cx: &Ctx) -> Vec<String> {
    [
        "crates/busbar-kernel/src",
        "crates/busbar-kernel-audit/src",
        "crates/busbar-kernel-breaker/src",
        "crates/busbar-kernel-egress/src",
        "crates/busbar-kernel-identity/src",
        "crates/busbar-kernel-ledger/src",
        "crates/busbar-kernel-scope/src",
        "crates/busbar-kernel-wal/src",
        "crates/busbar-contract/src",
        "crates/plugin-loader/src",
        "crates/busbar-core-admin/src",
        "crates/busbar-core-connector/src",
        "crates/busbar-core-oauth2/src",
    ]
    .into_iter()
    .map(str::to_string)
    .filter(|r| cx.exists(r))
    .collect()
}

/// MEDIUM. A neutral scan that fell to one file is refused on the denominator AND on the freeze
/// walk, by its floor — not read as a cleaner tree.
#[test]
fn a_neutral_scan_of_one_file_is_below_its_floor() {
    let cx = Ctx::workspace().expect("workspace");
    let ov = all_but_one(&cx, &neutral_roots_today(&cx));
    let v = PlanePurityGate.run(&cx.with_overlay(ov));
    assert_red_naming(&v, ROW_DENOMINATOR, "below its floor");
    assert_red_naming(&v, ROW_FREEZE, "below its floor");
}

/// MEDIUM. The plane scan has its own floor.
#[test]
fn a_plane_scan_of_one_file_is_below_its_floor() {
    let cx = Ctx::workspace().expect("workspace");
    let roots = crate::gates::kind_isolation::plane_kind_src_roots(&cx).expect("plane roots");
    let ov = all_but_one(&cx, &roots);
    let v = PlanePurityGate.run(&cx.with_overlay(ov));
    assert_red_naming(&v, ROW_DENOMINATOR, "plane_files=1");
    assert_red_naming(&v, ROW_DENOMINATOR, "below its floor");
}

/// MEDIUM. A strict ceiling raised in the change under judgement is refused against the base.
#[test]
fn a_strict_ceiling_raised_over_the_base_is_refused() {
    let cx = Ctx::workspace().expect("workspace");
    let mut ov = Overlay::new();
    let committed = strict_base_as_committed(&cx, &mut ov);
    let ceilings = strict::parse_ceilings(&committed);
    let Some(strict::Ceiling::At(n)) = ceilings.get("DIALECT").cloned() else {
        panic!("no DIALECT ceiling in {}", strict::STRICT_TOML);
    };
    ov.set(
        strict::STRICT_TOML,
        committed.replace(&format!("DIALECT = {n}"), &format!("DIALECT = {}", n + 1)),
    );
    let v = PlanePurityStrictGate.run(&cx.with_overlay(ov));
    assert_red_naming(&v, &strict_category_row("DIALECT"), "raised");
}

/// MEDIUM (part 22). A pragma whose claim names a real 1.5.5 key (`providers:`) does not excuse a
/// type the claim never names: the exemption is tied to what the line carries.
#[test]
fn a_frozen_wire_claim_does_not_cover_a_name_it_does_not_name() {
    let cx = Ctx::workspace().expect("workspace");
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-kernel/src/planted_q128_claim.rs",
        "pub struct S { pub mcp_v2: McpV2Cfg, } // plane-purity: frozen-wire the `providers:` key (frozen since 1.5.5)\n",
    );
    let v = PlanePurityGate.run(&cx.with_overlay(ov));
    assert_red_naming(&v, ROW_FROZEN_WIRE_CLAIM, "McpV2Cfg");
}

/// MEDIUM (part 22). An LLM IR type the plane declares but the hand list never named is a freeze
/// hit when a neutral crate names it.
#[test]
fn an_llm_ir_type_off_the_hand_list_holds_the_freeze_open() {
    let cx = Ctx::workspace().expect("workspace");
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-contract/src/planted_q128_freeze.rs",
        "pub fn f(_: IrWebSearch) {}\n",
    );
    let v = PlanePurityGate.run(&cx.with_overlay(ov));
    assert_red_naming(&v, ROW_FREEZE, "count=1");
}
