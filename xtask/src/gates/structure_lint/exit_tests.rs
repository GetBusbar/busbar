//! EXIT TESTS for the structure-lint instrument items 183, 184, 222, 223, 224 and 236.
//!
//! Each drives the SHIPPED gate over the real workspace with a planted overlay (or a planted table)
//! and requires the row the item is about to NAME the plant. Every one of them was a plant the gate
//! could not see: a scope of seven crate prefixes, a plane list of two, a debt list nothing read, a
//! branch nothing could reach. They are written against the gate's public surface only, so the
//! same file drops into the tree before the fix and goes red there.

use crate::ctx::{Ctx, Overlay};
use crate::gates::structure_lint::{plane_dups, StructureLintGate, Tables};
use crate::gates::Gate;
use crate::ledger::{Status, Verdict};

const AXIS_PURITY: &str = "structure-lint:axis:purity";
const UNLEDGERED: &str = "structure-lint:plane-dup:unledgered";
const LEDGER_INTEGRITY: &str = "structure-lint:plane-dup:ledger-integrity";
const STALE_LEDGER: &str = "structure-lint:plane-dup:stale-ledger";
const PLANE_ROOTS: &str = "structure-lint:plane-roots";
const GRANDFATHERED: &str = "structure-lint:oversized:grandfathered";

fn row<'v>(v: &'v Verdict, id: &str) -> (&'v Status, &'v str) {
    let r = v
        .rows
        .iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("the gate emitted no `{id}` row at all"));
    (&r.status, r.detail.as_str())
}

fn names(v: &Verdict, id: &str, needles: &[&str]) {
    let (status, detail) = row(v, id);
    assert_eq!(
        status,
        &Status::Fail,
        "{id} must be RED over the plant: {detail}"
    );
    for n in needles {
        assert!(detail.contains(n), "{id} must name `{n}`: {detail}");
    }
}

fn run(ov: Overlay) -> Verdict {
    let cx = Ctx::workspace().expect("workspace");
    StructureLintGate::new().run(&cx.with_overlay(ov))
}

fn real_tables() -> Tables {
    let cx = Ctx::workspace().expect("workspace");
    let mut throwaway = crate::gates::structure_lint::Findings::default();
    Tables::real(&crate::gates::structure_lint::roots::resolve(
        &cx,
        &mut throwaway,
    ))
}

fn run_tables(t: Tables) -> Verdict {
    let cx = Ctx::workspace().expect("workspace");
    StructureLintGate::with_tables(t).run(&cx)
}

const BRANCH: &str =
    "pub fn pick(transport: Transport) -> u8 {\n    if transport == Transport::Http { 1 } else { 0 }\n}\n";

/// Item 183: the money path and the contract crate are in the agnostic core the axis ban judges.
#[test]
fn item_183_the_axis_ban_judges_the_money_path_and_the_contract() {
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-kernel-ledger/src/planted_axis_branch.rs",
        BRANCH,
    );
    ov.set("crates/busbar-contract/src/planted_axis_branch.rs", BRANCH);
    names(
        &run(ov),
        AXIS_PURITY,
        &[
            "crates/busbar-kernel-ledger/src/planted_axis_branch.rs:2",
            "crates/busbar-contract/src/planted_axis_branch.rs:2",
        ],
    );
}

/// Item 184: a concern duplicated between two planes that are not mcp+a2a is seen.
#[test]
fn item_184_a_duplicate_between_llm_and_voice_is_seen() {
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-llm/src/planted_llm_voice_copy.rs",
        "pub fn planted_llm_voice_copy() {}\n",
    );
    ov.set(
        "crates/busbar-voice/src/planted_llm_voice_copy.rs",
        "pub fn planted_llm_voice_copy() {}\n",
    );
    names(
        &run(ov),
        UNLEDGERED,
        &[
            "`planted_llm_voice_copy`",
            "llm:crates/busbar-llm/src/planted_llm_voice_copy.rs:1",
            "voice:crates/busbar-voice/src/planted_llm_voice_copy.rs:1",
        ],
    );
}

/// Item 223: a plane-local copy of another plane's helper (voice beside a2a) is seen, and a name the
/// ledger signed for mcp+a2a is NOT excused when a third plane grows a copy of it.
#[test]
fn item_223_a_voice_copy_of_a_plane_helper_is_seen_and_a_signed_claim_does_not_stretch() {
    let signed = plane_dups::ledger()
        .into_iter()
        .find(|r| r.name == "judge")
        .expect("the ledger signs `judge` for mcp and a2a");
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-voice/src/planted_voice_a2a_copy.rs",
        format!(
            "pub fn planted_voice_a2a_copy() {{}}\npub fn {}() {{}}\n",
            signed.name
        ),
    );
    ov.set(
        "crates/busbar-a2a/src/a2a/planted_voice_a2a_copy.rs",
        "pub fn planted_voice_a2a_copy() {}\n",
    );
    names(
        &run(ov),
        UNLEDGERED,
        &[
            "`planted_voice_a2a_copy`",
            "voice:crates/busbar-voice/src/planted_voice_a2a_copy.rs:1",
            "`judge`",
            "voice:crates/busbar-voice/src/planted_voice_a2a_copy.rs:2",
        ],
    );
}

/// Item 224: the plane set is derived — a plane on no constant is compared, and a plane the old
/// constant never named (voice) is judged by the plane-roots row.
#[test]
fn item_224_the_plane_set_is_derived_not_spelled() {
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-planted/src/lib.rs",
        "pub const PLANE_DECL: busbar_kernel::plane::registry::PlaneDecl = PLANTED;\n\
         pub fn planted_derived_plane_helper() {}\n",
    );
    ov.set(
        "crates/busbar-a2a/src/a2a/planted_derived_plane_helper.rs",
        "pub fn planted_derived_plane_helper() {}\n",
    );
    ov.set(
        "crates/busbar-planted-twin/src/voice/mod.rs",
        "pub const PLANE_DECL: busbar_kernel::plane::registry::PlaneDecl = PLANTED;\n",
    );
    let v = run(ov);
    names(
        &v,
        UNLEDGERED,
        &[
            "`planted_derived_plane_helper`",
            "planted:crates/busbar-planted/src/lib.rs:2",
        ],
    );
    names(&v, PLANE_ROOTS, &["PLANE-ROOT-AMBIGUOUS", "`voice`"]);
}

/// Item 222: the grandfathered list is measured — green on the shipped list, red on an entry that
/// names nothing, an entry under the cap, and a list past its ceiling.
#[test]
fn item_222_the_grandfathered_list_is_a_measured_ratchet() {
    let cx = Ctx::workspace().expect("workspace");
    let shipped = StructureLintGate::new().run(&cx);
    let (status, detail) = row(&shipped, GRANDFATHERED);
    assert_eq!(
        status,
        &Status::Pass,
        "the shipped list must be live debt: {detail}"
    );

    let mut t = real_tables();
    let n = t.grandfathered.len();
    t.grandfathered = vec![
        "crates/the-oversized-file-that-moved/src/lib.rs".to_string(),
        "crates/busbar-kernel/src/lib.rs".to_string(),
    ];
    for i in 0..n {
        t.grandfathered.push(format!(
            "crates/busbar-kernel/src/planted_new_monster_{i}.rs"
        ));
    }
    names(
        &run_tables(t),
        GRANDFATHERED,
        &[
            "GRANDFATHER-MISSING",
            "the-oversized-file-that-moved",
            "GRANDFATHER-RETIRED",
            "crates/busbar-kernel/src/lib.rs",
            "GRANDFATHER-LIST-GREW",
        ],
    );
}

/// Item 236: the DEBT half is reachable — a DEBT row naming an undeclared concern is refused even
/// when its name is duplicated nowhere, and a declared concern nothing is owed against is stale.
#[test]
fn item_236_the_debt_half_of_the_plane_ledger_can_fail() {
    let mut t = real_tables();
    let mut debt = t.plane_ledger[0].clone();
    debt.name = "a_debt_row_for_an_undeclared_concern".to_string();
    debt.class = plane_dups::Class::Debt;
    debt.concern = "a-concern-nobody-declared".to_string();
    t.plane_ledger.push(debt);
    t.plane_concerns.push(plane_dups::Concern {
        id: "a-concern-nothing-is-owed-against".to_string(),
        owner: "crates/busbar-kernel/src/nowhere".to_string(),
        remedy: "none".to_string(),
    });
    let v = run_tables(t);
    names(
        &v,
        LEDGER_INTEGRITY,
        &[
            "a_debt_row_for_an_undeclared_concern",
            "a-concern-nobody-declared",
        ],
    );
    names(
        &v,
        STALE_LEDGER,
        &["STALE-CONCERN", "a-concern-nothing-is-owed-against"],
    );
}
