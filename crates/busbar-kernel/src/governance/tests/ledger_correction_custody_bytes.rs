// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Correction custody, byte for byte. The positives a correction branch gives up, the cells it
//! keeps and a target's captured basis are stored records, so their bytes may not move.
//!
//! Each expected text below was written by the code as it stood before a cell's fee splits
//! stopped being folded into maps (commit a3456db589): the same fixtures, run there, printed
//! them. The fixtures charge their fee eras out of order, hold one era at no count and one only
//! in the flushed split, because the stored order of what comes out is ascending by era whatever
//! order the requests arrived in.

use super::*;
use crate::governance::exact_debt::ExactModelDelta;
use busbar_kernel_ledger::cost::EntryId;

const WINDOW: u64 = 1_700_000_000;

fn dated(at: u64) -> RawRateEra {
    RawRateEra::legacy(at)
}

fn entry(at: u64, id: u8) -> RawRateEra {
    RawRateEra {
        effective_from: at,
        entry_id: Some(EntryId([id; 12])),
    }
}

fn units(rows: &[(&str, i128)]) -> BTreeMap<String, Count> {
    rows.iter()
        .map(|(unit, n)| ((*unit).to_owned(), Count::from_integer(*n).unwrap()))
        .collect()
}

/// A fee split as requests leave it: each era charged `charged` times in the order given, then
/// refunded `refunded` times, so an era can be held with no count.
fn split(rows: &[(RawRateEra, u64, u64)]) -> RawFeeEras {
    let mut eras = RawFeeEras::default();
    for (era, charged, _) in rows {
        for _ in 0..*charged {
            eras.charge(*era);
        }
    }
    for (era, _, refunded) in rows {
        for _ in 0..*refunded {
            eras.refund(*era);
        }
    }
    eras
}

/// A cell's model row through its one constructor, which answers nothing for an unnamed lane
/// with no count: a cell takes the rows it answers, as production does.
fn model(
    name: &str,
    era: RawRateEra,
    cur: &[(&str, i128)],
    flushed: &[(&str, i128)],
) -> Option<ModelCell> {
    ModelCell::new(name.into(), era, units(cur), units(flushed), units(flushed))
}

/// The accepted branch: eras first charged 900, 300, 300 under an exact entry, then 600 (charged
/// and refunded, so held at no count); its flushed split names 450, which the live split does not.
fn accepted() -> BudgetCell {
    BudgetCell {
        group_owners: ["team-a".to_owned()].into(),
        window_start: WINDOW,
        requests: 40,
        billable_requests: 20,
        flushed_requests: 10,
        flushed_billable_requests: 6,
        models: [
            model(
                "m",
                dated(900),
                &[("input", 90), ("output", 7)],
                &[("input", 30)],
            ),
            model(
                "m",
                RawRateEra::legacy(0),
                &[("input", 12)],
                &[("input", 2)],
            ),
            model("n", entry(300, 7), &[("input", 5)], &[]),
        ]
        .into_iter()
        .flatten()
        .collect(),
        fee_eras: split(&[
            (dated(900), 5, 0),
            (dated(300), 4, 0),
            (entry(300, 7), 2, 0),
            (dated(600), 1, 1),
        ]),
        flushed_fee_eras: split(&[(dated(300), 1, 0), (dated(900), 2, 0), (dated(450), 1, 0)]),
        last_touch: 77,
        ..Default::default()
    }
}

/// The branch as it stood before the correction was accepted.
fn before() -> BudgetCell {
    BudgetCell {
        group_owners: ["team-a".to_owned()].into(),
        window_start: WINDOW,
        requests: 25,
        billable_requests: 9,
        flushed_requests: 10,
        flushed_billable_requests: 2,
        models: [
            model("m", dated(900), &[("input", 50)], &[("input", 30)]),
            model("m", RawRateEra::legacy(0), &[("input", 6)], &[("input", 2)]),
            model("n", entry(300, 7), &[("input", 1)], &[]),
        ]
        .into_iter()
        .flatten()
        .collect(),
        fee_eras: split(&[(dated(300), 3, 0), (dated(900), 1, 0)]),
        flushed_fee_eras: split(&[(dated(900), 1, 0)]),
        last_touch: 70,
        ..Default::default()
    }
}

/// A cell carrying rolled windows' debts, signed, in both forms.
fn rolled_cell() -> BudgetCell {
    let debt = |requests: i128, model: &str, unit: &str, micros: i128| ExactUsageDelta {
        requests,
        billable_requests: requests - 1,
        models: vec![ExactModelDelta {
            model: model.into(),
            scale: COUNT_SCALE,
            usage_units: BTreeMap::from([(unit.to_owned(), micros)]),
        }],
    };
    BudgetCell {
        rolled: vec![
            (WINDOW - 60, debt(3, "m", "input", 4_500_000)),
            (WINDOW - 120, debt(-2, "n", "output", -250_000)),
        ],
        rolled_eras: vec![(
            WINDOW - 60,
            debt(0, &era_model(dated(900), "m"), "input", 4_500_000),
        )],
        ..accepted()
    }
}

fn text<T: serde::Serialize>(value: &T) -> String {
    String::from_utf8(busbar_contract::json::to_vec(value).expect("custody encodes"))
        .expect("custody JSON is text")
}

/// The records written for `name` against the ones recorded for it; each is printed first, so a
/// run at another commit shows what that commit writes.
fn same_bytes(name: &str, actual: &[String], recorded: &[&str]) {
    for (at, record) in actual.iter().enumerate() {
        eprintln!("CUSTODY-BYTES {name} {at} {record}");
    }
    assert_eq!(actual, recorded, "{name}: the stored custody bytes moved");
}

/// The positives a branch gives up (plain, then dated) and both cells it keeps (the cell, then
/// its accepted branch), as custody stores each.
fn positives(common_only: bool) -> [String; 4] {
    let mut cell = before();
    cell.correction = Some(Box::new(CorrectionBranch {
        op_id: busbar_contract::records::OpId([7; 16]),
        window: WINDOW,
        accepted: accepted(),
    }));
    let (plain, dated) = take_positives_mode(&mut cell, WINDOW, common_only)
        .expect("the branch resolves")
        .expect("the cell holds the branch");
    let kept = &cell.correction.as_ref().expect("branch retained").accepted;
    [
        text(&plain),
        text(&dated),
        text(&RawCell::capture(&cell).expect("captures")),
        text(&RawCell::capture(kept).expect("captures")),
    ]
}

const ALL_POSITIVES: [&str; 4] = [
    r#"{"requests":"30","billable_requests":"15","models":[{"scale":6,"model":"m","usage_units":{"input":"70000000","output":"7000000"}},{"scale":6,"model":"n","usage_units":{"input":"5000000"}}]}"#,
    r#"{"requests":"0","billable_requests":"0","models":[{"scale":6,"model":"900\u001fm","usage_units":{"input":"60000000","output":"7000000"}},{"scale":6,"model":"busbar.raw-era.v1:300:070707070707070707070707\u001fn","usage_units":{"input":"5000000"}},{"scale":6,"model":"300","usage_units":{"billable_requests":"3000000"}},{"scale":6,"model":"busbar.raw-era.v1:300:070707070707070707070707","usage_units":{"billable_requests":"2000000"}},{"scale":6,"model":"900","usage_units":{"billable_requests":"3000000"}}]}"#,
    r#"{"group_owners":["team-a"],"window_start":1700000000,"requests":25,"billable_requests":9,"flushed_requests":40,"flushed_billable_requests":17,"models":[{"model":"m","era":{"effective_from":900,"entry_id":null},"current":{"input":50},"flushed":{"input":90,"output":7},"flushed_era":{"input":90,"output":7}},{"model":"m","era":{"effective_from":0,"entry_id":null},"current":{"input":6},"flushed":{"input":12},"flushed_era":{"input":2}},{"model":"n","era":{"effective_from":300,"entry_id":[7,7,7,7,7,7,7,7,7,7,7,7]},"current":{"input":1},"flushed":{"input":5},"flushed_era":{"input":5}}],"fee_eras":[[{"effective_from":300,"entry_id":null},3],[{"effective_from":900,"entry_id":null},1]],"flushed_fee_eras":[[{"effective_from":300,"entry_id":null},3],[{"effective_from":300,"entry_id":[7,7,7,7,7,7,7,7,7,7,7,7]},2],[{"effective_from":900,"entry_id":null},4]],"rolled":[],"rolled_eras":[],"last_touch":70}"#,
    r#"{"group_owners":["team-a"],"window_start":1700000000,"requests":40,"billable_requests":20,"flushed_requests":40,"flushed_billable_requests":21,"models":[{"model":"m","era":{"effective_from":900,"entry_id":null},"current":{"input":90,"output":7},"flushed":{"input":90,"output":7},"flushed_era":{"input":90,"output":7}},{"model":"m","era":{"effective_from":0,"entry_id":null},"current":{"input":12},"flushed":{"input":12},"flushed_era":{"input":2}},{"model":"n","era":{"effective_from":300,"entry_id":[7,7,7,7,7,7,7,7,7,7,7,7]},"current":{"input":5},"flushed":{"input":5},"flushed_era":{"input":5}}],"fee_eras":[[{"effective_from":900,"entry_id":null},5],[{"effective_from":300,"entry_id":null},4],[{"effective_from":300,"entry_id":[7,7,7,7,7,7,7,7,7,7,7,7]},2]],"flushed_fee_eras":[[{"effective_from":300,"entry_id":null},4],[{"effective_from":300,"entry_id":[7,7,7,7,7,7,7,7,7,7,7,7]},2],[{"effective_from":450,"entry_id":null},1],[{"effective_from":900,"entry_id":null},5]],"rolled":[],"rolled_eras":[],"last_touch":77}"#,
];
const COMMON_POSITIVES: [&str; 4] = [
    r#"{"requests":"15","billable_requests":"7","models":[{"scale":6,"model":"m","usage_units":{"input":"24000000"}},{"scale":6,"model":"n","usage_units":{"input":"1000000"}}]}"#,
    r#"{"requests":"0","billable_requests":"0","models":[{"scale":6,"model":"900\u001fm","usage_units":{"input":"20000000"}},{"scale":6,"model":"busbar.raw-era.v1:300:070707070707070707070707\u001fn","usage_units":{"input":"1000000"}},{"scale":6,"model":"300","usage_units":{"billable_requests":"3000000"}}]}"#,
    r#"{"group_owners":["team-a"],"window_start":1700000000,"requests":25,"billable_requests":9,"flushed_requests":25,"flushed_billable_requests":9,"models":[{"model":"m","era":{"effective_from":900,"entry_id":null},"current":{"input":50},"flushed":{"input":50},"flushed_era":{"input":50}},{"model":"m","era":{"effective_from":0,"entry_id":null},"current":{"input":6},"flushed":{"input":6},"flushed_era":{"input":2}},{"model":"n","era":{"effective_from":300,"entry_id":[7,7,7,7,7,7,7,7,7,7,7,7]},"current":{"input":1},"flushed":{"input":1},"flushed_era":{"input":1}}],"fee_eras":[[{"effective_from":300,"entry_id":null},3],[{"effective_from":900,"entry_id":null},1]],"flushed_fee_eras":[[{"effective_from":300,"entry_id":null},3],[{"effective_from":900,"entry_id":null},1]],"rolled":[],"rolled_eras":[],"last_touch":70}"#,
    r#"{"group_owners":["team-a"],"window_start":1700000000,"requests":40,"billable_requests":20,"flushed_requests":25,"flushed_billable_requests":13,"models":[{"model":"m","era":{"effective_from":900,"entry_id":null},"current":{"input":90,"output":7},"flushed":{"input":50},"flushed_era":{"input":50}},{"model":"m","era":{"effective_from":0,"entry_id":null},"current":{"input":12},"flushed":{"input":6},"flushed_era":{"input":2}},{"model":"n","era":{"effective_from":300,"entry_id":[7,7,7,7,7,7,7,7,7,7,7,7]},"current":{"input":5},"flushed":{"input":1},"flushed_era":{"input":1}}],"fee_eras":[[{"effective_from":900,"entry_id":null},5],[{"effective_from":300,"entry_id":null},4],[{"effective_from":300,"entry_id":[7,7,7,7,7,7,7,7,7,7,7,7]},2]],"flushed_fee_eras":[[{"effective_from":300,"entry_id":null},4],[{"effective_from":450,"entry_id":null},1],[{"effective_from":900,"entry_id":null},2]],"rolled":[],"rolled_eras":[],"last_touch":77}"#,
];
const CAPTURED_CELL: [&str; 1] = [
    r#"{"group_owners":["team-a"],"window_start":1700000000,"requests":40,"billable_requests":20,"flushed_requests":10,"flushed_billable_requests":6,"models":[{"model":"m","era":{"effective_from":900,"entry_id":null},"current":{"input":90,"output":7},"flushed":{"input":30},"flushed_era":{"input":30}},{"model":"m","era":{"effective_from":0,"entry_id":null},"current":{"input":12},"flushed":{"input":2},"flushed_era":{"input":2}},{"model":"n","era":{"effective_from":300,"entry_id":[7,7,7,7,7,7,7,7,7,7,7,7]},"current":{"input":5},"flushed":{},"flushed_era":{}}],"fee_eras":[[{"effective_from":900,"entry_id":null},5],[{"effective_from":300,"entry_id":null},4],[{"effective_from":300,"entry_id":[7,7,7,7,7,7,7,7,7,7,7,7]},2]],"flushed_fee_eras":[[{"effective_from":300,"entry_id":null},1],[{"effective_from":900,"entry_id":null},2],[{"effective_from":450,"entry_id":null},1]],"rolled":[[1699999940,{"scale":6,"requests":"3","billable_requests":"2","models":{"m":{"input":"4500000"}}}],[1699999880,{"scale":6,"requests":"-2","billable_requests":"-3","models":{"n":{"output":"-250000"}}}]],"rolled_eras":[[1699999940,{"scale":6,"requests":"0","billable_requests":"-1","models":{"900\u001fm":{"input":"4500000"}}}]],"last_touch":77}"#,
];
const CAPTURED_TARGET: [&str; 3] = [
    r#"{"group_owners":["team-a"],"window_start":1700000000,"requests":30,"billable_requests":14,"flushed_requests":0,"flushed_billable_requests":0,"models":[{"model":"m","era":{"effective_from":0,"entry_id":null},"current":{"input":10},"flushed":{},"flushed_era":{}},{"model":"n","era":{"effective_from":0,"entry_id":null},"current":{},"flushed":{},"flushed_era":{}},{"model":"m","era":{"effective_from":900,"entry_id":null},"current":{"input":60,"output":7},"flushed":{},"flushed_era":{}},{"model":"n","era":{"effective_from":300,"entry_id":[7,7,7,7,7,7,7,7,7,7,7,7]},"current":{"input":5},"flushed":{},"flushed_era":{}}],"fee_eras":[[{"effective_from":300,"entry_id":null},3],[{"effective_from":300,"entry_id":[7,7,7,7,7,7,7,7,7,7,7,7]},2],[{"effective_from":900,"entry_id":null},3]],"flushed_fee_eras":[],"rolled":[],"rolled_eras":[],"last_touch":77}"#,
    r#"{"requests":30,"billable_requests":14,"models":[{"scale":6,"model":"m","usage_units":{"input":70000000,"output":7000000}},{"scale":6,"model":"n","usage_units":{"input":5000000}}]}"#,
    r#"{"requests":0,"billable_requests":0,"models":[{"scale":6,"model":"900\u001fm","usage_units":{"input":60000000,"output":7000000}},{"scale":6,"model":"busbar.raw-era.v1:300:070707070707070707070707\u001fn","usage_units":{"input":5000000}},{"scale":6,"model":"300","usage_units":{"billable_requests":3000000}},{"scale":6,"model":"busbar.raw-era.v1:300:070707070707070707070707","usage_units":{"billable_requests":2000000}},{"scale":6,"model":"900","usage_units":{"billable_requests":3000000}}]}"#,
];

#[test]
fn every_positive_a_current_branch_gives_up_keeps_its_bytes() {
    same_bytes("all-positives", &positives(false), &ALL_POSITIVES);
}

#[test]
fn the_common_positives_of_a_current_branch_keep_their_bytes() {
    same_bytes("common-positives", &positives(true), &COMMON_POSITIVES);
}

/// A record captured before the change, read back and captured again, is the same record.
#[test]
fn a_captured_cell_read_back_and_captured_again_is_the_same_record() {
    let captured = text(&RawCell::capture(&rolled_cell()).expect("captures"));
    same_bytes("captured-cell", &[captured], &CAPTURED_CELL);
    let stored: RawCell =
        busbar_contract::json::parse(CAPTURED_CELL[0].as_bytes()).expect("the record reads back");
    let restored = stored.restore("bucket").expect("the record restores");
    assert_eq!(
        text(&RawCell::capture(&restored).expect("captures")),
        CAPTURED_CELL[0],
        "restored and captured again"
    );
}

/// A target's basis for a correction: the fee differences land era by era, ascending.
#[test]
fn a_target_captured_for_a_correction_keeps_its_bytes() {
    let live = BudgetCell {
        flushed_fee_eras: split(&[(dated(300), 1, 0), (dated(900), 2, 0)]),
        ..accepted()
    };
    let (basis, plain, dated) = capture_target(
        "bucket",
        Some(&live),
        &UsageLedger::default(),
        &UsageLedger::default(),
        WINDOW,
    )
    .expect("the target captures");
    let captured = [
        text(&RawCell::capture(&basis).expect("captures")),
        text(&plain),
        text(&dated),
    ];
    same_bytes("captured-target", &captured, &CAPTURED_TARGET);
}

/// What this thread holds now: what it was handed less what it gave back, by jemalloc's own
/// per-thread counters.
#[cfg(not(target_env = "msvc"))]
fn held() -> u64 {
    let handed = tikv_jemalloc_ctl::thread::allocatedp::read()
        .expect("jemalloc's thread.allocatedp is readable")
        .get();
    let returned = tikv_jemalloc_ctl::thread::deallocatedp::read()
        .expect("jemalloc's thread.deallocatedp is readable")
        .get();
    handed.wrapping_sub(returned)
}

/// The custody record is an owned copy of the cell, kept only until it is encoded or restored:
/// when the record, its bytes and the cell read back from them are dropped, every byte they
/// allocated has gone back.
#[cfg(not(target_env = "msvc"))]
#[test]
fn a_custody_record_captured_encoded_and_read_back_releases_all_it_allocated() {
    let cell = rolled_cell();
    let work = || {
        let record = RawCell::capture(&cell).expect("captures");
        let bytes = busbar_contract::json::to_vec(&record).expect("encodes");
        let read: RawCell = busbar_contract::json::parse(&bytes).expect("decodes");
        let restored = read.restore("bucket").expect("restores");
        drop((record, bytes, restored));
    };
    // The first pass pays for anything made once per process or thread.
    work();
    let before = held();
    work();
    assert_eq!(
        held(),
        before,
        "the record, its bytes and the restored cell gave back all they allocated"
    );
}
