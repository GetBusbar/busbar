// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-WATCH-CEILING (ABI-MIN3-INTERFACE §14): Ceilings with a fake clock in `scan` (round 14).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).
//!
//! Arms (a)'s watchdog half, (e) and (f) run now: `scan` is one 100 ms tick per call, so the "fake clock" is the
//! number of calls, and the slot table's `hung` is driven directly. Arms (b)-(d) and (a)'s migrate refusal need
//! a booted lane-store fixture whose entries pass their ceilings, and stay ignored.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use busbar_plugin_abi::host::{enter, init, leave, scan};
use busbar_plugin_abi::host_side::scrub::Scrub;
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::instance::{ErrorBook, SlotRecord, SlotTable};

/// A slot number no other case's entries use.
const SLOT: u32 = 0x00AB_CDEF;
/// Two entry indices standing for a migrate that declared a long ceiling and one that did not.
const LONG_ENTRY: u8 = 10;
const SHORT_ENTRY: u8 = 11;

/// Leaves the entry on drop, so a failed assertion cannot leave this thread's word busy.
struct Entered;

impl Entered {
    fn at(slot: u32, entry: u8) -> Entered {
        init();
        enter(slot, entry);
        Entered
    }
}

impl Drop for Entered {
    fn drop(&mut self) {
        leave();
    }
}

/// Scan `ticks` times (100 ms each) with `ceiling_us` for this case's slot and no ceiling for any other word;
/// the tick (1-based) at which `(SLOT, entry)` was reported, if it was, and how often.
fn scan_ticks(ticks: u32, entry: u8, ceiling_us: u32) -> (Option<(u32, u64)>, usize) {
    let (mut at, mut reports) = (None, 0);
    for tick in 1..=ticks {
        scan(
            |slot, e| {
                if slot == SLOT && e == entry {
                    (ceiling_us, 1)
                } else {
                    (0, 0)
                }
            },
            |slot, _epoch, e, busy_ms| {
                if slot == SLOT && e == entry {
                    reports += 1;
                    at.get_or_insert((tick, busy_ms));
                }
            },
        );
    }
    (at, reports)
}

fn record() -> SlotRecord {
    SlotRecord {
        kind: KindCode::Store,
        name: Arc::from("lane"),
        scrub: Arc::new(Scrub::new()),
        errors: &ErrorBook::None,
        undeclared_warned: AtomicBool::new(false),
    }
}

#[test]
fn a_declared_long_ceiling_is_not_reported_and_the_default_is_reported_once_at_5_s() {
    {
        let _migrating = Entered::at(SLOT, LONG_ENTRY);
        // The declaration: CEIL_MIGRATE 3,600 s; the first poll runs 10 s (100 ticks).
        let (reported, count) = scan_ticks(100, LONG_ENTRY, 3_600_000_000);
        assert_eq!((reported, count), (None, 0), "10 s under a 3,600 s ceiling");
    }
    let _migrating = Entered::at(SLOT, SHORT_ENTRY);
    // The same entry with the default 5 s ceiling: seen at tick 1, reported when its busy time reaches 5 s.
    let (reported, count) = scan_ticks(100, SHORT_ENTRY, 5_000_000);
    let (tick, busy_ms) = reported.expect("the default ceiling is reported");
    // A Registry's own watchdog thread may share the global tick, so ticks can only come faster than this
    // case's scans: reported by the 51st scan at the latest (5 s + 100 ms), at a busy time of at least 5 s.
    assert!(busy_ms >= 5_000 && busy_ms % 100 == 0, "busy {busy_ms} ms");
    assert!(
        tick <= 51,
        "reported at scan {tick}: 5 s + 100 ms at the latest"
    );
    assert_eq!(count, 1, "reported once, never again");
}

/// (e) The reuse race: an entry ends, its slot is released and re-allocated to another instance between two
/// scans; `hung(slot, old_epoch, ..)` quarantines nobody. The control: the same call with the current epoch does.
#[test]
fn a_report_for_a_released_epoch_quarantines_the_slots_next_owner_not() {
    let table = Arc::new(SlotTable::new());
    let row = [5_000_000u32; 64];
    let first = table.alloc(record(), &row);
    let (slot, old_epoch) = (first.slot(), first.epoch());
    assert_eq!(table.watch_view(slot, 3), (5_000_000, old_epoch));
    drop(first);
    let second = table.alloc(record(), &row);
    assert_eq!(second.slot(), slot, "the released slot is re-allocated");
    assert!(second.epoch() > old_epoch, "with a later epoch");
    table.hung(slot, old_epoch, 3, 5_100);
    assert!(
        second.is_live(),
        "the old epoch's report quarantines nobody"
    );
    table.hung(slot, second.epoch(), 3, 5_100);
    assert!(
        !second.is_live(),
        "the current epoch's report quarantines its owner"
    );
}

/// (f) `scan` takes no Instance: the watchdog module names none in code (comments may say so).
#[test]
fn the_watchdog_module_names_no_instance() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../busbar-plugin-abi/src/host_side/watch.rs");
    let text = std::fs::read_to_string(&path).expect("watch.rs");
    for (n, line) in text.lines().enumerate() {
        let code = line.trim_start();
        if code.starts_with("//") {
            continue;
        }
        assert!(
            !code.contains("Instance"),
            "watch.rs:{}: the watchdog names an Instance: {code}",
            n + 1
        );
    }
}

#[test]
#[ignore = "owner: W1-L2 (blocked: arms (b)-(d) and (a)'s migrate refusal need a booted lane-store fixture whose describe/open/kind-method entries pass their ceilings under Registry (Quarantined ports, `describe.ceiling` DescribeInvalid, an INSTANCE built and closed); no stalling plugin!-built fixture exists in busbar-plugin-test; (a) watchdog half, (e) and (f) run as the sibling tests)"]
fn ceilings_quarantine_and_the_reuse_race() {
    todo!("owner: W1-L2 (C-WATCH-CEILING)")
}
