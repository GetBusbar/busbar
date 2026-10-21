// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RATE HOLDER AND DATER RIDE THE ROOT'S INSTALL RECORD (THE DESIGN Part 0: no process-global
//! fn-pointer or trait-object static seam beyond the two R6 exempts).
//!
//! The composition root lends the kernel its rate holder ([`RateApply`]) and its rate dater
//! ([`RateEpoch`]) on its one install record (`RootInstall::rate_apply`, `RootInstall::rate_epoch`),
//! and the governance book a build makes from that record carries them (`GovState::with_rates`) —
//! never a process-wide static of `rate_apply`. What the seam carries is unchanged: every staged,
//! applied and withdrawn rate reaches the record's holder with its figures verbatim, and an accrual
//! is dated, and a ledger read priced, by the record's dater.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use busbar_kernel::billing::RawTierRates;
use busbar_kernel::cost::{History, RateCard};
use busbar_kernel::governance::{GovState, MemoryStore};
use busbar_kernel::preflight::RootInstall;
use busbar_kernel::rate_apply::{
    dated_history, effective_from_at, rates_applied, rates_staged, rates_withdrawn, RateApply,
    RateEpoch, RawRates,
};

/// The figures one call carried: the lanes with their four tier rates, the open-class rates, the
/// flat figure, the present flag.
type Figures = (
    Vec<(String, RawTierRates)>,
    Vec<(String, String, u64)>,
    i64,
    bool,
);

/// One call the holder heard: which, and the figures it carried.
#[derive(Debug, Clone, PartialEq)]
enum Heard {
    Staged(Figures),
    Applied(Figures),
    Withdrawn,
}

/// The figures `rates` carries, as the holder writes them down.
fn figures(rates: &RawRates<'_>) -> Figures {
    (
        rates.lanes.to_vec(),
        rates.units.to_vec(),
        rates.flat_minor,
        rates.present,
    )
}

/// The root's holder and dater, as one object the way the root's card repricer is both.
struct Root {
    heard: Mutex<Vec<Heard>>,
    history: Arc<History>,
}

impl RateApply for Root {
    fn rates_staged(&self, rates: &RawRates<'_>) -> Result<(), String> {
        self.heard
            .lock()
            .unwrap()
            .push(Heard::Staged(figures(rates)));
        Ok(())
    }

    fn rates_withdrawn(&self) {
        self.heard.lock().unwrap().push(Heard::Withdrawn);
    }

    fn rates_applied(&self, rates: &RawRates<'_>) {
        self.heard
            .lock()
            .unwrap()
            .push(Heard::Applied(figures(rates)));
    }
}

impl RateEpoch for Root {
    fn effective_from_at(&self, at_ms: u64) -> u64 {
        at_ms - at_ms % 1_000
    }

    fn history(&self) -> Option<Arc<History>> {
        Some(Arc::clone(&self.history))
    }
}

/// The record's holder hears every rate the seam raises through the book lent it, with its figures
/// verbatim, and the record's dater dates every accrual and hands over the history the ledger reads
/// price through.
#[test]
fn the_install_records_holder_and_dater_answer_the_rate_seam() {
    let root: &'static Root = Box::leak(Box::new(Root {
        heard: Mutex::new(Vec::new()),
        history: Arc::new(History::opening(RateCard::absent(0), 0)),
    }));
    let record = RootInstall {
        rate_apply: Some(root),
        rate_epoch: Some(root),
        ..RootInstall::default()
    };
    assert!(
        record.rate_apply.is_some() && record.rate_epoch.is_some(),
        "the install record carries the root's holder and dater"
    );
    // The book a build makes from the record, lent the record's holder and dater.
    let book = GovState::new(Arc::new(MemoryStore::new()), None)
        .expect("governance builds")
        .with_rates(record.rate_apply, record.rate_epoch);

    // Four DISTINCT tier rates and an open-class rate, so a seam that carried the right lane with a
    // defaulted card is red rather than green.
    let lanes = [(
        "fast".to_string(),
        RawTierRates {
            input: Some(1_000),
            output: Some(2_000),
            cache_read: Some(3_000),
            cache_write: Some(4_000),
        },
    )];
    let units = [("fast".to_string(), "search_units".to_string(), 5_000)];
    let fees = busbar_kernel::config::PlaneFeesMap::new();
    let rates = RawRates {
        lanes: &lanes,
        units: &units,
        flat_minor: 11,
        present: true,
        plane_fees: &fees,
    };
    rates_staged(Some(&book), &rates).expect("the holder makes the rates durable");
    rates_withdrawn(Some(&book));
    rates_applied(Some(&book), &rates);
    assert_eq!(
        *root.heard.lock().unwrap(),
        vec![
            Heard::Staged((lanes.to_vec(), units.to_vec(), 11, true)),
            Heard::Withdrawn,
            Heard::Applied((lanes.to_vec(), units.to_vec(), 11, true)),
        ],
        "the record's holder heard each call once, in order, with every figure as resolved"
    );

    assert_eq!(
        effective_from_at(&book, 1_234_567),
        1_234_000,
        "an accrual is dated by the record's dater"
    );
    assert!(
        dated_history(&book).is_some_and(|h| Arc::ptr_eq(&h, &root.history)),
        "the ledger reads price through the record's dater's history"
    );
}

/// Every SHIPPED source file under `dir`: the `tests` directories and `test_support` are test code
/// as a whole.
fn shipped_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("the source directory reads") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            let test_code = path
                .file_name()
                .is_some_and(|n| n == "tests" || n == "test_support");
            if !test_code {
                shipped_sources(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `static` declared as an item on `code` (not the `'static` lifetime).
fn declares_static(code: &str) -> bool {
    code.match_indices("static ").any(|(at, _)| {
        code[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '\''))
    })
}

/// No shipped static of this crate holds the rate holder or the rate dater: `rate_apply` declares
/// no static at all, and no other file declares one whose type (its line or the next) names either
/// trait.
#[test]
fn no_shipped_static_holds_the_rate_holder_or_dater() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let rate_apply = std::fs::read_to_string(src.join("rate_apply.rs")).expect("rate_apply.rs");
    let held: Vec<&str> = rate_apply
        .lines()
        .filter(|l| declares_static(l.split("//").next().unwrap_or_default()))
        .collect();
    assert!(held.is_empty(), "rate_apply declares a static: {held:?}");

    let mut files = Vec::new();
    shipped_sources(&src, &mut files);
    files.sort();
    let mut hits = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("a source file reads");
        let lines: Vec<&str> = text.lines().collect();
        for (n, line) in lines.iter().enumerate() {
            let code = line.split("//").next().unwrap_or_default();
            if !declares_static(code) {
                continue;
            }
            let next = lines
                .get(n + 1)
                .map_or("", |l| l.split("//").next().unwrap_or_default());
            if ["RateApply", "RateEpoch"]
                .iter()
                .any(|t| code.contains(t) || next.contains(t))
            {
                hits.push(format!("{}:{}: {}", file.display(), n + 1, line.trim()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "a process-wide static holds the rate holder or dater:\n{}",
        hits.join("\n")
    );
}
