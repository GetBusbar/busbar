// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn cx() -> Ctx {
    Ctx::workspace().expect("workspace context")
}

/// AUDIT xtask-X3 FINDING 1: THE CARD-BUILD FILE IS SCANNED, AND ITS EXEMPTION IS ITS NAMED ITEMS.
/// The accumulation, the digest and the runtime price reads sit OUTSIDE every intake span in
/// `cost/rate.rs`, so a float in any of them is a finding.
#[test]
fn the_card_build_files_runtime_items_are_outside_every_intake_span() {
    let text = cx().read(CARD_BUILD_FILE).expect("the card-build file");
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for intake in MONEY_INTAKE.iter().filter(|i| i.file == CARD_BUILD_FILE) {
        match intake.item {
            IntakeItem::ConversionFn => {
                let b = find_boundary(&text, intake.boundary)
                    .unwrap_or_else(|| panic!("`fn {}` was not found", intake.boundary));
                spans.push((b.first_line, b.last_line));
            }
            IntakeItem::DecimalRecord => {
                let r = record_spans(&text, intake.boundary);
                assert!(!r.is_empty(), "`struct {}` was not found", intake.boundary);
                spans.extend(r);
            }
        }
    }
    for runtime in [
        "lane_pricing",
        "digest",
        "fee_of",
        "fee_unit_price_nanos",
        "lane_unpriced",
        "nanos_per_unit",
    ] {
        let b = find_boundary(&text, runtime)
            .unwrap_or_else(|| panic!("`fn {runtime}` is not in {CARD_BUILD_FILE}"));
        for (first, last) in &spans {
            assert!(
                b.last_line < *first || b.first_line > *last,
                "`fn {runtime}` ({}..={}) overlaps the exempt span {first}..={last}",
                b.first_line,
                b.last_line
            );
        }
    }
}

/// A DECIMAL RECORD IS ITS STRUCT AND ITS INHERENT IMPL, and nothing else: a trait impl for it, and
/// the fn after it, are scanned.
#[test]
fn a_decimal_record_is_its_struct_and_inherent_impl_only() {
    let src = "pub struct Rates {\n    pub a: f64,\n}\n\
               impl Rates {\n    fn pairs(self) -> [f64; 1] { [self.a] }\n}\n\
               impl Default for Rates {\n    fn default() -> Self { Rates { a: 0.0 } }\n}\n\
               pub fn after(r: Rates) -> u64 { (r.a * 2.0) as u64 }\n";
    assert_eq!(record_spans(src, "Rates"), vec![(1, 3), (4, 6)]);
    let mut exempt: IntakeSpans = std::collections::BTreeMap::new();
    exempt.insert("m.rs".into(), record_spans(src, "Rates"));
    let mut offenders = Vec::new();
    scan_file("m.rs", src, &exempt, &mut offenders);
    let lines: std::collections::BTreeSet<&str> = offenders
        .iter()
        .map(|o| o.split(':').nth(1).unwrap_or_default())
        .collect();
    assert_eq!(lines, ["8", "10"].into_iter().collect(), "{offenders:#?}");
    assert!(
        record_spans(src, "Absent").is_empty(),
        "an undeclared record exempts nothing"
    );
}
