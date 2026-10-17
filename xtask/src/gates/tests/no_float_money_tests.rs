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
        let b = find_boundary(&text, intake.boundary)
            .unwrap_or_else(|| panic!("`fn {}` was not found", intake.boundary));
        spans.push((b.first_line, b.last_line));
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

/// AUDIT XE HIGH 3: A ZERO DEFAULT REACHED THROUGH AN INTERMEDIATE COMBINATOR IS A HIT. Lines 2-4
/// narrow, map or filter before a zero default; line 5 refuses through `ok_or` and line 6 names a
/// non-zero default, and neither is a hit.
#[test]
fn a_zero_default_after_a_combinator_is_a_hit() {
    let src = "fn f(v: &Value) -> u64 {\n\
               \x20   let a = v.as_u64().and_then(|n| u32::try_from(n).ok()).unwrap_or(0);\n\
               \x20   let b = v.as_u64().map(|n| n as u32).unwrap_or_default();\n\
               \x20   let c = v.get(\"t\").and_then(Value::as_u64).filter(|n| *n > 0).map_or(0, |n| n);\n\
               \x20   let d = v.as_u64().map(|n| n as u32).ok_or(Refused)?;\n\
               \x20   let e = v.as_u64().map(|n| n as u32).unwrap_or(7);\n\
               }\n";
    let hits = scan_count_reads(src);
    let lines: Vec<usize> = hits.iter().map(|h| h.line).collect();
    assert_eq!(lines, vec![2, 3, 4], "the hits were {lines:?}");
}

/// AUDIT XE HIGH 1: THE CARRIERS ARE READ OFF THE TREE. The routing headroom ratio the audit
/// cast inside `try_admit` is one, and the hand-typed `blended_per_mtok` (declared nowhere) is not.
#[test]
fn the_derived_carriers_hold_the_trees_float_returning_items() {
    let cx = cx();
    let (files, problems) = crate_src_files(&cx);
    assert!(problems.is_empty(), "{problems:?}");
    let carriers = FloatCarriers::from_files(&production_only(&cx, files));
    assert!(
        carriers.fns.contains_key("rate_headroom"),
        "{:?}",
        carriers.fns
    );
    assert!(!carriers.fns.contains_key("blended_per_mtok"));
    assert!(carriers.len() >= FLOAT_CARRIER_FLOOR, "{}", carriers.len());
}

/// AUDIT XE HIGH 2: THE CAPABILITY MODULE KEYS THE POPULATION. Every type the hold module declares,
/// and the money-write capability, are in the key.
#[test]
fn the_money_capability_types_key_the_population() {
    let (key, problems) = money_type_key(&cx());
    assert!(problems.is_empty(), "{problems:?}");
    for want in ["Hold", "Posted", "HoldAccrual", "WriteMoney", "RateCard"] {
        assert!(key.iter().any(|k| k == want), "{want} is not in {key:?}");
    }
}
