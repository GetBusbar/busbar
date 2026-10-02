// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The llm plane's door, its static half: a Statement and tail the contract accepts, the needs
//! the dialects' schemes call for, the settings it reads, and the counts it reports.

use busbar_contract::abi::mechanism::check::check_needs;
use busbar_contract::abi::plane::check::{check_refusal_statuses, check_sections, check_tail};
use busbar_contract::abi::plane::{TAIL_FALLBACK, TAIL_PROBES, UNITS_REPORTED};
use busbar_plane_llm::dialect::DIALECTS;
use busbar_plane_llm::exchange::reply::Units;
use busbar_plane_llm::plane_door::{
    counts, read_settings, EGRESS_SCHEMES, NEEDS, OPEN_CLASSES, STATEMENT, TAIL, VERSION,
};

#[test]
fn the_statement_names_the_crate_version() {
    assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
}

#[test]
fn the_tail_is_one_the_contract_accepts() {
    assert_eq!(check_tail(TAIL), Ok(()));
    // SAFETY: the Statement's sections are a `'static` list of `sections_len` entries.
    let sections =
        unsafe { std::slice::from_raw_parts(STATEMENT.sections, STATEMENT.sections_len) };
    assert_eq!(check_sections(sections), Ok(()));
    assert_eq!(
        check_refusal_statuses(
            &busbar_plane_llm::refusal::REFUSAL_STATUSES,
            TAIL.dialects_len as u64
        ),
        Ok(())
    );
    assert_eq!(TAIL.flags, TAIL_FALLBACK | TAIL_PROBES);
    assert_eq!(TAIL.dialects_len, DIALECTS.len());
    assert_eq!(TAIL.op_classes_len, 7);
    assert_eq!(
        TAIL.billable_classes_len, 5,
        "tokens in, out, cache read, cache write, then the open classes"
    );
    assert_eq!(OPEN_CLASSES, &[("search_units", "units")]);
}

#[test]
fn every_dialects_egress_scheme_has_its_one_outbound_need() {
    assert_eq!(check_needs(NEEDS), Ok(()));
    assert_eq!(STATEMENT.needs_len, NEEDS.len());
    for d in DIALECTS {
        assert_eq!(
            EGRESS_SCHEMES
                .iter()
                .filter(|s| **s == d.egress_scheme)
                .count(),
            1,
            "{}",
            d.name
        );
    }
    assert_eq!(NEEDS.len(), EGRESS_SCHEMES.len());
}

#[test]
fn the_settings_read_as_the_tables_and_a_broken_section_is_refused() {
    assert!(read_settings(b"").is_ok(), "an empty blob is no section");
    let one =
        br#"{"providers":{"ant":{"protocol":"anthropic","base_url":"https://anthropic.example"}},
        "models":{"claude":{"provider":"ant"}},"pools":{"p":{"members":["claude"]}}}"#;
    let shaping = read_settings(one).expect("a well-formed generation reads");
    assert!(shaping.lane("claude").is_some());
    assert!(read_settings(b"not json").is_err());
    assert!(read_settings(br#"{"providers":7}"#).is_err());
}

#[test]
fn counts_are_the_far_ends_tokens_in_the_tails_class_order_and_nothing_before_one_is_reported() {
    assert!(counts(&Units::default()).is_empty());
    let units = Units {
        tokens_in: 7,
        tokens_out: 3,
        cache_read: 2,
        cache_write: 1,
        ..Units::default()
    };
    let got: Vec<(u32, u64)> = counts(&units).iter().map(|u| (u.class, u.amount)).collect();
    assert_eq!(got, vec![(0, 7), (1, 3), (2, 2), (3, 1)]);
    assert!(counts(&units).iter().all(|u| u.source == UNITS_REPORTED));
}

/// RED for the `$` G3 commit: an open count the far end reported reaches the kernel in its
/// declared class, beside or without token counts; before it, `counts()` dropped it.
#[test]
fn an_open_count_is_reported_in_its_declared_class_and_never_dropped() {
    let open = Units {
        open: std::collections::BTreeMap::from([("search_units".to_string(), 12)]),
        ..Units::default()
    };
    let got: Vec<(u32, u64, bool)> = counts(&open)
        .iter()
        .map(|u| (u.class, u.amount, u.source == UNITS_REPORTED))
        .collect();
    assert_eq!(got, vec![(4, 12, true)], "no token counts, one open count");
    let both = Units {
        tokens_in: 5,
        ..open.clone()
    };
    let classes: Vec<u32> = counts(&both).iter().map(|u| u.class).collect();
    assert_eq!(classes, vec![0, 1, 2, 3, 4]);
    let unknown = Units {
        open: std::collections::BTreeMap::from([("nothing_stated".to_string(), 3)]),
        ..Units::default()
    };
    assert!(
        counts(&unknown).is_empty(),
        "a class the plane does not state is warned, never counted under another class"
    );
}
