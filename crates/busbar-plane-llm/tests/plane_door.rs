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
    counts, read_settings, DENY_RESPONSE_HEADERS, EGRESS_SCHEMES, NEEDS, STATEMENT, TAIL, VERSION,
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
        TAIL.billable_classes_len, 4,
        "tokens in, out, cache read, cache write"
    );
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

/// RED for the keep mode: every need relays the far end's whole head but the governed fields, and
/// the deny list is exactly every dialect's governed response fields, each once.
#[test]
fn every_need_keeps_all_but_every_dialects_governed_response_fields() {
    use busbar_contract::abi::host::conn::connector::KEEP_ALL_EXCEPT_DENIED;
    let mut governed: Vec<&str> = DIALECTS
        .iter()
        .flat_map(|d| d.governed_response_headers.iter().copied())
        .collect();
    governed.sort_unstable();
    governed.dedup();
    let mut denied = DENY_RESPONSE_HEADERS.to_vec();
    denied.sort_unstable();
    assert_eq!(denied, governed);
    for n in NEEDS {
        assert_eq!(n.keep_mode, KEEP_ALL_EXCEPT_DENIED);
        assert_eq!(n.keep_response_headers_len, 0);
        assert_eq!(n.deny_response_headers_len, DENY_RESPONSE_HEADERS.len());
    }
}
