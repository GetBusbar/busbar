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
    claims, counts, read_settings, EGRESS_SCHEMES, NEEDS, STATEMENT, TAIL, VERSION,
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

/// The claim a POST on `path` meets: the exact claim on it, else the prefix claim with the longest
/// target whose subtree holds it (a claim's target and every path under it, at any depth).
fn claim_for(path: &str) -> busbar_contract::abi::sdk::publish::ClaimSpec {
    use busbar_contract::abi::plane::CLAIM_EXACT;
    let all = claims();
    let post = all.iter().filter(|c| c.verb == "POST");
    let exact = post
        .clone()
        .find(|c| c.flags & CLAIM_EXACT != 0 && c.target == path);
    let under = |c: &&busbar_contract::abi::sdk::publish::ClaimSpec| {
        let t = c.target.trim_end_matches('/');
        c.flags & CLAIM_EXACT == 0 && (path == c.target || path.starts_with(&format!("{t}/")))
    };
    exact
        .or_else(|| post.filter(under).max_by_key(|c| c.target.len()))
        .cloned()
        .unwrap_or_else(|| panic!("no claim takes POST {path}"))
}

fn dialect_of(claim: &busbar_contract::abi::sdk::publish::ClaimSpec) -> &'static str {
    DIALECTS[usize::from(claim.refusal_dialect)].name
}

/// THE PLANE STATES ITS PATHS AS CLAIMS (ARCHITECT Q-FL1, 2026-10-02): each dialect's own path is a
/// claim wearing the dialect its path shape names, the same rule a refusal renders by.
#[test]
fn every_dialects_path_is_a_claim_wearing_its_dialect() {
    use busbar_plane_llm::exchange::arrive::envelope_for;
    for path in [
        "/v1/messages",
        "/v1/chat/completions",
        "/v1/responses",
        "/v2/chat",
        "/v1beta/models/gemini-pro:generateContent",
        "/model/m/converse",
        "/model/m/converse-stream",
    ] {
        let claim = claim_for(path);
        assert_eq!(dialect_of(&claim), envelope_for(path), "POST {path}");
    }
}

/// THE PREVIOUS RELEASE'S FALLBACK IS A PREFIX CLAIM ON `/`, per verb, so a path no dialect names, at
/// any depth, still reaches the plane (`http.crosscut|unknown-path|bare` and `|openai-suffix`), and
/// a dialect path hit with another verb reaches `arrive`, which answers the dialect's 405.
#[test]
fn the_fallback_is_a_prefix_claim_on_the_root_for_every_verb() {
    use busbar_contract::abi::plane::{CLAIM_EXACT, CLAIM_OPEN};
    let all = claims();
    for verb in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
        let root = all
            .iter()
            .find(|c| c.verb == verb && c.target == "/")
            .unwrap_or_else(|| panic!("no fallback claim for {verb}"));
        assert_eq!(root.flags & (CLAIM_EXACT | CLAIM_OPEN), 0, "{verb} /");
        assert_eq!(
            dialect_of(root),
            busbar_plane_llm::exchange::arrive::envelope_for("/"),
            "{verb} /"
        );
    }
    for path in ["/definitely/unknown", "/x/v1/chat/completions", "/whatever"] {
        assert_eq!(claim_for(path).target, "/", "POST {path}");
    }
    // No claim is open: every llm path takes a credential, as it did.
    assert!(all.iter().all(|c| c.flags & CLAIM_OPEN == 0));
    // Every claim arrives over the one transport the far ends are reached over, and is named.
    assert!(all
        .iter()
        .all(|c| !c.verb.is_empty() && c.target.starts_with('/') && c.carrier == "http"));
}
