// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE UPSTREAM STATUS TABLE, checked here rather than three times over in the crates that
//! used to each declare it. The rows are data; these are the properties a row must have.

use std::collections::BTreeSet;

use busbar_contract::upstream::{Disposition, StatusClass};

/// Nine classes and four dispositions: the cardinalities the renderers outside this crate match
/// on exhaustively, so a row added here is a row every one of them has to answer for.
#[test]
fn the_table_has_nine_classes_and_four_dispositions() {
    assert_eq!(StatusClass::ALL.len(), 9);
    assert_eq!(Disposition::ALL.len(), 4);
}

/// Two classes that spell the same token are two classes an operator cannot tell apart.
#[test]
fn every_token_is_distinct_and_parses_back_to_its_class() {
    let mut seen = BTreeSet::new();
    for class in StatusClass::ALL {
        assert!(seen.insert(class.token()), "{class:?} shares a token");
        assert_eq!(StatusClass::parse(class.token()), Some(*class));
    }
}

/// Two dispositions that share a label are two failures a dashboard cannot tell apart.
#[test]
fn every_label_is_distinct() {
    let mut seen = BTreeSet::new();
    for d in Disposition::ALL {
        assert!(seen.insert(d.label()), "{d:?} shares a label");
    }
}

/// The tokens and labels, verbatim: operator spellings and dashboard dimensions are part of the
/// observable surface and are reworded only with the configurations and dashboards that read them.
#[test]
fn the_tokens_and_labels_are_the_pinned_bytes() {
    let tokens: Vec<&str> = StatusClass::ALL.iter().map(|c| c.token()).collect();
    assert_eq!(
        tokens,
        [
            "rate_limit",
            "overloaded",
            "server_error",
            "timeout",
            "network",
            "auth",
            "billing",
            "client_error",
            "context_length",
        ]
    );
    let labels: Vec<&str> = Disposition::ALL.iter().map(|d| d.label()).collect();
    assert_eq!(
        labels,
        [
            "client_fault",
            "transient_upstream",
            "hard_down",
            "context_length",
        ]
    );
}

/// The class-to-disposition column, verbatim — the money decision of the table.
#[test]
fn the_disposition_column_is_the_pinned_mapping() {
    use Disposition as D;
    use StatusClass as S;
    let rows: Vec<(S, D)> = S::ALL.iter().map(|c| (*c, c.disposition())).collect();
    assert_eq!(
        rows,
        [
            (S::RateLimit, D::TransientUpstream),
            (S::Overloaded, D::TransientUpstream),
            (S::ServerError, D::TransientUpstream),
            (S::Timeout, D::TransientUpstream),
            (S::Network, D::TransientUpstream),
            (S::Auth, D::HardDown),
            (S::Billing, D::HardDown),
            (S::ClientError, D::ClientFault),
            (S::ContextLength, D::ContextLength),
        ]
    );
}

/// A spelling that names no class is refused as a value, never as a panic: it is operator input.
#[test]
fn an_unknown_token_parses_to_none() {
    assert_eq!(StatusClass::parse("not_a_class"), None);
    assert_eq!(StatusClass::parse(""), None);
    assert_eq!(StatusClass::parse("Rate_Limit"), None);
}
