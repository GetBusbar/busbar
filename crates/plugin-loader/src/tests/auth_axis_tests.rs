// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`AuthRows`] over the registry: what it answers, and what it refuses to open.

use std::sync::Arc;
use std::time::Duration;

use super::AuthRows;
use crate::dispatch::{Budgets, DispatchConfig, Dispatcher};
use crate::PluginRegistry;

fn empty() -> AuthRows {
    let d = Arc::new(Dispatcher::new(DispatchConfig {
        workers: 1,
        budgets: Budgets::default(),
        watchdog_period: Duration::from_millis(20),
        ..DispatchConfig::default()
    }));
    AuthRows::new(Arc::new(PluginRegistry::empty()), d)
}

#[test]
fn a_module_no_row_answers_is_refused_by_name() {
    let rows = empty();
    assert!(!rows.answers("nobody"));
    assert!(!rows.linked("nobody"));
    assert!(rows.linked_names().is_empty());
    let err = rows
        .open("nobody", "nobody", &serde_json::json!({}))
        .err()
        .expect("refused");
    assert_eq!(err, "no `kind: auth` plugin answers to 'nobody'");
}

/// A verify-only fixture plugin whose verdict is never read: these tests read Statements.
struct Fixture;

impl busbar_contract::abi::sdk::auth_door::VerifyPlugin for Fixture {
    fn open(_settings: &[u8], _secrets: &[&[u8]]) -> Result<Self, &'static str> {
        Ok(Self)
    }

    fn verify(
        &self,
        _request: &busbar_contract::abi::sdk::auth_door::VerifyView<'_>,
    ) -> busbar_contract::abi::sdk::auth_door::Answer {
        busbar_contract::abi::sdk::auth_door::Verdict::Pass.into()
    }
}

/// The fixture's carrier marks, in the order its Statement states them (opaque words here).
const MARKS: &[busbar_contract::abi::mechanism::door::MarkWord] = &[
    busbar_contract::abi::sdk::auth_door::carrier("line-one"),
    busbar_contract::abi::sdk::auth_door::carrier("line-two"),
    busbar_contract::abi::sdk::auth_door::carrier("line-three"),
];

const DEFAULT_TAIL: &busbar_contract::abi::auth::AuthTail =
    &busbar_contract::abi::sdk::auth_door::verify_tail(
        busbar_contract::abi::auth::FACT_DEFAULT_INBOUND_STYLE,
        busbar_contract::abi::auth::AuthPoints::HEAD,
    );

const PLAIN_TAIL: &busbar_contract::abi::auth::AuthTail =
    &busbar_contract::abi::sdk::auth_door::verify_tail(
        0,
        busbar_contract::abi::auth::AuthPoints::HEAD,
    );

const fn stating(
    name: &'static str,
    tail: &'static busbar_contract::abi::auth::AuthTail,
    marks: &'static [busbar_contract::abi::mechanism::door::MarkWord],
) -> busbar_contract::abi::mechanism::door::Statement {
    busbar_contract::abi::sdk::auth_door::with_tail(
        busbar_contract::abi::mechanism::door::Statement {
            mark_words: marks.as_ptr(),
            mark_words_len: marks.len(),
            ..busbar_contract::abi::sdk::door::statement(name, "1.0.0", 4)
        },
        tail,
    )
}

mod default_a {
    busbar_contract::auth_verify_door!(
        super::Fixture,
        super::stating("default-a", super::DEFAULT_TAIL, super::MARKS)
    );
}

mod default_b {
    busbar_contract::auth_verify_door!(
        super::Fixture,
        super::stating("default-b", super::DEFAULT_TAIL, super::MARKS)
    );
}

mod plain {
    busbar_contract::auth_verify_door!(
        super::Fixture,
        super::stating("plain", super::PLAIN_TAIL, super::MARKS)
    );
}

mod markless_default {
    busbar_contract::auth_verify_door!(
        super::Fixture,
        super::stating("markless-default", super::DEFAULT_TAIL, &[])
    );
}

/// The auth rows over `doors`, each linked under its name.
fn linking(doors: &[(&str, busbar_contract::abi::mechanism::door::DoorFn)]) -> AuthRows {
    let d = Arc::new(Dispatcher::new(DispatchConfig {
        workers: 1,
        budgets: Budgets::default(),
        watchdog_period: Duration::from_millis(20),
        ..DispatchConfig::default()
    }));
    let linked = doors
        .iter()
        .map(|(name, door)| crate::LinkedPlugin::auth_door(name, *door))
        .collect();
    let registry = PluginRegistry::empty()
        .link(linked)
        .expect("the linked doors admit");
    AuthRows::new(Arc::new(registry), d)
}

/// THE HOST'S DEFAULT INBOUND STYLE (row 159, K3#1): the carriers of the one row stating
/// `FACT_DEFAULT_INBOUND_STYLE`, in its Statement's order; a row that does not state it lends
/// none, and no row stating it is none.
#[test]
fn the_default_inbound_style_is_the_one_stating_rows_carriers_in_order() {
    let rows = linking(&[("plain", plain::door), ("default-a", default_a::door)]);
    assert_eq!(
        rows.default_inbound_style(),
        Ok(vec![
            "line-one".to_string(),
            "line-two".to_string(),
            "line-three".to_string()
        ])
    );
    assert_eq!(rows.carriers("plain").len(), 3, "a row's own carriers");
    assert!(rows.carriers("nobody").is_empty());
    let none = linking(&[("plain", plain::door)]);
    assert_eq!(none.default_inbound_style(), Ok(Vec::new()));
}

/// TWO ROWS stating the default inbound style refuse boot, naming both (RED arm: one row answers).
#[test]
fn two_default_inbound_styles_refuse_naming_both() {
    let rows = linking(&[
        ("default-a", default_a::door),
        ("default-b", default_b::door),
    ]);
    assert_eq!(
        rows.default_inbound_style(),
        Err(super::two_default_inbound_styles(&[
            "default-a",
            "default-b"
        ]))
    );
}

/// The default inbound style IS its carriers: a Statement that states the fact and no carrier is
/// refused at load, so it states nothing here.
#[test]
fn a_default_inbound_style_with_no_carrier_is_refused_at_load() {
    let rows = linking(&[("markless-default", markless_default::door)]);
    assert_eq!(rows.default_inbound_style(), Ok(Vec::new()));
    let err = rows
        .open(
            "markless-default",
            "markless-default",
            &serde_json::json!({}),
        )
        .err()
        .expect("refused");
    assert!(
        err.contains("states the default inbound style and its Statement names no carrier"),
        "{err}"
    );
}

/// LAW 7 (BUSBAR-1.6.0.md Part 1: a plugin loads iff config uses it; ARCHITECT ruling 2026-10-20 on
/// root#7 / loader#9: reading a row's static declaration, its kind tail included, is reading, not
/// loading). The boot's fact reads — the credential readers, the default inbound style, the
/// operator row, a module's carriers — read every linked row's Statement and bind none; opening
/// the one module config names binds that row and no other.
#[test]
fn a_linked_row_the_configuration_does_not_name_is_never_bound() {
    let rows = linking(&[("plain", plain::door), ("default-a", default_a::door)]);
    let bound = || {
        rows.bound
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    };
    assert_eq!(rows.default_inbound_style().map(|c| c.len()), Ok(3));
    assert!(rows.credential_readers().is_empty());
    assert_eq!(rows.operator(), None);
    assert_eq!(rows.carriers("plain").len(), 3);
    assert_eq!(bound(), Vec::<String>::new(), "a fact read binds no row");
    rows.open("plain", "plain", &serde_json::json!({}))
        .expect("the named row opens");
    assert_eq!(
        bound(),
        vec!["plain".to_string()],
        "only the named row is bound"
    );
}
