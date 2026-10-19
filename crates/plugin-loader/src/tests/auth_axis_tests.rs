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

/// A configuration whose chain names `keys` and no auth module: the build's linked rows stating the
/// default inbound style are the ones it reads.
fn keys_named() -> busbar_contract::auth_calls::AuthUses {
    busbar_contract::auth_calls::AuthUses {
        keys: true,
        ..Default::default()
    }
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
        rows.default_inbound_style(&keys_named()),
        Ok(vec![
            "line-one".to_string(),
            "line-two".to_string(),
            "line-three".to_string()
        ])
    );
    assert_eq!(rows.carriers("plain").len(), 3, "a row's own carriers");
    assert!(rows.carriers("nobody").is_empty());
    let none = linking(&[("plain", plain::door)]);
    assert_eq!(none.default_inbound_style(&keys_named()), Ok(Vec::new()));
}

/// TWO ROWS stating the default inbound style refuse boot, naming both (RED arm: one row answers).
#[test]
fn two_default_inbound_styles_refuse_naming_both() {
    let rows = linking(&[
        ("default-a", default_a::door),
        ("default-b", default_b::door),
    ]);
    assert_eq!(
        rows.default_inbound_style(&keys_named()),
        Err(super::two_default_inbound_styles(&[
            "default-a",
            "default-b"
        ]))
    );
}

/// A dropped-in row's own carrier mark.
const DROPPED_MARKS: &[busbar_contract::abi::mechanism::door::MarkWord] =
    &[busbar_contract::abi::sdk::auth_door::carrier(
        "dropped-line",
    )];

/// The linked `default-a` beside a DROPPED-IN row, `dropped-default`, that states the default
/// inbound style too: its signed manifest carries its Statement rendering, and its library bytes are
/// not a library, so opening it is the only way to learn anything the rendering does not state.
fn with_dropped_default() -> AuthRows {
    let st = stating("dropped-default", DEFAULT_TAIL, DROPPED_MARKS);
    // SAFETY: every list the Statement names is `'static` and of its stated count.
    let rendering =
        unsafe { busbar_contract::abi::mechanism::rendering::render(&st) }.expect("renders");
    let manifest = crate::sign::Manifest {
        statement: Some(hex::encode(rendering)),
        ..crate::both_ways::statement(
            "auth",
            "dropped-default",
            "dropped-default",
            busbar_contract::abi::auth::ABI_VERSION,
        )
    };
    let registry = crate::both_ways::dropped("law7-dropped-default", manifest, b"not a library")
        .link(vec![crate::LinkedPlugin::auth_door(
            "default-a",
            default_a::door,
        )])
        .expect("the linked door admits");
    let d = Arc::new(Dispatcher::new(DispatchConfig {
        workers: 1,
        budgets: Budgets::default(),
        watchdog_period: Duration::from_millis(20),
        ..DispatchConfig::default()
    }));
    AuthRows::new(Arc::new(registry), d)
}

/// The dropped-in libraries this thread asked the loader to open.
fn dropped_opens() -> u64 {
    crate::dispatch::load::DROPPED_OPENS.with(std::cell::Cell::get)
}

fn line_marks() -> Vec<String> {
    vec![
        "line-one".to_string(),
        "line-two".to_string(),
        "line-three".to_string(),
    ]
}

/// LAW 7 ON THE AUTH AXIS (BUSBAR-1.6.0.md §2 "A plugin loads if and only if config uses it. There
/// are no special plugins."; §4 "A store, secret, auth, hook or export plugin loads iff some entry
/// under its kind's key names its module"): an auth row config does not use is never opened, and
/// moves no line the host reads a caller's credential from. Every fact reader runs; none opens the
/// dropped-in row, and its default inbound style counts for nothing. RED before: each reader bound
/// every `kind: auth` row to read its facts, so the dropped-in library was opened (and, had it
/// opened, its style would have refused the boot as a second default).
#[test]
fn an_unconfigured_dropped_in_row_is_never_opened_and_moves_no_line() {
    let rows = with_dropped_default();
    let before = dropped_opens();
    assert_eq!(
        rows.default_inbound_style(&keys_named()),
        Ok(line_marks()),
        "the linked default-build row's lines, as 1.5.5 read them"
    );
    let _ = (
        rows.operator(),
        rows.credential_readers(),
        rows.carriers("default-a"),
        rows.carriers("dropped-default"),
        rows.answers("dropped-default"),
    );
    assert_eq!(dropped_opens(), before, "no dropped-in library was opened");
}

/// A CONFIGURED dropped-in row is read off its signed rendering, still unopened: config naming it
/// makes its default inbound style the host's. RED before: its facts were read only by opening it,
/// and a library that would not open stated nothing.
#[test]
fn a_configured_dropped_in_rows_style_is_read_off_its_rendering_unopened() {
    let rows = with_dropped_default();
    let before = dropped_opens();
    let named = busbar_contract::auth_calls::AuthUses {
        modules: vec!["dropped-default".to_string()],
        keys: true,
        ..Default::default()
    };
    assert_eq!(
        rows.default_inbound_style(&named),
        Ok(vec!["dropped-line".to_string()])
    );
    assert_eq!(
        rows.carriers("dropped-default"),
        vec!["dropped-line".to_string()]
    );
    assert_eq!(
        dropped_opens(),
        before,
        "read off the rendering, never opened"
    );
}

/// TWO CONFIGURED rows stating the default inbound style refuse the boot, naming both, linked rows
/// first; a 1.5.5 `keys` configuration whose providers all use another style still reads the build's
/// own lines. RED before (the refusal): the dropped-in row's style was read only by opening it.
#[test]
fn two_configured_default_styles_refuse_and_a_keys_config_keeps_the_builds_lines() {
    let rows = with_dropped_default();
    let both = busbar_contract::auth_calls::AuthUses {
        modules: vec!["default-a".to_string(), "dropped-default".to_string()],
        ..Default::default()
    };
    assert_eq!(
        rows.default_inbound_style(&both),
        Err(super::two_default_inbound_styles(&[
            "default-a",
            "dropped-default"
        ]))
    );
    let other_styles = busbar_contract::auth_calls::AuthUses {
        styles: vec![
            "jwt-bearer".to_string(),
            "oauth-client-credentials".to_string(),
        ],
        keys: true,
        ..Default::default()
    };
    assert_eq!(rows.default_inbound_style(&other_styles), Ok(line_marks()));
}

/// The default inbound style IS its carriers: a Statement that states the fact and no carrier is
/// refused at load, so it states nothing here.
#[test]
fn a_default_inbound_style_with_no_carrier_is_refused_at_load() {
    let rows = linking(&[("markless-default", markless_default::door)]);
    assert_eq!(rows.default_inbound_style(&keys_named()), Ok(Vec::new()));
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
