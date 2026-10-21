// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`Sugars::declare`]: the shorthand a secret plugin's Statement declares is read off its
//! rewrites, and the host refuses two plugins claiming one word or one role, a core-grammar word,
//! a sugar with no settings key and a fact about a word the Statement does not declare. The words
//! here are test words, no source's.

use super::*;
use crate::abi::mechanism::door::{
    REWRITE_ALIAS, REWRITE_SUGAR, REWRITE_SUGAR_NAMES, REWRITE_SUGAR_ROLE, REWRITE_SUGAR_SHOWN,
    SUGAR_ROLE_PATH,
};

fn rw(class: u32, from: &str, to: &str) -> (u32, String, String) {
    (class, from.to_string(), to.to_string())
}

#[test]
fn a_declared_sugar_carries_its_key_placeholder_and_what_its_value_names() {
    let mut s = Sugars::default();
    s.declare(
        "busbar-secret-probe",
        &[
            rw(REWRITE_ALIAS, "probe", ""),
            rw(REWRITE_SUGAR, "probe", "slot"),
            rw(REWRITE_SUGAR_SHOWN, "probe", "SLOT"),
            rw(REWRITE_SUGAR_NAMES, "probe", "the probe slot"),
            rw(REWRITE_SUGAR_ROLE, "probe", SUGAR_ROLE_PATH),
        ],
    )
    .expect("one plugin declares one sugar");
    let sugar = s.get("probe").expect("the declared word reads back");
    assert_eq!(sugar.plugin, "busbar-secret-probe");
    assert_eq!(sugar.setting, "slot");
    assert_eq!(sugar.shown, "SLOT");
    assert_eq!(sugar.names, "the probe slot");
    assert_eq!(
        s.with_role(SUGAR_ROLE_PATH).map(|x| x.word.as_str()),
        Some("probe")
    );
    assert!(
        s.get("slot").is_none(),
        "a settings key is not a sugar word"
    );
}

#[test]
fn unstated_facts_default_to_the_settings_key() {
    let mut s = Sugars::default();
    s.declare("p", &[rw(REWRITE_SUGAR, "probe", "slot")])
        .unwrap();
    let sugar = s.get("probe").unwrap();
    assert_eq!(sugar.shown, "slot");
    assert_eq!(sugar.names, "the slot");
}

#[test]
fn a_statement_without_sugar_declares_nothing() {
    let mut s = Sugars::default();
    s.declare("p", &[rw(REWRITE_ALIAS, "probe", "")]).unwrap();
    assert!(s.is_empty());
}

#[test]
fn every_refusal_names_what_it_refuses() {
    let mut s = Sugars::default();
    s.declare("first", &[rw(REWRITE_SUGAR, "probe", "slot")])
        .unwrap();
    let two = s
        .clone()
        .declare("second", &[rw(REWRITE_SUGAR, "probe", "other")])
        .unwrap_err();
    assert!(two.contains("'first'") && two.contains("'second'"), "{two}");
    let core = Sugars::default()
        .declare("p", &[rw(REWRITE_SUGAR, "module", "slot")])
        .unwrap_err();
    assert!(core.contains("core"), "{core}");
    let keyless = Sugars::default()
        .declare("p", &[rw(REWRITE_SUGAR, "probe", "")])
        .unwrap_err();
    assert!(keyless.contains("no settings key"), "{keyless}");
    let stray = Sugars::default()
        .declare("p", &[rw(REWRITE_SUGAR_NAMES, "probe", "the slot")])
        .unwrap_err();
    assert!(stray.contains("does not declare"), "{stray}");
    let role = Sugars::default()
        .declare(
            "p",
            &[
                rw(REWRITE_SUGAR, "probe", "slot"),
                rw(REWRITE_SUGAR_ROLE, "probe", "elsewhere"),
            ],
        )
        .unwrap_err();
    assert!(role.contains("does not name"), "{role}");
    let mut held = Sugars::default();
    held.declare(
        "first",
        &[
            rw(REWRITE_SUGAR, "probe", "slot"),
            rw(REWRITE_SUGAR_ROLE, "probe", SUGAR_ROLE_PATH),
        ],
    )
    .unwrap();
    let taken = held
        .declare(
            "second",
            &[
                rw(REWRITE_SUGAR, "other", "slot"),
                rw(REWRITE_SUGAR_ROLE, "other", SUGAR_ROLE_PATH),
            ],
        )
        .unwrap_err();
    assert!(
        taken.contains("'first'") && taken.contains("'second'"),
        "{taken}"
    );
    assert!(
        held.get("other").is_none(),
        "a refused declaration adds nothing"
    );
}
