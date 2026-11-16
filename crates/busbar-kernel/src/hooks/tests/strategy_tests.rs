// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-STRATEGY-WORD (IF §12.25, §14), kernel arms: how a pool's strategy word resolves at config load.

use super::{resolve_strategy, StrategyBinding};
use crate::path_claims::ConfigRefused;

/// The admitted hook images and the words each declares (`Registry::hook_words`).
fn words() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (
            "hook-ranking",
            vec!["cheapest", "fastest", "least_busy", "usage"],
        ),
        ("hook-webrequest", vec![]),
        ("hook-other", vec!["usage2"]),
        ("hook-dup-a", vec!["twice"]),
        ("hook-dup-b", vec!["twice"]),
    ]
}

/// A 1.5.5 pool naming `cheapest` with no `hooks.cheapest` configured: one implicit instance named after the
/// word, of the unique declaring image.
#[test]
fn an_unconfigured_word_opens_one_implicit_instance() {
    for word in ["cheapest", "fastest", "least_busy", "usage"] {
        let got = resolve_strategy(word, &[], &words()).expect("the unique declaring image serves");
        assert_eq!(
            got,
            StrategyBinding {
                word: word.into(),
                instance: word.into(),
                implicit: true,
            }
        );
    }
}

/// A configured `hooks.cheapest` of the declaring plugin is used instead (its settings apply).
#[test]
fn a_configured_instance_of_that_name_is_used() {
    let configured = [("cheapest", "hook-ranking"), ("audit", "hook-webrequest")];
    let got = resolve_strategy("cheapest", &configured, &words()).expect("configured instance");
    assert_eq!(
        got,
        StrategyBinding {
            word: "cheapest".into(),
            instance: "cheapest".into(),
            implicit: false,
        }
    );
}

/// A configured `hooks.cheapest` of a plugin that does not declare the word refuses with the §12.25 text, even
/// though another image declares it: the operator's name wins and must be right.
#[test]
fn a_configured_instance_that_does_not_declare_the_word_is_refused() {
    let configured = [("cheapest", "hook-webrequest")];
    assert_eq!(
        resolve_strategy("cheapest", &configured, &words()),
        Err(ConfigRefused(
            "hook instance `cheapest` does not declare the strategy word `cheapest`".into()
        ))
    );
}

#[test]
fn an_unknown_word_is_refused() {
    assert_eq!(
        resolve_strategy("nearest", &[], &words()),
        Err(ConfigRefused(
            "ranking strategy `nearest` has no admitted hook plugin".into()
        ))
    );
}

#[test]
fn a_word_declared_by_two_images_is_refused() {
    assert_eq!(
        resolve_strategy("twice", &[], &words()),
        Err(ConfigRefused(
            "ranking strategy `twice` is declared by several hook plugins; configure `hooks.twice` with a `module:`"
                .into()
        ))
    );
    // Configuring it by name settles the ambiguity.
    let configured = [("twice", "hook-dup-b")];
    let got = resolve_strategy("twice", &configured, &words()).expect("configured settles it");
    assert!(!got.implicit);
}

/// Matching is exact: no prefix, case or substring match turns one word into another.
#[test]
fn words_match_exactly() {
    assert!(resolve_strategy("usage", &[], &words()).is_ok_and(|b| b.implicit));
    assert!(resolve_strategy("Cheapest", &[], &words()).is_err());
    assert!(resolve_strategy("cheap", &[], &words()).is_err());
}
