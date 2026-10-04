// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The published suite's own mechanics, with no plugin as the subject: the exact comparator, the
//! leg comparison, the perturbation the RED arms run, the profile guard. (Every plugin is proven by
//! its own repo running the suite; busbar tests only its own code.)

use super::{exact, perturbed, profile, same, Step, EXPECT_RELEASE_ENV};

fn step(label: &str, answer: &str, crossed: u64, pinned: u64) -> Step {
    Step {
        label: label.into(),
        answer: answer.into(),
        crossed,
        pinned,
    }
}

fn honest() -> Vec<Step> {
    vec![
        step("open", "Ready", 1, 1),
        step("ready", "Ok(())", 0, 0),
        step("read", "Ready lease=true", 2, 2),
    ]
}

#[test]
fn exact_passes_every_count_at_its_pin() {
    assert_eq!(exact(&honest()), Ok(()));
}

#[test]
fn exact_refuses_a_count_one_above_or_below_its_pin() {
    let mut over = honest();
    over[2].crossed = 3;
    let mut under = honest();
    under[0].crossed = 0;
    let e = exact(&over).expect_err("one crossing too many");
    assert!(e.contains("'read': 3 crossing(s), pinned 2"), "{e}");
    let e = exact(&under).expect_err("a skipped crossing");
    assert!(e.contains("'open': 0 crossing(s), pinned 1"), "{e}");
}

#[test]
fn a_comparator_that_only_wants_more_than_zero_is_not_this_one() {
    // Every op crossing twice is "above zero" everywhere it crossed at all.
    let doubled: Vec<Step> = honest()
        .into_iter()
        .map(|mut s| {
            s.crossed *= 2;
            s
        })
        .collect();
    assert!(doubled
        .iter()
        .filter(|s| s.pinned > 0)
        .all(|s| s.crossed > 0));
    assert!(exact(&doubled).is_err());
}

#[test]
fn perturbed_moves_exactly_one_pin_and_the_comparator_sees_it() {
    for at in 0..honest().len() {
        let p = perturbed(honest(), at);
        let moved: Vec<usize> = p
            .iter()
            .zip(honest())
            .enumerate()
            .filter(|(_, (a, b))| a.pinned != b.pinned)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(moved, [at]);
        assert!(exact(&p).is_err());
    }
}

#[test]
fn same_refuses_a_different_answer_count_or_length() {
    assert_eq!(same(&honest(), &honest()), Ok(()));
    let mut other = honest();
    other[2].answer = "Failed".into();
    assert!(same(&honest(), &other)
        .expect_err("answers differ")
        .contains("part at 'read'"));
    let mut other = honest();
    other[0].crossed = 2;
    assert!(same(&honest(), &other).is_err());
    let mut short = honest();
    short.pop();
    assert!(same(&honest(), &short)
        .expect_err("a leg stopped early")
        .contains("3 steps, the dropped 2"));
}

#[test]
fn the_profile_guard_refuses_a_debug_build_only_when_release_was_asked_for() {
    // Reads the variable only; never sets it (tests share the process environment).
    if std::env::var_os(EXPECT_RELEASE_ENV).is_none() {
        profile(true);
    }
    profile(false);
    let asked = std::panic::catch_unwind(|| {
        if std::env::var_os(EXPECT_RELEASE_ENV).is_some() {
            profile(true);
        }
    });
    assert_eq!(
        asked.is_err(),
        std::env::var_os(EXPECT_RELEASE_ENV).is_some()
    );
}
