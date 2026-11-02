// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::credential_flush_results;

#[test]
fn failures_preserve_first_refusal_and_attempt_every_selected_answer() {
    for admin_fails in [true, false] {
        let answers = [
            if admin_fails {
                Err("admin refusal".into())
            } else {
                Ok(3)
            },
            Ok(7),
            if admin_fails {
                Ok(5)
            } else {
                Err("data refusal".into())
            },
            Ok(11),
        ];
        let mut attempted = Vec::new();
        let result =
            credential_flush_results(answers.into_iter().enumerate().map(|(index, answer)| {
                attempted.push(index);
                answer
            }));
        assert_eq!(
            attempted,
            [0, 1, 2, 3],
            "a refusal never skips later modules"
        );
        assert_eq!(
            result,
            Err(if admin_fails {
                "admin refusal"
            } else {
                "data refusal"
            }
            .into())
        );
    }
    assert_eq!(
        credential_flush_results([Err("first".into()), Ok(3), Err("later".into())]),
        Err("first".into())
    );
}

#[test]
fn successful_answers_sum_both_chains_and_an_empty_selection_is_zero() {
    assert_eq!(credential_flush_results([Ok(3), Ok(5)]), Ok(8));
    assert_eq!(credential_flush_results(std::iter::empty()), Ok(0));
}
