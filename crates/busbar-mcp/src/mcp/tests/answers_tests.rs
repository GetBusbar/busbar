// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SCREEN BOTH ANSWER-GATHERING SURFACES RUN, tested where it is decided.
//!
//! Each of these was watched to fail first. Before `answers::merge_guarded` existed the task
//! runner's merge was `merge_answers`, which inserted every delivered key over the arguments and
//! returned no `Result` at all — so every refusal asserted here had nothing to come from, and the
//! rewrite test below dispatched the metadata address.

use super::*;

/// The arguments a benign `tools/call` created the task with: a public host, screened and passed by
/// the argument guard inside `upstream::authorise`.
fn benign() -> serde_json::Value {
    serde_json::json!({ "url": "https://example.com/report.json" })
}

/// The operator's approved schema for that tool. `url` is declared URL-ish, which is what puts it in
/// the guard's walk by declaration rather than only by the undeclared-`http(s)` detector.
fn schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": { "url": { "type": "string", "format": "uri" } },
    })
}

/// THE DEFECT THIS MODULE EXISTS FOR. A create the guard set passed, followed by an update that
/// rewrites the ONE argument the guard screened into a cloud-metadata address, must be refused —
/// not merged and dispatched. The rewrite is refused on the FIRST rule it breaks: `url` is not a key
/// any ask round declared, and it names an argument the caller already sent.
#[test]
fn an_update_that_rewrites_a_screened_argument_is_refused_rather_than_merged() {
    let mut answers = serde_json::Map::new();
    answers.insert(
        "url".into(),
        serde_json::json!("https://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    );
    let refusal = merge_guarded(
        "fs.fetch",
        ["confirm"],
        &benign(),
        &answers,
        Some(&schema()),
        SsrfPolicy {
            allow_private: false,
        },
    )
    .expect_err(
        "an answer rewriting an argument the guard set already screened must refuse the dispatch; \
         merging it means the payload that was inspected is not the payload that travels",
    );
    assert!(
        matches!(refusal, AnswerRefusal::Undeclared(_)),
        "the key rule fires before the walk, so the operator is told which key was wrong rather \
         than which address: {refusal:?}"
    );
    assert!(
        refusal.to_string().contains("`url`"),
        "the refusal has to name the offending key or an operator cannot diagnose it: {refusal}"
    );
    assert_eq!(refusal.audit_reason(), "caller_ask_answer_undeclared");
}

/// The SECOND rule, reached only once the first cannot fire: a key that IS declared and that the
/// caller did NOT already send still has to produce arguments the guard admits. Here the operator
/// asked for `callback`, so the key rule passes — and the walk over the MERGED document refuses the
/// metadata address. This is the arm `create_task`'s pre-merge `authorise` structurally cannot
/// reach, because the value did not exist when it ran.
#[test]
fn a_declared_answer_carrying_a_metadata_address_is_refused_by_the_walk_over_the_merged_arguments()
{
    let mut answers = serde_json::Map::new();
    answers.insert(
        "callback".into(),
        serde_json::json!("http://169.254.169.254/latest/api/token"),
    );
    let refusal = merge_guarded(
        "fs.fetch",
        ["callback"],
        &benign(),
        &answers,
        Some(&schema()),
        SsrfPolicy {
            allow_private: false,
        },
    )
    .expect_err(
        "the argument guard has to run over the arguments the answers PRODUCE; running it only over \
         the ones the caller first sent screens a document that never travels",
    );
    assert_eq!(refusal.audit_reason(), "tool_argument_refused");
    assert!(
        refusal.to_string().contains("169.254.169.254"),
        "the refusal names the offending value: {refusal}"
    );
}

/// AND THE HONEST ANSWER STILL GETS THROUGH. A declared key the caller did not already send is
/// merged, and the merged document is what comes back — otherwise the screen would be a gate with
/// no output and the whole exchange would be pointless.
#[test]
fn a_declared_answer_naming_no_sent_argument_merges_into_the_arguments() {
    let mut answers = serde_json::Map::new();
    answers.insert("confirm".into(), serde_json::json!("yes"));
    let merged = merge_guarded(
        "fs.fetch",
        ["confirm"],
        &benign(),
        &answers,
        Some(&schema()),
        SsrfPolicy {
            allow_private: false,
        },
    )
    .expect("a declared answer that rewrites nothing is exactly what an ask round is for");
    assert_eq!(merged["confirm"], "yes");
    assert_eq!(
        merged["url"], "https://example.com/report.json",
        "the caller's own argument survives the merge unchanged"
    );
}

/// NO ANSWERS IS NOT A SPECIAL CASE. The function stays total: an empty map returns the caller's own
/// arguments, still walked, so a caller that answers nothing is neither refused nor unscreened.
#[test]
fn no_answers_returns_the_callers_own_arguments_and_still_walks_them() {
    let merged = merge_guarded(
        "fs.fetch",
        ["confirm"],
        &benign(),
        &serde_json::Map::new(),
        Some(&schema()),
        SsrfPolicy {
            allow_private: false,
        },
    )
    .expect("a benign document with no answers is admissible");
    assert_eq!(merged, benign());
}
