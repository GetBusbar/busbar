// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE PLACE GATHERED ANSWERS BECOME TOOL ARGUMENTS.
//!
//! Two surfaces gather input from busbar's OWN caller and then merge what came back into the tool
//! arguments that go upstream: the synchronous `tools/call` retry (`inputResponses` riding the
//! retry request) and the task path (`tasks/update` delivering into a parked task, merged by the
//! detached runner when it resumes). They are the same act, and until this module they were two
//! implementations of it — with only one of them screened.
//!
//! ## What went wrong with two implementations
//!
//! The synchronous path screens the answers before it merges them: an answer may bind only a key
//! this capability's own ask rounds DECLARED, and may never name an argument the caller already
//! sent — because the confirmation the caller approved was displayed over those arguments, and an
//! approval that carries out a different call than the one it described is the same defect as an
//! approval that is not required at all. It then runs the whole remaining guard set (the egress
//! plan and the schema-aware URL/host walk) over the MERGED arguments, because the merged
//! arguments are the ones that travel.
//!
//! The task path did neither. `tasks/update` accepted every key the caller sent, `merge_answers`
//! inserted all of them over the arguments, and the argument guard had already run — inside
//! `create_task`, over the PRE-merge arguments. So a benign create (`url` naming a public host)
//! followed by an update rewriting `url` to a cloud-metadata address dispatched the rewritten
//! call: the screen inspected one payload while a different one travelled, which is exactly the
//! policy-enforcement-point bypass the synchronous path's ordering exists to close.
//!
//! ## The rule
//!
//! [`merge_guarded`] is that one implementation. Both paths call it, so neither can drift from the
//! other, and a guard added here is added to both. It refuses rather than drops: a caller whose
//! answer is being ignored has to be told, or the next attacker to try it learns nothing and the
//! next honest client debugs a value that vanished.
//!
//! ## Cost
//!
//! Nothing calls it when no answers were gathered — the common `tools/call` with no ask round pays
//! not one byte. On the paths that do gather, it costs one key-set walk plus the schema-aware walk
//! the dispatch was going to pay for anyway.

use super::client::ssrf::SsrfPolicy;

/// Why a set of gathered answers, or the arguments they produced, is refused.
///
/// Two arms rather than one string because the two REPORT differently: an undeclared answer is the
/// caller naming something it was never asked for (a grant-shaped refusal), and a refused argument
/// is the merged document failing the same walk `upstream::authorise` runs (a setup-shaped one).
/// The synchronous path renders each in the shape its surface already uses; the task path fails
/// the task with the message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AnswerRefusal {
    /// The answer named a key this capability's ask rounds never declared, or one that would
    /// rewrite an argument the caller already sent.
    Undeclared(String),
    /// The MERGED arguments failed the schema-aware URL/host walk.
    Argument(String),
}

impl std::fmt::Display for AnswerRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnswerRefusal::Undeclared(m) | AnswerRefusal::Argument(m) => f.write_str(m),
        }
    }
}

/// The audit reason each arm records under. The SAME tokens the synchronous path already writes,
/// so folding the two implementations together changed no audit vocabulary.
impl AnswerRefusal {
    pub(crate) fn audit_reason(&self) -> &'static str {
        match self {
            AnswerRefusal::Undeclared(_) => "caller_ask_answer_undeclared",
            AnswerRefusal::Argument(_) => "tool_argument_refused",
        }
    }
}

/// Screen `answers`, merge them over `sealed`, and screen the RESULT.
///
/// * `capability` — the namespaced tool, named in the refusal so an operator can find it.
/// * `declared` — every key this capability's own ask rounds asked for, in any round.
/// * `sealed` — the arguments as the caller sent them, i.e. the ones any confirmation was
///   displayed over.
/// * `answers` — what came back.
/// * `schema` — the operator's APPROVED `inputSchema` from the catalogue snapshot, never one an
///   upstream offered at refresh time. `None` is walked as `{"type": "object"}` rather than
///   skipped, for the reason `upstream::authorise` gives: skipping would make "declare no schema"
///   the way past the check.
/// * `policy` — the same SSRF policy the dispatch will use.
///
/// Returns the merged arguments. An empty `answers` still runs the walk on the caller's own
/// arguments, which is free of surprises and keeps the function total.
pub(crate) fn merge_guarded<'a>(
    capability: &str,
    declared: impl IntoIterator<Item = &'a str>,
    sealed: &serde_json::Value,
    answers: &serde_json::Map<String, serde_json::Value>,
    schema: Option<&serde_json::Value>,
    policy: SsrfPolicy,
) -> Result<serde_json::Value, AnswerRefusal> {
    let declared: std::collections::BTreeSet<&str> = declared.into_iter().collect();
    let sealed_keys: std::collections::BTreeSet<&str> = sealed
        .as_object()
        .map(|o| o.keys().map(String::as_str).collect())
        .unwrap_or_default();
    if let Some(offending) = answers
        .keys()
        .find(|k| !declared.contains(k.as_str()) || sealed_keys.contains(k.as_str()))
    {
        return Err(AnswerRefusal::Undeclared(format!(
            "the answer named `{offending}`, which is not one of the inputs \
             `{capability}` requested — an answer may only supply what was asked for, and may \
             never rewrite an argument the confirmation was shown for."
        )));
    }
    let mut merged = sealed
        .as_object()
        .cloned()
        .unwrap_or_else(serde_json::Map::new);
    for (key, value) in answers {
        merged.insert(key.clone(), value.clone());
    }
    let merged = serde_json::Value::Object(merged);
    let fallback = serde_json::json!({ "type": "object" });
    let schema = schema.unwrap_or(&fallback);
    super::client::argguard::guard(schema, &merged, policy)
        .map_err(|e| AnswerRefusal::Argument(e.to_string()))?;
    Ok(merged)
}

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/answers_tests.rs"]
mod answers_tests;
