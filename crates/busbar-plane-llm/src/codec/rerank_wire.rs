// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RERANK WIRE SHAPE TWO DIALECTS SPEAK ALIKE: the `documents[]` a rerank request ranks and
//! the `results[]` its answer carries. Every rerank wire this plane reads states both members the
//! same way (a document is a bare string or a `{text}` object; a result is
//! `{index, relevance_score, document?}`), so each dialect's rerank reader calls these rather than a
//! sibling dialect's handler (design F3 SELF-CONTAINED: a dialect never imports a sibling).

use crate::codec::ir::rerank::RerankResult;
use crate::codec::keys;
use serde_json::Value;

/// A ranked text as the wire states it: a bare string, or a `{text}` object.
fn text_of(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string).or_else(|| {
        v.get(keys::TEXT)
            .and_then(Value::as_str)
            .map(str::to_string)
    })
}

/// `documents[]` -> the texts to rank. Bare strings and `{text}` objects both normalize to strings;
/// an entry that is neither is skipped.
pub fn read_documents(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(text_of).collect())
        .unwrap_or_default()
}

/// `results[] -> [{index, relevance_score, document?}]`. `document` is the ranked text echoed when
/// the request set `return_documents`; one wire returns it as a `{text}` object, another as a bare
/// string — both are accepted, anything else is `None`.
pub fn read_results(v: Option<&Value>) -> Vec<RerankResult> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| {
                    Some(RerankResult {
                        index: x.get(keys::INDEX).and_then(Value::as_u64)? as usize,
                        relevance_score: x.get(keys::RELEVANCE_SCORE).and_then(Value::as_f64)?,
                        document: x.get(keys::DOCUMENT).and_then(text_of),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}
