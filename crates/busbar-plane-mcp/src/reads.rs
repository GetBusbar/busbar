// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TWO READS ANSWERED FROM THE SECTION: `prompts/get` and `resources/read`. No upstream is
//! contacted; the content is the operator's own, with the caller's text substituted into it and the
//! whole passed through the markup strip after substitution, never before.
//!
//! Pure: the request's params, the generation's [`Catalogue`] and the caller's `admit` predicate
//! in; the answer's bytes or its refusal out. A prompt that asks its caller for input first
//! ([`PromptEntry::ask_caller`]) reaches [`prompts_get`] only once that exchange let it through.
//!
//! The answers and the refusals are the served engine's: a missing member is `400` + `-32602`;
//! not found and not granted are one `404` + `-32000`; a uri two reachable approvals answer is
//! `409` + `-32000` naming them.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::arrival::Refusal;
use crate::catalogue::{complete, Catalogue, Lookup, PromptEntry, ResourceEntry, ResourceTemplateEntry};
use crate::codec::{CODE_INVALID_PARAMS, CODE_REFUSED};
use crate::config::PromptContentCfg;
use crate::sanitize::{normalise, normalise_opt};

/// The status of a read that names nothing the caller may see.
pub const STATUS_NOT_FOUND: u32 = 404;

/// The status of a uri more than one reachable approval answers.
pub const STATUS_CONFLICT: u32 = 409;

fn refusal(status: u32, id: &Value, code: i64, message: String, data: Option<Value>) -> Refusal {
    Refusal {
        status,
        id: Some(id.clone()),
        code,
        message,
        data,
    }
}

fn string_param<'a>(params: Option<&'a Value>, key: &str) -> Option<&'a str> {
    params.and_then(|p| p.get(key)).and_then(Value::as_str)
}

/// Substitute `{arg}` placeholders from `params.arguments`, in ONE pass over the template: an
/// argument's value is never read for placeholders, and an unknown placeholder is left as written.
/// Only string arguments substitute.
#[must_use]
pub fn substitute_arguments(template: &str, params: Option<&Value>) -> String {
    let Some(args) = params
        .and_then(|p| p.get("arguments"))
        .and_then(Value::as_object)
    else {
        return template.to_string();
    };
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            out.push_str(&rest[open..]);
            return out;
        };
        let name = &after[..close];
        match args.get(name).and_then(Value::as_str) {
            Some(text) => out.push_str(text),
            None => {
                out.push('{');
                out.push_str(name);
                out.push('}');
            }
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

/// The `messages` a prompt renders, in whichever form the operator declared: substituted first,
/// normalised second. Media payloads are opaque and pass untouched.
fn render_messages(prompt: &PromptEntry, params: Option<&Value>) -> Vec<Value> {
    let render = |s: &str| normalise(&substitute_arguments(s, params));
    if prompt.messages.is_empty() {
        return vec![json!({
            "role": "user",
            "content": {
                "type": "text",
                "text": render(prompt.template.as_deref().unwrap_or("")),
            },
        })];
    }
    prompt
        .messages
        .iter()
        .map(|m| {
            let content = match &m.content {
                PromptContentCfg::Text { text } => json!({ "type": "text", "text": render(text) }),
                PromptContentCfg::Image { data, mime_type } => {
                    json!({ "type": "image", "data": data, "mimeType": mime_type })
                }
                PromptContentCfg::Audio { data, mime_type } => {
                    json!({ "type": "audio", "data": data, "mimeType": mime_type })
                }
                PromptContentCfg::Resource { resource } => {
                    let mut r = Map::new();
                    r.insert("uri".into(), render(&resource.uri).into());
                    if let Some(m) = &resource.mime_type {
                        r.insert("mimeType".into(), m.clone().into());
                    }
                    if let Some(t) = &resource.text {
                        r.insert("text".into(), render(t).into());
                    }
                    if let Some(b) = &resource.blob {
                        r.insert("blob".into(), b.clone().into());
                    }
                    json!({ "type": "resource", "resource": r })
                }
            };
            json!({ "role": m.role, "content": content })
        })
        .collect()
}

/// The prompt `params.name` names, under the caller's grants.
///
/// # Errors
///
/// `400` + `-32602` without a string `params.name`; `404` + `-32000` for a prompt that does not
/// exist or is not the caller's, in one sentence.
pub fn prompt_named<'c>(
    catalogue: &'c Catalogue,
    id: &Value,
    params: Option<&Value>,
    admit: &impl Fn(&str, &str) -> bool,
) -> Result<&'c PromptEntry, Refusal> {
    let Some(name) = string_param(params, "name") else {
        return Err(refusal(
            crate::checks::STATUS,
            id,
            CODE_INVALID_PARAMS,
            "`params.name` is required and must be a string.".to_string(),
            None,
        ));
    };
    catalogue.prompt_for(admit, name).ok_or_else(|| {
        refusal(
            STATUS_NOT_FOUND,
            id,
            CODE_REFUSED,
            format!("`{name}` is not a prompt this server exposes."),
            None,
        )
    })
}

/// `prompts/get`'s answer for a prompt [`prompt_named`] found.
#[must_use]
pub fn prompts_get(prompt: &PromptEntry, id: &Value, params: Option<&Value>) -> Vec<u8> {
    complete(
        id,
        json!({
            "description": normalise_opt(prompt.description.as_deref()),
            "messages": render_messages(prompt, params),
        }),
    )
}

fn concrete_content(res: &ResourceEntry) -> Value {
    let mut content = Map::new();
    content.insert("uri".into(), res.uri.clone().into());
    if let Some(m) = &res.mime_type {
        content.insert("mimeType".into(), m.clone().into());
    }
    match &res.blob {
        Some(blob) => {
            content.insert("blob".into(), blob.clone().into());
        }
        None => {
            content.insert(
                "text".into(),
                normalise(res.text.as_deref().unwrap_or("")).into(),
            );
        }
    }
    Value::Object(content)
}

fn templated_content(
    requested: &str,
    template: &ResourceTemplateEntry,
    bindings: &BTreeMap<String, String>,
) -> Value {
    let mut text = template.text.clone().unwrap_or_default();
    for (name, value) in bindings {
        text = text.replace(&format!("{{{name}}}"), value);
    }
    let mut content = Map::new();
    content.insert("uri".into(), requested.into());
    if let Some(m) = &template.mime_type {
        content.insert("mimeType".into(), m.clone().into());
    }
    content.insert("text".into(), normalise(&text).into());
    Value::Object(content)
}

fn ambiguous(id: &Value, uri: &str, candidates: &[String]) -> Refusal {
    refusal(
        STATUS_CONFLICT,
        id,
        CODE_REFUSED,
        format!(
            "`{uri}` is answered by more than one approval you are granted ({}). \
             Narrow the grant so exactly one of them applies.",
            candidates.join(", ")
        ),
        Some(json!({ "reason": "resource_ambiguous", "candidates": candidates })),
    )
}

/// `resources/read`: a concrete approval first, a template second, never a guess between two.
///
/// # Errors
///
/// `400` + `-32602` without a string `params.uri`; `409` + `-32000` for an ambiguity; `404` +
/// `-32000` for a uri nothing the caller may see answers.
pub fn resources_read(
    catalogue: &Catalogue,
    id: &Value,
    params: Option<&Value>,
    admit: &impl Fn(&str, &str) -> bool,
) -> Result<Vec<u8>, Refusal> {
    let Some(uri) = string_param(params, "uri") else {
        return Err(refusal(
            crate::checks::STATUS,
            id,
            CODE_INVALID_PARAMS,
            "`params.uri` is required and must be a string.".to_string(),
            None,
        ));
    };
    let content = match catalogue.resource_by_uri(admit, uri) {
        Lookup::One(res) => concrete_content(res),
        Lookup::Ambiguous(candidates) => return Err(ambiguous(id, uri, &candidates)),
        Lookup::NotFound => match catalogue.resource_template_for(admit, uri) {
            Lookup::One((template, bindings)) => templated_content(uri, template, &bindings),
            Lookup::Ambiguous(candidates) => return Err(ambiguous(id, uri, &candidates)),
            Lookup::NotFound => {
                return Err(refusal(
                    STATUS_NOT_FOUND,
                    id,
                    CODE_REFUSED,
                    format!("`{uri}` is not a resource this server exposes."),
                    None,
                ))
            }
        },
    };
    let mut result = json!({ "contents": [content] });
    if let Some(obj) = result.as_object_mut() {
        obj.insert("cacheScope".into(), crate::catalogue::CACHE_SCOPE.into());
        obj.insert("ttlMs".into(), crate::catalogue::CACHE_TTL_MS.into());
    }
    Ok(complete(id, result))
}

#[cfg(test)]
#[path = "tests/reads.rs"]
mod tests;
