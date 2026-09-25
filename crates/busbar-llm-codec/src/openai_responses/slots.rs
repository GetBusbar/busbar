// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Responses spelling of the Q57 typed IR slots (ir-slots-landed.md): what the reader FILLS and
//! the writer EMITS for each request / block slot the Responses dialect can carry. Every helper here
//! returns the ABSENT value for an absent wire member, so a request that never carried a concept
//! gains nothing on the wire.

use super::*;

/// IR-03. The Responses `metadata` map (string -> string) in the caller's key order. `None` when
/// absent or when the member is not a string-valued object (the raw member still rides `extra` for a
/// same-protocol relay; a mis-typed map is not re-shaped into something the caller never sent).
pub(super) fn read_metadata(v: Option<&serde_json::Value>) -> Option<Vec<(String, String)>> {
    let obj = v?.as_object()?;
    obj.iter()
        .map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
        .collect()
}

/// IR-03 writer half: the metadata map back as a JSON object.
pub(super) fn write_metadata(pairs: &[(String, String)]) -> serde_json::Value {
    serde_json::Value::Object(
        pairs
            .iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect(),
    )
}

/// A string-valued top-level member (IR-06 `safety_identifier` / `prompt_cache_key`).
pub(super) fn read_string(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<String> {
    obj.get(key).and_then(|v| v.as_str()).map(String::from)
}

/// IR-08. `input_image.detail` → the IR detail. An unknown word is dropped with a warn rather than
/// coerced onto a fidelity the caller did not ask for.
pub(super) fn read_image_detail(item: &serde_json::Value) -> Option<crate::ir::IrImageDetail> {
    let word = item.get("detail").and_then(|d| d.as_str())?;
    let detail = crate::ir::IrImageDetail::parse(word);
    if detail.is_none() {
        tracing::warn!(
            detail = word,
            "dropping unknown input_image.detail on Responses ir parse: the word is not one of \
             auto/low/high; the image survives, its detail hint does not"
        );
    }
    detail
}

/// IR-17. Which reasoning array a Responses `reasoning` item filled: `content[]` alone is the full
/// reasoning, `summary[]` alone is a summary. Both (or neither) → `None`: the reader keeps its
/// concatenated text and no writer is told a kind the item did not have.
pub(super) fn reasoning_kind(item: &serde_json::Value) -> Option<crate::ir::IrThinkingKind> {
    let has_text = |key: &str| {
        item.get(key).and_then(|a| a.as_array()).is_some_and(|arr| {
            arr.iter().any(|p| {
                p.get("text")
                    .and_then(|t| t.as_str())
                    .is_some_and(|t| !t.is_empty())
            })
        })
    };
    match (has_text("content"), has_text("summary")) {
        (true, false) => Some(crate::ir::IrThinkingKind::Full),
        (false, true) => Some(crate::ir::IrThinkingKind::Summary),
        _ => None,
    }
}

/// IR-17 writer half: the `summary` / `content` members of a written `reasoning` item. A `Summary`
/// block's text goes into `summary[]` (a `summary_text` part) and `content` is omitted; a `Full` or
/// unknown block keeps the pre-slot shape (`summary: []`, the text as a `reasoning_text` part).
pub(super) fn insert_reasoning_text(
    item: &mut serde_json::Map<String, serde_json::Value>,
    text: &str,
    kind: Option<crate::ir::IrThinkingKind>,
) {
    if kind == Some(crate::ir::IrThinkingKind::Summary) {
        item.insert(
            "summary".to_string(),
            serde_json::json!([{ "type": "summary_text", "text": text }]),
        );
    } else {
        item.insert("summary".to_string(), serde_json::Value::Array(Vec::new()));
        item.insert(
            "content".to_string(),
            serde_json::json!([{ "type": CONTENT_TYPE_REASONING_TEXT, "text": text }]),
        );
    }
}

/// IR-18 (RSP-13). Whether a thinking signature may be written as this dialect's
/// `encrypted_content`: only a blob OpenAI minted (or one of unknown origin — the pre-slot
/// behaviour). An Anthropic / Gemini / other-Bedrock signature is a foreign blob a Responses
/// backend cannot decrypt, so it is not sent.
pub(super) fn own_signature(origin: Option<crate::ir::IrSignatureOrigin>) -> bool {
    matches!(origin, None | Some(crate::ir::IrSignatureOrigin::OpenAi))
}

/// IR-10 (RSP-15). The Responses `tool_choice:{type:"allowed_tools", mode, tools:[…]}` form → the
/// IR `(tool_choice, allowed_tools)` pair: the names of the listed function tools, and `Auto`
/// (`mode:"auto"`, or absent) / `Required` (`mode:"required"`). `None` for any other object.
pub(super) fn read_allowed_tools(
    o: &serde_json::Map<String, serde_json::Value>,
) -> Option<(crate::ir::IrToolChoice, Vec<String>)> {
    if o.get("type").and_then(|t| t.as_str()) != Some("allowed_tools") {
        return None;
    }
    let choice = match o.get("mode").and_then(|m| m.as_str()) {
        Some("required") => crate::ir::IrToolChoice::Required,
        _ => crate::ir::IrToolChoice::Auto,
    };
    let mut names = Vec::new();
    for t in o
        .get("tools")
        .and_then(|t| t.as_array())
        .into_iter()
        .flatten()
    {
        match (
            t.get("type").and_then(|v| v.as_str()),
            t.get("name").and_then(|v| v.as_str()),
        ) {
            (Some("function"), Some(name)) => names.push(name.to_string()),
            (kind, _) => tracing::warn!(
                tool_type = kind.unwrap_or(""),
                "dropping a non-function entry from a Responses allowed_tools tool_choice on ir \
                 parse: the IR subset names function tools only"
            ),
        }
    }
    Some((choice, names))
}

/// IR-10 writer half: the subset as the Responses `allowed_tools` tool choice. `Required` →
/// `mode:"required"`; anything else (`Auto`, or no directive) → `mode:"auto"`.
pub(super) fn write_allowed_tools(
    names: &[String],
    choice: Option<&crate::ir::IrToolChoice>,
) -> serde_json::Value {
    let mode = if choice == Some(&crate::ir::IrToolChoice::Required) {
        "required"
    } else {
        "auto"
    };
    let tools: Vec<serde_json::Value> = names
        .iter()
        .map(|n| serde_json::json!({ "type": "function", "name": n }))
        .collect();
    serde_json::json!({ "type": "allowed_tools", "mode": mode, "tools": tools })
}

/// The members a Responses `web_search` tool carries that the IR models.
const WEB_SEARCH_KEYS: [&str; 4] = ["type", "filters", "user_location", "search_context_size"];

/// IR-11. A Responses hosted tool the IR models NEUTRALLY: `web_search` / `web_search_preview` →
/// `WebSearch`, `code_interpreter` on an auto container → `CodeExecution`. A tool is recognised
/// only when EVERY member it carries has an IR slot; one carrying a member the IR cannot hold (a
/// `file_search` vector store, an explicit code-interpreter container id or `file_ids`, an unknown
/// web-search member) stays the raw same-protocol `IrTool::hosted` object, which the seam drops
/// with its existing warn — never a typed tool that silently lost part of its configuration.
pub(super) fn read_hosted_tool(tool: &serde_json::Value) -> Option<crate::ir::IrHostedTool> {
    let obj = tool.as_object()?;
    match obj.get("type").and_then(|t| t.as_str())? {
        "web_search" | "web_search_preview" => {
            if obj.keys().any(|k| !WEB_SEARCH_KEYS.contains(&k.as_str())) {
                return None;
            }
            let mut ws = crate::ir::IrWebSearch::default();
            if let Some(filters) = obj.get("filters").filter(|f| !f.is_null()) {
                let fobj = filters.as_object()?;
                if fobj.keys().any(|k| k != "allowed_domains") {
                    return None;
                }
                ws.allowed_domains = fobj
                    .get("allowed_domains")
                    .and_then(|d| d.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|d| d.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
            }
            if let Some(loc) = obj.get("user_location").filter(|l| !l.is_null()) {
                let lobj = loc.as_object()?;
                let field = |k: &str| lobj.get(k).and_then(|v| v.as_str()).map(String::from);
                ws.user_location = Some(crate::ir::IrUserLocation {
                    city: field("city"),
                    region: field("region"),
                    country: field("country"),
                    timezone: field("timezone"),
                });
            }
            if let Some(size) = obj.get("search_context_size").filter(|s| !s.is_null()) {
                ws.search_context_size = Some(crate::ir::IrVerbosity::parse(size.as_str()?)?);
            }
            Some(crate::ir::IrHostedTool::WebSearch(ws))
        }
        "code_interpreter" => {
            let auto_container = obj.get("container").is_some_and(|c| {
                c.get("type").and_then(|t| t.as_str()) == Some("auto")
                    && c.as_object().is_some_and(|co| co.len() == 1)
            });
            (auto_container && obj.len() == 2).then_some(crate::ir::IrHostedTool::CodeExecution)
        }
        _ => None,
    }
}

/// IR-11 writer half: a neutral hosted tool in the Responses spelling, or `None` for a kind this
/// dialect has no tool for (`WebFetch`), dropped with a warn. A web-search field Responses cannot
/// express (`max_uses`, `blocked_domains`) is dropped with a warn and the tool is kept.
pub(super) fn write_hosted_tool(tool: &crate::ir::IrHostedTool) -> Option<serde_json::Value> {
    match tool {
        crate::ir::IrHostedTool::WebSearch(ws) => {
            let mut out = serde_json::Map::new();
            out.insert("type".to_string(), serde_json::json!("web_search"));
            if !ws.allowed_domains.is_empty() {
                out.insert(
                    "filters".to_string(),
                    serde_json::json!({ "allowed_domains": ws.allowed_domains }),
                );
            }
            if let Some(loc) = &ws.user_location {
                let mut l = serde_json::Map::new();
                l.insert("type".to_string(), serde_json::json!("approximate"));
                for (k, v) in [
                    ("city", &loc.city),
                    ("region", &loc.region),
                    ("country", &loc.country),
                    ("timezone", &loc.timezone),
                ] {
                    if let Some(v) = v {
                        l.insert(k.to_string(), serde_json::json!(v));
                    }
                }
                out.insert("user_location".to_string(), serde_json::Value::Object(l));
            }
            if let Some(size) = ws.search_context_size {
                out.insert(
                    "search_context_size".to_string(),
                    serde_json::json!(size.as_str()),
                );
            }
            if ws.max_uses.is_some() || !ws.blocked_domains.is_empty() {
                tracing::warn!(
                    "responses writer: the web_search tool models no `max_uses` / \
                     `blocked_domains`; dropping them and keeping the tool (lossy-by-target)"
                );
            }
            Some(serde_json::Value::Object(out))
        }
        crate::ir::IrHostedTool::CodeExecution => Some(serde_json::json!({
            "type": "code_interpreter",
            "container": { "type": "auto" }
        })),
        crate::ir::IrHostedTool::WebFetch(_) => {
            tracing::warn!(
                hosted_tool = tool.kind_str(),
                "responses writer: /v1/responses has no hosted URL-fetch tool; dropping it \
                 (lossy-by-target)"
            );
            None
        }
    }
}

/// IR-14 reader half: the role of the folded system entries. `Some(Developer)` / `Some(System)`
/// only when every folded `input` entry used that role AND no top-level `instructions` string was
/// folded beside them (`instructions` names no role, so a mix is unknown); `None` otherwise.
pub(super) fn system_role(
    saw_system: bool,
    saw_developer: bool,
    saw_instructions: bool,
) -> Option<crate::ir::IrSystemRole> {
    match (saw_system, saw_developer, saw_instructions) {
        (false, true, false) => Some(crate::ir::IrSystemRole::Developer),
        (true, false, false) => Some(crate::ir::IrSystemRole::System),
        _ => None,
    }
}
