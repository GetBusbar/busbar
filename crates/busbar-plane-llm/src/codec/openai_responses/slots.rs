// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Responses spelling of the Q57 typed IR slots (ir-slots-landed.md): what the reader FILLS and
//! the writer EMITS for each request / block slot the Responses dialect can carry. Every helper here
//! returns the ABSENT value for an absent wire member, so a request that never carried a concept
//! gains nothing on the wire.

use super::*;

/// IR-08. `input_image.detail` → the IR detail. An unknown word is dropped with a warn rather than
/// coerced onto a fidelity the caller did not ask for.
pub(super) fn read_image_detail(
    item: &serde_json::Value,
) -> Option<crate::codec::ir::IrImageDetail> {
    let word = item.get(keys::DETAIL).and_then(|d| d.as_str())?;
    let detail = crate::codec::ir::IrImageDetail::parse(word);
    if detail.is_none() {
        crate::codec::drops::writer_drop!(
            crate::codec::drops::wire("input[].content[].detail"),
            &crate::codec::diagnostics::IR_DROP_UNMODELED_KEYS,
            [detail = word,],
            "dropping unknown input_image.detail on Responses ir parse: the word is not one of \
             auto/low/high; the image survives, its detail hint does not"
        );
    }
    detail
}

/// IR-17. Which reasoning array a Responses `reasoning` item filled: `content[]` alone is the full
/// reasoning, `summary[]` alone is a summary. Both (or neither) → `None`: the reader keeps its
/// concatenated text and no writer is told a kind the item did not have.
pub(super) fn reasoning_kind(item: &serde_json::Value) -> Option<crate::codec::ir::IrThinkingKind> {
    let has_text = |key: &str| {
        item.get(key).and_then(|a| a.as_array()).is_some_and(|arr| {
            arr.iter().any(|p| {
                p.get(keys::TEXT)
                    .and_then(|t| t.as_str())
                    .is_some_and(|t| !t.is_empty())
            })
        })
    };
    match (has_text(keys::CONTENT), has_text(SUMMARY)) {
        (true, false) => Some(crate::codec::ir::IrThinkingKind::Full),
        (false, true) => Some(crate::codec::ir::IrThinkingKind::Summary),
        _ => None,
    }
}

/// IR-17 writer half: the `summary` / `content` members of a written `reasoning` item. A `Summary`
/// block's text goes into `summary[]` (a `summary_text` part) and `content` is omitted; a `Full` or
/// unknown block keeps the pre-slot shape (`summary: []`, the text as a `reasoning_text` part).
pub(super) fn insert_reasoning_text(
    item: &mut serde_json::Map<String, serde_json::Value>,
    text: &str,
    kind: Option<crate::codec::ir::IrThinkingKind>,
) {
    if kind == Some(crate::codec::ir::IrThinkingKind::Summary) {
        item.insert(
            SUMMARY.to_string(),
            serde_json::json!([{ (keys::TYPE): SUMMARY_TEXT, (keys::TEXT): text }]),
        );
    } else {
        item.insert(SUMMARY.to_string(), serde_json::Value::Array(Vec::new()));
        item.insert(
            keys::CONTENT.to_string(),
            serde_json::json!([{ (keys::TYPE): CONTENT_TYPE_REASONING_TEXT, (keys::TEXT): text }]),
        );
    }
}

/// IR-18 (RSP-13). Whether a thinking signature may be written as this dialect's
/// `encrypted_content`: only a blob OpenAI minted (or one of unknown origin — the pre-slot
/// behaviour). An Anthropic / Gemini / other-Bedrock signature is a foreign blob a Responses
/// backend cannot decrypt, so it is not sent.
pub(super) fn own_signature(origin: Option<crate::codec::ir::IrSignatureOrigin>) -> bool {
    matches!(
        origin,
        None | Some(crate::codec::ir::IrSignatureOrigin::OpenAi)
    )
}

/// IR-10 (RSP-15). The Responses `tool_choice:{type:"allowed_tools", mode, tools:[…]}` form → the
/// IR `(tool_choice, allowed_tools)` pair: the names of the listed function tools, and `Auto`
/// (`mode:"auto"`, or absent) / `Required` (`mode:"required"`). `None` for any other object.
pub(super) fn read_allowed_tools(
    o: &serde_json::Map<String, serde_json::Value>,
) -> Option<(crate::codec::ir::IrToolChoice, Vec<String>)> {
    if o.get(keys::TYPE).and_then(|t| t.as_str()) != Some(keys::ALLOWED_TOOLS) {
        return None;
    }
    let choice = match o.get(keys::MODE).and_then(|m| m.as_str()) {
        Some(keys::REQUIRED) => crate::codec::ir::IrToolChoice::Required,
        _ => crate::codec::ir::IrToolChoice::Auto,
    };
    let mut names = Vec::new();
    for t in o
        .get(keys::TOOLS)
        .and_then(|t| t.as_array())
        .into_iter()
        .flatten()
    {
        match (
            t.get(keys::TYPE).and_then(|v| v.as_str()),
            t.get(keys::NAME).and_then(|v| v.as_str()),
        ) {
            (Some(keys::FUNCTION), Some(name)) => names.push(name.to_string()),
            (kind, _) => crate::codec::drops::writer_drop!(
                crate::codec::drops::wire("tool_choice.tools[]"),
                &crate::codec::diagnostics::IR_DROP_UNMODELED_KEYS,
                [tool_type = kind.unwrap_or(""),],
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
    choice: Option<&crate::codec::ir::IrToolChoice>,
) -> serde_json::Value {
    let mode = if choice == Some(&crate::codec::ir::IrToolChoice::Required) {
        keys::REQUIRED
    } else {
        keys::AUTO
    };
    let tools: Vec<serde_json::Value> = names
        .iter()
        .map(|n| serde_json::json!({ (keys::TYPE): keys::FUNCTION, (keys::NAME): n }))
        .collect();
    serde_json::json!({ (keys::TYPE): keys::ALLOWED_TOOLS, (keys::MODE): mode, (keys::TOOLS): tools })
}

/// The members a Responses `web_search` tool carries that the IR models.
const WEB_SEARCH_KEYS: [&str; 4] = [
    keys::TYPE,
    FILTERS,
    keys::USER_LOCATION,
    keys::SEARCH_CONTEXT_SIZE,
];

/// IR-11. A Responses hosted tool the IR models NEUTRALLY: `web_search` / `web_search_preview` →
/// `WebSearch`, `code_interpreter` on an auto container → `CodeExecution`. A tool is recognised
/// only when EVERY member it carries has an IR slot; one carrying a member the IR cannot hold (a
/// `file_search` vector store, an explicit code-interpreter container id or `file_ids`, an unknown
/// web-search member) stays the raw same-protocol `IrTool::hosted` object, which the seam drops
/// with its existing warn — never a typed tool that silently lost part of its configuration.
pub(super) fn read_hosted_tool(tool: &serde_json::Value) -> Option<crate::codec::ir::IrHostedTool> {
    let obj = tool.as_object()?;
    match obj.get(keys::TYPE).and_then(|t| t.as_str())? {
        keys::WEB_SEARCH | "web_search_preview" => {
            if obj.keys().any(|k| !WEB_SEARCH_KEYS.contains(&k.as_str())) {
                return None;
            }
            let mut search = crate::codec::ir::IrWebSearch::default();
            if let Some(filters) = obj.get(FILTERS).filter(|f| !f.is_null()) {
                let fobj = filters.as_object()?;
                if fobj.keys().any(|k| k != keys::ALLOWED_DOMAINS) {
                    return None;
                }
                search.allowed_domains = fobj
                    .get(keys::ALLOWED_DOMAINS)
                    .and_then(|d| d.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|d| d.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
            }
            if let Some(loc) = obj.get(keys::USER_LOCATION).filter(|l| !l.is_null()) {
                search.user_location = Some(crate::codec::ir::IrUserLocation::read_members(
                    loc.as_object()?,
                ));
            }
            if let Some(size) = obj.get(keys::SEARCH_CONTEXT_SIZE).filter(|s| !s.is_null()) {
                search.search_context_size =
                    Some(crate::codec::ir::IrVerbosity::parse(size.as_str()?)?);
            }
            Some(crate::codec::ir::IrHostedTool::WebSearch(search))
        }
        CODE_INTERPRETER => {
            let auto_container = obj.get(keys::CONTAINER).is_some_and(|c| {
                c.get(keys::TYPE).and_then(|t| t.as_str()) == Some(keys::AUTO)
                    && c.as_object().is_some_and(|co| co.len() == 1)
            });
            (auto_container && obj.len() == 2)
                .then_some(crate::codec::ir::IrHostedTool::CodeExecution)
        }
        // OAI-09: the flat Responses custom tool.
        keys::CUSTOM => crate::codec::ir::IrCustomTool::read_members(obj, &[keys::TYPE])
            .map(crate::codec::ir::IrHostedTool::Custom),
        _ => None,
    }
}

/// IR-11 writer half: a neutral hosted tool in the Responses spelling, or `None` for a kind this
/// dialect has no tool for (`WebFetch`), dropped with a warn. A web-search field Responses cannot
/// express (`max_uses`, `blocked_domains`) is dropped with a warn and the tool is kept.
pub(super) fn write_hosted_tool(
    tool: &crate::codec::ir::IrHostedTool,
) -> Option<serde_json::Value> {
    match tool {
        crate::codec::ir::IrHostedTool::WebSearch(search) => {
            let mut out = serde_json::Map::new();
            out.insert(keys::TYPE.to_string(), serde_json::json!(keys::WEB_SEARCH));
            if !search.allowed_domains.is_empty() {
                out.insert(
                    FILTERS.to_string(),
                    serde_json::json!({ (keys::ALLOWED_DOMAINS): search.allowed_domains }),
                );
            }
            if let Some(loc) = &search.user_location {
                out.insert(keys::USER_LOCATION.to_string(), loc.write_flat());
            }
            if let Some(size) = search.search_context_size {
                out.insert(
                    keys::SEARCH_CONTEXT_SIZE.to_string(),
                    serde_json::json!(size.as_str()),
                );
            }
            if search.max_uses.is_some() || !search.blocked_domains.is_empty() {
                crate::codec::drops::writer_drop!(
                    crate::codec::drops::member("tools"),
                    &crate::codec::diagnostics::IR_DROP_UNMODELED_KEYS,
                    [],
                    "responses writer: the web_search tool models no `max_uses` / \
                     `blocked_domains`; dropping them and keeping the tool (lossy-by-target)"
                );
            }
            Some(serde_json::Value::Object(out))
        }
        crate::codec::ir::IrHostedTool::CodeExecution => Some(serde_json::json!({
            (keys::TYPE): CODE_INTERPRETER,
            (keys::CONTAINER): { (keys::TYPE): keys::AUTO }
        })),
        crate::codec::ir::IrHostedTool::WebFetch(_) => {
            crate::codec::drops::writer_drop!(
                crate::codec::drops::member("tools"),
                &crate::codec::diagnostics::IR_DROP_HOSTED_TOOLS,
                [hosted_tool = tool.kind_str(),],
                "responses writer: /v1/responses has no hosted URL-fetch tool; dropping it \
                 (lossy-by-target)"
            );
            None
        }
        // OAI-09: a custom (free-text / grammar) tool, flat on this wire.
        crate::codec::ir::IrHostedTool::Custom(c) => {
            let mut out = serde_json::Map::new();
            out.insert(keys::TYPE.to_string(), serde_json::json!(keys::CUSTOM));
            out.extend(c.write_members());
            Some(serde_json::Value::Object(out))
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
) -> Option<crate::codec::ir::IrSystemRole> {
    match (saw_system, saw_developer, saw_instructions) {
        (false, true, false) => Some(crate::codec::ir::IrSystemRole::Developer),
        (true, false, false) => Some(crate::codec::ir::IrSystemRole::System),
        _ => None,
    }
}
