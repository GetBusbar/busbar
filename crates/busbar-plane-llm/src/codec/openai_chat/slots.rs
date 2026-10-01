// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The irregular half of the Q57 typed IR request slots on the OpenAI Chat Completions wire
//! (ir-slots-landed.md). The flat members (`metadata`, `service_tier`, `store`,
//! `safety_identifier`, `prompt_cache_key`, `verbosity`) are rows in `fields.rs`, walked by
//! `codec::carry`; what stays here is code no row can state, each case named:
//!
//! | Chat member                | IR slot                      | Why it is code |
//! |----------------------------|------------------------------|----------------|
//! | `modalities`               | `IrRequest::output_modalities` (IR-19) | `audio` needs the `audio` member |
//! | `web_search_options`       | `IrRequest::hosted_tools` (`WebSearch`, IR-11) | one search per request, nested location |
//! | `tool_choice.allowed_tools`| `IrRequest::allowed_tools` + `tool_choice` (IR-10) | tool-choice semantics |
//! | `tools[]` `custom` entries | `IrRequest::hosted_tools` (`Custom`, OAI-09) | a tools-array entry |
//!
//! Same-dialect fidelity: a value the typed slot cannot hold exactly (a non-string metadata value,
//! an unknown tier word, an unknown `web_search_options` member) is parked RAW in `extra` by the
//! walker; `extra` is written last (it wins on the same dialect) and is cleared on the
//! cross-protocol seam, where the typed slot is what crosses.

use crate::codec::ir::{
    IrHostedTool, IrModality, IrRequest, IrToolChoice, IrUserLocation, IrVerbosity, IrWebSearch,
};

/// The `tool_choice.type` of a Chat allowed-tools subset.
const TOOL_CHOICE_ALLOWED_TOOLS: &str = "allowed_tools";

/// IR-10: the allowed-tools subset of `tool_choice`, then the `tool_choice` fidelity park.
/// `tool_choice` is modeled by the reader's own `read_openai_tool_choice`; a shape neither that nor
/// the allowed-tools read understands (a `custom` tool target, a future type) would be dropped even
/// OpenAI→OpenAI, so it rides `extra` raw.
pub(super) fn read_tool_choice_slots(
    obj: &serde_json::Map<String, serde_json::Value>,
    ir: &mut IrRequest,
) {
    if let Some((names, mode)) = obj.get("tool_choice").and_then(read_allowed_tools) {
        ir.allowed_tools = Some(names);
        ir.tool_choice = Some(mode);
    }
    if let Some(raw) = obj.get("tool_choice") {
        if write_tool_choice(ir).as_ref() != Some(raw) {
            ir.extra.insert("tool_choice".to_string(), raw.clone());
        }
    }
}

/// OAI-09: a Chat `{"type":"custom","custom":{name, description?, format?}}`
/// tool → the typed custom hosted tool; `None` for any other tool, or a custom tool carrying a
/// member the IR cannot hold (it stays the raw same-protocol tool).
pub(super) fn read_custom_tool(tool: &serde_json::Value) -> Option<IrHostedTool> {
    let obj = tool.as_object()?;
    if obj.get("type").and_then(|t| t.as_str()) != Some("custom")
        || obj.keys().any(|k| k != "type" && k != "custom")
    {
        return None;
    }
    crate::codec::ir::IrCustomTool::read_members(obj.get("custom")?.as_object()?, &[])
        .map(IrHostedTool::Custom)
}

/// The `tools[]` entries for the IR's custom tools, in the Chat spelling.
pub(super) fn write_custom_tools(req: &IrRequest) -> Vec<serde_json::Value> {
    req.hosted_tools
        .iter()
        .filter_map(|t| match t {
            IrHostedTool::Custom(c) => Some(serde_json::json!({
                "type": "custom",
                "custom": serde_json::Value::Object(c.write_members()),
            })),
            _ => None,
        })
        .collect()
}

/// The hosted-tool kinds the Chat writer cannot express (for `dropped_egress_controls`).
pub(super) fn dropped_hosted_kinds(req: &IrRequest) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for tool in &req.hosted_tools {
        if matches!(
            tool,
            IrHostedTool::CodeExecution | IrHostedTool::WebFetch(_)
        ) {
            let k = tool.kind_str();
            if !out.contains(&k) {
                out.push(k);
            }
        }
    }
    out
}

/// The Chat `tool_choice` the writer emits for `req` (before its no-tools guard): the allowed-tools
/// subset when one is set (IR-10), else the plain directive.
pub(super) fn write_tool_choice(req: &IrRequest) -> Option<serde_json::Value> {
    if let Some(names) = &req.allowed_tools {
        let mode = match req.tool_choice {
            Some(IrToolChoice::Required) => "required",
            _ => "auto",
        };
        let tools: Vec<serde_json::Value> = names
            .iter()
            .map(
                |n| serde_json::json!({"type": super::TOOL_TYPE_FUNCTION, "function": {"name": n}}),
            )
            .collect();
        return Some(serde_json::json!({
            "type": TOOL_CHOICE_ALLOWED_TOOLS,
            TOOL_CHOICE_ALLOWED_TOOLS: {"mode": mode, "tools": tools},
        }));
    }
    Some(match req.tool_choice.as_ref()? {
        IrToolChoice::Auto => serde_json::json!("auto"),
        IrToolChoice::None => serde_json::json!("none"),
        IrToolChoice::Required => serde_json::json!("required"),
        IrToolChoice::Tool { name } => {
            serde_json::json!({"type": super::TOOL_TYPE_FUNCTION, "function": {"name": name}})
        }
    })
}

/// Hook (`modalities`, IR-19): every entry must be a known word, else the slot is left absent.
pub(super) fn read_modalities(v: &serde_json::Value, ir: &mut IrRequest) {
    ir.output_modalities = v.as_array().and_then(|arr| {
        arr.iter()
            .map(|m| m.as_str().and_then(IrModality::parse))
            .collect()
    });
}

/// Hook (`modalities`, IR-19). Chat accepts `text` and `audio`. `audio` output also REQUIRES the
/// `audio` request member (the voice and format), which is a vendor catalogue the IR does not carry
/// — so it is written only when the Chat caller's own `audio` member rides alongside (same
/// dialect); cross-protocol it is dropped with a warn rather than sent as a request OpenAI rejects.
/// `image` has no Chat output modality.
pub(super) fn write_modalities(req: &IrRequest) -> Option<serde_json::Value> {
    let has_audio_member = req.extra.contains_key("audio");
    let mut out: Vec<serde_json::Value> = Vec::new();
    for m in req.output_modalities.as_deref()? {
        match m {
            IrModality::Text => out.push(serde_json::json!(m.as_str())),
            IrModality::Audio if has_audio_member => out.push(serde_json::json!(m.as_str())),
            IrModality::Audio | IrModality::Image => {
                tracing::warn!(
                    modality = m.as_str(),
                    "dropping an output modality on OpenAI Chat egress: Chat produces image output \
                     never, and audio output only beside its own `audio` request member, which \
                     does not cross dialects"
                );
            }
        }
    }
    (!out.is_empty()).then_some(serde_json::Value::Array(out))
}

/// Hook (`web_search_options`, IR-11): Chat `web_search_options{search_context_size,
/// user_location:{type:"approximate", approximate:{city, region, country, timezone}}}` → the
/// neutral web search.
pub(super) fn read_web_search(v: &serde_json::Value, ir: &mut IrRequest) {
    let Some(o) = v.as_object() else {
        return;
    };
    let search_context_size = o
        .get("search_context_size")
        .and_then(|s| s.as_str())
        .and_then(IrVerbosity::parse);
    let user_location = o
        .get("user_location")
        .and_then(|l| l.get("approximate"))
        .and_then(|a| a.as_object())
        .map(|a| {
            let s = |k: &str| a.get(k).and_then(|v| v.as_str()).map(String::from);
            IrUserLocation {
                city: s("city"),
                region: s("region"),
                country: s("country"),
                timezone: s("timezone"),
            }
        });
    ir.hosted_tools.push(IrHostedTool::WebSearch(IrWebSearch {
        search_context_size,
        user_location,
        ..Default::default()
    }));
}

/// Hook (`web_search_options`, IR-11): the first hosted web search, in Chat's one member. A second
/// search, and every hosted kind Chat has no built-in for, is dropped with a warn; a custom tool is
/// a `tools[]` entry (`write_custom_tools`), not this member.
pub(super) fn write_web_search(req: &IrRequest) -> Option<serde_json::Value> {
    let mut written = None;
    for tool in &req.hosted_tools {
        match tool {
            IrHostedTool::WebSearch(ws) if written.is_none() => {
                written = Some(web_search_options(ws));
            }
            IrHostedTool::WebSearch(_) => {
                tracing::warn!(
                    "dropping a second hosted web search on OpenAI Chat egress: Chat has one \
                     `web_search_options` member per request"
                );
            }
            IrHostedTool::CodeExecution | IrHostedTool::WebFetch(_) => {
                tracing::warn!(
                    hosted_tool = tool.kind_str(),
                    "dropping a hosted tool on OpenAI Chat egress: Chat Completions has no \
                     built-in tool of this kind (only web search, as `web_search_options`)"
                );
            }
            IrHostedTool::Custom(_) => {}
        }
    }
    written
}

/// One web search as `web_search_options`. `max_uses` and the domain filters have no Chat member:
/// they are dropped with a warn and the search itself is kept.
fn web_search_options(ws: &IrWebSearch) -> serde_json::Value {
    if ws.max_uses.is_some() || !ws.allowed_domains.is_empty() || !ws.blocked_domains.is_empty() {
        tracing::warn!(
            "dropping web search max_uses / domain filters on OpenAI Chat egress: \
             `web_search_options` has no member for them; the search itself is kept"
        );
    }
    let mut o = serde_json::Map::new();
    if let Some(size) = ws.search_context_size {
        o.insert(
            "search_context_size".to_string(),
            serde_json::json!(size.as_str()),
        );
    }
    if let Some(loc) = &ws.user_location {
        let mut a = serde_json::Map::new();
        for (k, v) in [
            ("city", &loc.city),
            ("region", &loc.region),
            ("country", &loc.country),
            ("timezone", &loc.timezone),
        ] {
            if let Some(v) = v {
                a.insert(k.to_string(), serde_json::json!(v));
            }
        }
        o.insert(
            "user_location".to_string(),
            serde_json::json!({"type": "approximate", "approximate": serde_json::Value::Object(a)}),
        );
    }
    serde_json::Value::Object(o)
}

/// Chat `tool_choice:{type:"allowed_tools", allowed_tools:{mode, tools:[{type:"function",
/// function:{name}}]}}` → (the FUNCTION tool names, the directive). A `custom` tool entry has no
/// cross-dialect tool to name (OAI-09), so it is not listed; a subset with no function tool left is
/// not a subset at all.
fn read_allowed_tools(v: &serde_json::Value) -> Option<(Vec<String>, IrToolChoice)> {
    if v.get("type").and_then(|t| t.as_str()) != Some(TOOL_CHOICE_ALLOWED_TOOLS) {
        return None;
    }
    let at = v.get(TOOL_CHOICE_ALLOWED_TOOLS)?;
    let mode = match at.get("mode").and_then(|m| m.as_str())? {
        "auto" => IrToolChoice::Auto,
        "required" => IrToolChoice::Required,
        _ => return None,
    };
    let names: Vec<String> = at
        .get("tools")?
        .as_array()?
        .iter()
        .filter(|t| t.get("type").and_then(|x| x.as_str()) == Some(super::TOOL_TYPE_FUNCTION))
        .filter_map(|t| {
            t.get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
                .map(String::from)
        })
        .collect();
    (!names.is_empty()).then_some((names, mode))
}
