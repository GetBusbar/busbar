// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Anthropic spelling of the Q57 typed request slots: hosted (server) tools, service tier and the slots Anthropic cannot carry.

/// Versioned `type` prefixes of the Anthropic server tools whose KIND the IR models (IR-11). The
/// version suffix names Anthropic's own schema revision and is not carried; the writer picks one.
pub(super) const HOSTED_TYPE_PREFIX_WEB_SEARCH: &str = "web_search_";
pub(super) const HOSTED_TYPE_PREFIX_WEB_FETCH: &str = "web_fetch_";
pub(super) const HOSTED_TYPE_PREFIX_CODE_EXECUTION: &str = "code_execution_";

/// The server-tool versions this writer emits for a hosted tool that crossed the seam (IR-11). The
/// BASIC variants, not the newest: they are accepted by every Claude model that has the tool,
/// including the older generations and the Vertex / Foundry-hosted surfaces, which do not offer the
/// `_20260209` dynamic-filtering variants — the lane's model is not known here, and the newest
/// variant would 400 there. `code_execution_20250825` is the version every current model lists.
pub(super) const HOSTED_TOOL_WEB_SEARCH: &str = "web_search_20250305";
pub(super) const HOSTED_TOOL_WEB_FETCH: &str = "web_fetch_20250910";
pub(super) const HOSTED_TOOL_CODE_EXECUTION: &str = "code_execution_20250825";

/// An Anthropic server tool of a KIND the IR models → [`crate::ir::IrHostedTool`] (IR-11, ANT-13).
/// `None` for a function tool or any other Anthropic-defined tool (`bash_*`, `text_editor_*`,
/// `mcp_toolset`, …), which `read_tool` keeps as a raw same-protocol-only hosted `IrTool`.
pub(super) fn read_hosted_tool(tool_val: &serde_json::Value) -> Option<crate::ir::IrHostedTool> {
    let obj = tool_val.as_object()?;
    let ty = obj.get("type")?.as_str()?;
    let max_uses = || {
        obj.get("max_uses")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok())
    };
    let domains = |k: &str| -> Vec<String> {
        obj.get(k)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|d| d.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    if ty.starts_with(HOSTED_TYPE_PREFIX_WEB_SEARCH) {
        let user_location = obj
            .get("user_location")
            .and_then(|v| v.as_object())
            .map(|l| {
                let text = |k: &str| l.get(k).and_then(|v| v.as_str()).map(String::from);
                crate::ir::IrUserLocation {
                    city: text("city"),
                    region: text("region"),
                    country: text("country"),
                    timezone: text("timezone"),
                }
            });
        Some(crate::ir::IrHostedTool::WebSearch(crate::ir::IrWebSearch {
            max_uses: max_uses(),
            allowed_domains: domains("allowed_domains"),
            blocked_domains: domains("blocked_domains"),
            user_location,
            search_context_size: None,
        }))
    } else if ty.starts_with(HOSTED_TYPE_PREFIX_WEB_FETCH) {
        Some(crate::ir::IrHostedTool::WebFetch(crate::ir::IrWebFetch {
            max_uses: max_uses(),
            allowed_domains: domains("allowed_domains"),
            blocked_domains: domains("blocked_domains"),
        }))
    } else if ty.starts_with(HOSTED_TYPE_PREFIX_CODE_EXECUTION) {
        Some(crate::ir::IrHostedTool::CodeExecution)
    } else {
        None
    }
}

/// [`crate::ir::IrHostedTool`] → the Anthropic server-tool definition (IR-11). Anthropic accepts
/// `allowed_domains` OR `blocked_domains`, never both: a foreign source that set both keeps the
/// allow-list (the narrower constraint) and the block-list is dropped with a warn. A web-search
/// `search_context_size` has no Anthropic member and is dropped with a warn; the tool is kept.
pub(super) fn write_hosted_tool(tool: &crate::ir::IrHostedTool) -> Option<serde_json::Value> {
    fn put_limits(
        obj: &mut serde_json::Map<String, serde_json::Value>,
        max_uses: Option<u32>,
        allowed: &[String],
        blocked: &[String],
    ) {
        if let Some(n) = max_uses {
            obj.insert("max_uses".to_string(), serde_json::json!(n));
        }
        if !allowed.is_empty() {
            obj.insert("allowed_domains".to_string(), serde_json::json!(allowed));
            if !blocked.is_empty() {
                tracing::warn!(
                    "dropping hosted-tool blocked_domains on Anthropic egress: Anthropic accepts \
                     allowed_domains or blocked_domains, not both; the allow-list is kept"
                );
            }
        } else if !blocked.is_empty() {
            obj.insert("blocked_domains".to_string(), serde_json::json!(blocked));
        }
    }
    let mut obj = serde_json::Map::new();
    match tool {
        crate::ir::IrHostedTool::WebSearch(ws) => {
            obj.insert(
                "type".to_string(),
                serde_json::json!(HOSTED_TOOL_WEB_SEARCH),
            );
            obj.insert("name".to_string(), serde_json::json!("web_search"));
            put_limits(
                &mut obj,
                ws.max_uses,
                &ws.allowed_domains,
                &ws.blocked_domains,
            );
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
                obj.insert("user_location".to_string(), serde_json::Value::Object(l));
            }
            if ws.search_context_size.is_some() {
                tracing::warn!(
                    "dropping web search search_context_size on Anthropic egress: the Anthropic web \
                     search tool has no such member; the tool is kept"
                );
            }
        }
        crate::ir::IrHostedTool::WebFetch(wf) => {
            obj.insert("type".to_string(), serde_json::json!(HOSTED_TOOL_WEB_FETCH));
            obj.insert("name".to_string(), serde_json::json!("web_fetch"));
            put_limits(
                &mut obj,
                wf.max_uses,
                &wf.allowed_domains,
                &wf.blocked_domains,
            );
        }
        crate::ir::IrHostedTool::CodeExecution => {
            obj.insert(
                "type".to_string(),
                serde_json::json!(HOSTED_TOOL_CODE_EXECUTION),
            );
            obj.insert("name".to_string(), serde_json::json!("code_execution"));
        }
        // OAI-09: Anthropic has no free-text / grammar tool (N): dropped with a warn and reported
        // by `dropped_egress_controls`.
        crate::ir::IrHostedTool::Custom(_) => {
            tracing::warn!(
                hosted_tool = tool.kind_str(),
                "dropping an OpenAI custom tool on Anthropic egress: Anthropic has no free-text / \
                 grammar tool (lossy-by-target)"
            );
            return None;
        }
    }
    Some(serde_json::Value::Object(obj))
}

/// Anthropic request `service_tier` → IR (IR-04): `auto` → Auto, `standard_only` → Default.
pub(super) fn read_anthropic_service_tier(word: &str) -> Option<crate::ir::IrServiceTier> {
    match word {
        "auto" => Some(crate::ir::IrServiceTier::Auto),
        "standard_only" => Some(crate::ir::IrServiceTier::Default),
        _ => None,
    }
}

/// IR service tier → Anthropic request `service_tier` (IR-04): Auto / Priority → `auto` (use
/// Priority capacity when the org has it), Default → `standard_only`. Flex / Scale have no
/// Anthropic form: `None` (dropped with a warn, reported by `dropped_egress_controls`).
pub(super) fn write_anthropic_service_tier(tier: crate::ir::IrServiceTier) -> Option<&'static str> {
    match tier {
        crate::ir::IrServiceTier::Auto | crate::ir::IrServiceTier::Priority => Some("auto"),
        crate::ir::IrServiceTier::Default => Some("standard_only"),
        crate::ir::IrServiceTier::Flex | crate::ir::IrServiceTier::Scale => None,
    }
}

/// The Q57 request slots the Anthropic Messages API has no form for (ir-slots-landed.md "N" for
/// Anthropic): each one a request carries is dropped by `write_request` with a warn and reported
/// from `dropped_egress_controls`. `metadata` is the free-form map (Anthropic's `metadata` holds
/// only `user_id`, which carries as `user`); output modalities other than text have no form.
pub(super) fn anthropic_unrepresentable_slots(req: &crate::ir::IrRequest) -> Vec<&'static str> {
    let mut dropped = Vec::new();
    if req.metadata.is_some() {
        dropped.push("metadata");
    }
    if req
        .service_tier
        .is_some_and(|t| write_anthropic_service_tier(t).is_none())
    {
        dropped.push("service_tier");
    }
    if req.store.is_some() {
        dropped.push("store");
    }
    if req.safety_identifier.is_some() {
        dropped.push("safety_identifier");
    }
    if req.prompt_cache_key.is_some() {
        dropped.push("prompt_cache_key");
    }
    if req.verbosity.is_some() {
        dropped.push("verbosity");
    }
    if req
        .output_modalities
        .as_ref()
        .is_some_and(|m| m.iter().any(|x| *x != crate::ir::IrModality::Text))
    {
        dropped.push("output_modalities");
    }
    // OAI-09: an OpenAI custom tool has no Anthropic form.
    if req
        .hosted_tools
        .iter()
        .any(|t| matches!(t, crate::ir::IrHostedTool::Custom(_)))
    {
        dropped.push("custom_tool");
    }
    dropped
}
