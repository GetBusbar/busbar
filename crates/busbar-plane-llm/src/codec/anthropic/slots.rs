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

/// An Anthropic server tool of a KIND the IR models → [`crate::codec::ir::IrHostedTool`] (IR-11, ANT-13).
/// `None` for a function tool or any other Anthropic-defined tool (`bash_*`, `text_editor_*`,
/// `mcp_toolset`, …), which `read_tool` keeps as a raw same-protocol-only hosted `IrTool`.
pub(super) fn read_hosted_tool(
    tool_val: &serde_json::Value,
) -> Option<crate::codec::ir::IrHostedTool> {
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
            .map(crate::codec::ir::IrUserLocation::read_members);
        Some(crate::codec::ir::IrHostedTool::WebSearch(
            crate::codec::ir::IrWebSearch {
                max_uses: max_uses(),
                allowed_domains: domains("allowed_domains"),
                blocked_domains: domains("blocked_domains"),
                user_location,
                search_context_size: None,
            },
        ))
    } else if ty.starts_with(HOSTED_TYPE_PREFIX_WEB_FETCH) {
        Some(crate::codec::ir::IrHostedTool::WebFetch(
            crate::codec::ir::IrWebFetch {
                max_uses: max_uses(),
                allowed_domains: domains("allowed_domains"),
                blocked_domains: domains("blocked_domains"),
            },
        ))
    } else if ty.starts_with(HOSTED_TYPE_PREFIX_CODE_EXECUTION) {
        Some(crate::codec::ir::IrHostedTool::CodeExecution)
    } else {
        None
    }
}

/// [`crate::codec::ir::IrHostedTool`] → the Anthropic server-tool definition (IR-11). Anthropic accepts
/// `allowed_domains` OR `blocked_domains`, never both: a foreign source that set both keeps the
/// allow-list (the narrower constraint) and the block-list is dropped with a warn. A web-search
/// `search_context_size` has no Anthropic member and is dropped with a warn; the tool is kept.
pub(super) fn write_hosted_tool(
    tool: &crate::codec::ir::IrHostedTool,
) -> Option<serde_json::Value> {
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
        crate::codec::ir::IrHostedTool::WebSearch(ws) => {
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
                obj.insert("user_location".to_string(), loc.write_flat());
            }
            if ws.search_context_size.is_some() {
                tracing::warn!(
                    "dropping web search search_context_size on Anthropic egress: the Anthropic web \
                     search tool has no such member; the tool is kept"
                );
            }
        }
        crate::codec::ir::IrHostedTool::WebFetch(wf) => {
            obj.insert("type".to_string(), serde_json::json!(HOSTED_TOOL_WEB_FETCH));
            obj.insert("name".to_string(), serde_json::json!("web_fetch"));
            put_limits(
                &mut obj,
                wf.max_uses,
                &wf.allowed_domains,
                &wf.blocked_domains,
            );
        }
        crate::codec::ir::IrHostedTool::CodeExecution => {
            obj.insert(
                "type".to_string(),
                serde_json::json!(HOSTED_TOOL_CODE_EXECUTION),
            );
            obj.insert("name".to_string(), serde_json::json!("code_execution"));
        }
        // OAI-09: Anthropic has no free-text / grammar tool (N): dropped with a warn and reported
        // by `dropped_egress_controls`.
        crate::codec::ir::IrHostedTool::Custom(_) => {
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
