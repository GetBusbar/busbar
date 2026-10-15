// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The Anthropic spelling of the Q57 typed request slots: hosted (server) tools, service tier and the slots Anthropic cannot carry.

use crate::codec::keys;

/// Versioned `type` prefixes of the Anthropic server tools whose KIND the IR models (IR-11). The
/// version suffix names Anthropic's own schema revision and is not carried; the writer picks one.
pub(super) const HOSTED_TYPE_PREFIX_WEB_SEARCH: &str = "web_search_";
pub(super) const HOSTED_TYPE_PREFIX_WEB_FETCH: &str = "web_fetch_";
pub(super) const HOSTED_TYPE_PREFIX_CODE_EXECUTION: &str = "code_execution_";

/// An Anthropic server tool of a KIND the IR models → [`crate::codec::ir::IrHostedTool`] (IR-11, ANT-13).
/// `None` for a function tool or any other Anthropic-defined tool (`bash_*`, `text_editor_*`,
/// `mcp_toolset`, …), which `read_tool` keeps as a raw same-protocol-only hosted `IrTool`.
pub(super) fn read_hosted_tool(
    tool_val: &serde_json::Value,
) -> Option<crate::codec::ir::IrHostedTool> {
    let obj = tool_val.as_object()?;
    let ty = obj.get(keys::TYPE)?.as_str()?;
    let max_uses = || {
        obj.get(super::MAX_USES)
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
            .get(keys::USER_LOCATION)
            .and_then(|v| v.as_object())
            .map(crate::codec::ir::IrUserLocation::read_members);
        Some(crate::codec::ir::IrHostedTool::WebSearch(
            crate::codec::ir::IrWebSearch {
                max_uses: max_uses(),
                allowed_domains: domains(keys::ALLOWED_DOMAINS),
                blocked_domains: domains(super::BLOCKED_DOMAINS),
                user_location,
                search_context_size: None,
            },
        ))
    } else if ty.starts_with(HOSTED_TYPE_PREFIX_WEB_FETCH) {
        Some(crate::codec::ir::IrHostedTool::WebFetch(
            crate::codec::ir::IrWebFetch {
                max_uses: max_uses(),
                allowed_domains: domains(keys::ALLOWED_DOMAINS),
                blocked_domains: domains(super::BLOCKED_DOMAINS),
            },
        ))
    } else if ty.starts_with(HOSTED_TYPE_PREFIX_CODE_EXECUTION) {
        Some(crate::codec::ir::IrHostedTool::CodeExecution)
    } else {
        None
    }
}
