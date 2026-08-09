// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROUTING KEY: `{server}_{tool}`, and nothing else.
//!
//! `mcp-design.md` §3.0 states the one rule the whole client direction hangs on:
//!
//! > Route ONLY on bound identity = `(registered-server-id, namespaced-tool-name, schema/description
//! > hash)`. NEVER route on untrusted tool descriptions.
//!
//! This module is that rule as a TYPE. A [`ToolKey`] is the only thing dispatch resolves, the only
//! thing a scope grant names, and the only thing an audit row records. A tool's free-text
//! description is not a field of it, which is the point: a hostile description cannot influence a
//! routing decision that has no way to read one.
//!
//! ## Why the key is a PAIR that RENDERS, rather than a string that is PARSED
//!
//! `{server}_{tool}` is a rendering, and every rendering has an ambiguity question. Server `a_b`
//! offering tool `c` and server `a` offering tool `b_c` both render `a_b_c`. That is not cosmetic:
//! the rendered form is the VALUE of a `ScopeRef{kind: "mcp_tool"}` grant (§3.8), so an ambiguous
//! rendering is a grant for one tool silently admitting another — a confused deputy created by a
//! separator.
//!
//! Two ways to close it, and only one of them survives contact with real tool names. Forbidding `_`
//! in TOOL names is a non-starter: `read_file` is the design doc's own example. Forbidding `_` in
//! SERVER ids costs an operator nothing (they choose the id at registration, and `-` is right
//! there), and it makes the split at the FIRST `_` total and unambiguous. So that is the rule, it is
//! enforced at construction, and [`ToolKey::parse`] is exact rather than best-effort.
//!
//! ## What "bound identity" adds on top of the key
//!
//! The key names the tool. [`BoundIdentity`] is the key plus the schema/description DIGEST the
//! operator approved — the third component of §3.0. Dispatch validates against the bound identity,
//! not the key, so a tool whose schema drifted under a live cache is refused even though its name is
//! unchanged. The digest lives in `super::catalogue`; this module owns the naming.

use std::fmt;

/// Why a server id or tool name was refused. Both arms are construction-time refusals: a malformed
/// identity must never reach the point where it is compared against a grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NameError {
    /// A server id was empty, or a tool name was.
    Empty { what: &'static str },
    /// A server id contained `_`, which would make `{server}_{tool}` ambiguous. See the module
    /// header: this is the separator-as-confused-deputy case, refused at the door.
    ServerIdHasSeparator(String),
    /// A name carried a character that is not `[A-Za-z0-9_.-]`. Tool and server names travel in
    /// scope-grant values, header values and audit resources; a name carrying whitespace, a quote,
    /// a control character or a `/` is a name that renders differently depending on which of those
    /// it is being written into, and a value compared for equality must have exactly one spelling.
    IllegalCharacter { what: &'static str, name: String },
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NameError::Empty { what } => write!(f, "an MCP {what} may not be empty"),
            NameError::ServerIdHasSeparator(id) => write!(
                f,
                "MCP server id `{id}` contains `_`, which is the `{{server}}_{{tool}}` separator. \
                 A server id containing the separator makes the namespaced tool name ambiguous, \
                 and that name is the value of an `mcp_tool` scope grant — so the ambiguity would \
                 be a grant for one tool admitting another. Use `-` instead."
            ),
            NameError::IllegalCharacter { what, name } => write!(
                f,
                "MCP {what} `{name}` contains a character outside `[A-Za-z0-9_.-]`. This name is \
                 compared for exact equality as a scope-grant value and written into headers and \
                 audit rows, so it must have exactly one spelling."
            ),
        }
    }
}

/// The `{server}_{tool}` separator, named once so the rendering, the parse and the refusal above
/// cannot disagree about what it is.
const SEP: char = '_';

fn legal(name: &str) -> bool {
    name.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
}

/// A registered upstream MCP server's id. Validated at construction, so every later use is a
/// comparison rather than a re-check.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ServerId(String);

impl ServerId {
    pub(crate) fn new(id: &str) -> Result<Self, NameError> {
        if id.is_empty() {
            return Err(NameError::Empty { what: "server id" });
        }
        if !legal(id) {
            return Err(NameError::IllegalCharacter {
                what: "server id",
                name: id.to_string(),
            });
        }
        if id.contains(SEP) {
            return Err(NameError::ServerIdHasSeparator(id.to_string()));
        }
        Ok(Self(id.to_string()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ServerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// THE ROUTING KEY. A `(server, tool)` pair that RENDERS as `{server}_{tool}`.
///
/// It is deliberately a pair and not a string: equality is structural, so two different tools can
/// never compare equal because their renderings collided, and the rendering is derived rather than
/// stored so there is no second copy to drift.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ToolKey {
    server: ServerId,
    tool: String,
}

impl ToolKey {
    pub(crate) fn new(server: ServerId, tool: &str) -> Result<Self, NameError> {
        if tool.is_empty() {
            return Err(NameError::Empty { what: "tool name" });
        }
        if !legal(tool) {
            return Err(NameError::IllegalCharacter {
                what: "tool name",
                name: tool.to_string(),
            });
        }
        Ok(Self {
            server,
            tool: tool.to_string(),
        })
    }

    pub(crate) fn server(&self) -> &ServerId {
        &self.server
    }

    pub(crate) fn tool(&self) -> &str {
        &self.tool
    }

    /// The namespaced name: `{server}_{tool}`. THE value of an `mcp_tool` scope grant, and the name
    /// an upstream tool is exposed under.
    pub(crate) fn namespaced(&self) -> String {
        format!("{}{SEP}{}", self.server.0, self.tool)
    }

    /// Recover the pair from a rendering. EXACT, not best-effort: the split is at the FIRST `_`, and
    /// that is total because a server id may not contain one.
    ///
    /// A rendering that does not round-trip is refused rather than guessed at. This function is what
    /// a scope-grant value is read back through, so "guess" here means "admit a tool the operator
    /// did not name".
    pub(crate) fn parse(namespaced: &str) -> Result<Self, NameError> {
        let (server, tool) = namespaced
            .split_once(SEP)
            .ok_or(NameError::Empty { what: "tool name" })?;
        ToolKey::new(ServerId::new(server)?, tool)
    }
}

impl fmt::Display for ToolKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{SEP}{}", self.server.0, self.tool)
    }
}

/// THE BOUND IDENTITY of §3.0: the registered server, the namespaced tool, and the schema/
/// description digest the operator approved.
///
/// Every one of the three is authenticated state — an id the operator registered, a name derived
/// from it, and a digest the operator approved. None of them is free text an upstream chose the
/// content of at refresh time. That is the whole property, and it is why this struct has no
/// `description` field: a routing decision made over this value cannot read one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BoundIdentity {
    pub(crate) key: ToolKey,
    /// The approved `sha256:…` digest over the tool's name, description and input schema. See
    /// `super::catalogue::tool_digest`.
    pub(crate) digest: String,
}

#[cfg(test)]
#[path = "tests/identity_tests.rs"]
mod identity_tests;
