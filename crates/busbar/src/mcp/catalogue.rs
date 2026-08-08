// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CATALOGUE ASSEMBLY: what tools does THIS caller have?
//!
//! `tools/list` is the CATALOGUE and it is the risky half of the plane. DISPATCH reuses machinery
//! busbar already has (pools, breakers, failover, budgets); assembling a catalogue is new work, and
//! it is where aggregation, name collision, per-caller scoping and the interaction with a
//! quarantined upstream all land at once.
//!
//! ## Three gates, in this order
//!
//! 1. TRUST. Is this tool the thing the operator approved, at the digest they approved it at? That
//!    question is [`crate::trust`]'s and it is asked through `Approval::serves`, the SAME comparison
//!    the operator's drift view uses. There is no second state machine here and there must never be
//!    one: a dispatch gate that is a separate opinion is a gate that can disagree with the screen
//!    the operator is looking at.
//! 2. UNAMBIGUOUS NAMING. `{server}_{tool}` must name exactly one thing.
//! 3. AUTHORIZATION. The caller's key scopes, and nothing else.
//!
//! Trust runs before scope on purpose. "You may not have this" and "nobody may have this yet" are
//! different operator actions, and reporting the second as the first sends them to the wrong screen.
//!
//! ## The catalogue is AUTHORIZATION, not routing
//!
//! Which tools a caller sees is decided by that caller's key scopes: `mcp_server` grants a whole
//! upstream, `mcp_tool` grants one namespaced tool. There is no filter verb in the reply contract,
//! no hook on this path and no tagging: TAGS GROUP, IDENTITY IDENTIFIES, and this function is
//! answering a question about identity. A hook participates in DISPATCH ordering, which is a
//! different path with different inputs.

use std::collections::{BTreeMap, BTreeSet};

use super::spec::{CataloguePage, ToolDefinition};
use crate::trust::{Approval, PinnedArtifact};
use serde_json::{Map, Value};

/// The longest tool name that can be a stable identifier. A name is carried in a scope grant, in an
/// audit row and in an approval record, so an unbounded one is an unbounded row in each of them.
pub(crate) const MAX_TOOL_NAME: usize = 128;

/// The caller's grants. A trait rather than a concrete key so this stays testable without
/// manufacturing a whole key record, and so the A2A plane can hand it the same shape.
pub(crate) trait ScopeCheck {
    /// The store's own semantics, unchanged: an omitted scope list is a wildcard, and a list that
    /// omits a KIND is fail-closed for that kind.
    fn scope_allowed(&self, kind: &str, value: &str) -> bool;
}

impl ScopeCheck for busbar_api::VirtualKey {
    fn scope_allowed(&self, kind: &str, value: &str) -> bool {
        // Named explicitly rather than through method syntax: with the trait in scope, `self.scope_allowed`
        // reads as though it might dispatch back into this impl.
        busbar_api::VirtualKey::scope_allowed(self, kind, value)
    }
}

/// One upstream's offer, paired with what the operator approved about it.
pub(crate) struct ServerCatalogue<'a, A: PinnedArtifact> {
    server: String,
    approval: &'a Approval<A>,
    tools: Vec<ToolDefinition>,
}

impl<'a, A: PinnedArtifact> ServerCatalogue<'a, A> {
    pub(crate) fn new(
        server: impl Into<String>,
        approval: &'a Approval<A>,
        tools: Vec<ToolDefinition>,
    ) -> Self {
        ServerCatalogue {
            server: server.into(),
            approval,
            tools,
        }
    }
}

/// One tool as the caller sees it: the BOUND IDENTITY plus the definition to show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CatalogueEntry {
    /// `{server}_{tool}`. THE ROUTING KEY, and the value an `mcp_tool` grant names.
    pub(crate) qualified_name: String,
    pub(crate) server: String,
    pub(crate) tool: String,
    /// The digest this tool is being served at, which is the digest it was approved at.
    pub(crate) digest: String,
    pub(crate) definition: ToolDefinition,
}

/// Why a tool the upstream offered is not in this caller's catalogue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Excluded {
    /// The trust lifecycle does not serve it: unapproved, drifted, rejected or suspended.
    Trust,
    /// The caller holds no grant that reaches it.
    Scope,
    /// Its namespaced name is claimed by more than one tool.
    Ambiguous,
    /// Its name cannot be a stable identifier.
    UnusableName,
}

/// One dropped tool, with its reason. Kept rather than discarded because "the tool I registered is
/// not in the list" is the question an operator asks most, and an empty catalogue with no
/// explanation is the least debuggable thing this code could produce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Exclusion {
    pub(crate) server: String,
    pub(crate) tool: String,
    pub(crate) reason: Excluded,
}

/// The assembled answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Catalogue {
    pub(crate) entries: Vec<CatalogueEntry>,
    pub(crate) excluded: Vec<Exclusion>,
}

/// A name that can be a stable identifier: non-empty, bounded, and made only of characters that
/// survive being a scope value, an audit resource and a config key unaltered.
fn usable_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_TOOL_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

/// ASSEMBLE the catalogue for one caller.
///
/// Deterministic: the output depends on the inputs and not on the order the registry iterated in.
/// That matters because the catalogue is cached per caller and compared for change, so an
/// order-dependent assembly would report drift that is not drift.
pub(crate) fn assemble<A: PinnedArtifact, S: ScopeCheck>(
    servers: &[ServerCatalogue<'_, A>],
    scopes: &S,
) -> Catalogue {
    let mut excluded: Vec<Exclusion> = Vec::new();
    // Keyed by the qualified name, so a name claimed twice is visible before anything is served.
    let mut claims: BTreeMap<String, Vec<CatalogueEntry>> = BTreeMap::new();

    for s in servers {
        for t in &s.tools {
            let drop = |reason| Exclusion {
                server: s.server.clone(),
                tool: t.name.clone(),
                reason,
            };
            if !usable_name(&s.server) || !usable_name(&t.name) {
                excluded.push(drop(Excluded::UnusableName));
                continue;
            }
            // THE TRUST GATE. Not a re-implementation of one: this is the lifecycle's own
            // comparison, so the catalogue and the operator's changes queue cannot disagree.
            let digest = digest_of(t);
            if !s.approval.serves(&t.name, &digest) {
                excluded.push(drop(Excluded::Trust));
                continue;
            }
            let qualified_name = format!("{}_{}", s.server, t.name);
            claims
                .entry(qualified_name.clone())
                .or_default()
                .push(CatalogueEntry {
                    qualified_name,
                    server: s.server.clone(),
                    tool: t.name.clone(),
                    digest,
                    definition: t.clone(),
                });
        }
    }

    let mut entries = Vec::new();
    for (qualified, mut claimants) in claims {
        if claimants.len() > 1 {
            // AMBIGUITY IS FATAL TO EVERY CLAIMANT. `{server}_{tool}` is not injective when a
            // server id contains an underscore, and picking one claimant means the tool a caller
            // reaches depends on registry order, which also lets a newly registered server SHADOW an
            // existing tool. Both are dropped, and both are reported so an operator can rename one.
            for c in claimants {
                excluded.push(Exclusion {
                    server: c.server,
                    tool: c.tool,
                    reason: Excluded::Ambiguous,
                });
            }
            continue;
        }
        let entry = claimants.remove(0);
        // THE AUTHORIZATION GATE. A grant on the SERVER reaches every tool on it; a grant on the
        // TOOL reaches exactly that one. They are alternatives rather than a conjunction: requiring
        // both would make the server kind unusable, because a key that names any scope at all is
        // fail-closed for every kind it does not name.
        let allowed = scopes.scope_allowed("mcp_server", &entry.server)
            || scopes.scope_allowed("mcp_tool", &qualified);
        if !allowed {
            excluded.push(Exclusion {
                server: entry.server,
                tool: entry.tool,
                reason: Excluded::Scope,
            });
            continue;
        }
        entries.push(entry);
    }

    entries.sort_by(|a, b| a.qualified_name.cmp(&b.qualified_name));
    excluded.sort_by(|a, b| (&a.server, &a.tool).cmp(&(&b.server, &b.tool)));
    Catalogue { entries, excluded }
}

/// THE PER-TOOL DIGEST: what the operator approves and what a refresh is compared against.
///
/// It covers everything the server said about the tool, DESCRIPTION INCLUDED. That is deliberate:
/// description injection is a real attack class, so a changed description is drift and demotes the
/// upstream pending re-approval, rather than being adopted quietly because "only the prose changed".
///
/// Object members are canonically ordered first, because JSON objects are unordered and a server
/// that re-serializes its own schema may emit the same schema with the keys in another order. If
/// that changed the digest, such a server would quarantine itself on a refresh that changed nothing.
pub(crate) fn digest_of(tool: &ToolDefinition) -> String {
    let canonical = canonicalize(&tool.to_value());
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    format!("sha256:{}", crate::sigv4::sha256_hex(&bytes))
}

/// Rebuild a value with every object's members in sorted order, recursively. Written out rather
/// than relying on the JSON map type's ordering, so the digest cannot change because a dependency
/// somewhere in the workspace turned on insertion-order maps.
fn canonicalize(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let sorted: BTreeSet<&String> = m.keys().collect();
            let mut out = Map::new();
            for k in sorted {
                out.insert(k.clone(), canonicalize(&m[k]));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

// Paging ------------------------------------------------------------------------------------------

/// What to do after a page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Collected {
    /// Ask again with these params.
    More(Value),
    /// The catalogue is complete.
    Done,
}

/// Why paging stopped early. Every arm is a peer driving our work rather than the other way round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PageError {
    /// A cursor was handed back that had already been used: a loop.
    CursorRepeated(String),
    TooManyPages {
        limit: usize,
    },
    TooManyTools {
        limit: usize,
    },
    /// The same tool name arrived on two different pages.
    DuplicateTool(String),
}

impl std::fmt::Display for PageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PageError::CursorRepeated(c) => {
                write!(
                    f,
                    "the catalogue cursor `{c}` was offered twice: a paging loop"
                )
            }
            PageError::TooManyPages { limit } => {
                write!(f, "the catalogue ran past {limit} pages")
            }
            PageError::TooManyTools { limit } => {
                write!(f, "the catalogue offered more than {limit} tools")
            }
            PageError::DuplicateTool(name) => {
                write!(f, "the catalogue offers `{name}` on more than one page")
            }
        }
    }
}

/// Collects a paginated CATALOGUE, bounded on every axis the SERVER controls.
///
/// A cursor is opaque and server-chosen, so "keep asking until it stops" is an unbounded fetch
/// driven by the peer. The repeat check catches the loop at its first cycle, which is the
/// difference between one wasted round trip and a hundred; the page and tool caps catch the
/// version of the same attack that never repeats a cursor.
pub(crate) struct PageCollector {
    tools: Vec<ToolDefinition>,
    cursors: BTreeSet<String>,
    pages: usize,
    max_pages: usize,
    max_tools: usize,
}

impl PageCollector {
    pub(crate) fn new(max_pages: usize, max_tools: usize) -> Self {
        PageCollector {
            tools: Vec::new(),
            cursors: BTreeSet::new(),
            pages: 0,
            max_pages,
            max_tools,
        }
    }

    pub(crate) fn accept(&mut self, page: CataloguePage) -> Result<Collected, PageError> {
        if self.pages >= self.max_pages {
            return Err(PageError::TooManyPages {
                limit: self.max_pages,
            });
        }
        self.pages += 1;

        if self.tools.len() + page.tools.len() > self.max_tools {
            return Err(PageError::TooManyTools {
                limit: self.max_tools,
            });
        }
        for t in &page.tools {
            if self.tools.iter().any(|had| had.name == t.name) {
                return Err(PageError::DuplicateTool(t.name.clone()));
            }
        }
        let next = page.next_params();
        let cursor = page.next_cursor.clone();
        self.tools.extend(page.tools);

        match (next, cursor) {
            (Some(params), Some(cursor)) => {
                if !self.cursors.insert(cursor.clone()) {
                    return Err(PageError::CursorRepeated(cursor));
                }
                Ok(Collected::More(params))
            }
            _ => Ok(Collected::Done),
        }
    }

    pub(crate) fn into_tools(self) -> Vec<ToolDefinition> {
        self.tools
    }
}

#[cfg(test)]
#[path = "tests/catalogue_tests.rs"]
mod catalogue_tests;
