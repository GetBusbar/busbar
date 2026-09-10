// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CATALOGUE AS DATA: one row per approved capability, as this plane holds it.
//!
//! ## What a row is
//!
//! A listing of this protocol is a walk over what the operator approved, minus what the caller may
//! not see, minus what is quarantined, rendered. The walk, the grant and the trust filter are units'
//! and the kernel's; the RENDERED ROW is data, and data is what a plane may hold. So a row carries
//! exactly three things: which of the four catalogues it belongs to, the two coordinates a grant
//! names it by — the server and the published name — and the wire form the row is written onto a
//! listing as.
//!
//! ## Where a row comes from
//!
//! A row is the body of one record under [`crate::records::SCHEMA_CATALOGUE`], which is the schema
//! [`crate::served::Reads::CatalogueSnapshot`] already declares the listings are composed from. The
//! grammar of that body is THIS module's — a plane declares its own schemas and the shape of what
//! sits under them — and the composition root writes rows in it and reads them back through the
//! record leg. What the root writes them FROM is the root's business: today it is the protocol's
//! existing catalogue snapshot, rendered once at assembly, so a row's wire form is the existing
//! server's own rendering by construction rather than a second one written here.
//!
//! ## What is deliberately NOT on a row
//!
//! No entitlement decision and no trust state. A row says which grant names it and not whether the
//! caller holds that grant; that is the scope walk's answer, made per caller, and a row that carried
//! it would be a row composed for one caller and served to another. Quarantine is a fact about a
//! live sighting rather than about an approval, so it is not on the row either — which is exactly
//! why the one listing that reads it is not composed from rows alone. See `served.rs`.

use serde_json::Value;

/// Which of the four catalogues a row belongs to.
///
/// Four and not one, because the four listings are four answers under four members and a client
/// reads the member rather than the request. A row of the wrong kind on a listing is a row of
/// another protocol's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowKind {
    /// An approved tool, listed under `tools`.
    Tool,
    /// An approved prompt, listed under `prompts`.
    Prompt,
    /// An approved concrete resource, listed under `resources`.
    Resource,
    /// An approved resource template, listed under `resourceTemplates`.
    ResourceTemplate,
}

impl RowKind {
    /// Every kind, in the order the four listings are declared.
    pub const ALL: &'static [RowKind] = &[
        RowKind::Tool,
        RowKind::Prompt,
        RowKind::Resource,
        RowKind::ResourceTemplate,
    ];

    /// The kind as the record body spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RowKind::Tool => "tool",
            RowKind::Prompt => "prompt",
            RowKind::Resource => "resource",
            RowKind::ResourceTemplate => "resource_template",
        }
    }

    /// The kind a record body spells, or `None` for a word this grammar does not have.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        RowKind::ALL.iter().copied().find(|k| k.as_str() == word)
    }
}

/// THE TWO GRANT KINDS EVERY ROW IS NAMED BY, in the order an operator reads them.
///
/// `mcp_server` is "may this caller reach this upstream at all" and `mcp_tool` is "may it reach
/// this capability", and BOTH are required for every kind of row alike — a prompt is a capability
/// of a server, so a caller with no reach to the server has no reach to its prompts. The pair is
/// the protocol's grant vocabulary and is stated here so the root's walk over rows and the existing
/// server's walk over entries name the same two kinds by construction; the root pins the two
/// spellings against the server's own constants.
pub const SCOPE_KIND_SERVER: &str = "mcp_server";
/// The second grant kind: the published name, for every kind of row. See [`SCOPE_KIND_SERVER`].
pub const SCOPE_KIND_TOOL: &str = "mcp_tool";

/// The member of the record body that carries the kind.
pub const MEMBER_KIND: &str = "kind";
/// The member that carries the registered server the row belongs to — the first grant coordinate.
pub const MEMBER_SERVER: &str = "server";
/// The member that carries the published name — the second grant coordinate, and the value an
/// `mcp_tool` grant names for every one of the four kinds.
pub const MEMBER_NAME: &str = "name";
/// The member that carries the row's wire form, exactly as a listing writes it.
pub const MEMBER_WIRE: &str = "wire";

/// One catalogue row, as this plane holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// Which catalogue this row is on.
    pub kind: RowKind,
    /// The registered server the capability belongs to. What an `mcp_server` grant names.
    pub server: String,
    /// The published, namespaced name. What an `mcp_tool` grant names, for every kind alike.
    pub name: String,
    /// The row as a listing writes it. Rendered ONCE, where the row was written, and carried
    /// verbatim: this plane neither re-renders it nor reads into it.
    pub wire: Value,
}

impl Row {
    /// The record body for this row, in this module's grammar.
    ///
    /// # Errors
    /// The wire form could not be serialised, which a value built by a serialiser cannot fail at;
    /// the arm exists so a row is never written as a truncated body.
    pub fn encode(&self) -> Result<Vec<u8>, busbar_contract::wire::Encode> {
        let body = serde_json::json!({
            MEMBER_KIND: self.kind.as_str(),
            MEMBER_SERVER: self.server,
            MEMBER_NAME: self.name,
            MEMBER_WIRE: self.wire,
        });
        serde_json::to_vec(&body).map_err(|_| busbar_contract::wire::Encode::Unrepresentable)
    }

    /// One row read back out of a record body, or `None` for a body that is not one.
    ///
    /// `None` rather than an error, and rather than a partial row: a record under this schema that
    /// is not in this grammar is a record this plane did not write, and the honest reading of it is
    /// that it is not a row — a listing composed with it in would be a listing composed from bytes
    /// nobody vouched for.
    #[must_use]
    pub fn decode(body: &[u8]) -> Option<Row> {
        let value: Value = serde_json::from_slice(body).ok()?;
        let object = value.as_object()?;
        let kind = RowKind::parse(object.get(MEMBER_KIND)?.as_str()?)?;
        let server = object.get(MEMBER_SERVER)?.as_str()?.to_string();
        let name = object.get(MEMBER_NAME)?.as_str()?.to_string();
        let wire = object.get(MEMBER_WIRE)?.clone();
        Some(Row {
            kind,
            server,
            name,
            wire,
        })
    }

    /// Every row a record scan handed back, in the scan's order, skipping bodies that are not rows.
    #[must_use]
    pub fn decode_all<B: AsRef<[u8]>>(bodies: &[B]) -> Vec<Row> {
        bodies
            .iter()
            .filter_map(|body| Row::decode(body.as_ref()))
            .collect()
    }
}

/// The wire forms of every row of one kind, in row order.
///
/// The one projection a listing is composed by, written once so the four listings cannot disagree
/// about what "the rows of this kind" means. The ORDER is the rows' own, never re-sorted here: the
/// root hands rows in the order the existing catalogue lists them, and a listing that re-sorted
/// would be a listing whose order nobody re-derived.
#[must_use]
pub fn wire_of(rows: &[Row], kind: RowKind) -> Vec<Value> {
    rows.iter()
        .filter(|row| row.kind == kind)
        .map(|row| row.wire.clone())
        .collect()
}

#[cfg(test)]
#[path = "tests/catalogue.rs"]
mod tests;
