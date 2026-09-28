//! The operation vocabulary: which `(method, path)` is which priced operation.
//!
//! jev serves exactly two operations, both byte-identity passthrough to `api.typesafe.ai`
//! (JEV-DESIGN-SIGNED-v4.md, "C-6 REVERSED"): the decision call and the model catalogue. Unlike
//! MCP/A2A, which name their operation in a JSON-RPC method member, jev names it in the HTTP verb
//! and path — so the table below is keyed on those, read off the transport's own reserved facts
//! (`busbar_contract::transport::facts::PATH`/`METHOD`), the same seam `busbar-plane-a2a`'s
//! `surface_of` reads.

use busbar_contract::ids::OpClassId;

/// `POST /v1/systemone` — the decision call. Priced on the request it carries and metered on the
/// usage the SUCCESS response reports (billable-success only, per the signed design's C-3).
pub const OP_SYSTEMONE: OpClassId = OpClassId::new("systemone");

/// `GET /v1/models` — the provider's own model catalogue, relayed byte-identically. No busbar
/// catalogue synthesis: this is typesafe's list, and only this plane may serve it.
pub const OP_MODELS: OpClassId = OpClassId::new("models");

/// Every operation class this plane's units can be, in declaration order.
pub const OP_CLASSES: &[OpClassId] = &[OP_SYSTEMONE, OP_MODELS];

/// The path jev's decision call is mounted on.
pub const PATH_SYSTEMONE: &str = "/v1/systemone";

/// The path jev's model catalogue is mounted on.
pub const PATH_MODELS: &str = "/v1/models";

/// One row of the method table: which `(verb, path)` is which operation, and whether the request
/// carries a body this plane must wait for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MethodRow {
    /// The operation class this row declares.
    pub op: OpClassId,
    /// The HTTP verb the request arrives as.
    pub verb: &'static str,
    /// The path the request arrives on.
    pub path: &'static str,
    /// Whether this operation's REQUEST carries a body this plane must read before it is complete.
    /// `systemone` is a POST with a JSON body; `models` is a bodyless GET.
    pub has_request_body: bool,
}

/// The method table, in declaration order.
pub const METHODS: &[MethodRow] = &[
    MethodRow {
        op: OP_SYSTEMONE,
        verb: "POST",
        path: PATH_SYSTEMONE,
        has_request_body: true,
    },
    MethodRow {
        op: OP_MODELS,
        verb: "GET",
        path: PATH_MODELS,
        has_request_body: false,
    },
];

/// Which row a `(verb, path)` pair names, where one does.
///
/// The path match is exact — jev's two surfaces are both fixed paths, not a pattern family the way
/// A2A's task collection is — so there is no most-specific-wins question to settle here.
#[must_use]
pub fn row_for(verb: &str, path: &str) -> Option<&'static MethodRow> {
    METHODS
        .iter()
        .find(|r| r.path == path && r.verb.eq_ignore_ascii_case(verb))
}

#[cfg(test)]
#[path = "tests/ops.rs"]
mod tests;
